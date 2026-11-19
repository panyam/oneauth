package apiauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newIntakeMux mounts MountAuthorize with a browser middleware that
// refuses every POST, standing in for CSRF protection, so a test can see
// which POSTs reach it. pushed opts the mount into PAR.
func newIntakeMux(t *testing.T, pushed core.PushedAuthorizationRequestStore) *http.ServeMux {
	t.Helper()
	appStore := core.NewInMemoryAppStore()
	require.NoError(t, seedClient(appStore, "client-x", "https://app.example/cb"))
	oa := NewOneAuth(OneAuthConfig{
		AuthorizationCodeStore: core.NewInMemoryAuthorizationCodeStore(),
		AppStore:               appStore,
	})
	mux := http.NewServeMux()
	MountAuthorize(mux, AuthorizeMountConfig{
		OneAuth:              oa,
		IssuerURL:            "https://issuer.example",
		SubjectFromRequest:   func(r *http.Request) string { return "user-1" },
		CSRFTokenFromRequest: func(r *http.Request) string { return "csrf" },
		PushedStore:          pushed,
		BrowserMiddleware: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					http.Error(w, "csrf refused", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
			})
		},
	})
	return mux
}

func postForm(mux http.Handler, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func getAuthorize(mux http.Handler, q url.Values) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	return rec
}

// redirectQuery returns the query of a redirect to the client's
// redirect_uri, failing the test if the response is anything else.
func redirectQuery(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	require.Equal(t, http.StatusFound, rec.Code, "want a redirect to the client, got body %q", rec.Body.String())
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "https://app.example/cb", loc.Scheme+"://"+loc.Host+loc.Path)
	return loc.Query()
}

// An authorization request sent as a form POST is handled like the same
// request sent by GET. OIDC Core §3.1.2.1 requires both.
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func TestAuthorizeIntake_PostedRequestIsRedirectedToGet(t *testing.T) {
	mux := newIntakeMux(t, nil)
	q := authorizeQuery(t)
	rec := postForm(mux, q)

	require.Equal(t, http.StatusSeeOther, rec.Code, "body %q", rec.Body.String())
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "/authorize", loc.Path)
	assert.Equal(t, q, loc.Query())

	follow := getAuthorize(mux, loc.Query())
	assert.Equal(t, http.StatusOK, follow.Code, "the GET renders the consent page")
	assert.Contains(t, follow.Body.String(), `value="approve"`)
}

// The consent form's own POST carries `action`, and still goes through
// the browser middleware (CSRF) to Decide. Only a POST without `action`
// is treated as a new authorization request.
func TestAuthorizeIntake_ConsentDecisionStillPassesTheBrowserMiddleware(t *testing.T) {
	mux := newIntakeMux(t, nil)
	for _, action := range []string{"approve", "deny", ""} {
		form := authorizeQuery(t)
		form.Set("action", action)
		rec := postForm(mux, form)
		assert.Equal(t, http.StatusForbidden, rec.Code, "action=%q must reach the middleware", action)
	}
}

// A posted request is redirected before any validation, so the GET that
// follows applies every check. Here an unregistered redirect_uri gets the
// error page rather than a redirect to it.
func TestAuthorizeIntake_PostedRequestIsValidatedByTheGet(t *testing.T) {
	mux := newIntakeMux(t, nil)
	q := authorizeQuery(t)
	q.Set("redirect_uri", "https://evil.example/cb")
	rec := postForm(mux, q)
	require.Equal(t, http.StatusSeeOther, rec.Code)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	follow := getAuthorize(mux, loc.Query())
	assert.Equal(t, http.StatusBadRequest, follow.Code)
	assert.Empty(t, follow.Header().Get("Location"))
}

// oneauth doesn't support request objects, so a `request` parameter is
// refused with request_not_supported, at the redirect URI, with the
// outer state. Ignoring it would lose the object's state and nonce.
// See: https://openid.net/specs/openid-connect-core-1_0.html#RequestObject (§6.1)
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthError
func TestAuthorizeIntake_RequestObjectIsRefused(t *testing.T) {
	mux := newIntakeMux(t, nil)
	q := authorizeQuery(t)
	q.Set("request", "eyJhbGciOiJub25lIn0.eyJzdGF0ZSI6ImlubmVyIn0.")

	got := redirectQuery(t, getAuthorize(mux, q))
	assert.Equal(t, "request_not_supported", got.Get("error"))
	assert.Equal(t, "state-1", got.Get("state"))
	assert.Empty(t, got.Get("code"))
}

// With no outer redirect_uri there is nowhere safe to send the error, so
// the page shows it, still naming request_not_supported.
func TestAuthorizeIntake_RequestObjectWithoutOuterRedirectURIShowsTheError(t *testing.T) {
	mux := newIntakeMux(t, nil)
	q := authorizeQuery(t)
	q.Del("redirect_uri")
	q.Set("request", "eyJhbGciOiJub25lIn0.e30.")

	rec := getAuthorize(mux, q)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, rec.Header().Get("Location"))
	assert.Contains(t, rec.Body.String(), "request_not_supported")
}

// A request_uri this server can't resolve is refused with
// request_uri_not_supported at the redirect URI (OIDC Core §6.2), when
// the outer parameters name a registered redirect URI. That covers a
// server without PAR, and a reference that isn't one PAR issued.
// See: https://openid.net/specs/openid-connect-core-1_0.html#RequestUriParameter
func TestAuthorizeIntake_UnresolvableRequestURIIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name       string
		pushed     core.PushedAuthorizationRequestStore
		requestURI string
	}{
		{"no PAR, https reference", nil, "https://rp.example/request.jwt"},
		{"no PAR, PAR-shaped reference", nil, core.PushedRequestURIPrefix + "abc"},
		{"PAR, https reference", core.NewInMemoryPushedAuthorizationRequestStore(), "https://rp.example/request.jwt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := newIntakeMux(t, tc.pushed)
			q := authorizeQuery(t)
			q.Set("request_uri", tc.requestURI)

			got := redirectQuery(t, getAuthorize(mux, q))
			assert.Equal(t, "request_uri_not_supported", got.Get("error"))
			assert.Equal(t, "state-1", got.Get("state"))
		})
	}
}

// An unknown PAR reference is still a display error: PAR requests carry
// only client_id and request_uri, so there is no trusted redirect URI.
func TestAuthorizeIntake_UnknownPushedReferenceStillShowsTheErrorPage(t *testing.T) {
	mux := newIntakeMux(t, core.NewInMemoryPushedAuthorizationRequestStore())
	rec := getAuthorize(mux, url.Values{"client_id": {"client-x"}, "request_uri": {core.PushedRequestURIPrefix + "nope"}})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unknown request_uri")
}
