package apiauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newAuthorizeMux mounts MountAuthorize against the supplied APIAuth +
// AuthorizationCodeStore + AppStore (any may be nil to opt out) and
// returns the mux. The verifier auto-approves "user-1" for tests that
// don't want to drive the consent screen.
func newAuthorizeMux(t *testing.T, autoApprove string) (*http.ServeMux, *core.InMemoryAuthorizationCodeStore) {
	t.Helper()
	codeStore := core.NewInMemoryAuthorizationCodeStore()
	appStore := core.NewInMemoryAppStore()
	require.NoError(t, seedClient(appStore, "client-x", "https://app.example/cb"))

	oa := NewOneAuth(OneAuthConfig{
		AuthorizationCodeStore: codeStore,
		AppStore:               appStore,
	})
	mux := http.NewServeMux()
	MountAuthorize(mux, AuthorizeMountConfig{
		OneAuth:              oa,
		IssuerURL:            "https://issuer.example",
		EmitIssParameter:     true,
		SubjectFromRequest:   func(r *http.Request) string { return r.Header.Get("X-Test-Subject") },
		CSRFTokenFromRequest: func(r *http.Request) string { return "csrf" },
		AutoApproveSubject:   autoApprove,
	})
	return mux, codeStore
}

func seedClient(store core.AppRegistrationStore, clientID string, redirectURIs ...string) error {
	_, err := store.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID:     clientID,
		ClientName:   "Test Client",
		RedirectURIs: redirectURIs,
	}})
	return err
}

// authorizeQuery returns a well-formed /authorize query string for the
// fixture client. Tests override specific fields via the returned
// Values before calling Encode.
func authorizeQuery(t *testing.T) url.Values {
	t.Helper()
	_, challenge := pkceFixture(t)
	return url.Values{
		"client_id":             {"client-x"},
		"redirect_uri":          {"https://app.example/cb"},
		"response_type":         {"code"},
		"scope":                 {"read"},
		"state":                 {"state-1"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
}

// TestMountAuthorize_RegistersTwoRoutes pins the mux contract — the
// helper attaches both methods so the consent + decision flow is
// complete on one mux call.
func TestMountAuthorize_RegistersTwoRoutes(t *testing.T) {
	mux, _ := newAuthorizeMux(t, "")
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/authorize?client_id=x"},
		{http.MethodPost, "/authorize"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			assert.NotEqual(t, http.StatusNotFound, w.Code, "route MUST be registered")
		})
	}
}

// TestConsent_AutoApprove_RedirectsWithCode pins the conformance-
// fixture path: AutoApproveSubject short-circuits the consent screen
// and emits a §4.1.2 success redirect with code + state + iss.
func TestConsent_AutoApprove_RedirectsWithCode(t *testing.T) {
	mux, codeStore := newAuthorizeMux(t, "user-1")

	form := authorizeQuery(t)
	r := httptest.NewRequest(http.MethodGet, "/authorize?"+form.Encode(), nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	require.Equal(t, http.StatusFound, w.Code)
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "app.example", loc.Host)
	q := loc.Query()
	require.NotEmpty(t, q.Get("code"))
	assert.Equal(t, "state-1", q.Get("state"))
	assert.Equal(t, "https://issuer.example", q.Get("iss"), "iss MUST be emitted (EmitIssParameter=true)")

	// Code was persisted and the subject was bound from
	// AutoApproveSubject.
	g, err := codeStore.GetAuthorizationCode(r.Context(), &core.GetAuthorizationCodeRequest{Code: q.Get("code")})
	require.NoError(t, err)
	assert.Equal(t, "user-1", g.Code.Subject)
}

// TestConsent_NoSubject_RedirectsToLogin pins the auth-required path:
// when SubjectFromRequest returns "" the handler bounces to login
// with the original URL preserved as `next`.
func TestConsent_NoSubject_RedirectsToLogin(t *testing.T) {
	mux, _ := newAuthorizeMux(t, "")
	form := authorizeQuery(t)
	r := httptest.NewRequest(http.MethodGet, "/authorize?"+form.Encode(), nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	require.Equal(t, http.StatusSeeOther, w.Code, "unauthenticated MUST redirect to login")
	loc, _ := url.Parse(w.Header().Get("Location"))
	assert.Equal(t, "/auth/login", loc.Path)
	assert.NotEmpty(t, loc.Query().Get("next"))
	assert.Contains(t, loc.Query().Get("next"), "client_id=client-x", "the next URL MUST round-trip the original request so the user lands back on /authorize after login")
}

// TestConsent_RendersClientNameAndScopes pins the rendered HTML
// surface — the consent screen MUST show the registered client_name
// and the requested scopes so the user can make an informed decision.
func TestConsent_RendersClientNameAndScopes(t *testing.T) {
	mux, _ := newAuthorizeMux(t, "")
	form := authorizeQuery(t)
	form.Set("scope", "read write admin")
	r := httptest.NewRequest(http.MethodGet, "/authorize?"+form.Encode(), nil)
	r.Header.Set("X-Test-Subject", "user-1")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "Test Client", "consent MUST render the registered client_name, not just the client_id")
	for _, s := range []string{"read", "write", "admin"} {
		assert.Contains(t, body, s, "consent MUST list each requested scope")
	}
	// The hidden inputs MUST round-trip the request to the decision
	// handler so the user clicking Approve preserves the state /
	// challenge / redirect_uri values.
	assert.Contains(t, body, `name="state" value="state-1"`)
	assert.Contains(t, body, `name="redirect_uri" value="https://app.example/cb"`)
}

// TestDecide_Approve_IssuesCode pins the post-consent happy path:
// POST with action=approve redirects with code + state + iss.
func TestDecide_Approve_IssuesCode(t *testing.T) {
	mux, _ := newAuthorizeMux(t, "")
	form := authorizeQuery(t)
	form.Set("action", "approve")
	r := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Test-Subject", "user-2")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	require.Equal(t, http.StatusFound, w.Code)
	loc, _ := url.Parse(w.Header().Get("Location"))
	assert.NotEmpty(t, loc.Query().Get("code"))
}

// TestDecide_Deny_RedirectsWithAccessDenied pins RFC 6749 §4.1.2.1
// — the deny path redirects to the client's redirect_uri with
// `error=access_denied` and preserved state.
func TestDecide_Deny_RedirectsWithAccessDenied(t *testing.T) {
	mux, _ := newAuthorizeMux(t, "")
	form := authorizeQuery(t)
	form.Set("action", "deny")
	r := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Test-Subject", "user-1")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	require.Equal(t, http.StatusFound, w.Code)
	loc, _ := url.Parse(w.Header().Get("Location"))
	assert.Equal(t, "access_denied", loc.Query().Get("error"))
	assert.Equal(t, "state-1", loc.Query().Get("state"), "state MUST round-trip on error per RFC 6749 §4.1.2.1")
}

// TestConsent_UnregisteredRedirect_DisplaysErrorPage pins §4.1.2.1's
// "do not redirect" rule for unregistered redirect_uri — the handler
// renders a 400 HTML error page (via the AppStore-backed allowlist)
// instead of forwarding the error to a (potentially attacker-controlled)
// redirect_uri.
func TestConsent_UnregisteredRedirect_DisplaysErrorPage(t *testing.T) {
	mux, _ := newAuthorizeMux(t, "")

	form := authorizeQuery(t)
	form.Set("redirect_uri", "https://attacker.example/cb")
	r := httptest.NewRequest(http.MethodGet, "/authorize?"+form.Encode(), nil)
	r.Header.Set("X-Test-Subject", "user-1")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	require.Equal(t, http.StatusBadRequest, w.Code, "§4.1.2.1: unregistered redirect_uri MUST NOT receive a redirect — render an error page")
	assert.NotEmpty(t, w.Body.String())
	assert.NotEqual(t, http.StatusFound, w.Code, "MUST NOT redirect to an unregistered redirect_uri")
}
