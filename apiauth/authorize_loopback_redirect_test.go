package apiauth

// Loopback redirect matching at /authorize (RFC 8252 §7.3). A native app
// registers a loopback redirect once and binds whatever ephemeral port the
// OS hands it on each login, so the AS has to accept any port there while
// still matching scheme, host, path and query exactly.
//
// References:
//   - RFC 8252 §7.3 (https://www.rfc-editor.org/rfc/rfc8252#section-7.3)
//   - RFC 8252 §8.3 (https://www.rfc-editor.org/rfc/rfc8252#section-8.3)
//   - RFC 6749 §3.1.2.2 (https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2.2)
//   - CWE-601 (https://cwe.mitre.org/data/definitions/601.html)
//   - See: https://github.com/panyam/oneauth/issues/389

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/core"
)

func TestRedirectURIMatches(t *testing.T) {
	cases := []struct {
		name, registered, requested string
		want                        bool
	}{
		{"exact https", "https://app.example/cb", "https://app.example/cb", true},
		{"https port differs", "https://app.example:8443/cb", "https://app.example:9443/cb", false},
		{"non-loopback http port differs", "http://app.example:8080/cb", "http://app.example:9090/cb", false},

		{"ipv4 loopback any port", "http://127.0.0.1:0/callback", "http://127.0.0.1:53111/callback", true},
		{"ipv4 loopback registered without port", "http://127.0.0.1/callback", "http://127.0.0.1:53111/callback", true},
		{"ipv6 loopback any port", "http://[::1]:8080/callback", "http://[::1]:53111/callback", true},
		{"localhost any port", "http://localhost:8080/callback", "http://localhost:53111/callback", true},
		{"loopback exact", "http://127.0.0.1:53111/callback", "http://127.0.0.1:53111/callback", true},
		{"loopback with query", "http://127.0.0.1/cb?x=1", "http://127.0.0.1:4000/cb?x=1", true},

		{"loopback host differs", "http://127.0.0.1:0/callback", "http://localhost:53111/callback", false},
		{"loopback path differs", "http://127.0.0.1/callback", "http://127.0.0.1:53111/other", false},
		{"loopback query differs", "http://127.0.0.1/cb?x=1", "http://127.0.0.1:4000/cb?x=2", false},
		{"loopback scheme differs", "http://127.0.0.1/callback", "https://127.0.0.1:53111/callback", false},
		{"https loopback port not relaxed", "https://127.0.0.1:8443/callback", "https://127.0.0.1:9443/callback", false},
		{"userinfo smuggling", "http://127.0.0.1/callback", "http://evil@127.0.0.1:53111/callback", false},
		{"lookalike host", "http://127.0.0.1/callback", "http://127.0.0.1.evil.example:53111/callback", false},
		{"fragment", "http://127.0.0.1/callback", "http://127.0.0.1:53111/callback#x", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, RedirectURIMatches(tc.registered, tc.requested))
		})
	}
}

func loopbackAuthorizeMux(t *testing.T, registered string) *http.ServeMux {
	t.Helper()
	appStore := core.NewInMemoryAppStore()
	require.NoError(t, seedClient(appStore, "native-cli", registered))
	mux := http.NewServeMux()
	MountAuthorize(mux, AuthorizeMountConfig{
		OneAuth: NewOneAuth(OneAuthConfig{
			AuthorizationCodeStore: core.NewInMemoryAuthorizationCodeStore(),
			AppStore:               appStore,
		}),
		IssuerURL:            "https://issuer.example",
		SubjectFromRequest:   func(r *http.Request) string { return "" },
		CSRFTokenFromRequest: func(r *http.Request) string { return "" },
		AutoApproveSubject:   "user-1",
	})
	return mux
}

func authorizeLoopback(t *testing.T, mux *http.ServeMux, redirect string) *httptest.ResponseRecorder {
	t.Helper()
	q := authorizeQuery(t)
	q.Set("client_id", "native-cli")
	q.Set("redirect_uri", redirect)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	return w
}

// A client registered with one loopback port and requesting another gets
// its code at the port it asked for.
func TestAuthorize_LoopbackRedirectAnyPort(t *testing.T) {
	mux := loopbackAuthorizeMux(t, "http://127.0.0.1:0/callback")
	w := authorizeLoopback(t, mux, "http://127.0.0.1:53111/callback")

	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:53111", loc.Host, "code goes to the requested port")
	assert.NotEmpty(t, loc.Query().Get("code"))
}

// Relaxing the port must not relax anything else: a different loopback path
// is still an unregistered redirect, rendered as an error page.
func TestAuthorize_LoopbackRedirectPathStillExact(t *testing.T) {
	mux := loopbackAuthorizeMux(t, "http://127.0.0.1:0/callback")
	w := authorizeLoopback(t, mux, "http://127.0.0.1:53111/elsewhere")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Empty(t, w.Header().Get("Location"), "MUST NOT redirect to an unregistered redirect_uri")
}
