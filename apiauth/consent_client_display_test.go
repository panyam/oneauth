package apiauth

// The consent page shows the client's registered logo and links to its
// policy and terms (OIDC Registration §2, issue 507), and lets only the
// logo's origin through the page's CSP.
//
// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
// See: https://github.com/panyam/oneauth/issues/507

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const strictCSP = "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'"

// consentPageFor renders the consent page for client-x, registered with app's
// display fields, behind a middleware that sets strictCSP as the reference
// server does.
func consentPageFor(t *testing.T, app core.AppRegistration) *httptest.ResponseRecorder {
	t.Helper()
	appStore := core.NewInMemoryAppStore()
	app.ClientID, app.ClientName, app.RedirectURIs = "client-x", "Test Client", []string{"https://app.example/cb"}
	_, err := appStore.SaveApp(context.Background(), &core.SaveAppRequest{App: &app})
	require.NoError(t, err)
	mux := http.NewServeMux()
	MountAuthorize(mux, AuthorizeMountConfig{
		OneAuth:              NewOneAuth(OneAuthConfig{AuthorizationCodeStore: core.NewInMemoryAuthorizationCodeStore(), AppStore: appStore}),
		IssuerURL:            "https://issuer.example",
		SubjectFromRequest:   func(*http.Request) string { return "user-1" },
		CSRFTokenFromRequest: func(*http.Request) string { return "csrf" },
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/authorize?"+authorizeQuery(t).Encode(), nil)
	w.Header().Set("Content-Security-Policy", strictCSP)
	mux.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	return w
}

func TestConsent_ShowsClientLogoPolicyAndTerms(t *testing.T) {
	w := consentPageFor(t, core.AppRegistration{
		LogoURI: "https://cdn.example/logo.png", PolicyURI: "https://app.example/privacy", TOSURI: "https://app.example/terms",
	})
	body := w.Body.String()
	assert.Contains(t, body, `<img id="client-logo" src="https://cdn.example/logo.png"`)
	assert.Contains(t, body, `<a id="client-policy" href="https://app.example/privacy"`)
	assert.Contains(t, body, `<a id="client-tos" href="https://app.example/terms"`)
	assert.Equal(t, "default-src 'self'; img-src 'self' data: https://cdn.example; frame-ancestors 'none'",
		w.Header().Get("Content-Security-Policy"), "only the logo's origin is let through")
}

func TestConsent_NoDisplayURIs_PageAndCSPUnchanged(t *testing.T) {
	w := consentPageFor(t, core.AppRegistration{})
	body := w.Body.String()
	assert.NotContains(t, body, `id="client-logo"`)
	assert.NotContains(t, body, `id="client-policy"`)
	assert.NotContains(t, body, `id="client-tos"`)
	assert.Equal(t, strictCSP, w.Header().Get("Content-Security-Policy"))
}

func TestAllowImageOrigin(t *testing.T) {
	for _, tc := range []struct{ name, csp, want string }{
		{"no CSP: images already allowed", "", ""},
		{"img-src extended", "img-src 'self'; script-src 'self'", "img-src 'self' https://cdn.example; script-src 'self'"},
		{"falls back to default-src", "default-src 'self'; script-src 'none'", "default-src 'self'; script-src 'none'; img-src 'self' https://cdn.example"},
		{"no img-src or default-src: nothing restricts images", "frame-ancestors 'none'", "frame-ancestors 'none'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.csp != "" {
				h.Set("Content-Security-Policy", tc.csp)
			}
			allowImageOrigin(h, "https://cdn.example/a/logo.png?v=1")
			assert.Equal(t, tc.want, h.Get("Content-Security-Policy"))
		})
	}
}
