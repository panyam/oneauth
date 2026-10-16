package main

// The reference server's CSRF middleware binds tokens to the login
// session, shares its key across instances, and marks the cookie Secure
// whenever clients reach the server over https.
//
// See: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#signed-double-submit-cookie-recommended
// See: https://github.com/panyam/oneauth/issues/408

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCSRF_ServerBindsTokensToTheLoginSession(t *testing.T) {
	cfg := loadYAML(t, "server:\n  public_url: https://auth.example.com\njwt:\n  secret_key: \"csrf-server-test-secret-32-bytes\"\n")
	m := buildCSRF(cfg)
	assert.True(t, m.Secure, "https public_url behind a proxy still means Secure")
	require.NotNil(t, m.SessionID)
	assert.NotEmpty(t, m.Secret, "derived from jwt.secret_key so every instance agrees")

	withCookie := func(v string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if v != "" {
			r.AddCookie(&http.Cookie{Name: "oa_token", Value: v})
		}
		return r
	}
	a, b := m.SessionID(withCookie("session-jwt-a")), m.SessionID(withCookie("session-jwt-b"))
	assert.NotEqual(t, a, b, "different logins, different bindings")
	assert.Equal(t, "", m.SessionID(withCookie("")), "logged out binds to the empty session")
	assert.NotContains(t, a, "session-jwt-a", "the session cookie itself isn't the binding")
}
