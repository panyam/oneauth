package oauth2_test

// Every cookie the OAuth redirectors set or delete is Secure and HttpOnly:
// the state and verifier guard the callback, and the callback URL picks
// where the user lands.
//
// See: https://www.rfc-editor.org/rfc/rfc6265#section-4.1.2.5
// See: https://cwe.mitre.org/data/definitions/614.html
// See: https://cwe.mitre.org/data/definitions/1004.html

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	xoauth2 "golang.org/x/oauth2"

	"github.com/panyam/oneauth/oauth2"
)

func assertCookieFlags(t *testing.T, cookies []*http.Cookie, want int) {
	t.Helper()
	assert.Len(t, cookies, want)
	for _, c := range cookies {
		assert.True(t, c.Secure, "%s must be Secure", c.Name)
		assert.True(t, c.HttpOnly, "%s must be HttpOnly", c.Name)
	}
}

func TestCookieFlags_RedirectorsSetSecureHttpOnlyCookies(t *testing.T) {
	cfg := &xoauth2.Config{ClientID: "c", Endpoint: xoauth2.Endpoint{AuthURL: "https://idp.example/authorize"}}
	for name, h := range map[string]http.HandlerFunc{
		"with PKCE":    oauth2.OauthRedirectorWithPKCE(cfg),
		"without PKCE": oauth2.OauthRedirectorNoPKCE(cfg),
	} {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h(rr, httptest.NewRequest(http.MethodGet, "/?callbackURL=/home", nil))
			want := 3 // callback URL, state, verifier
			if name == "without PKCE" {
				want = 2
			}
			assertCookieFlags(t, rr.Result().Cookies(), want)
		})
	}
}

func TestCookieFlags_ClearingTheVerifierKeepsTheFlags(t *testing.T) {
	rr := httptest.NewRecorder()
	oauth2.ClearPKCECookie(rr)
	assertCookieFlags(t, rr.Result().Cookies(), 1)
}
