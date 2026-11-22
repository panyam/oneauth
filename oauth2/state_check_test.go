// Tests that the GitHub and Google callbacks check state through VerifyState:
// one error text for every failure, and no echo of the cookie value.

package oauth2_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/panyam/oneauth/oauth2"
	oauth2lib "golang.org/x/oauth2"
)

func stateCheckProviders(t *testing.T) map[string]http.Handler {
	t.Helper()
	handle := func(authtype, provider string, token *oauth2lib.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
		t.Errorf("HandleUser ran for %s despite a bad state", provider)
	}
	return map[string]http.Handler{
		"github": oauth2.NewGithubOAuth2("id", "secret", "http://localhost/callback", handle).Handler(),
		"google": oauth2.NewGoogleOAuth2("id", "secret", "http://localhost/callback", handle).Handler(),
	}
}

// The state cookie is a CSRF secret, so a 400 page must not repeat it.
// See: https://cwe.mitre.org/data/definitions/209.html
func TestCallbackStateMismatchDoesNotEchoCookie(t *testing.T) {
	for name, h := range stateCheckProviders(t) {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/callback/?code=c&state=attacker", nil)
			req.AddCookie(&http.Cookie{Name: "oauthstate", Value: "cookie-secret-value"})
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rr.Code)
			}
			if strings.Contains(rr.Body.String(), "cookie-secret-value") {
				t.Errorf("body echoes the state cookie: %q", rr.Body.String())
			}
			if got := strings.TrimSpace(rr.Body.String()); got != "invalid oauth state" {
				t.Errorf("body = %q, want %q", got, "invalid oauth state")
			}
		})
	}
}

func TestCallbackMissingStateCookieUsesSameError(t *testing.T) {
	for name, h := range stateCheckProviders(t) {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/callback/?code=c&state=s", nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rr.Code)
			}
			if got := strings.TrimSpace(rr.Body.String()); got != "invalid oauth state" {
				t.Errorf("body = %q, want %q", got, "invalid oauth state")
			}
		})
	}
}
