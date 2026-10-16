package federatedauth_test

// After a federated login the user is sent back to the URL the login
// started from, which the caller supplied as ?callbackURL=. Only a local
// path is honored, or the login flow becomes an open redirect that lands
// a freshly signed-in user on another site.
//
// See: https://cwe.mitre.org/data/definitions/601.html
// See: https://www.rfc-editor.org/rfc/rfc9700#section-4.11
// See: https://github.com/panyam/oneauth/issues/88

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alexedwards/scs/v2"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/panyam/oneauth/accounts"
	"github.com/panyam/oneauth/federatedauth"
	"github.com/panyam/oneauth/httpauth"
)

type fakeAuthUserStore struct {
	accounts.UserStore
	accounts.IdentityStore
	accounts.ChannelStore
}

func (fakeAuthUserStore) EnsureAuthUser(string, string, *oauth2.Token, map[string]any) (accounts.User, error) {
	return &accounts.BasicUser{ID: "user-1"}, nil
}

func TestSaveUserAndRedirect_OnlyLocalCallbackURLs(t *testing.T) {
	t.Setenv("OAUTH2_BASE_URL", "")
	oa := (&httpauth.OneAuth{AppName: "App", Session: scs.New(), JWTSecretKey: "federated-test-secret-32-chars!!"}).EnsureDefaults()
	bridge := federatedauth.NewOAuthBridge(oa, fakeAuthUserStore{})
	h := oa.Session.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bridge.SaveUserAndRedirect("oauth", "google", &oauth2.Token{}, map[string]any{}, w, r)
	}))

	for callback, want := range map[string]string{
		"/dashboard":                "/dashboard",
		"/dashboard?tab=apps":       "/dashboard?tab=apps",
		"https://evil.example/home": "/",
		"//evil.example/home":       "/",
		"javascript:alert(1)":       "/",
	} {
		t.Run(callback, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/google/callback", nil)
			req.AddCookie(&http.Cookie{Name: "oauthCallbackURL", Value: callback})
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusFound, rr.Code)
			assert.Equal(t, want, rr.Header().Get("Location"))
		})
	}
}
