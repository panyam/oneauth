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
	"net/url"
	"strings"
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

// Email login and signup post callbackURL with the request instead of going
// through the OAuth redirect that sets the cookie. The redirect honors it the
// same way, and the cookie still wins when both are there.
func TestSaveUserAndRedirect_RequestCallbackURL(t *testing.T) {
	t.Setenv("OAUTH2_BASE_URL", "")
	oa := (&httpauth.OneAuth{AppName: "App", Session: scs.New(), JWTSecretKey: "federated-test-secret-32-chars!!"}).EnsureDefaults()
	bridge := federatedauth.NewOAuthBridge(oa, fakeAuthUserStore{})
	h := oa.Session.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bridge.SaveUserAndRedirect("local", "local", nil, map[string]any{}, w, r)
	}))

	cases := []struct {
		name, query, form, cookie, want string
	}{
		{name: "query", query: "/notations/x/compose", want: "/notations/x/compose"},
		{name: "form", form: "/notations/x/compose", want: "/notations/x/compose"},
		{name: "query off-site", query: "https://evil.example/home", want: "/"},
		{name: "form off-site", form: "//evil.example/home", want: "/"},
		{name: "none", want: "/"},
		{name: "cookie wins", query: "/from-query", cookie: "/from-cookie", want: "/from-cookie"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			target := "/login"
			if c.query != "" {
				target += "?callbackURL=" + url.QueryEscape(c.query)
			}
			body := url.Values{"email": {"a@example.com"}}
			if c.form != "" {
				body.Set("callbackURL", c.form)
			}
			req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if c.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "oauthCallbackURL", Value: c.cookie})
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusFound, rr.Code)
			assert.Equal(t, c.want, rr.Header().Get("Location"))
		})
	}
}
