package oidc_test

// An app's own test, written the way issue 566 asks apps to write theirs:
// mount the provider, point it at oidctest, and sign in with a plain HTTP
// client standing in for the browser. The overage test resolves groups
// through the fake's Graph route with EntraGroups.
//
// See: https://github.com/panyam/oneauth/issues/566
// See: https://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"

	"github.com/panyam/oneauth/oauth2/oidc"
	"github.com/panyam/oneauth/oauth2/oidc/oidctest"
)

// plainHTTPJar drops Secure from stored cookies. The provider's cookies
// are Secure, which a browser honours on http://127.0.0.1 and Go's
// cookiejar does not.
type plainHTTPJar struct{ http.CookieJar }

func (j plainHTTPJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	for _, c := range cookies {
		c.Secure = false
	}
	j.CookieJar.SetCookies(u, cookies)
}

func TestOIDCSignIn_AppWithBrowser(t *testing.T) {
	iss := oidctest.New(t, oidctest.WithClient("agni", "secret"))
	iss.AddUser("u-123", map[string]any{"email": "ada@example.com", "email_verified": true})
	iss.SignInAs("u-123")

	mux := http.NewServeMux()
	app := httptest.NewServer(mux)
	t.Cleanup(app.Close)
	signedIn := make(chan map[string]any, 1)
	p, err := oidc.New(context.Background(), oidc.Config{
		Issuer: iss.URL, ClientID: "agni", ClientSecret: "secret",
		CallbackURL: app.URL + "/auth/oidc/callback/",
		HandleUser: func(_, _ string, _ *xoauth2.Token, claims map[string]any, w http.ResponseWriter, _ *http.Request) {
			signedIn <- claims
			_, _ = io.WriteString(w, "signed in")
		},
	})
	require.NoError(t, err)
	mux.Handle("/auth/oidc/", http.StripPrefix("/auth/oidc", p.Handler()))

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: plainHTTPJar{jar}, Timeout: 10 * time.Second}
	resp, err := browser.Get(app.URL + "/auth/oidc/")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	assert.Equal(t, "signed in", string(body))

	claims := <-signedIn
	assert.Equal(t, "u-123", claims["sub"])
	assert.True(t, oidc.AllowList{EmailDomains: []string{"example.com"}}.Allows(claims))
}

func TestOIDCSignIn_GroupsOverageResolvedThroughGraph(t *testing.T) {
	iss := oidctest.New(t, oidctest.WithClient(testClientID, testSecret), oidctest.WithGroupsOverage())
	iss.AddUser("u-123", map[string]any{"groups": []string{"g-ops", "g-eng"}})
	p, _ := newProvider(t, iss)

	da, err := p.DeviceAuth(context.Background())
	require.NoError(t, err)
	require.True(t, iss.Approve(da.UserCode, "u-123"))
	token, claims, err := p.DeviceAccessToken(context.Background(), da)
	require.NoError(t, err)

	list := oidc.AllowList{Groups: []string{"g-eng"}}
	assert.Equal(t, oidc.Decision{GroupsOverage: true}, list.Decide(claims.Claims))

	d, err := list.Resolve(context.Background(), claims.Claims,
		oidc.EntraGroups{AccessToken: token.AccessToken, GraphURL: iss.GraphURL()}.Groups)
	require.NoError(t, err)
	assert.Equal(t, oidc.Decision{Allowed: true, Rule: oidc.RuleGroup, GroupsOverage: true}, d)
}
