package keycloak_test

// The generic OIDC sign-in provider (oauth2/oidc) against Keycloak as a
// real OpenID Provider. An app mounts the provider, a browser signs in on
// Keycloak's login form, and HandleUser receives Keycloak's verified ID
// token claims. AllowList then admits the realm's user by email domain.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
// See: https://github.com/panyam/oneauth/issues/542

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"

	"github.com/panyam/oneauth/oauth2/oidc"
)

// plainHTTPJar drops Secure from cookies it stores. The provider's cookies
// are Secure, which a browser honours on http://127.0.0.1 and Go's
// cookiejar does not.
type plainHTTPJar struct{ http.CookieJar }

func (j plainHTTPJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	for _, c := range cookies {
		c.Secure = false
	}
	j.CookieJar.SetCookies(u, cookies)
}

func TestKeycloakOIDCSignIn_WebFlow(t *testing.T) {
	skipIfKeycloakNotRunning(t)

	signedIn := make(chan map[string]any, 1)
	mux := http.NewServeMux()
	app := httptest.NewServer(mux)
	t.Cleanup(app.Close)

	p, err := oidc.New(context.Background(), oidc.Config{
		Issuer:       realmURL(),
		ClientID:     confidentialClientID,
		ClientSecret: confidentialClientSecret,
		CallbackURL:  app.URL + "/auth/oidc/callback/",
		ProviderName: "keycloak",
		HandleUser: func(authtype, provider string, token *xoauth2.Token, claims map[string]any, w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "keycloak", provider)
			signedIn <- claims
			_, _ = io.WriteString(w, "signed in")
		},
	})
	require.NoError(t, err)
	mux.Handle("/auth/oidc/", http.StripPrefix("/auth/oidc", p.Handler()))

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: plainHTTPJar{jar}, Timeout: 20 * time.Second}
	resp, err := browser.Get(app.URL + "/auth/oidc/")
	require.NoError(t, err)
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`).FindSubmatch(page)
	require.NotNil(t, m, "no Keycloak login form (HTTP %d)", resp.StatusCode)

	resp, err = browser.PostForm(html.UnescapeString(string(m[1])), url.Values{
		"username": {testUsername}, "password": {testPassword}, "credentialId": {""},
	})
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	assert.Equal(t, "signed in", string(body))

	claims := <-signedIn
	assert.Equal(t, p.Metadata().Issuer, claims["iss"])
	assert.NotEmpty(t, claims["sub"])
	assert.NotEmpty(t, claims["nonce"])
	assert.Equal(t, "testuser@example.com", claims["email"])
	assert.True(t, oidc.AllowList{EmailDomains: []string{"example.com"}}.Allows(claims))
	assert.False(t, oidc.AllowList{EmailDomains: []string{"other.example"}}.Allows(claims))
}

// A CLI signs in with the device flow. The test plays the person: it opens
// verification_uri_complete in a browser and logs in, while the provider
// polls the token endpoint.
func TestKeycloakOIDCSignIn_DeviceFlow(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	p, err := oidc.New(context.Background(), oidc.Config{
		Issuer: realmURL(), ClientID: confidentialClientID, ClientSecret: confidentialClientSecret,
		HandleUser: func(string, string, *xoauth2.Token, map[string]any, http.ResponseWriter, *http.Request) {},
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	da, err := p.DeviceAuth(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, da.VerificationURIComplete)

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, Timeout: 20 * time.Second}
	resp, err := browser.Get(da.VerificationURIComplete)
	require.NoError(t, err)
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`).FindSubmatch(page)
	require.NotNil(t, m, "no Keycloak login form (HTTP %d)", resp.StatusCode)
	resp, err = browser.PostForm(html.UnescapeString(string(m[1])), url.Values{
		"username": {testUsername}, "password": {testPassword}, "credentialId": {""},
	})
	require.NoError(t, err)
	consent, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Keycloak asks for consent on every device grant.
	action := regexp.MustCompile(`<form[^>]*action="([^"]*login-actions/consent[^"]*)"`).FindSubmatch(consent)
	code := regexp.MustCompile(`name="code" value="([^"]+)"`).FindSubmatch(consent)
	require.NotNil(t, action, "no consent form at %s", resp.Request.URL)
	require.NotNil(t, code)
	consentURL, err := resp.Request.URL.Parse(html.UnescapeString(string(action[1])))
	require.NoError(t, err)
	resp, err = browser.PostForm(consentURL.String(), url.Values{"code": {string(code[1])}, "accept": {"Yes"}})
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	token, claims, err := p.DeviceAccessToken(ctx, da)
	require.NoError(t, err)
	assert.NotEmpty(t, token.AccessToken)
	assert.Equal(t, p.Metadata().Issuer, claims.Issuer)
	assert.Equal(t, "testuser@example.com", claims.Claims["email"])
}
