package keycloak_test

// Side-by-side comparisons with Keycloak for the issue 88 DPoP slice and the
// refresh-grant client check (issue 395), plus the SDK's DPoP paths driven
// against Keycloak as the authorization server.
//
// The comparison tests send the same request to Keycloak and to an
// in-process oneauth AS and assert on both answers. Where the two agree the
// test asserts agreement. Where they differ on purpose, the test pins both
// answers, so a change on either side shows up here instead of in a bug
// report. docs/SECURITY_AUDIT.md lists the differences and why we keep them.
//
// References:
//   - RFC 6749 §5.2, §6 (https://www.rfc-editor.org/rfc/rfc6749)
//   - RFC 9449 §4.3, §5, §10 (https://www.rfc-editor.org/rfc/rfc9449)
//   - RFC 3986 §6.2.2 (https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2)
//   - See: https://github.com/panyam/oneauth/issues/88
//   - See: https://github.com/panyam/oneauth/issues/395

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/stores/fs"
)

func keycloakTokenEndpoint() string {
	return realmURL() + "/protocol/openid-connect/token"
}

// answer is one token endpoint's response, reduced to what the comparisons
// look at.
type answer struct {
	Status int
	Error  string
	Token  bool
}

func (a answer) String() string {
	if a.Token {
		return fmt.Sprintf("%d token", a.Status)
	}
	return fmt.Sprintf("%d %s", a.Status, a.Error)
}

func postForm(t *testing.T, target string, form url.Values, proof string) answer {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body struct {
		Error       string `json:"error"`
		AccessToken string `json:"access_token"`
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &body)
	return answer{Status: resp.StatusCode, Error: body.Error, Token: body.AccessToken != ""}
}

// oneauthMirror is an in-process oneauth AS registered with the same client
// IDs, secret and auth styles as the Keycloak realm, so a request can be
// replayed against it unchanged.
type oneauthMirror struct {
	tokenURL     string
	refreshStore core.RefreshTokenStore
}

func newOneauthMirror(t *testing.T, cfg func(*apiauth.OneAuthConfig)) *oneauthMirror {
	t.Helper()
	ks := keys.NewInMemoryKeyStore()
	apps := core.NewInMemoryAppStore()
	_, err := ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID: confidentialClientID, Key: []byte(confidentialClientSecret), Algorithm: "HS256",
	}})
	require.NoError(t, err)
	for id, method := range map[string]string{confidentialClientID: "client_secret_post", publicClientID: "none", dpopClientID: "none"} {
		_, err := apps.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
			ClientID: id, TokenEndpointAuthMethod: method, DPoPBoundAccessTokens: id == dpopClientID,
		}})
		require.NoError(t, err)
	}
	store := fs.NewFSRefreshTokenStore(t.TempDir())

	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)
	tokenURL := "http://" + server.Listener.Addr().String() + "/token"
	oaCfg := apiauth.OneAuthConfig{
		KeyStore:     ks,
		AppStore:     apps,
		SigningKey:   []byte("keycloak-mirror-jwt-secret-32chr"),
		SigningAlg:   "HS256",
		Issuer:       "oneauth-keycloak-mirror",
		RefreshStore: store,
		DPoP:         apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{EndpointURL: tokenURL}),
	}
	if cfg != nil {
		cfg(&oaCfg)
	}
	mux.Handle("POST /token", apiauth.NewTokenEndpointHandler(apiauth.NewOneAuth(oaCfg)))
	server.Start()
	t.Cleanup(server.Close)
	return &oneauthMirror{tokenURL: tokenURL, refreshStore: store}
}

func (m *oneauthMirror) refreshTokenFor(t *testing.T, clientID string) string {
	t.Helper()
	created, err := m.refreshStore.CreateRefreshToken(context.Background(), &core.CreateRefreshTokenRequest{
		Subject: "testuser", ClientID: clientID, Scopes: []string{"openid"},
	})
	require.NoError(t, err)
	return created.Token.Token
}

func keycloakRefreshTokenFor(t *testing.T, clientID, secret string) string {
	t.Helper()
	return getPasswordToken(t, keycloakTokenEndpoint(), clientID, secret, testUsername, testPassword).RefreshToken
}

// The refresh grant's client checks, compared case by case. Keycloak and
// oneauth agree on every status. The one code that differs is the answer to
// a confidential client with missing or wrong credentials: Keycloak says
// unauthorized_client, and oneauth keeps invalid_client, which is what RFC
// 6749 §5.2 names for failed client authentication.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-5.2
func TestKeycloakCompare_RefreshClientChecks(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	mirror := newOneauthMirror(t, nil)

	type side struct {
		owner, ownerSecret string
	}
	cases := []struct {
		name     string
		owner    side
		form     url.Values
		keycloak answer
		oneauth  answer
	}{
		{
			name:     "public client's token presented by the confidential client",
			owner:    side{publicClientID, ""},
			form:     url.Values{"client_id": {confidentialClientID}, "client_secret": {confidentialClientSecret}},
			keycloak: answer{Status: 400, Error: "invalid_grant"},
			oneauth:  answer{Status: 400, Error: "invalid_grant"},
		},
		{
			name:     "confidential client's token presented by the public client",
			owner:    side{confidentialClientID, confidentialClientSecret},
			form:     url.Values{"client_id": {publicClientID}},
			keycloak: answer{Status: 400, Error: "invalid_grant"},
			oneauth:  answer{Status: 400, Error: "invalid_grant"},
		},
		{
			name:     "public client's token with no client_id",
			owner:    side{publicClientID, ""},
			form:     url.Values{},
			keycloak: answer{Status: 401, Error: "invalid_client"},
			oneauth:  answer{Status: 401, Error: "invalid_client"},
		},
		{
			name:     "confidential client without its secret",
			owner:    side{confidentialClientID, confidentialClientSecret},
			form:     url.Values{"client_id": {confidentialClientID}},
			keycloak: answer{Status: 401, Error: "unauthorized_client"},
			oneauth:  answer{Status: 401, Error: "invalid_client"},
		},
		{
			name:     "confidential client with the wrong secret",
			owner:    side{confidentialClientID, confidentialClientSecret},
			form:     url.Values{"client_id": {confidentialClientID}, "client_secret": {"not-the-secret"}},
			keycloak: answer{Status: 401, Error: "unauthorized_client"},
			oneauth:  answer{Status: 401, Error: "invalid_client"},
		},
		{
			name:     "public client with its own client_id",
			owner:    side{publicClientID, ""},
			form:     url.Values{"client_id": {publicClientID}},
			keycloak: answer{Status: 200, Token: true},
			oneauth:  answer{Status: 200, Token: true},
		},
		{
			name:     "confidential client with its secret",
			owner:    side{confidentialClientID, confidentialClientSecret},
			form:     url.Values{"client_id": {confidentialClientID}, "client_secret": {confidentialClientSecret}},
			keycloak: answer{Status: 200, Token: true},
			oneauth:  answer{Status: 200, Token: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			send := func(target, token string) answer {
				form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}}
				for k, v := range tc.form {
					form[k] = v
				}
				return postForm(t, target, form, "")
			}
			kc := send(keycloakTokenEndpoint(), keycloakRefreshTokenFor(t, tc.owner.owner, tc.owner.ownerSecret))
			oa := send(mirror.tokenURL, mirror.refreshTokenFor(t, tc.owner.owner))
			assert.Equal(t, tc.keycloak, kc, "Keycloak")
			assert.Equal(t, tc.oneauth, oa, "oneauth")
			assert.Equal(t, kc.Status, oa.Status, "the two disagree on the status: Keycloak %s, oneauth %s", kc, oa)
		})
	}
}

// A client registered for DPoP-bound tokens that sends no proof. Both
// refuse with 400 and issue nothing. Keycloak says invalid_request, oneauth
// says invalid_dpop_proof. RFC 9449 names no code for a missing proof, and
// Keycloak also uses invalid_request for a proof whose htu is wrong, where
// §5 does name invalid_dpop_proof, so we keep the code that tells a client
// which fix to make.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-5.2
func TestKeycloakCompare_MissingProofForBoundClient(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	mirror := newOneauthMirror(t, nil)
	form := url.Values{
		"grant_type": {"password"}, "client_id": {dpopClientID},
		"username": {testUsername}, "password": {testPassword}, "scope": {"openid"},
	}

	kc := postForm(t, keycloakTokenEndpoint(), form, "")
	assert.Equal(t, answer{Status: 400, Error: "invalid_request"}, kc, "Keycloak")

	// The mirror has no password grant, so it answers the same client's
	// refresh request, which the policy covers the same way.
	oa := postForm(t, mirror.tokenURL, url.Values{
		"grant_type": {"refresh_token"}, "client_id": {dpopClientID}, "refresh_token": {mirror.refreshTokenFor(t, dpopClientID)},
	}, "")
	assert.Equal(t, answer{Status: 400, Error: "invalid_dpop_proof"}, oa, "oneauth")
}

// The same proofs with differently spelled htu values, judged by Keycloak's
// token endpoint and by a oneauth validator pinned to the same URL.
//
// They agree on case, a query string, a trailing slash and a different host.
// They differ on three spellings oneauth accepts and Keycloak refuses: a
// fragment, a percent-encoded unreserved character, and a "." segment. RFC
// 9449 §4.3 has the server ignore the fragment and compare after RFC 3986
// §6.2.2 normalization, under which all three name the same URL.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.3
func TestKeycloakCompare_HTUSpellings(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	te := keycloakTokenEndpoint()
	u, err := url.Parse(te)
	require.NoError(t, err)
	validator := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{EndpointURL: te})
	key := newDPoPKey(t)
	form := url.Values{
		"grant_type": {"password"}, "client_id": {dpopClientID},
		"username": {testUsername}, "password": {testPassword}, "scope": {"openid"},
	}
	otherHost := strings.Replace(te, "localhost", "127.0.0.1", 1)
	if otherHost == te {
		otherHost = strings.Replace(te, u.Hostname(), "localhost", 1)
	}

	for _, tc := range []struct {
		name                  string
		htu                   string
		keycloakOK, oneauthOK bool
	}{
		{"exact", te, true, true},
		{"upper-case scheme and host", "HTTP://" + strings.ToUpper(u.Host) + u.Path, true, true},
		{"query string", te + "?x=1", true, true},
		{"trailing slash", te + "/", false, false},
		{"another host", otherHost, false, false},
		{"fragment", te + "#f", false, true},
		{"percent-encoded unreserved", strings.Replace(te, "oneauth-test", "oneauth%2Dtest", 1), false, true},
		{"dot segment", strings.Replace(te, "/protocol/", "/protocol/./", 1), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kc := postForm(t, te, form, key.proof(t, http.MethodPost, tc.htu, ""))
			assert.Equal(t, tc.keycloakOK, kc.Token, "Keycloak answered %s", kc)

			req := httptest.NewRequest(http.MethodPost, te, nil)
			req.Header.Set("DPoP", key.proof(t, http.MethodPost, tc.htu, ""))
			_, err := validator.Confirm(context.Background(), req)
			assert.Equal(t, tc.oneauthOK, err == nil, "oneauth: %v", err)
		})
	}
}

// The SDK against Keycloak as the token server: a DPoP password grant, then
// RefreshToken with the same key keeps the binding. Keycloak binds a public
// client's refresh token to its key (§5), so another key is refused.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-5
func TestKeycloakDPoP_SDKRefreshKeepsTheBinding(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	meta := &client.ASMetadata{TokenEndpoint: keycloakTokenEndpoint()}
	key, err := client.NewDPoPKey()
	require.NoError(t, err)
	c := client.NewAuthClient(keycloakURL(), nil, client.WithASMetadata(meta), client.WithDPoPKey(key))

	cred, err := c.Login(context.Background(), &client.LoginRequest{
		Username: testUsername, Password: testPassword, ClientID: dpopClientID, Scope: "openid",
	})
	require.NoError(t, err)
	require.NotEmpty(t, cred.RefreshToken)
	assert.True(t, strings.EqualFold(cred.TokenType, "DPoP"), cred.TokenType)
	assert.Equal(t, key.Thumbprint(), jktOf(t, cred.AccessToken))

	other, err := client.NewDPoPKey()
	require.NoError(t, err)
	_, err = client.NewAuthClient(keycloakURL(), nil, client.WithASMetadata(meta), client.WithDPoPKey(other)).
		RefreshToken(context.Background(), &client.RefreshTokenRequest{ClientID: dpopClientID, RefreshToken: cred.RefreshToken})
	var te *client.TokenError
	require.ErrorAs(t, err, &te, "Keycloak must refuse a bound refresh token under another key")

	refreshed, err := c.RefreshToken(context.Background(), &client.RefreshTokenRequest{
		ClientID: dpopClientID, RefreshToken: cred.RefreshToken,
	})
	require.NoError(t, err)
	assert.Equal(t, key.Thumbprint(), jktOf(t, refreshed.AccessToken))
}

// LoginWithBrowser with a DPoP key against Keycloak: dpop_jkt goes on the
// authorize URL, so Keycloak binds the code, and the SDK has to prove the
// key on the code exchange as well.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-10
func TestKeycloakDPoP_SDKBrowserLogin(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	key, err := client.NewDPoPKey()
	require.NoError(t, err)
	req, _ := headlessLoginRequest(t, dpopClientID, keycloakPasswordLogin(t, testUsername, testPassword))
	req.Scopes = []string{"openid"}

	cred, err := client.NewAuthClient(keycloakURL(), nil, client.WithDPoPKey(key)).LoginWithBrowser(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, key.Thumbprint(), jktOf(t, cred.AccessToken))
}

// keycloakPasswordLogin is an OpenBrowser that fills in Keycloak's login
// form, then follows the redirects to the SDK's loopback listener.
func keycloakPasswordLogin(t *testing.T, username, password string) func(string) error {
	action := regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`)
	return func(authURL string) error {
		jar, _ := cookiejar.New(nil)
		browser := &http.Client{Jar: jar, Timeout: 20 * time.Second}
		resp, err := browser.Get(authURL)
		if err != nil {
			return err
		}
		page, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		m := action.FindSubmatch(page)
		if m == nil {
			return fmt.Errorf("no Keycloak login form at %s (HTTP %d)", authURL, resp.StatusCode)
		}
		resp, err = browser.PostForm(html.UnescapeString(string(m[1])), url.Values{
			"username": {username}, "password": {password}, "credentialId": {""},
		})
		if err != nil {
			return err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return nil
	}
}

func jktOf(t *testing.T, accessToken string) string {
	t.Helper()
	cnf, _ := parseJWTClaims(t, accessToken)["cnf"].(map[string]any)
	jkt, _ := cnf["jkt"].(string)
	return jkt
}
