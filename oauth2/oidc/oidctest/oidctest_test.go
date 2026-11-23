package oidctest_test

// The fake's own contract, spoken as raw HTTP so each check names the wire
// answer an app's client sees. oauth2/oidc's provider tests then run the
// real client against it.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-5.2
// See: https://www.rfc-editor.org/rfc/rfc7636
// See: https://www.rfc-editor.org/rfc/rfc8628#section-3.5
// See: https://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims
// See: https://github.com/panyam/oneauth/issues/566

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/oauth2/oidc/oidctest"
)

const (
	clientID    = "app"
	secret      = "app-secret"
	redirectURI = "http://app.test/cb"
	verifier    = "a-verifier-long-enough-to-satisfy-rfc-7636-forty-three-chars"
)

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func newIssuer(t *testing.T, opts ...oidctest.Option) *oidctest.Server {
	iss := oidctest.New(t, append([]oidctest.Option{oidctest.WithClient(clientID, secret)}, opts...)...)
	iss.AddUser("u-123", map[string]any{
		"email": "ada@example.com", "email_verified": true, "groups": []string{"g-eng"}, "sub": "ignored",
	})
	return iss
}

func challenge(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorize sends the browser to /authorize and returns the redirect back.
func authorize(t *testing.T, iss *oidctest.Server, edit func(url.Values)) (*http.Response, url.Values) {
	t.Helper()
	q := url.Values{
		"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"},
		"scope": {"openid email"}, "state": {"st-1"}, "nonce": {"n-1"},
		"code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"},
	}
	if edit != nil {
		edit(q)
	}
	resp, err := noRedirect.Get(iss.URL + "/authorize?" + q.Encode())
	require.NoError(t, err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		return resp, nil
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	return resp, loc.Query()
}

// post sends a form to the fake and decodes the JSON answer.
func post(t *testing.T, iss *oidctest.Server, path string, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(iss.URL+path, form)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return resp.StatusCode, body
}

func redeem(t *testing.T, iss *oidctest.Server, code string, edit func(url.Values)) (int, map[string]any) {
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
		"code_verifier": {verifier}, "client_id": {clientID}, "client_secret": {secret},
	}
	if edit != nil {
		edit(form)
	}
	return post(t, iss, "/token", form)
}

func verify(t *testing.T, iss *oidctest.Server, resp map[string]any, nonce string) *client.IDTokenClaims {
	t.Helper()
	raw, _ := resp["id_token"].(string)
	claims, err := client.VerifyIDToken(context.Background(), &client.VerifyIDTokenRequest{
		IDToken: raw, Issuer: iss.URL, ClientID: clientID, Nonce: nonce,
		Keys: keys.NewJWKSKeyStore(iss.URL + "/jwks"), AccessToken: resp["access_token"].(string),
	})
	require.NoError(t, err)
	return claims
}

// segment decodes part i of a JWT (0 header, 1 payload) without checking
// the signature, for a check on what the fake put there.
func segment(t *testing.T, raw string, i int) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	require.Len(t, parts, 3)
	b, err := base64.RawURLEncoding.DecodeString(parts[i])
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	return m
}

func TestDiscovery(t *testing.T) {
	iss := newIssuer(t)
	meta, err := client.DiscoverASWithContext(context.Background(), iss.URL)
	require.NoError(t, err)
	assert.Equal(t, iss.URL, meta.Issuer)
	assert.Equal(t, iss.URL+"/authorize", meta.AuthorizationEndpoint)
	assert.Equal(t, iss.URL+"/token", meta.TokenEndpoint)
	assert.Equal(t, iss.URL+"/device_authorization", meta.DeviceAuthorizationEndpoint)
	assert.Equal(t, iss.URL+"/logout", meta.EndSessionEndpoint)

	resp, err := http.Get(meta.JWKSURI)
	require.NoError(t, err)
	defer resp.Body.Close()
	var set struct{ Keys []map[string]any }
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&set))
	require.Len(t, set.Keys, 1)
	assert.Equal(t, "RSA", set.Keys[0]["kty"])
	assert.Equal(t, "RS256", set.Keys[0]["alg"])
	assert.Equal(t, oidctest.KeyID, set.Keys[0]["kid"])
}

func TestDiscovery_Edit(t *testing.T) {
	iss := newIssuer(t, oidctest.WithDiscovery(func(doc map[string]any) {
		delete(doc, "device_authorization_endpoint")
	}))
	meta, err := client.DiscoverASWithContext(context.Background(), iss.URL)
	require.NoError(t, err)
	assert.Empty(t, meta.DeviceAuthorizationEndpoint)
}

func TestCodeFlow(t *testing.T) {
	iss := newIssuer(t)
	iss.SignInAs("u-123")
	_, back := authorize(t, iss, nil)
	require.NotEmpty(t, back.Get("code"))
	assert.Equal(t, "st-1", back.Get("state"))
	assert.Equal(t, iss.URL, back.Get("iss"), "RFC 9207 iss on the authorization response")

	status, resp := redeem(t, iss, back.Get("code"), nil)
	require.Equal(t, http.StatusOK, status, resp)
	claims := verify(t, iss, resp, "n-1")
	assert.Equal(t, "u-123", claims.Subject, "the fake's sub wins over the user's claims")
	assert.Equal(t, "ada@example.com", claims.Claims["email"])
	assert.Equal(t, []any{"g-eng"}, claims.Claims["groups"])
	assert.NotEmpty(t, claims.Claims["at_hash"])

	assert.Equal(t, "RS256", segment(t, resp["id_token"].(string), 0)["alg"])
}

func TestCodeFlow_ClientSecretBasic(t *testing.T) {
	iss := newIssuer(t)
	iss.SignInAs("u-123")
	_, back := authorize(t, iss, nil)
	req, _ := http.NewRequest(http.MethodPost, iss.URL+"/token", strings.NewReader(url.Values{
		"grant_type": {"authorization_code"}, "code": {back.Get("code")},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAuthorize_Refusals(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(url.Values)
		want string
	}{
		"no PKCE":          {func(q url.Values) { q.Del("code_challenge"); q.Del("code_challenge_method") }, "invalid_request"},
		"plain PKCE":       {func(q url.Values) { q.Set("code_challenge_method", "plain") }, "invalid_request"},
		"no openid scope":  {func(q url.Values) { q.Set("scope", "email") }, "invalid_scope"},
		"token response":   {func(q url.Values) { q.Set("response_type", "token") }, "unsupported_response_type"},
		"nobody signed in": {nil, "login_required"},
	} {
		t.Run(name, func(t *testing.T) {
			iss := newIssuer(t)
			if name != "nobody signed in" {
				iss.SignInAs("u-123")
			}
			_, back := authorize(t, iss, tc.edit)
			assert.Equal(t, tc.want, back.Get("error"))
			assert.Empty(t, back.Get("code"))
			assert.Equal(t, "st-1", back.Get("state"))
		})
	}
}

// An unknown client or a bad redirect_uri must not redirect anywhere
// (RFC 6749 §4.1.2.1).
func TestAuthorize_NoRedirectToUntrustedURI(t *testing.T) {
	iss := newIssuer(t)
	iss.SignInAs("u-123")
	for name, edit := range map[string]func(url.Values){
		"unknown client":       func(q url.Values) { q.Set("client_id", "someone") },
		"relative redirect":    func(q url.Values) { q.Set("redirect_uri", "/cb") },
		"missing redirect_uri": func(q url.Values) { q.Del("redirect_uri") },
	} {
		t.Run(name, func(t *testing.T) {
			resp, _ := authorize(t, iss, edit)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Empty(t, resp.Header.Get("Location"))
		})
	}
}

func TestToken_Refusals(t *testing.T) {
	for name, tc := range map[string]struct {
		edit       func(url.Values)
		wantStatus int
		want       string
	}{
		"wrong verifier":     {func(f url.Values) { f.Set("code_verifier", verifier+"x") }, 400, "invalid_grant"},
		"other redirect_uri": {func(f url.Values) { f.Set("redirect_uri", "http://app.test/other") }, 400, "invalid_grant"},
		"wrong secret":       {func(f url.Values) { f.Set("client_secret", "nope") }, 401, "invalid_client"},
		"unknown client":     {func(f url.Values) { f.Set("client_id", "someone") }, 401, "invalid_client"},
		"unknown grant":      {func(f url.Values) { f.Set("grant_type", "password") }, 400, "unsupported_grant_type"},
	} {
		t.Run(name, func(t *testing.T) {
			iss := newIssuer(t)
			iss.SignInAs("u-123")
			_, back := authorize(t, iss, nil)
			status, resp := redeem(t, iss, back.Get("code"), tc.edit)
			assert.Equal(t, tc.wantStatus, status)
			assert.Equal(t, tc.want, resp["error"])
		})
	}
}

func TestToken_CodeWorksOnce(t *testing.T) {
	iss := newIssuer(t)
	iss.SignInAs("u-123")
	_, back := authorize(t, iss, nil)
	status, _ := redeem(t, iss, back.Get("code"), nil)
	require.Equal(t, http.StatusOK, status)
	status, resp := redeem(t, iss, back.Get("code"), nil)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", resp["error"])
}

func TestPublicClient(t *testing.T) {
	iss := oidctest.New(t, oidctest.WithClient("cli", ""))
	iss.AddUser("u-1", nil)
	status, da := post(t, iss, "/device_authorization", url.Values{"client_id": {"cli"}, "scope": {"openid"}})
	require.Equal(t, http.StatusOK, status, da)
	require.True(t, iss.Approve(da["user_code"].(string), "u-1"))
	status, resp := post(t, iss, "/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {da["device_code"].(string)}, "client_id": {"cli"},
	})
	assert.Equal(t, http.StatusOK, status, resp)
}

func startDevice(t *testing.T, iss *oidctest.Server) (deviceCode, userCode string) {
	t.Helper()
	status, da := post(t, iss, "/device_authorization", url.Values{
		"client_id": {clientID}, "client_secret": {secret}, "scope": {"openid"},
	})
	require.Equal(t, http.StatusOK, status, da)
	assert.Equal(t, float64(1), da["interval"])
	assert.Regexp(t, `^[A-Z]{4}-[A-Z]{4}$`, da["user_code"])
	assert.Contains(t, da["verification_uri_complete"], url.QueryEscape(da["user_code"].(string)))
	return da["device_code"].(string), da["user_code"].(string)
}

func poll(t *testing.T, iss *oidctest.Server, deviceCode string) (int, map[string]any) {
	return post(t, iss, "/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode}, "client_id": {clientID}, "client_secret": {secret},
	})
}

func TestDeviceFlow_Approve(t *testing.T) {
	iss := newIssuer(t)
	dc, uc := startDevice(t, iss)

	_, resp := poll(t, iss, dc)
	assert.Equal(t, "authorization_pending", resp["error"])
	time.Sleep(oidctest.DefaultDeviceInterval)

	assert.False(t, iss.Approve(uc, "nobody"), "unknown sub")
	assert.False(t, iss.Approve("ZZZZ-ZZZZ", "u-123"), "unknown user code")
	require.True(t, iss.Approve(uc, "u-123"))
	assert.False(t, iss.Approve(uc, "u-123"), "already answered")

	status, resp := poll(t, iss, dc)
	require.Equal(t, http.StatusOK, status, resp)
	claims := verify(t, iss, resp, "")
	assert.Equal(t, "u-123", claims.Subject)
	assert.Nil(t, claims.Claims["nonce"])

	time.Sleep(oidctest.DefaultDeviceInterval)
	_, resp = poll(t, iss, dc)
	assert.Equal(t, "invalid_grant", resp["error"], "a device code yields tokens once")
}

// A poll sooner than the interval gets slow_down, even once approved, as
// Keycloak answers. Waiting the interval gets the tokens.
func TestDeviceFlow_SlowDown(t *testing.T) {
	iss := newIssuer(t)
	dc, uc := startDevice(t, iss)
	_, resp := poll(t, iss, dc)
	assert.Equal(t, "authorization_pending", resp["error"])
	require.True(t, iss.Approve(uc, "u-123"))

	status, resp := poll(t, iss, dc)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "slow_down", resp["error"])

	time.Sleep(oidctest.DefaultDeviceInterval)
	status, resp = poll(t, iss, dc)
	assert.Equal(t, http.StatusOK, status, resp)
}

// Two people approve two codes. Each poll gets its own person's token.
func TestDeviceFlow_TwoPeople(t *testing.T) {
	iss := newIssuer(t)
	iss.AddUser("u-456", map[string]any{"email": "bob@example.com"})
	dc1, uc1 := startDevice(t, iss)
	dc2, uc2 := startDevice(t, iss)
	require.True(t, iss.Approve(uc2, "u-456"))
	require.True(t, iss.Approve(uc1, "u-123"))

	_, r1 := poll(t, iss, dc1)
	_, r2 := poll(t, iss, dc2)
	assert.Equal(t, "u-123", verify(t, iss, r1, "").Subject)
	assert.Equal(t, "u-456", verify(t, iss, r2, "").Subject)
}

func TestDeviceFlow_Deny(t *testing.T) {
	iss := newIssuer(t)
	dc, uc := startDevice(t, iss)
	require.True(t, iss.Deny(uc))
	assert.False(t, iss.Deny(uc))
	assert.False(t, iss.Approve(uc, "u-123"))
	status, resp := poll(t, iss, dc)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "access_denied", resp["error"])
}

func TestDeviceFlow_Expired(t *testing.T) {
	iss := newIssuer(t, oidctest.WithDeviceExpiry(10*time.Millisecond))
	dc, uc := startDevice(t, iss)
	time.Sleep(20 * time.Millisecond)
	assert.False(t, iss.Approve(uc, "u-123"))
	_, resp := poll(t, iss, dc)
	assert.Equal(t, "expired_token", resp["error"])
}

func TestDeviceAuthorization_NeedsClientSecret(t *testing.T) {
	iss := newIssuer(t)
	status, resp := post(t, iss, "/device_authorization", url.Values{"client_id": {clientID}})
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid_client", resp["error"])
}

func TestGroupsOverage(t *testing.T) {
	iss := newIssuer(t, oidctest.WithGroupsOverage())
	iss.AddUser("u-none", map[string]any{"email": "carol@example.com"})
	dc, uc := startDevice(t, iss)
	require.True(t, iss.Approve(uc, "u-123"))
	_, resp := poll(t, iss, dc)
	claims := verify(t, iss, resp, "").Claims

	assert.NotContains(t, claims, "groups")
	assert.Equal(t, map[string]any{"groups": "src1"}, claims["_claim_names"])
	assert.Equal(t, map[string]any{"src1": map[string]any{"endpoint": iss.GraphURL() + "/me/getMemberObjects"}}, claims["_claim_sources"])

	req, _ := http.NewRequest(http.MethodPost, iss.GraphURL()+"/me/getMemberObjects", strings.NewReader(`{"securityEnabledOnly":false}`))
	req.Header.Set("Authorization", "Bearer "+resp["access_token"].(string))
	gr, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer gr.Body.Close()
	var body struct{ Value []string }
	require.NoError(t, json.NewDecoder(gr.Body).Decode(&body))
	assert.Equal(t, []string{"g-eng"}, body.Value)

	dc, uc = startDevice(t, iss)
	require.True(t, iss.Approve(uc, "u-none"))
	_, resp = poll(t, iss, dc)
	assert.NotContains(t, verify(t, iss, resp, "").Claims, "_claim_names", "no groups, no overage")
}

func TestGraph_RefusesUnknownToken(t *testing.T) {
	iss := newIssuer(t)
	req, _ := http.NewRequest(http.MethodPost, iss.GraphURL()+"/me/getMemberObjects", nil)
	req.Header.Set("Authorization", "Bearer not-issued")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestLogout_RedirectsWithState(t *testing.T) {
	iss := newIssuer(t)
	resp, err := noRedirect.Get(iss.URL + "/logout?" + url.Values{
		"post_logout_redirect_uri": {"http://app.test/bye"}, "state": {"s-9"},
	}.Encode())
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "http://app.test/bye?state=s-9", resp.Header.Get("Location"))
}

func TestEdits_IDTokenClaimsAndTokenResponse(t *testing.T) {
	iss := newIssuer(t,
		oidctest.WithIDTokenClaims(func(c map[string]any) { c["aud"] = "someone-else" }),
		oidctest.WithTokenResponse(func(r map[string]any) { r["extra"] = "x" }),
	)
	dc, uc := startDevice(t, iss)
	require.True(t, iss.Approve(uc, "u-123"))
	_, resp := poll(t, iss, dc)
	assert.Equal(t, "x", resp["extra"])
	assert.Equal(t, "someone-else", segment(t, resp["id_token"].(string), 1)["aud"])
}

func TestSignInAs_UnknownUserPanics(t *testing.T) {
	iss := newIssuer(t)
	assert.Panics(t, func() { iss.SignInAs("nobody") })
}
