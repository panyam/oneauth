package keycloak_test

// oidctest, the fake OpenID Provider apps test against, compared with
// Keycloak on the same requests. Each probe runs against both and checks
// the error code an app's client would see. A fake written from the RFCs
// shares every misreading with the code it tests. A real provider breaks
// that tie (memories/feedback_live_test_corrects_fakes.md).
//
// Keycloak answers bad client credentials with unauthorized_client, and
// RFC 6749 §5.2 says invalid_client. The fake follows the RFC, so that
// probe checks the 401 and logs the code.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-5.2
// See: https://www.rfc-editor.org/rfc/rfc8628#section-3.5
// See: https://www.rfc-editor.org/rfc/rfc9207
// See: https://github.com/panyam/oneauth/issues/566

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/oauth2/oidc/oidctest"
)

// parityRedirectURI matches test-confidential's http://127.0.0.1:*
// redirect URIs. Nothing listens there, since the browser stops at it.
const parityRedirectURI = "http://127.0.0.1:1/cb"

const parityVerifier = "parity-verifier-long-enough-for-rfc-7636-forty-three"

var (
	kcLoginForm   = regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`)
	kcConsentForm = regexp.MustCompile(`<form[^>]*action="([^"]*login-actions/consent[^"]*)"`)
	kcConsentCode = regexp.MustCompile(`name="code" value="([^"]+)"`)
)

// parityIdP is one provider under comparison. signIn sends a browser to
// authURL and returns the query the provider redirected back with.
// approve and deny answer a device code as the person would.
type parityIdP struct {
	issuer, clientID, secret string
	signIn                   func(t *testing.T, authURL string) url.Values
	approve, deny            func(t *testing.T, verificationURIComplete, userCode string)
}

func parityFake(t *testing.T) parityIdP {
	iss := oidctest.New(t, oidctest.WithClient(confidentialClientID, confidentialClientSecret, parityRedirectURI))
	iss.AddUser("u-1", map[string]any{"email": "testuser@example.com"})
	iss.SignInAs("u-1")
	return parityIdP{
		issuer: iss.URL, clientID: confidentialClientID, secret: confidentialClientSecret,
		signIn: func(t *testing.T, authURL string) url.Values {
			return parityFollow(t, &http.Client{}, authURL, nil)
		},
		approve: func(t *testing.T, _, userCode string) { require.True(t, iss.Approve(userCode, "u-1")) },
		deny:    func(t *testing.T, _, userCode string) { require.True(t, iss.Deny(userCode)) },
	}
}

func parityKeycloak(t *testing.T) parityIdP {
	skipIfKeycloakNotRunning(t)
	return parityIdP{
		issuer: realmURL(), clientID: confidentialClientID, secret: confidentialClientSecret,
		signIn: func(t *testing.T, authURL string) url.Values {
			jar, _ := cookiejar.New(nil)
			return parityFollow(t, &http.Client{Jar: jar}, authURL, kcLogin)
		},
		approve: func(t *testing.T, uri, _ string) { kcAnswerDevice(t, uri, url.Values{"accept": {"Yes"}}) },
		deny:    func(t *testing.T, uri, _ string) { kcAnswerDevice(t, uri, url.Values{"cancel": {"No"}}) },
	}
}

// parityFollow GETs authURL and follows redirects until one reaches
// parityRedirectURI, filling in a login page with login when one shows.
func parityFollow(t *testing.T, hc *http.Client, authURL string, login func(*testing.T, *http.Client, []byte) *http.Response) url.Values {
	t.Helper()
	hc.Timeout = 20 * time.Second
	hc.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), parityRedirectURI) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	resp, err := hc.Get(authURL)
	require.NoError(t, err)
	if resp.StatusCode == http.StatusOK && login != nil {
		page, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		resp = login(t, hc, page)
	}
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	back, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	return back.Query()
}

func kcLogin(t *testing.T, hc *http.Client, page []byte) *http.Response {
	t.Helper()
	m := kcLoginForm.FindSubmatch(page)
	require.NotNil(t, m, "no Keycloak login form")
	resp, err := hc.PostForm(html.UnescapeString(string(m[1])), url.Values{
		"username": {testUsername}, "password": {testPassword}, "credentialId": {""},
	})
	require.NoError(t, err)
	return resp
}

// kcAnswerDevice logs in at the device verification page and answers the
// consent form Keycloak shows for every device grant.
func kcAnswerDevice(t *testing.T, verificationURIComplete string, answer url.Values) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: 20 * time.Second}
	resp, err := hc.Get(verificationURIComplete)
	require.NoError(t, err)
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp = kcLogin(t, hc, page)
	consent, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	action := kcConsentForm.FindSubmatch(consent)
	code := kcConsentCode.FindSubmatch(consent)
	require.NotNil(t, action, "no consent form")
	require.NotNil(t, code)
	consentURL, err := resp.Request.URL.Parse(html.UnescapeString(string(action[1])))
	require.NoError(t, err)
	answer.Set("code", string(code[1]))
	resp, err = hc.PostForm(consentURL.String(), answer)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func parityPost(t *testing.T, endpoint string, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(endpoint, form)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return resp.StatusCode, body
}

// forEachIdP runs probe against the fake and against Keycloak, which skips
// when Keycloak isn't running.
func forEachIdP(t *testing.T, probe func(t *testing.T, idp parityIdP, meta *client.ASMetadata)) {
	for name, mk := range map[string]func(*testing.T) parityIdP{"oidctest": parityFake, "keycloak": parityKeycloak} {
		t.Run(name, func(t *testing.T) {
			idp := mk(t)
			meta, err := client.DiscoverAS(idp.issuer)
			require.NoError(t, err)
			probe(t, idp, meta)
		})
	}
}

func parityCode(t *testing.T, idp parityIdP, meta *client.ASMetadata) url.Values {
	t.Helper()
	sum := sha256.Sum256([]byte(parityVerifier))
	back := idp.signIn(t, meta.AuthorizationEndpoint+"?"+url.Values{
		"client_id": {idp.clientID}, "redirect_uri": {parityRedirectURI}, "response_type": {"code"},
		"scope": {"openid"}, "state": {"st-1"}, "nonce": {"n-1"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	}.Encode())
	require.NotEmpty(t, back.Get("code"), "no code: %v", back)
	return back
}

func parityRedeem(t *testing.T, idp parityIdP, meta *client.ASMetadata, code string, edit func(url.Values)) (int, map[string]any) {
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {parityRedirectURI},
		"code_verifier": {parityVerifier}, "client_id": {idp.clientID}, "client_secret": {idp.secret},
	}
	if edit != nil {
		edit(form)
	}
	return parityPost(t, meta.TokenEndpoint, form)
}

func TestOidctestParity_CodeFlow(t *testing.T) {
	forEachIdP(t, func(t *testing.T, idp parityIdP, meta *client.ASMetadata) {
		back := parityCode(t, idp, meta)
		assert.Equal(t, "st-1", back.Get("state"))
		assert.Equal(t, meta.Issuer, back.Get("iss"), "RFC 9207 iss on the authorization response")

		status, resp := parityRedeem(t, idp, meta, back.Get("code"), nil)
		require.Equal(t, http.StatusOK, status, resp)
		assert.NotEmpty(t, resp["id_token"])

		status, resp = parityRedeem(t, idp, meta, back.Get("code"), nil)
		assert.Equal(t, http.StatusBadRequest, status, "a code works once")
		assert.Equal(t, "invalid_grant", resp["error"])
	})
}

func TestOidctestParity_TokenRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		edit       func(url.Values)
		wantStatus int
		wantError  string // empty: only log what the provider says
	}{
		"wrong verifier":     {func(f url.Values) { f.Set("code_verifier", parityVerifier+"x") }, 400, "invalid_grant"},
		"other redirect_uri": {func(f url.Values) { f.Set("redirect_uri", "http://127.0.0.1:2/cb") }, 400, "invalid_grant"},
		"unknown code":       {func(f url.Values) { f.Set("code", "not-a-code") }, 400, "invalid_grant"},
		"unknown grant":      {func(f url.Values) { f.Set("grant_type", "nope") }, 400, "unsupported_grant_type"},
		"wrong secret":       {func(f url.Values) { f.Set("client_secret", "nope") }, 401, ""},
	} {
		t.Run(name, func(t *testing.T) {
			forEachIdP(t, func(t *testing.T, idp parityIdP, meta *client.ASMetadata) {
				back := parityCode(t, idp, meta)
				status, resp := parityRedeem(t, idp, meta, back.Get("code"), tc.edit)
				assert.Equal(t, tc.wantStatus, status, resp)
				if tc.wantError != "" {
					assert.Equal(t, tc.wantError, resp["error"])
				} else {
					t.Logf("error = %v", resp["error"])
				}
			})
		})
	}
}

func parityStartDevice(t *testing.T, idp parityIdP, meta *client.ASMetadata) map[string]any {
	t.Helper()
	status, da := parityPost(t, meta.DeviceAuthorizationEndpoint, url.Values{
		"client_id": {idp.clientID}, "client_secret": {idp.secret}, "scope": {"openid"},
	})
	require.Equal(t, http.StatusOK, status, da)
	return da
}

func parityPoll(t *testing.T, idp parityIdP, meta *client.ASMetadata, da map[string]any) (int, map[string]any) {
	return parityPost(t, meta.TokenEndpoint, url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {da["device_code"].(string)}, "client_id": {idp.clientID}, "client_secret": {idp.secret},
	})
}

// parityWait waits the polling interval the device response named.
func parityWait(da map[string]any) {
	time.Sleep(time.Duration(da["interval"].(float64)) * time.Second)
}

// Both providers answer slow_down to a poll sooner than the interval, even
// once approved, and tokens after waiting it.
func TestOidctestParity_DeviceApproved(t *testing.T) {
	forEachIdP(t, func(t *testing.T, idp parityIdP, meta *client.ASMetadata) {
		da := parityStartDevice(t, idp, meta)
		assert.NotEmpty(t, da["verification_uri_complete"])
		_, resp := parityPoll(t, idp, meta, da)
		assert.Equal(t, "authorization_pending", resp["error"])

		idp.approve(t, da["verification_uri_complete"].(string), da["user_code"].(string))
		status, resp := parityPoll(t, idp, meta, da)
		assert.Equal(t, "slow_down", resp["error"], "polled sooner than the interval")

		parityWait(da)
		status, resp = parityPoll(t, idp, meta, da)
		require.Equal(t, http.StatusOK, status, resp)
		assert.NotEmpty(t, resp["id_token"])

		parityWait(da)
		status, resp = parityPoll(t, idp, meta, da)
		assert.Equal(t, http.StatusBadRequest, status, "a device code yields tokens once")
		assert.Equal(t, "invalid_grant", resp["error"])
	})
}

func TestOidctestParity_DeviceDenied(t *testing.T) {
	forEachIdP(t, func(t *testing.T, idp parityIdP, meta *client.ASMetadata) {
		da := parityStartDevice(t, idp, meta)
		idp.deny(t, da["verification_uri_complete"].(string), da["user_code"].(string))
		status, resp := parityPoll(t, idp, meta, da)
		assert.Equal(t, http.StatusBadRequest, status, resp)
		assert.Equal(t, "access_denied", resp["error"])
	})
}

func TestOidctestParity_DeviceRefusals(t *testing.T) {
	forEachIdP(t, func(t *testing.T, idp parityIdP, meta *client.ASMetadata) {
		status, resp := parityPost(t, meta.DeviceAuthorizationEndpoint, url.Values{"client_id": {idp.clientID}})
		assert.Equal(t, http.StatusUnauthorized, status, "RFC 8628 §3.1: a confidential client authenticates here")
		t.Logf("no secret: error = %v", resp["error"])

		status, resp = parityPoll(t, idp, meta, map[string]any{"device_code": "not-a-code"})
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_grant", resp["error"])
	})
}

// An unregistered redirect_uri gets 400 and no redirect from both, so a
// wrong callback URL in an app fails against the fake as it would live.
func TestOidctestParity_UnregisteredRedirectURI(t *testing.T) {
	forEachIdP(t, func(t *testing.T, idp parityIdP, meta *client.ASMetadata) {
		noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := noRedirect.Get(meta.AuthorizationEndpoint + "?" + url.Values{
			"client_id": {idp.clientID}, "redirect_uri": {"https://evil.example/cb"}, "response_type": {"code"},
			"scope": {"openid"}, "state": {"st-1"}, "code_challenge": {"x"}, "code_challenge_method": {"S256"},
		}.Encode())
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("Location"))
	})
}
