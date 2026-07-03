// Confidential-client authentication via client_secret_basic (the
// Authorization: Basic header) on every grant whose token-endpoint dispatch
// forwards credentials to the shared confidential-client gate: jwt-bearer
// (RFC 7523), token-exchange / ID-JAG (RFC 8693), authorization_code
// (RFC 6749 §4.1.3), and device_code (RFC 8628) — issue 362.
//
// Before the fix, parseTokenRequest only read credentials from the form body,
// so the four dispatchers never saw a Basic-header secret and a
// client_secret_basic confidential client was rejected "client authentication
// required". The enforcement logic (issue 356/358) was correct; only the
// Basic-header extraction was missing on these paths. These tests pin that a
// correct Basic secret is accepted and a wrong one is rejected invalid_client.
//
// See:
//   - RFC 6749 §2.3.1: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
//   - RFC 7523 §3:     https://www.rfc-editor.org/rfc/rfc7523#section-3
//   - draft-ietf-oauth-identity-assertion-authz-grant-04 (ID-JAG)
//   - oneauth issue 362 (this); 356 / 358 (the confidential-client gate)
package apiauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// postFormBasic posts an x-www-form-urlencoded token request with client
// credentials in the Authorization: Basic header instead of the form body,
// mirroring a client_secret_basic client.
func postFormBasic(t *testing.T, h http.Handler, form url.Values, user, pass string) (int, map[string]any) {
	t.Helper()
	req := tokenForm(t, form)
	req.SetBasicAuth(user, pass)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var body map[string]any
	if rr.Body.Len() > 0 {
		_ = json.Unmarshal(rr.Body.Bytes(), &body)
	}
	return rr.Code, body
}

// --- jwt-bearer ------------------------------------------------------------

func TestJwtBearer_ConfidentialClient_BasicAuth_CorrectSecret_Succeeds(t *testing.T) {
	e := newConfClientEnv(t)
	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", e.mint(t, "", nil))
	// Credentials via Authorization: Basic, NOT the form body.

	status, body := postFormBasic(t, e.apiAuth, form, e.confClientID, e.confSecret)
	assert.Equal(t, http.StatusOK, status, "client_secret_basic MUST authenticate the confidential client")
	assert.NotEmpty(t, body["access_token"])
}

func TestJwtBearer_ConfidentialClient_BasicAuth_WrongSecret_InvalidClient(t *testing.T) {
	e := newConfClientEnv(t)
	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", e.mint(t, "", nil))

	status, body := postFormBasic(t, e.apiAuth, form, e.confClientID, "WRONG")
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid_client", body["error"])
}

// --- ID-JAG redemption -----------------------------------------------------

func TestIDJAG_Redeem_ConfidentialNamedClient_BasicAuth_Succeeds(t *testing.T) {
	e := newConfClientEnv(t)
	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", e.mintIDJAG(t, e.confClientID, "jti-basic-1"))
	// Authenticate as the named confidential client via Basic.

	status, body := postFormBasic(t, e.apiAuth, form, e.confClientID, e.confSecret)
	require.Equal(t, http.StatusOK, status, body)
	accessToken, _ := body["access_token"].(string)
	require.NotEmpty(t, accessToken)
	_, claims := parseUnverified(t, accessToken)
	assert.Equal(t, e.confClientID, claims["client_id"], "issued token binds the ID-JAG client_id")
}

// --- token-exchange --------------------------------------------------------

func TestTokenExchange_ConfidentialClient_BasicAuth_CorrectSecret_Succeeds(t *testing.T) {
	e := newConfClientEnv(t)
	form := url.Values{}
	form.Set("grant_type", apiauth.TokenExchangeGrantType)
	form.Set("subject_token", e.mint(t, "", nil))
	form.Set("subject_token_type", apiauth.TokenTypeJWT)

	status, body := postFormBasic(t, e.apiAuth, form, e.confClientID, e.confSecret)
	assert.Equal(t, http.StatusOK, status, body)
	assert.NotEmpty(t, body["access_token"])
}

func TestTokenExchange_ConfidentialClient_BasicAuth_WrongSecret_InvalidClient(t *testing.T) {
	e := newConfClientEnv(t)
	form := url.Values{}
	form.Set("grant_type", apiauth.TokenExchangeGrantType)
	form.Set("subject_token", e.mint(t, "", nil))
	form.Set("subject_token_type", apiauth.TokenTypeJWT)

	status, body := postFormBasic(t, e.apiAuth, form, e.confClientID, "WRONG")
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid_client", body["error"])
}

// --- authorization_code ----------------------------------------------------

func TestAuthCodeRedeem_ConfidentialClient_BasicAuth_CorrectSecret_Succeeds(t *testing.T) {
	fx, store := setupConfidentialAuthCode(t)
	seedAuthCodeFor(t, store, "code-basic", acConfClientID)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code-basic"},
		"code_verifier": {authcodeTestVerifier},
		"redirect_uri":  {authcodeTestRedirect},
		// client_id/secret via Authorization: Basic, not the form.
	}
	status, body := postFormBasic(t, fx, form, acConfClientID, acConfSecret)
	require.Equal(t, http.StatusOK, status, body)
	assert.NotEmpty(t, body["access_token"])
}

func TestAuthCodeRedeem_ConfidentialClient_BasicAuth_WrongSecret_InvalidClient(t *testing.T) {
	fx, store := setupConfidentialAuthCode(t)
	seedAuthCodeFor(t, store, "code-basic-wrong", acConfClientID)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code-basic-wrong"},
		"code_verifier": {authcodeTestVerifier},
		"redirect_uri":  {authcodeTestRedirect},
	}
	status, body := postFormBasic(t, fx, form, acConfClientID, "WRONG")
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid_client", body["error"])
}

// --- device_code -----------------------------------------------------------

func TestDeviceGrant_ConfidentialClient_BasicAuth_CorrectSecret_Succeeds(t *testing.T) {
	auth, _ := setupConfidentialDevice(t)
	devHandler := &apiauth.DeviceAuthorizationHandler{
		Store:           auth.DeviceAuthStore(),
		VerificationURI: "https://auth.example/device",
	}
	deviceCode, userCode := runDeviceAuthorize(t, devHandler, "client-conf")
	require.NoError(t, auth.ApproveDeviceAuthorization(httptest.NewRequest(http.MethodPost, "/", nil), userCode, "alice", nil))

	// Rewind LastPolledAt so slow_down doesn't fire on the first real poll.
	_, _ = auth.DeviceAuthStore().UpdatePollingState(context.Background(), &core.UpdatePollingStateRequest{
		DeviceCode: deviceCode,
		PolledAt:   time.Now().Add(-time.Hour),
	})

	status, body := postFormBasic(t, auth, url.Values{
		"grant_type":  {apiauth.DeviceCodeGrantType},
		"device_code": {deviceCode},
		// client_id/secret via Authorization: Basic.
	}, "client-conf", "conf-secret")
	require.Equal(t, http.StatusOK, status, body)
	assert.NotEmpty(t, body["access_token"])
}

func TestDeviceGrant_ConfidentialClient_BasicAuth_WrongSecret_InvalidClient(t *testing.T) {
	auth, _ := setupConfidentialDevice(t)
	devHandler := &apiauth.DeviceAuthorizationHandler{
		Store:           auth.DeviceAuthStore(),
		VerificationURI: "https://auth.example/device",
	}
	deviceCode, userCode := runDeviceAuthorize(t, devHandler, "client-conf")
	require.NoError(t, auth.ApproveDeviceAuthorization(httptest.NewRequest(http.MethodPost, "/", nil), userCode, "alice", nil))

	status, body := postFormBasic(t, auth, url.Values{
		"grant_type":  {apiauth.DeviceCodeGrantType},
		"device_code": {deviceCode},
	}, "client-conf", "WRONG-SECRET")
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid_client", body["error"])
}

// --- device authorization endpoint (RFC 8628 §3.1) -------------------------

// newBasicAuthDeviceAuthzHandler builds a POST /device/authorize handler whose
// ClientAuthenticator validates one confidential client's secret from the
// KeyStore, so client authentication actually runs at the authorization step
// (step 1) — not just at the token step.
func newBasicAuthDeviceAuthzHandler(t *testing.T, clientID, secret string) *apiauth.DeviceAuthorizationHandler {
	t.Helper()
	ks := keys.NewInMemoryKeyStore()
	_, err := ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID:  clientID,
		Key:       []byte(secret),
		Algorithm: "HS256",
	}})
	require.NoError(t, err)
	return &apiauth.DeviceAuthorizationHandler{
		Store:               core.NewInMemoryDeviceAuthorizationStore(),
		VerificationURI:     "https://auth.example/device",
		ClientAuthenticator: apiauth.NewClientAuthenticator(ks),
	}
}

func TestDeviceAuthorize_ConfidentialClient_BasicAuth_CorrectSecret_Succeeds(t *testing.T) {
	h := newBasicAuthDeviceAuthzHandler(t, "client-conf", "conf-secret")
	// client_id/secret via Authorization: Basic, absent from the form.
	status, body := postFormBasic(t, h, url.Values{"scope": {"read"}}, "client-conf", "conf-secret")
	require.Equal(t, http.StatusOK, status, body)
	assert.NotEmpty(t, body["device_code"])
	assert.NotEmpty(t, body["user_code"])
}

func TestDeviceAuthorize_ConfidentialClient_BasicAuth_WrongSecret_InvalidClient(t *testing.T) {
	h := newBasicAuthDeviceAuthzHandler(t, "client-conf", "conf-secret")
	status, body := postFormBasic(t, h, url.Values{"scope": {"read"}}, "client-conf", "WRONG")
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid_client", body["error"])
}
