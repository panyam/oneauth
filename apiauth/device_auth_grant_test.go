package apiauth_test

// Tests for RFC 8628 Device Authorization Grant — the /device/authorize
// endpoint and the token-endpoint branch that polls a device_code.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupDevice(t *testing.T) (*apiauth.APIAuth, core.DeviceAuthorizationStore) {
	t.Helper()
	store := core.NewInMemoryDeviceAuthorizationStore()
	auth := &apiauth.APIAuth{
		JWTSecretKey:      "device-test-secret-32chars-min!!",
		JWTIssuer:         "test-issuer",
		RefreshTokenStore: newInMemoryRefreshStore(),
		DeviceAuthStore:   store,
	}
	return auth, store
}

func deviceAuthorizeForm(t *testing.T, clientID, scope string) *http.Request {
	t.Helper()
	form := url.Values{"client_id": {clientID}}
	if scope != "" {
		form.Set("scope", scope)
	}
	req := httptest.NewRequest(http.MethodPost, "/device/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func tokenForm(t *testing.T, vals url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestDeviceAuthorize_HappyPath(t *testing.T) {
	auth, _ := setupDevice(t)
	h := &apiauth.DeviceAuthorizationHandler{
		Store:           auth.DeviceAuthStore,
		VerificationURI: "https://auth.example/device",
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, deviceAuthorizeForm(t, "client-x", "read write"))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.NotEmpty(t, body["device_code"])
	assert.NotEmpty(t, body["user_code"])
	assert.Equal(t, "https://auth.example/device", body["verification_uri"])
	assert.NotZero(t, body["expires_in"])
	assert.NotZero(t, body["interval"])
}

func TestDeviceAuthorize_MissingClientID(t *testing.T) {
	auth, _ := setupDevice(t)
	h := &apiauth.DeviceAuthorizationHandler{
		Store:           auth.DeviceAuthStore,
		VerificationURI: "https://auth.example/device",
	}
	rr := httptest.NewRecorder()
	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/device/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_client")
}

func TestDeviceAuthorize_VerificationURICompleteEmitted(t *testing.T) {
	auth, _ := setupDevice(t)
	h := &apiauth.DeviceAuthorizationHandler{
		Store:                           auth.DeviceAuthStore,
		VerificationURI:                 "https://auth.example/device",
		VerificationURICompleteTemplate: "https://auth.example/device?user_code=%s",
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, deviceAuthorizeForm(t, "client-x", ""))
	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "verification_uri_complete")
	assert.Contains(t, body, "user_code=")
}

func runDeviceAuthorize(t *testing.T, h http.Handler, clientID string) (deviceCode, userCode string) {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, deviceAuthorizeForm(t, clientID, "read"))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	return body["device_code"].(string), body["user_code"].(string)
}

func TestDeviceGrant_PendingThenApproved(t *testing.T) {
	auth, _ := setupDevice(t)
	devHandler := &apiauth.DeviceAuthorizationHandler{
		Store:           auth.DeviceAuthStore,
		VerificationURI: "https://auth.example/device",
	}
	deviceCode, userCode := runDeviceAuthorize(t, devHandler, "client-x")

	// First poll → authorization_pending.
	form := url.Values{
		"grant_type":  {apiauth.DeviceCodeGrantType},
		"device_code": {deviceCode},
		"client_id":   {"client-x"},
	}
	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenForm(t, form))
	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "authorization_pending")

	// User approves.
	approveReq := httptest.NewRequest(http.MethodPost, "/", nil)
	require.NoError(t, auth.ApproveDeviceAuthorization(approveReq, userCode, "alice", nil))

	// Next poll → token issued.
	// Bypass the slow_down guard — in real polling the device respects
	// the interval; tests need to immediately re-poll. The grant handler
	// reads LastPolledAt vs IntervalSeconds, so we reset LastPolledAt
	// by re-fetching and writing a stale poll time via UpdatePollingState.
	_, _ = auth.DeviceAuthStore.UpdatePollingState(context.Background(), &core.UpdatePollingStateRequest{
		DeviceCode: deviceCode,
		PolledAt:   time.Now().Add(-time.Hour),
		SlowDown:   false,
	})
	rr = httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenForm(t, form))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var out map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
	assert.NotEmpty(t, out["access_token"])
	assert.NotEmpty(t, out["refresh_token"], "refresh token issued when RefreshTokenStore is configured")
	assert.Equal(t, "Bearer", out["token_type"])
}

func TestDeviceGrant_SlowDownOnFastPoll(t *testing.T) {
	auth, _ := setupDevice(t)
	devHandler := &apiauth.DeviceAuthorizationHandler{
		Store:           auth.DeviceAuthStore,
		VerificationURI: "https://auth.example/device",
	}
	deviceCode, _ := runDeviceAuthorize(t, devHandler, "client-x")

	form := url.Values{
		"grant_type":  {apiauth.DeviceCodeGrantType},
		"device_code": {deviceCode},
		"client_id":   {"client-x"},
	}
	// First poll lands as authorization_pending and records LastPolledAt.
	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenForm(t, form))
	require.Equal(t, http.StatusBadRequest, rr.Code)

	// Immediate second poll → slow_down.
	rr = httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenForm(t, form))
	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "slow_down")
}

func TestDeviceGrant_AccessDenied(t *testing.T) {
	auth, _ := setupDevice(t)
	devHandler := &apiauth.DeviceAuthorizationHandler{
		Store:           auth.DeviceAuthStore,
		VerificationURI: "https://auth.example/device",
	}
	deviceCode, userCode := runDeviceAuthorize(t, devHandler, "client-x")

	require.NoError(t, auth.DenyDeviceAuthorization(httptest.NewRequest(http.MethodPost, "/", nil), userCode))

	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenForm(t, url.Values{
		"grant_type":  {apiauth.DeviceCodeGrantType},
		"device_code": {deviceCode},
		"client_id":   {"client-x"},
	}))
	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "access_denied")
}

func TestDeviceGrant_ExpiredToken(t *testing.T) {
	auth, store := setupDevice(t)
	devHandler := &apiauth.DeviceAuthorizationHandler{
		Store:           auth.DeviceAuthStore,
		VerificationURI: "https://auth.example/device",
	}
	deviceCode, _ := runDeviceAuthorize(t, devHandler, "client-x")

	// Force expiry by rewriting the record's ExpiresAt.
	g, err := store.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: deviceCode})
	require.NoError(t, err)
	g.Authorization.ExpiresAt = time.Now().Add(-time.Minute)
	// Delete + recreate keeps in-memory invariants simple; FS test
	// covers persistence on its own track.
	_, _ = store.DeleteDeviceAuthorization(context.Background(), &core.DeleteDeviceAuthorizationRequest{DeviceCode: deviceCode})
	_, err = store.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: g.Authorization})
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenForm(t, url.Values{
		"grant_type":  {apiauth.DeviceCodeGrantType},
		"device_code": {deviceCode},
		"client_id":   {"client-x"},
	}))
	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "expired_token")
}

func TestDeviceGrant_UnknownDeviceCode(t *testing.T) {
	auth, _ := setupDevice(t)
	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenForm(t, url.Values{
		"grant_type":  {apiauth.DeviceCodeGrantType},
		"device_code": {"never-existed"},
		"client_id":   {"client-x"},
	}))
	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant")
}

func TestDeviceGrant_MissingClientID_BindingBypass_Rejected(t *testing.T) {
	// Regression test: a stolen device_code MUST NOT be redeemable by
	// simply omitting client_id from the polling request. Pre-fix the
	// handler short-circuited the check when req.ClientID was empty,
	// letting any caller bypass the RFC 8628 §3.4 binding requirement.
	auth, _ := setupDevice(t)
	devHandler := &apiauth.DeviceAuthorizationHandler{
		Store:           auth.DeviceAuthStore,
		VerificationURI: "https://auth.example/device",
	}
	deviceCode, userCode := runDeviceAuthorize(t, devHandler, "client-x")
	require.NoError(t, auth.ApproveDeviceAuthorization(httptest.NewRequest(http.MethodPost, "/", nil), userCode, "alice", nil))

	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenForm(t, url.Values{
		"grant_type":  {apiauth.DeviceCodeGrantType},
		"device_code": {deviceCode},
		// client_id intentionally absent
	}))
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "invalid_grant")
	assert.NotContains(t, rr.Body.String(), "access_token",
		"missing client_id MUST NOT yield an access token even when the authorization is approved")
}

func TestDeviceGrant_ClientIDMismatch(t *testing.T) {
	auth, _ := setupDevice(t)
	devHandler := &apiauth.DeviceAuthorizationHandler{
		Store:           auth.DeviceAuthStore,
		VerificationURI: "https://auth.example/device",
	}
	deviceCode, _ := runDeviceAuthorize(t, devHandler, "client-x")

	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenForm(t, url.Values{
		"grant_type":  {apiauth.DeviceCodeGrantType},
		"device_code": {deviceCode},
		"client_id":   {"different-client"}, // wrong
	}))
	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant")
}

// setupConfidentialDevice wires a confidential client: the AppStore
// registers `client-conf` with token_endpoint_auth_method=client_secret_post,
// the KeyStore holds the matching secret, and APIAuth gets ClientKeyStore
// so the lazy ClientAuthenticator can validate it.
func setupConfidentialDevice(t *testing.T) (*apiauth.APIAuth, core.DeviceAuthorizationStore) {
	t.Helper()
	store := core.NewInMemoryDeviceAuthorizationStore()
	apps := core.NewInMemoryAppStore()
	_, err := apps.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID:                "client-conf",
		TokenEndpointAuthMethod: "client_secret_post",
		SigningAlg:              "HS256",
	}})
	require.NoError(t, err)
	ks := keys.NewInMemoryKeyStore()
	_, err = ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID:  "client-conf",
		Key:       []byte("conf-secret"),
		Algorithm: "HS256",
	}})
	require.NoError(t, err)
	auth := &apiauth.APIAuth{
		JWTSecretKey:      "device-test-secret-32chars-min!!",
		JWTIssuer:         "test-issuer",
		RefreshTokenStore: newInMemoryRefreshStore(),
		DeviceAuthStore:   store,
		AppStore:          apps,
		ClientKeyStore:    ks,
	}
	return auth, store
}

func TestDeviceGrant_ConfidentialClient_WithCorrectCreds_Succeeds(t *testing.T) {
	auth, _ := setupConfidentialDevice(t)
	devHandler := &apiauth.DeviceAuthorizationHandler{
		Store:           auth.DeviceAuthStore,
		VerificationURI: "https://auth.example/device",
	}
	deviceCode, userCode := runDeviceAuthorize(t, devHandler, "client-conf")
	require.NoError(t, auth.ApproveDeviceAuthorization(httptest.NewRequest(http.MethodPost, "/", nil), userCode, "alice", nil))

	// Rewind LastPolledAt so slow_down doesn't fire on the first real poll.
	_, _ = auth.DeviceAuthStore.UpdatePollingState(context.Background(), &core.UpdatePollingStateRequest{
		DeviceCode: deviceCode,
		PolledAt:   time.Now().Add(-time.Hour),
	})

	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenForm(t, url.Values{
		"grant_type":    {apiauth.DeviceCodeGrantType},
		"device_code":   {deviceCode},
		"client_id":     {"client-conf"},
		"client_secret": {"conf-secret"},
	}))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "access_token")
}

func TestDeviceGrant_ConfidentialClient_MissingCreds_Rejected(t *testing.T) {
	// The whole point of #266: a stolen device_code MUST NOT redeem when
	// the registered client is confidential and the redeemer doesn't
	// present credentials. Pre-fix this returned 200 + access_token.
	auth, _ := setupConfidentialDevice(t)
	devHandler := &apiauth.DeviceAuthorizationHandler{
		Store:           auth.DeviceAuthStore,
		VerificationURI: "https://auth.example/device",
	}
	deviceCode, userCode := runDeviceAuthorize(t, devHandler, "client-conf")
	require.NoError(t, auth.ApproveDeviceAuthorization(httptest.NewRequest(http.MethodPost, "/", nil), userCode, "alice", nil))

	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenForm(t, url.Values{
		"grant_type":  {apiauth.DeviceCodeGrantType},
		"device_code": {deviceCode},
		"client_id":   {"client-conf"},
		// client_secret intentionally absent
	}))
	require.Equal(t, http.StatusUnauthorized, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "invalid_client")
	assert.NotContains(t, rr.Body.String(), "access_token")
}

func TestDeviceGrant_ConfidentialClient_WrongCreds_Rejected(t *testing.T) {
	auth, _ := setupConfidentialDevice(t)
	devHandler := &apiauth.DeviceAuthorizationHandler{
		Store:           auth.DeviceAuthStore,
		VerificationURI: "https://auth.example/device",
	}
	deviceCode, userCode := runDeviceAuthorize(t, devHandler, "client-conf")
	require.NoError(t, auth.ApproveDeviceAuthorization(httptest.NewRequest(http.MethodPost, "/", nil), userCode, "alice", nil))

	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenForm(t, url.Values{
		"grant_type":    {apiauth.DeviceCodeGrantType},
		"device_code":   {deviceCode},
		"client_id":     {"client-conf"},
		"client_secret": {"WRONG-SECRET"},
	}))
	require.Equal(t, http.StatusUnauthorized, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "invalid_client")
}

func TestDeviceGrant_AppStoreSet_UnregisteredClient_Rejected(t *testing.T) {
	// Fail-CLOSED: once AppStore is wired, an unregistered client_id
	// MUST NOT redeem a device_code — even with a syntactically valid
	// authorization in the device store. Silently falling back to the
	// form-`client_id`-only path would subvert the operator's intent
	// in wiring AppStore (issue 266 security review).
	store := core.NewInMemoryDeviceAuthorizationStore()
	apps := core.NewInMemoryAppStore() // empty — no clients registered
	auth := &apiauth.APIAuth{
		JWTSecretKey:      "device-test-secret-32chars-min!!",
		JWTIssuer:         "test-issuer",
		RefreshTokenStore: newInMemoryRefreshStore(),
		DeviceAuthStore:   store,
		AppStore:          apps,
	}
	devHandler := &apiauth.DeviceAuthorizationHandler{
		Store:           store,
		VerificationURI: "https://auth.example/device",
	}
	deviceCode, userCode := runDeviceAuthorize(t, devHandler, "client-ghost")
	require.NoError(t, auth.ApproveDeviceAuthorization(httptest.NewRequest(http.MethodPost, "/", nil), userCode, "alice", nil))

	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenForm(t, url.Values{
		"grant_type":  {apiauth.DeviceCodeGrantType},
		"device_code": {deviceCode},
		"client_id":   {"client-ghost"},
	}))
	require.Equal(t, http.StatusUnauthorized, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "invalid_client")
	assert.NotContains(t, rr.Body.String(), "access_token")
}

func TestDeviceGrant_PublicClient_NoCredsRequired(t *testing.T) {
	// Auth method `none` → form client_id alone is the identifier. The
	// new confidential-client enforcement MUST NOT regress this case.
	store := core.NewInMemoryDeviceAuthorizationStore()
	apps := core.NewInMemoryAppStore()
	_, err := apps.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID:                "client-public",
		TokenEndpointAuthMethod: "none",
		SigningAlg:              "HS256",
	}})
	require.NoError(t, err)
	auth := &apiauth.APIAuth{
		JWTSecretKey:      "device-test-secret-32chars-min!!",
		JWTIssuer:         "test-issuer",
		RefreshTokenStore: newInMemoryRefreshStore(),
		DeviceAuthStore:   store,
		AppStore:          apps,
	}
	devHandler := &apiauth.DeviceAuthorizationHandler{
		Store:           store,
		VerificationURI: "https://auth.example/device",
	}
	deviceCode, userCode := runDeviceAuthorize(t, devHandler, "client-public")
	require.NoError(t, auth.ApproveDeviceAuthorization(httptest.NewRequest(http.MethodPost, "/", nil), userCode, "alice", nil))
	_, _ = store.UpdatePollingState(context.Background(), &core.UpdatePollingStateRequest{
		DeviceCode: deviceCode,
		PolledAt:   time.Now().Add(-time.Hour),
	})

	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenForm(t, url.Values{
		"grant_type":  {apiauth.DeviceCodeGrantType},
		"device_code": {deviceCode},
		"client_id":   {"client-public"},
	}))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "access_token")
}

func TestDeviceGrant_TokenEndpointWithoutStore_UnsupportedGrant(t *testing.T) {
	auth := &apiauth.APIAuth{
		JWTSecretKey:      "device-test-secret-32chars-min!!",
		JWTIssuer:         "test-issuer",
		RefreshTokenStore: newInMemoryRefreshStore(),
		// DeviceAuthStore intentionally nil.
	}
	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenForm(t, url.Values{
		"grant_type":  {apiauth.DeviceCodeGrantType},
		"device_code": {"any"},
	}))
	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "unsupported_grant_type")
}
