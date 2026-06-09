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
