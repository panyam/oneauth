package apiauth_test

// RFC 8707 resource indicators on the device-code and password grants
// (issue 523). The device flow takes `resource` at /device/authorize,
// stores it with the authorization, and lets the token request narrow it,
// the way the code grant does. The password grant takes it on the token
// request, like client_credentials. Refresh tokens from both keep the
// resources, so a refreshed token has the same audience.
//
// References:
//   - RFC 8707 §2, §2.1, §2.2 (https://www.rfc-editor.org/rfc/rfc8707)
//   - RFC 8628 §3.1 (https://www.rfc-editor.org/rfc/rfc8628#section-3.1)
//   - See: https://github.com/panyam/oneauth/issues/523

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/accounts"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
)

func resourceDeviceFixture(t *testing.T, allowed ...string) (*apiAuthFixture, *apiauth.DeviceAuthorizationHandler) {
	t.Helper()
	store := core.NewInMemoryDeviceAuthorizationStore()
	fx := newAPIAuthFixture(apiauth.OneAuthConfig{
		SigningKey: []byte("device-test-secret-32chars-min!!"), SigningAlg: "HS256",
		Issuer: "https://as.example", Audience: "https://default-aud.example",
		RefreshStore: newInMemoryRefreshStore(), DeviceAuthStore: store, AllowedResources: allowed,
	}, nil)
	return fx, &apiauth.DeviceAuthorizationHandler{
		Store: store, VerificationURI: "https://as.example/device", AllowedResources: allowed,
	}
}

func postJSON(t *testing.T, h http.Handler, path string, form url.Values) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	body := map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr.Code, body
}

// deviceApproved runs /device/authorize with resources, approves the user
// code, and returns the device_code ready to redeem.
func deviceApproved(t *testing.T, fx *apiAuthFixture, h http.Handler, resources ...string) string {
	t.Helper()
	form := url.Values{"client_id": {"tv-app"}, "scope": {"read"}}
	for _, r := range resources {
		form.Add("resource", r)
	}
	status, body := postJSON(t, h, "/device/authorize", form)
	require.Equal(t, http.StatusOK, status, body)
	deviceCode, userCode := body["device_code"].(string), body["user_code"].(string)
	require.NoError(t, fx.ApproveDeviceAuthorization(httptest.NewRequest(http.MethodPost, "/", nil), userCode, "alice", nil))
	_, _ = fx.DeviceAuthStore().UpdatePollingState(context.Background(), &core.UpdatePollingStateRequest{
		DeviceCode: deviceCode, PolledAt: time.Now().Add(-time.Hour),
	})
	return deviceCode
}

func redeemDevice(t *testing.T, fx *apiAuthFixture, deviceCode string, resources ...string) (int, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {apiauth.DeviceCodeGrantType}, "device_code": {deviceCode}, "client_id": {"tv-app"}}
	for _, r := range resources {
		form.Add("resource", r)
	}
	return postJSON(t, fx, "/api/token", form)
}

func refreshAud(t *testing.T, h http.Handler, refreshToken, clientID string) any {
	t.Helper()
	status, body := postJSON(t, h, "/api/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {clientID},
	})
	require.Equal(t, http.StatusOK, status, body)
	return audOf(t, body["access_token"].(string))
}

// See: https://www.rfc-editor.org/rfc/rfc8707#section-2.1
func TestResourceIndicators_DeviceGrantCarriesTheAuthorizedResources(t *testing.T) {
	fx, h := resourceDeviceFixture(t, mcpA, mcpB)
	status, body := redeemDevice(t, fx, deviceApproved(t, fx, h, mcpA))
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, mcpA, audOf(t, body["access_token"].(string)))
	assert.Equal(t, mcpA, refreshAud(t, fx, body["refresh_token"].(string), "tv-app"), "refresh keeps the resource")
}

// See: https://www.rfc-editor.org/rfc/rfc8707#section-2.2
func TestResourceIndicators_DeviceTokenRequestNarrowsButCannotWiden(t *testing.T) {
	fx, h := resourceDeviceFixture(t, mcpA, mcpB)
	status, body := redeemDevice(t, fx, deviceApproved(t, fx, h, mcpA, mcpB), mcpB)
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, mcpB, audOf(t, body["access_token"].(string)))

	status, body = redeemDevice(t, fx, deviceApproved(t, fx, h, mcpA), mcpB)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_target", body["error"])
}

// A device authorization with no resource lets the token request name one
// the AS serves, as client_credentials does.
func TestResourceIndicators_DeviceResourceOnTheTokenRequestAlone(t *testing.T) {
	fx, h := resourceDeviceFixture(t, mcpA, mcpB)
	status, body := redeemDevice(t, fx, deviceApproved(t, fx, h), mcpB)
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, mcpB, audOf(t, body["access_token"].(string)))

	status, body = redeemDevice(t, fx, deviceApproved(t, fx, h), "https://other.example/mcp")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_target", body["error"])
}

// See: https://www.rfc-editor.org/rfc/rfc8707#section-2
func TestResourceIndicators_DeviceAuthorizeRefusesAnUnknownResource(t *testing.T) {
	_, h := resourceDeviceFixture(t, mcpA)
	status, body := postJSON(t, h, "/device/authorize", url.Values{"client_id": {"tv-app"}, "resource": {mcpB}})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_target", body["error"])
}

func TestResourceIndicators_DeviceIgnoredWithoutAnAllowlist(t *testing.T) {
	fx, h := resourceDeviceFixture(t)
	status, body := redeemDevice(t, fx, deviceApproved(t, fx, h, mcpA), mcpA)
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, "https://default-aud.example", audOf(t, body["access_token"].(string)))
}

func resourcePasswordFixture(t *testing.T, allowed ...string) *apiAuthFixture {
	t.Helper()
	return newAPIAuthFixture(apiauth.OneAuthConfig{
		SigningKey: []byte("password-test-secret-32chars-ok!"), SigningAlg: "HS256",
		Issuer: "https://as.example", Audience: "https://default-aud.example",
		RefreshStore: newInMemoryRefreshStore(), AllowedResources: allowed,
		ValidateCredentials: func(username, password, _ string) (accounts.User, error) {
			if username == "alice" && password == "right" {
				return &accounts.BasicUser{ID: "alice"}, nil
			}
			return nil, errors.New("bad credentials")
		},
	}, nil)
}

func passwordWithResources(t *testing.T, fx *apiAuthFixture, resources ...string) (int, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"right"}, "client_id": {"cli"}}
	for _, r := range resources {
		form.Add("resource", r)
	}
	return postJSON(t, fx, "/api/token", form)
}

// See: https://www.rfc-editor.org/rfc/rfc8707#section-2
func TestResourceIndicators_PasswordGrantBindsTheAudience(t *testing.T) {
	fx := resourcePasswordFixture(t, mcpA, mcpB)
	status, body := passwordWithResources(t, fx, mcpA)
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, mcpA, audOf(t, body["access_token"].(string)))
	assert.Equal(t, mcpA, refreshAud(t, fx, body["refresh_token"].(string), "cli"), "refresh keeps the resource")

	status, body = passwordWithResources(t, fx, "https://other.example/mcp")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_target", body["error"])
}

func TestResourceIndicators_PasswordIgnoredWithoutAnAllowlist(t *testing.T) {
	status, body := passwordWithResources(t, resourcePasswordFixture(t), mcpA)
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, "https://default-aud.example", audOf(t, body["access_token"].(string)))
}

// MountDeviceFlow hands the AS's allowlist to /device/authorize, so a
// mounted device flow refuses a resource the AS doesn't serve.
func TestResourceIndicators_MountedDeviceFlowChecksResources(t *testing.T) {
	cfg := defaultMountCfg()
	cfg.OneAuth = apiauth.NewOneAuth(apiauth.OneAuthConfig{
		DeviceAuthStore: core.NewInMemoryDeviceAuthorizationStore(), AllowedResources: []string{mcpA},
	})
	mux := http.NewServeMux()
	apiauth.MountDeviceFlow(mux, cfg)

	status, body := postJSON(t, mux, "/device/authorize", url.Values{"client_id": {"tv-app"}, "resource": {mcpB}})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_target", body["error"])

	status, body = postJSON(t, mux, "/device/authorize", url.Values{"client_id": {"tv-app"}, "resource": {mcpA}})
	assert.Equal(t, http.StatusOK, status, body)
}
