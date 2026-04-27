package e2e_test

// E2E tests for OAuth 2.0 Token Revocation (RFC 7009).
// These tests verify the full revocation flow through the auth server:
// get a token, revoke it via /oauth/revoke, verify it's no longer valid.
//
// See: https://www.rfc-editor.org/rfc/rfc7009

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRevocation_E2E_AccessToken verifies the full access token revocation
// flow: get a token, revoke it, then introspect to confirm it's inactive.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2
func TestRevocation_E2E_AccessToken(t *testing.T) {
	env := NewTestEnv(t)
	clientID, clientSecret := RegisterApp(t, env, "revoke-e2e.example.com")
	defer NewTestClient(env).Delete("/apps/" + clientID)

	// Get a token
	body, _ := json.Marshal(map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"scope":         "read",
	})
	tokenResp, _ := http.Post(env.BaseURL()+"/api/token", "application/json",
		strings.NewReader(string(body)))
	tokenData := ReadJSON(tokenResp)
	accessToken := tokenData["access_token"].(string)
	require.NotEmpty(t, accessToken)

	// Introspect — should be active
	introResp := introspectToken(t, env, accessToken, clientID, clientSecret)
	assert.Equal(t, true, introResp["active"])

	// Revoke via /oauth/revoke
	revokeResp := revokeToken(t, env, accessToken, "access_token", clientID, clientSecret)
	assert.Equal(t, http.StatusOK, revokeResp.StatusCode)

	// Introspect again — should be inactive
	introResp = introspectToken(t, env, accessToken, clientID, clientSecret)
	assert.Equal(t, false, introResp["active"])
}

// TestRevocation_E2E_RefreshToken verifies that a revoked refresh token
// cannot be used to obtain new access tokens.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2
func TestRevocation_E2E_RefreshToken(t *testing.T) {
	env := NewTestEnv(t)

	// Create a user and get a token pair (access + refresh)
	email, password := CreateTestUser(t, env, "revoke-refresh")

	body, _ := json.Marshal(map[string]any{
		"grant_type": "password",
		"username":   email,
		"password":   password,
	})
	tokenResp, _ := http.Post(env.BaseURL()+"/api/token", "application/json",
		strings.NewReader(string(body)))
	tokenData := ReadJSON(tokenResp)
	refreshToken := tokenData["refresh_token"].(string)
	require.NotEmpty(t, refreshToken)

	// Revoke the refresh token
	// Use empty client creds — the E2E auth server's revocation handler
	// accepts the app registered via password grant path
	// Actually we need a registered client for auth. Let's register one.
	clientID, clientSecret := RegisterApp(t, env, "revoke-rt.example.com")
	defer NewTestClient(env).Delete("/apps/" + clientID)

	revokeResp := revokeToken(t, env, refreshToken, "refresh_token", clientID, clientSecret)
	assert.Equal(t, http.StatusOK, revokeResp.StatusCode)

	// Try to refresh — should fail
	refreshBody, _ := json.Marshal(map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	})
	refreshResp, _ := http.Post(env.BaseURL()+"/api/token", "application/json",
		strings.NewReader(string(refreshBody)))
	refreshData := ReadJSON(refreshResp)
	assert.Equal(t, "invalid_grant", refreshData["error"],
		"revoked refresh token should not be usable")
}

// TestRevocation_E2E_Discovery verifies that the revocation_endpoint is
// advertised in AS metadata.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2
func TestRevocation_E2E_Discovery(t *testing.T) {
	env := NewTestEnv(t)

	resp, err := http.Get(env.BaseURL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	meta := ReadJSON(resp)

	revEndpoint, ok := meta["revocation_endpoint"]
	require.True(t, ok, "AS metadata must include revocation_endpoint")
	assert.Contains(t, revEndpoint.(string), "/oauth/revoke")
}

// TestRevocation_E2E_GarbageToken verifies that revoking a garbage token
// returns 200 OK without revealing any information.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.2
func TestRevocation_E2E_GarbageToken(t *testing.T) {
	env := NewTestEnv(t)
	clientID, clientSecret := RegisterApp(t, env, "revoke-garbage.example.com")
	defer NewTestClient(env).Delete("/apps/" + clientID)

	revokeResp := revokeToken(t, env, "not-a-real-token-at-all", "", clientID, clientSecret)
	assert.Equal(t, http.StatusOK, revokeResp.StatusCode)
}

// --- Helpers ---

func revokeToken(t *testing.T, env *TestEnv, token, hint, clientID, clientSecret string) *http.Response {
	t.Helper()
	form := url.Values{"token": {token}}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	req, _ := http.NewRequest("POST", env.BaseURL()+"/oauth/revoke",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func introspectToken(t *testing.T, env *TestEnv, token, clientID, clientSecret string) map[string]any {
	t.Helper()
	form := url.Values{"token": {token}}
	req, _ := http.NewRequest("POST", env.BaseURL()+"/oauth/introspect",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	resp, _ := http.DefaultClient.Do(req)
	return ReadJSON(resp)
}
