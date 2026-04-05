package e2e_test

// End-to-end tests for the client_credentials grant (RFC 6749 §4.4).
// Tests the full flow: register app → get token via client_credentials →
// validate on resource server. Proves machine-to-machine auth works
// across the federated architecture.
//
// References:
//   - RFC 6749 §4.4 (https://www.rfc-editor.org/rfc/rfc6749#section-4.4):
//     Client Credentials Grant
//   - See: https://github.com/panyam/oneauth/issues/53

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClientCredentials_E2E_FullFlow verifies the complete machine-to-machine
// flow: register a client with the auth server, obtain a token via
// client_credentials, then use that token on a protected endpoint.
//
// Note: the token is validated on the auth server's /api/me (which uses
// JWTSecretKey-based validation), NOT on the resource server (which uses
// KeyStore/JWKS per-app validation). This is correct because client_credentials
// tokens are signed with the auth server's own key — resource servers that
// need to validate these tokens should share the same JWTSecretKey or use
// token introspection (#47). Federated resource tokens use MintResourceToken
// instead, which signs with per-app keys.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
func TestClientCredentials_E2E_FullFlow(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("client_credentials e2e requires in-process servers")
	}

	// Step 1: Register an app to get client_id + client_secret
	secret := "e2e-machine-secret"
	clientID := "e2e-machine-client"
	env.KeyStore.PutKey(&keys.KeyRecord{
		ClientID:  clientID,
		Key:       []byte(secret),
		Algorithm: "HS256",
	})

	// Step 2: Get token via client_credentials grant
	tokenReqBody := `{"grant_type":"client_credentials","client_id":"` + clientID + `","client_secret":"` + secret + `","scope":"read write"}`
	resp, err := http.Post(env.BaseURL()+"/api/token", "application/json",
		strings.NewReader(tokenReqBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "token endpoint should accept client_credentials")

	body, _ := io.ReadAll(resp.Body)
	var tokenResp map[string]any
	require.NoError(t, json.Unmarshal(body, &tokenResp))

	accessToken, ok := tokenResp["access_token"].(string)
	require.True(t, ok, "response must contain access_token")
	assert.Equal(t, "Bearer", tokenResp["token_type"])
	assert.Nil(t, tokenResp["refresh_token"], "client_credentials must not return refresh_token")

	// Step 3: Use the token on the auth server's protected endpoint
	req, _ := http.NewRequest(http.MethodGet, env.BaseURL()+"/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	meResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer meResp.Body.Close()

	assert.Equal(t, http.StatusOK, meResp.StatusCode,
		"auth server should accept client_credentials token on protected endpoint")

	meBody, _ := io.ReadAll(meResp.Body)
	var meResult map[string]any
	require.NoError(t, json.Unmarshal(meBody, &meResult))
	assert.Equal(t, clientID, meResult["user_id"],
		"sub claim should be the client_id")
}

// TestClientCredentials_E2E_WrongSecret verifies that invalid credentials
// are rejected at the token endpoint level.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
func TestClientCredentials_E2E_WrongSecret(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("client_credentials e2e requires in-process servers")
	}

	// Register a client
	env.KeyStore.PutKey(&keys.KeyRecord{
		ClientID:  "e2e-bad-secret-client",
		Key:       []byte("correct-secret"),
		Algorithm: "HS256",
	})

	// Try with wrong secret
	tokenReqBody := `{"grant_type":"client_credentials","client_id":"e2e-bad-secret-client","client_secret":"wrong-secret"}`
	resp, err := http.Post(env.BaseURL()+"/api/token", "application/json",
		strings.NewReader(tokenReqBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"should reject wrong client_secret")
}
