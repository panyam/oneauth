package e2e_test

// End-to-end tests for the Token Introspection endpoint (RFC 7662).
// Tests the full flow: register a resource server client, get a user token,
// then introspect it via the auth server's /oauth/introspect endpoint.
//
// References:
//   - RFC 7662 (https://www.rfc-editor.org/rfc/rfc7662):
//     "OAuth 2.0 Token Introspection"
//   - See: https://github.com/panyam/oneauth/issues/47

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntrospection_E2E_ActiveToken verifies the full introspection flow:
// 1. Register a resource server client in the KeyStore
// 2. Create a user and get an access token via password grant
// 3. Resource server calls /oauth/introspect with the token
// 4. Auth server returns active=true with claims
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.2
func TestIntrospection_E2E_ActiveToken(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("introspection e2e requires in-process servers")
	}

	// Register a resource server client that can call introspection
	rsClientID := "e2e-resource-server"
	rsSecret := "rs-introspection-secret"
	env.KeyStore.PutKey(&keys.KeyRecord{
		ClientID:  rsClientID,
		Key:       []byte(rsSecret),
		Algorithm: "HS256",
	})

	// Create a user and get an access token
	email, password := CreateTestUser(t, env, "introspect-user")
	accessToken, _ := LoginForTokens(t, env, email, password)
	require.NotEmpty(t, accessToken)

	// Introspect the token
	data := url.Values{"token": {accessToken}}
	req, _ := http.NewRequest(http.MethodPost, env.BaseURL()+"/oauth/introspect",
		strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rsClientID, rsSecret)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	// RFC 7662 §2.2: responses MUST include Cache-Control: no-store
	assert.Contains(t, resp.Header.Get("Cache-Control"), "no-store")

	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	require.NoError(t, json.Unmarshal(body, &result))

	assert.Equal(t, true, result["active"])
	assert.NotEmpty(t, result["sub"], "sub should contain the user ID")
	assert.Equal(t, "access_token", result["token_type"])
}

// TestIntrospection_E2E_RevokedToken verifies that a blacklisted token
// returns active=false via introspection. This is a key advantage over
// JWKS-based validation — the auth server checks the blacklist centrally.
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.2
func TestIntrospection_E2E_RevokedToken(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("introspection e2e requires in-process servers")
	}

	rsClientID := "e2e-rs-revoke"
	rsSecret := "rs-revoke-secret"
	env.KeyStore.PutKey(&keys.KeyRecord{
		ClientID:  rsClientID,
		Key:       []byte(rsSecret),
		Algorithm: "HS256",
	})

	// Get a token
	email, password := CreateTestUser(t, env, "revoke-introspect")
	accessToken, _ := LoginForTokens(t, env, email, password)

	// Revoke it via blacklist (extract jti from the JWT payload)
	parts := strings.Split(accessToken, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	json.Unmarshal(payload, &claims)
	jti := claims["jti"].(string)
	env.Blacklist.Revoke(jti, time.Now().Add(time.Hour))

	// Introspect — should be inactive
	data := url.Values{"token": {accessToken}}
	req, _ := http.NewRequest(http.MethodPost, env.BaseURL()+"/oauth/introspect",
		strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rsClientID, rsSecret)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

	assert.Equal(t, false, result["active"],
		"revoked token should be inactive via introspection")
}

// TestIntrospection_E2E_UnauthenticatedCaller verifies that calling
// introspection without credentials is rejected.
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.1
func TestIntrospection_E2E_UnauthenticatedCaller(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("introspection e2e requires in-process servers")
	}

	data := url.Values{"token": {"any-token"}}
	resp, err := http.Post(env.BaseURL()+"/oauth/introspect",
		"application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
