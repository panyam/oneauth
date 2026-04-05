package e2e_test

// End-to-end tests for DCR (RFC 7591) + Introspection Client (RFC 7662).
// Full flow: register client via DCR → get token via client_credentials →
// validate via introspection endpoint.
//
// References:
//   - RFC 7591: Dynamic Client Registration
//   - RFC 7662: Token Introspection
//   - See: https://github.com/panyam/oneauth/issues/48
//   - See: https://github.com/panyam/oneauth/issues/55

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDCR_E2E_RegisterAndUse verifies the full DCR flow: register a client
// via POST /apps/dcr (RFC 7591 format), then use the returned credentials
// to obtain a token via client_credentials grant.
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1
func TestDCR_E2E_RegisterAndUse(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("DCR e2e requires in-process servers")
	}

	// Step 1: Register via DCR
	c := NewTestClient(env)
	dcrResp := c.PostJSON("/apps/dcr", map[string]any{
		"client_name":                  "E2E DCR App",
		"client_uri":                   "https://e2e-dcr.example.com",
		"grant_types":                  []string{"client_credentials"},
		"token_endpoint_auth_method":   "client_secret_post",
	})
	require.Equal(t, 201, dcrResp.StatusCode)

	dcrData := ReadJSON(dcrResp)
	clientID := dcrData["client_id"].(string)
	clientSecret := dcrData["client_secret"].(string)
	assert.NotEmpty(t, clientID)
	assert.NotEmpty(t, clientSecret)
	assert.Equal(t, "E2E DCR App", dcrData["client_name"])
	assert.NotNil(t, dcrData["client_id_issued_at"])

	// Step 2: Use credentials to get a token via client_credentials
	tokenBody := map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"scope":         "read write",
	}
	tokenBodyJSON, _ := json.Marshal(tokenBody)
	tokenResp, err := http.Post(env.BaseURL()+"/api/token", "application/json",
		strings.NewReader(string(tokenBodyJSON)))
	require.NoError(t, err)
	defer tokenResp.Body.Close()

	assert.Equal(t, http.StatusOK, tokenResp.StatusCode,
		"DCR-registered client should be able to get a token")

	tokenData, _ := io.ReadAll(tokenResp.Body)
	var tokenResult map[string]any
	json.Unmarshal(tokenData, &tokenResult)
	assert.NotEmpty(t, tokenResult["access_token"])
}

// TestDCR_E2E_AppAppearsInList verifies that DCR-registered clients appear
// in the AppRegistrar list endpoint (GET /apps).
func TestDCR_E2E_AppAppearsInList(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("DCR e2e requires in-process servers")
	}

	c := NewTestClient(env)
	dcrResp := c.PostJSON("/apps/dcr", map[string]any{
		"client_name": "Listed App",
	})
	require.Equal(t, 201, dcrResp.StatusCode)
	dcrData := ReadJSON(dcrResp)
	clientID := dcrData["client_id"].(string)

	// Check list
	listResp := c.Get("/apps")
	listData := ReadJSON(listResp)
	apps := listData["apps"].([]any)

	found := false
	for _, app := range apps {
		if app.(map[string]any)["client_id"] == clientID {
			found = true
			break
		}
	}
	assert.True(t, found, "DCR-registered client should appear in /apps list")
}

// TestIntrospectionClient_E2E_ValidateViaIntrospection verifies that a
// resource server can validate tokens using the IntrospectionValidator
// (calling the auth server's /oauth/introspect endpoint) instead of local
// JWT validation. This is the full #55 flow.
//
// See: https://www.rfc-editor.org/rfc/rfc7662
func TestIntrospectionClient_E2E_ValidateViaIntrospection(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("Introspection client e2e requires in-process servers")
	}

	// Register a resource server client for introspection auth
	rsClientID := "e2e-rs-introspect-client"
	rsSecret := "e2e-rs-secret"
	env.KeyStore.PutKey(&keys.KeyRecord{
		ClientID:  rsClientID,
		Key:       []byte(rsSecret),
		Algorithm: "HS256",
	})

	// Create a user and get an access token
	email, password := CreateTestUser(t, env, "introspect-client-user")
	accessToken, _ := LoginForTokens(t, env, email, password)

	// Create an IntrospectionValidator pointing at the auth server
	validator := &apiauth.IntrospectionValidator{
		IntrospectionURL: env.BaseURL() + "/oauth/introspect",
		ClientID:         rsClientID,
		ClientSecret:     rsSecret,
	}

	// Validate the token via introspection
	result, err := validator.Validate(accessToken)
	require.NoError(t, err)
	assert.True(t, result.Active, "valid token should be active via introspection")
	assert.NotEmpty(t, result.Sub, "sub should be present")

	// Validate via middleware integration
	userID, scopes, authType, _, err := validator.ValidateForMiddleware(accessToken)
	require.NoError(t, err)
	assert.NotEmpty(t, userID)
	assert.Equal(t, "introspection", authType)
	_ = scopes // scopes may be empty depending on login
}
