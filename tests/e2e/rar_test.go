package e2e_test

// E2E tests for RFC 9396 Rich Authorization Requests.
// These tests verify the full RAR flow through the auth server: register an app,
// request a client_credentials token with authorization_details, introspect it,
// and verify the details round-trip correctly.
//
// See: https://www.rfc-editor.org/rfc/rfc9396

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRAR_ClientCredentials_FullFlow verifies the complete RAR flow:
// 1. Register app via /apps/register
// 2. Request client_credentials token with authorization_details via /api/token
// 3. Verify authorization_details in response body
// 4. Verify authorization_details in JWT claims
// 5. Introspect the token and verify authorization_details in introspection response
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-5
func TestRAR_ClientCredentials_FullFlow(t *testing.T) {
	env := NewTestEnv(t)
	clientID, clientSecret := RegisterApp(t, env, "rar-flow.example.com")
	defer NewTestClient(env).Delete("/apps/" + clientID)

	// Step 1: Request token with authorization_details (JSON body)
	details := []map[string]any{
		{
			"type":    "payment_initiation",
			"actions": []string{"initiate"},
			"locations": []string{"https://bank.example.com/payments"},
			"instructedAmount": map[string]any{
				"currency": "EUR",
				"amount":   "45.00",
			},
			"creditorName": "Merchant A",
		},
	}

	body := map[string]any{
		"grant_type":            "client_credentials",
		"client_id":             clientID,
		"client_secret":         clientSecret,
		"scope":                 "payments",
		"authorization_details": details,
	}
	bodyJSON, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", env.BaseURL()+"/api/token",
		strings.NewReader(string(bodyJSON)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	tokenResp := ReadJSON(resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "token request failed: %v", tokenResp)

	// Step 2: Verify authorization_details in response body
	ad, ok := tokenResp["authorization_details"]
	require.True(t, ok, "response missing authorization_details")
	adArray := ad.([]any)
	require.Len(t, adArray, 1)
	adObj := adArray[0].(map[string]any)
	assert.Equal(t, "payment_initiation", adObj["type"])
	assert.Equal(t, "Merchant A", adObj["creditorName"])

	// scope should also be present
	assert.Equal(t, "payments", tokenResp["scope"])

	// Step 3: Verify authorization_details in JWT
	accessToken := tokenResp["access_token"].(string)
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(accessToken, jwt.MapClaims{})
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)

	jwtAD, ok := claims["authorization_details"]
	require.True(t, ok, "JWT missing authorization_details claim")
	jwtADArray := jwtAD.([]any)
	require.Len(t, jwtADArray, 1)
	assert.Equal(t, "payment_initiation", jwtADArray[0].(map[string]any)["type"])

	// Step 4: Introspect and verify
	form := url.Values{"token": {accessToken}}
	introReq, _ := http.NewRequest("POST", env.BaseURL()+"/oauth/introspect",
		strings.NewReader(form.Encode()))
	introReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introReq.SetBasicAuth(clientID, clientSecret)
	introResp, err := http.DefaultClient.Do(introReq)
	require.NoError(t, err)
	introResult := ReadJSON(introResp)
	require.Equal(t, http.StatusOK, introResp.StatusCode)
	assert.Equal(t, true, introResult["active"])

	introAD, ok := introResult["authorization_details"]
	require.True(t, ok, "introspection response missing authorization_details")
	introADArray := introAD.([]any)
	require.Len(t, introADArray, 1)
	assert.Equal(t, "payment_initiation", introADArray[0].(map[string]any)["type"])
}

// TestRAR_CoexistsWithScopes verifies that authorization_details and scope
// can be used independently in the same token request.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-7
func TestRAR_CoexistsWithScopes(t *testing.T) {
	env := NewTestEnv(t)
	clientID, clientSecret := RegisterApp(t, env, "rar-scope.example.com")
	defer NewTestClient(env).Delete("/apps/" + clientID)

	body := map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"scope":         "read write",
		"authorization_details": []map[string]any{
			{"type": "account_information", "actions": []string{"list_accounts"}},
		},
	}
	bodyJSON, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", env.BaseURL()+"/api/token",
		strings.NewReader(string(bodyJSON)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	tokenResp := ReadJSON(resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Both scope and authorization_details should be present
	assert.Equal(t, "read write", tokenResp["scope"])
	ad := tokenResp["authorization_details"].([]any)
	assert.Len(t, ad, 1)
	assert.Equal(t, "account_information", ad[0].(map[string]any)["type"])
}

// TestRAR_InvalidType_Rejected verifies that authorization_details with a
// missing type field are rejected with invalid_authorization_details error.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-5.2
func TestRAR_InvalidType_Rejected(t *testing.T) {
	env := NewTestEnv(t)
	clientID, clientSecret := RegisterApp(t, env, "rar-invalid.example.com")
	defer NewTestClient(env).Delete("/apps/" + clientID)

	body := map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"authorization_details": []map[string]any{
			{"actions": []string{"read"}}, // missing "type"
		},
	}
	bodyJSON, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", env.BaseURL()+"/api/token",
		strings.NewReader(string(bodyJSON)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	errResp := ReadJSON(resp)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_authorization_details", errResp["error"])
}

// TestRAR_FormEncoded verifies that authorization_details can be sent as a
// JSON-encoded string in a form-encoded request body.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-6.1
func TestRAR_FormEncoded(t *testing.T) {
	env := NewTestEnv(t)
	clientID, clientSecret := RegisterApp(t, env, "rar-form.example.com")
	defer NewTestClient(env).Delete("/apps/" + clientID)

	details := []map[string]any{
		{"type": "signing_service", "actions": []string{"sign"}},
	}
	detailsJSON, _ := json.Marshal(details)

	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {clientID},
		"client_secret":         {clientSecret},
		"authorization_details": {string(detailsJSON)},
	}

	req, _ := http.NewRequest("POST", env.BaseURL()+"/api/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	tokenResp := ReadJSON(resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "response: %v", tokenResp)

	ad := tokenResp["authorization_details"].([]any)
	require.Len(t, ad, 1)
	assert.Equal(t, "signing_service", ad[0].(map[string]any)["type"])
}

// TestRAR_NoDetails_Unchanged verifies that existing token requests without
// authorization_details continue to work exactly as before — no
// authorization_details field appears in the response.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-5
func TestRAR_NoDetails_Unchanged(t *testing.T) {
	env := NewTestEnv(t)
	clientID, clientSecret := RegisterApp(t, env, "rar-compat.example.com")
	defer NewTestClient(env).Delete("/apps/" + clientID)

	body := map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"scope":         "read",
	}
	bodyJSON, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", env.BaseURL()+"/api/token",
		strings.NewReader(string(bodyJSON)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	tokenResp := ReadJSON(resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	_, hasAD := tokenResp["authorization_details"]
	assert.False(t, hasAD, "authorization_details should not appear when not requested")
	assert.NotEmpty(t, tokenResp["access_token"])
	assert.Equal(t, "read", tokenResp["scope"])
}
