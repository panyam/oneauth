package apiauth_test

// Tests for RFC 9396 Rich Authorization Requests support in the token endpoint
// and introspection handler.
//
// See: https://www.rfc-editor.org/rfc/rfc9396

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupRARAuth creates an APIAuth with a registered client for RAR testing.
func setupRARAuth(t *testing.T) (*apiauth.APIAuth, *keys.InMemoryKeyStore) {
	t.Helper()
	ks := keys.NewInMemoryKeyStore()
	ks.PutKey(&keys.KeyRecord{
		ClientID:  "test-client",
		Key:       []byte("test-client-secret"),
		Algorithm: "HS256",
	})

	auth := &apiauth.APIAuth{
		JWTSecretKey:   "rar-test-jwt-secret-32chars-min!",
		JWTIssuer:      "test-issuer",
		ClientKeyStore: ks,
	}
	return auth, ks
}

// TestTokenEndpoint_ClientCredentials_WithRAR verifies that client_credentials
// tokens carry authorization_details in both the response body and the JWT.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-5
func TestTokenEndpoint_ClientCredentials_WithRAR(t *testing.T) {
	auth, _ := setupRARAuth(t)

	details := []core.AuthorizationDetail{
		{
			Type:      "payment_initiation",
			Actions:   []string{"initiate"},
			Locations: []string{"https://bank.example.com/payments"},
			Extra: map[string]any{
				"instructedAmount": map[string]any{
					"currency": "EUR",
					"amount":   "45.00",
				},
			},
		},
	}
	detailsJSON, _ := json.Marshal(details)

	body := map[string]any{
		"grant_type":            "client_credentials",
		"client_id":             "test-client",
		"client_secret":         "test-client-secret",
		"authorization_details": details,
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader(string(bodyJSON)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "response: %s", rr.Body.String())

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

	// Token response must include authorization_details
	ad, ok := resp["authorization_details"]
	require.True(t, ok, "response missing authorization_details")
	adArray, ok := ad.([]any)
	require.True(t, ok, "authorization_details should be an array")
	assert.Len(t, adArray, 1)

	adObj := adArray[0].(map[string]any)
	assert.Equal(t, "payment_initiation", adObj["type"])

	// Decode the JWT and verify the claim is embedded
	tokenStr := resp["access_token"].(string)
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	require.NoError(t, err)
	claims := token.Claims.(jwt.MapClaims)

	jwtAD, ok := claims["authorization_details"]
	require.True(t, ok, "JWT missing authorization_details claim")
	jwtADArray, ok := jwtAD.([]any)
	require.True(t, ok)
	assert.Len(t, jwtADArray, 1)

	_ = detailsJSON // used implicitly via body
}

// TestTokenEndpoint_ClientCredentials_InvalidRAR verifies that a missing type
// field in authorization_details produces the invalid_authorization_details
// error code per RFC 9396 §5.2.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-5.2
func TestTokenEndpoint_ClientCredentials_InvalidRAR(t *testing.T) {
	auth, _ := setupRARAuth(t)

	body := map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     "test-client",
		"client_secret": "test-client-secret",
		"authorization_details": []map[string]any{
			{"actions": []string{"read"}}, // missing "type"
		},
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader(string(bodyJSON)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "invalid_authorization_details", resp["error"])
}

// TestTokenEndpoint_FormEncoded_RAR verifies that authorization_details can be
// sent as a JSON-encoded string in form-encoded requests per RFC 9396 §6.1.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-6.1
func TestTokenEndpoint_FormEncoded_RAR(t *testing.T) {
	auth, _ := setupRARAuth(t)

	details := []core.AuthorizationDetail{
		{Type: "account_information", Actions: []string{"list_accounts"}},
	}
	detailsJSON, _ := json.Marshal(details)

	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {"test-client"},
		"client_secret":         {"test-client-secret"},
		"authorization_details": {string(detailsJSON)},
	}

	req := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "response: %s", rr.Body.String())

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

	ad, ok := resp["authorization_details"]
	require.True(t, ok, "response missing authorization_details")
	adArray := ad.([]any)
	assert.Len(t, adArray, 1)
	assert.Equal(t, "account_information", adArray[0].(map[string]any)["type"])
}

// TestTokenEndpoint_FormEncoded_InvalidRARJSON verifies that malformed JSON in
// the authorization_details form parameter produces an error.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-6.1
func TestTokenEndpoint_FormEncoded_InvalidRARJSON(t *testing.T) {
	auth, _ := setupRARAuth(t)

	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {"test-client"},
		"client_secret":         {"test-client-secret"},
		"authorization_details": {"not valid json"},
	}

	req := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "invalid_authorization_details", resp["error"])
}

// TestCreateAccessToken_StandardClaimsGuard_RAR verifies that CustomClaimsFunc
// cannot override the authorization_details claim.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2
func TestCreateAccessToken_StandardClaimsGuard_RAR(t *testing.T) {
	auth := &apiauth.APIAuth{
		JWTSecretKey: "rar-guard-test-secret-32chars-m!",
		CustomClaimsFunc: func(userID string, scopes []string) (map[string]any, error) {
			return map[string]any{
				"authorization_details": []map[string]any{
					{"type": "injected", "actions": []string{"admin"}},
				},
			}, nil
		},
	}

	details := []core.AuthorizationDetail{
		{Type: "legitimate", Actions: []string{"read"}},
	}

	token, _, err := auth.CreateAccessToken("user-1", []string{"read"}, details)
	require.NoError(t, err)

	// Parse JWT and verify the custom claim was blocked
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)

	ad := claims["authorization_details"].([]any)
	adObj := ad[0].(map[string]any)
	assert.Equal(t, "legitimate", adObj["type"], "CustomClaimsFunc should not override authorization_details")
}

// TestIntrospection_WithRAR verifies that the introspection response includes
// authorization_details when the token contains them.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-9.1
func TestIntrospection_WithRAR(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	ks.PutKey(&keys.KeyRecord{
		ClientID:  "resource-server",
		Key:       []byte("rs-secret"),
		Algorithm: "HS256",
	})

	auth := &apiauth.APIAuth{
		JWTSecretKey:   "introspect-rar-secret-32chars-m!",
		JWTIssuer:      "test-issuer",
		ClientKeyStore: ks,
	}

	handler := &apiauth.IntrospectionHandler{
		Auth:           auth,
		ClientKeyStore: ks,
	}

	details := []core.AuthorizationDetail{
		{
			Type:    "payment_initiation",
			Actions: []string{"initiate"},
			Extra:   map[string]any{"creditorName": "Merchant A"},
		},
	}

	token, _, err := auth.CreateAccessToken("user-rar", []string{"payments"}, details)
	require.NoError(t, err)

	// Introspect the token
	rr := postIntrospect(t, handler, token, "resource-server", "rs-secret")

	require.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, true, resp["active"])

	// authorization_details must be present
	ad, ok := resp["authorization_details"]
	require.True(t, ok, "introspection response missing authorization_details")
	adArray, ok := ad.([]any)
	require.True(t, ok)
	assert.Len(t, adArray, 1)
	assert.Equal(t, "payment_initiation", adArray[0].(map[string]any)["type"])
}

// TestIntrospection_WithoutRAR verifies that the introspection response does
// not include authorization_details when the token has none.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-9.1
func TestIntrospection_WithoutRAR(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	ks.PutKey(&keys.KeyRecord{
		ClientID:  "resource-server",
		Key:       []byte("rs-secret"),
		Algorithm: "HS256",
	})

	auth := &apiauth.APIAuth{
		JWTSecretKey:   "introspect-norar-secret-32ch-m!",
		JWTIssuer:      "test-issuer",
		ClientKeyStore: ks,
	}

	handler := &apiauth.IntrospectionHandler{
		Auth:           auth,
		ClientKeyStore: ks,
	}

	token, _, err := auth.CreateAccessToken("user-normal", []string{"read"}, nil)
	require.NoError(t, err)

	rr := postIntrospect(t, handler, token, "resource-server", "rs-secret")

	require.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, true, resp["active"])

	_, ok := resp["authorization_details"]
	assert.False(t, ok, "authorization_details should not appear when token has none")
}

// TestTokenEndpoint_NoRAR_Unchanged verifies that existing token requests
// without authorization_details continue to work exactly as before.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-5
func TestTokenEndpoint_NoRAR_Unchanged(t *testing.T) {
	auth, _ := setupRARAuth(t)

	body := map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     "test-client",
		"client_secret": "test-client-secret",
		"scope":         "read write",
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader(string(bodyJSON)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

	// authorization_details should not be present
	_, ok := resp["authorization_details"]
	assert.False(t, ok, "authorization_details should not appear when not requested")

	// Normal fields should still work
	assert.NotEmpty(t, resp["access_token"])
	assert.Equal(t, "Bearer", resp["token_type"])
	assert.Equal(t, "read write", resp["scope"])
}
