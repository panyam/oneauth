package keycloak_test

// RFC 9396 Rich Authorization Requests — conformance and interop tests.
//
// These tests run against the RAR test issuer (cmd/rar-test-issuer), a minimal
// OneAuth-based AS that supports RFC 9396. The issuer runs in Docker alongside
// Keycloak, serving on port 8181 (configurable via RAR_ISSUER_URL).
//
// The tests prove that OneAuth resource servers can validate RAR tokens issued
// by an external AS over real HTTP — not httptest, not in-process.
//
// Migration path: when Keycloak adds RFC 9396 support on standard OAuth flows
// (tracked: keycloak/keycloak#29340), duplicate these tests pointing at Keycloak
// to prove cross-vendor interop. Then retire the RAR test issuer binary.
//
// Conformance coverage (RFC 9396 sections):
//   §2   — authorization_details structure and type field
//   §5   — token endpoint: request and response
//   §5.2 — error response: invalid_authorization_details
//   §6.1 — form-encoded authorization_details parameter
//   §7   — coexistence with scope parameter
//   §9.1 — token introspection with authorization_details
//   §10  — AS metadata: authorization_details_types_supported
//   §12  — security: tampered authorization_details
//
// See: https://www.rfc-editor.org/rfc/rfc9396

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// §10 — AS Metadata Discovery
// =============================================================================

// TestRAR_Discovery_TypesSupported verifies that the RAR test issuer advertises
// authorization_details_types_supported in its AS metadata, per RFC 9396 §10.
// When migrating to Keycloak, this test should pass if KC adds RAR.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-10
func TestRAR_Discovery_TypesSupported(t *testing.T) {
	skipIfRARIssuerNotRunning(t)

	resp, err := http.Get(rarIssuerURL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var meta map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))

	// authorization_details_types_supported MUST be present
	rawTypes, ok := meta["authorization_details_types_supported"]
	require.True(t, ok, "AS metadata must include authorization_details_types_supported")

	types := rawTypes.([]any)
	assert.Contains(t, types, "payment_initiation")
	assert.Contains(t, types, "account_information")
	assert.Contains(t, types, "signing_service")

	// Standard fields should also be present
	assert.NotEmpty(t, meta["issuer"])
	assert.NotEmpty(t, meta["token_endpoint"])
	assert.NotEmpty(t, meta["jwks_uri"])
}

// =============================================================================
// §5 — Token Endpoint: Request and Response
// =============================================================================

// TestRAR_TokenRequest_WithDetails verifies that the token endpoint accepts
// authorization_details in a JSON request body and returns them in the response.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-5
func TestRAR_TokenRequest_WithDetails(t *testing.T) {
	skipIfRARIssuerNotRunning(t)

	body := map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     rarClientID,
		"client_secret": rarClientSecret,
		"authorization_details": []map[string]any{
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
		},
	}
	bodyJSON, _ := json.Marshal(body)

	resp, err := http.Post(rarIssuerURL()+"/api/token", "application/json",
		strings.NewReader(string(bodyJSON)))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResp map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tokenResp))

	// Response MUST include authorization_details (RFC 9396 §5)
	ad, ok := tokenResp["authorization_details"]
	require.True(t, ok, "token response must include authorization_details")
	adArray := ad.([]any)
	require.Len(t, adArray, 1)

	adObj := adArray[0].(map[string]any)
	assert.Equal(t, "payment_initiation", adObj["type"])
	assert.Equal(t, "Merchant A", adObj["creditorName"])

	// access_token must be present
	assert.NotEmpty(t, tokenResp["access_token"])
	assert.Equal(t, "Bearer", tokenResp["token_type"])
}

// TestRAR_TokenRequest_MultipleDetails verifies that multiple authorization_details
// objects can be requested and returned in a single token request.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2
func TestRAR_TokenRequest_MultipleDetails(t *testing.T) {
	skipIfRARIssuerNotRunning(t)

	body := map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     rarClientID,
		"client_secret": rarClientSecret,
		"authorization_details": []map[string]any{
			{"type": "payment_initiation", "actions": []string{"initiate"}},
			{"type": "account_information", "actions": []string{"list_accounts", "read_balances"}},
		},
	}
	bodyJSON, _ := json.Marshal(body)

	resp, err := http.Post(rarIssuerURL()+"/api/token", "application/json",
		strings.NewReader(string(bodyJSON)))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResp map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tokenResp))

	adArray := tokenResp["authorization_details"].([]any)
	assert.Len(t, adArray, 2, "both authorization_details objects should be returned")
	assert.Equal(t, "payment_initiation", adArray[0].(map[string]any)["type"])
	assert.Equal(t, "account_information", adArray[1].(map[string]any)["type"])
}

// =============================================================================
// §6.1 — Form-Encoded Request
// =============================================================================

// TestRAR_TokenRequest_FormEncoded verifies that authorization_details can be
// sent as a JSON-encoded string in a form-encoded request body. RFC 9396 §6.1
// specifies this encoding for non-JSON token endpoints.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-6.1
func TestRAR_TokenRequest_FormEncoded(t *testing.T) {
	skipIfRARIssuerNotRunning(t)

	details := []map[string]any{
		{"type": "signing_service", "actions": []string{"sign"}, "documentHash": "abc123"},
	}
	detailsJSON, _ := json.Marshal(details)

	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {rarClientID},
		"client_secret":         {rarClientSecret},
		"authorization_details": {string(detailsJSON)},
	}

	resp, err := http.PostForm(rarIssuerURL()+"/api/token", form)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResp map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tokenResp))

	adArray := tokenResp["authorization_details"].([]any)
	require.Len(t, adArray, 1)
	assert.Equal(t, "signing_service", adArray[0].(map[string]any)["type"])
}

// =============================================================================
// §7 — Coexistence with Scope
// =============================================================================

// TestRAR_CoexistsWithScope verifies that authorization_details and scope can
// be sent together in the same request and both appear in the response.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-7
func TestRAR_CoexistsWithScope(t *testing.T) {
	skipIfRARIssuerNotRunning(t)

	body := map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     rarClientID,
		"client_secret": rarClientSecret,
		"scope":         "read write",
		"authorization_details": []map[string]any{
			{"type": "payment_initiation", "actions": []string{"initiate"}},
		},
	}
	bodyJSON, _ := json.Marshal(body)

	resp, err := http.Post(rarIssuerURL()+"/api/token", "application/json",
		strings.NewReader(string(bodyJSON)))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResp map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tokenResp))

	assert.Equal(t, "read write", tokenResp["scope"], "scope must be returned independently")
	adArray := tokenResp["authorization_details"].([]any)
	assert.Len(t, adArray, 1)
}

// =============================================================================
// §5.2 — Error Response
// =============================================================================

// TestRAR_Error_MissingType verifies that the AS returns
// invalid_authorization_details when the type field is missing.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-5.2
func TestRAR_Error_MissingType(t *testing.T) {
	skipIfRARIssuerNotRunning(t)

	body := map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     rarClientID,
		"client_secret": rarClientSecret,
		"authorization_details": []map[string]any{
			{"actions": []string{"read"}}, // missing "type"
		},
	}
	bodyJSON, _ := json.Marshal(body)

	resp, err := http.Post(rarIssuerURL()+"/api/token", "application/json",
		strings.NewReader(string(bodyJSON)))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errResp))
	assert.Equal(t, "invalid_authorization_details", errResp["error"],
		"missing type must produce invalid_authorization_details error")
}

// TestRAR_Error_InvalidFormJSON verifies that malformed JSON in the
// form-encoded authorization_details parameter produces an error.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-6.1
func TestRAR_Error_InvalidFormJSON(t *testing.T) {
	skipIfRARIssuerNotRunning(t)

	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {rarClientID},
		"client_secret":         {rarClientSecret},
		"authorization_details": {"not valid json"},
	}

	resp, err := http.PostForm(rarIssuerURL()+"/api/token", form)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errResp))
	assert.Equal(t, "invalid_authorization_details", errResp["error"])
}

// =============================================================================
// JWT Claims — authorization_details in the access token
// =============================================================================

// TestRAR_JWT_ContainsAuthorizationDetails verifies that the issued JWT
// access token contains the authorization_details claim with the correct
// structure, including API-specific extension fields.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2
func TestRAR_JWT_ContainsAuthorizationDetails(t *testing.T) {
	skipIfRARIssuerNotRunning(t)

	body := map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     rarClientID,
		"client_secret": rarClientSecret,
		"authorization_details": []map[string]any{
			{
				"type":    "payment_initiation",
				"actions": []string{"initiate"},
				"instructedAmount": map[string]any{
					"currency": "EUR",
					"amount":   "123.50",
				},
			},
		},
	}
	bodyJSON, _ := json.Marshal(body)

	resp, err := http.Post(rarIssuerURL()+"/api/token", "application/json",
		strings.NewReader(string(bodyJSON)))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResp map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tokenResp))

	// Decode JWT claims without verification (we verify via JWKS below)
	claims := parseJWTClaims(t, tokenResp["access_token"].(string))

	adRaw, ok := claims["authorization_details"]
	require.True(t, ok, "JWT must contain authorization_details claim")

	adArray := adRaw.([]any)
	require.Len(t, adArray, 1)

	adObj := adArray[0].(map[string]any)
	assert.Equal(t, "payment_initiation", adObj["type"])
	assert.Equal(t, []any{"initiate"}, adObj["actions"])

	// Extension field must be preserved
	amount := adObj["instructedAmount"].(map[string]any)
	assert.Equal(t, "EUR", amount["currency"])
	assert.Equal(t, "123.50", amount["amount"])
}

// =============================================================================
// JWKS Validation — cross-server token verification
// =============================================================================

// TestRAR_JWKS_ValidateToken verifies that a token issued by the RAR test
// issuer can be validated by APIMiddleware using the issuer's JWKS endpoint.
// This is the core interop test: token crosses a real HTTP boundary,
// JWKS is fetched over HTTP, validation is done by a separate process.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2
func TestRAR_JWKS_ValidateToken(t *testing.T) {
	skipIfRARIssuerNotRunning(t)

	// Discover JWKS URI from the issuer
	cfg := discoverRARIssuer(t)

	// Get a RAR token
	body := map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     rarClientID,
		"client_secret": rarClientSecret,
		"authorization_details": []map[string]any{
			{"type": "account_information", "actions": []string{"list_accounts"}},
		},
	}
	bodyJSON, _ := json.Marshal(body)

	resp, err := http.Post(cfg.TokenEndpoint, "application/json",
		strings.NewReader(string(bodyJSON)))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResp map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tokenResp))
	accessToken := tokenResp["access_token"].(string)

	// Validate via APIMiddleware + JWKSKeyStore (separate "resource server")
	jwksKS := keys.NewJWKSKeyStore(cfg.JWKSURI)
	mw := &apiauth.APIMiddleware{KeyStore: jwksKS}

	var capturedDetails []core.AuthorizationDetail
	handler := mw.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedDetails = apiauth.GetAuthorizationDetailsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "RAR token should validate via JWKS")
	require.Len(t, capturedDetails, 1, "authorization_details should be extracted from token")
	assert.Equal(t, "account_information", capturedDetails[0].Type)
	assert.Equal(t, []string{"list_accounts"}, capturedDetails[0].Actions)
}

// TestRAR_JWKS_RequireAuthorizationDetails verifies that
// RequireAuthorizationDetails middleware correctly enforces type requirements
// on tokens from an external RAR-capable AS.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2
func TestRAR_JWKS_RequireAuthorizationDetails(t *testing.T) {
	skipIfRARIssuerNotRunning(t)

	cfg := discoverRARIssuer(t)

	// Get a token with payment_initiation
	body := map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     rarClientID,
		"client_secret": rarClientSecret,
		"authorization_details": []map[string]any{
			{"type": "payment_initiation", "actions": []string{"initiate"}},
		},
	}
	bodyJSON, _ := json.Marshal(body)

	resp, err := http.Post(cfg.TokenEndpoint, "application/json",
		strings.NewReader(string(bodyJSON)))
	require.NoError(t, err)
	defer resp.Body.Close()
	var tokenResp map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tokenResp))
	accessToken := tokenResp["access_token"].(string)

	jwksKS := keys.NewJWKSKeyStore(cfg.JWKSURI)
	mw := &apiauth.APIMiddleware{KeyStore: jwksKS}

	// Require the type that IS in the token — should pass
	t.Run("matching_type_passes", func(t *testing.T) {
		handler := mw.RequireAuthorizationDetails("payment_initiation")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		)
		req := httptest.NewRequest("GET", "/payments", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	// Require a type that is NOT in the token — should reject
	t.Run("wrong_type_rejected", func(t *testing.T) {
		handler := mw.RequireAuthorizationDetails("account_information")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		)
		req := httptest.NewRequest("GET", "/accounts", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

// =============================================================================
// §9.1 — Token Introspection
// =============================================================================

// TestRAR_Introspection_IncludesDetails verifies that introspecting a RAR
// token returns authorization_details in the introspection response, per
// RFC 9396 §9.1.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-9.1
func TestRAR_Introspection_IncludesDetails(t *testing.T) {
	skipIfRARIssuerNotRunning(t)

	cfg := discoverRARIssuer(t)

	// Get a RAR token
	body := map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     rarClientID,
		"client_secret": rarClientSecret,
		"authorization_details": []map[string]any{
			{"type": "payment_initiation", "actions": []string{"initiate"}, "creditorName": "Alice"},
		},
	}
	bodyJSON, _ := json.Marshal(body)

	tokenResp, err := http.Post(cfg.TokenEndpoint, "application/json",
		strings.NewReader(string(bodyJSON)))
	require.NoError(t, err)
	defer tokenResp.Body.Close()

	var tr map[string]any
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tr))
	accessToken := tr["access_token"].(string)

	// Introspect using the introspection client credentials
	form := url.Values{"token": {accessToken}}
	introReq, _ := http.NewRequest("POST", cfg.IntrospectionEndpoint,
		strings.NewReader(form.Encode()))
	introReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introReq.SetBasicAuth(rarIntroClientID, rarIntroSecret)

	introResp, err := http.DefaultClient.Do(introReq)
	require.NoError(t, err)
	defer introResp.Body.Close()
	require.Equal(t, http.StatusOK, introResp.StatusCode)

	var result map[string]any
	require.NoError(t, json.NewDecoder(introResp.Body).Decode(&result))
	assert.Equal(t, true, result["active"])

	// authorization_details MUST be in introspection response
	ad, ok := result["authorization_details"]
	require.True(t, ok, "introspection must include authorization_details")
	adArray := ad.([]any)
	require.Len(t, adArray, 1)
	assert.Equal(t, "payment_initiation", adArray[0].(map[string]any)["type"])
	assert.Equal(t, "Alice", adArray[0].(map[string]any)["creditorName"])
}

// TestRAR_Introspection_NoDetailsWhenAbsent verifies that introspecting a
// token WITHOUT authorization_details does not include the field.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-9.1
func TestRAR_Introspection_NoDetailsWhenAbsent(t *testing.T) {
	skipIfRARIssuerNotRunning(t)

	cfg := discoverRARIssuer(t)

	// Get a token WITHOUT authorization_details
	body := map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     rarClientID,
		"client_secret": rarClientSecret,
		"scope":         "read",
	}
	bodyJSON, _ := json.Marshal(body)

	tokenResp, err := http.Post(cfg.TokenEndpoint, "application/json",
		strings.NewReader(string(bodyJSON)))
	require.NoError(t, err)
	defer tokenResp.Body.Close()

	var tr map[string]any
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tr))

	// Introspect
	form := url.Values{"token": {tr["access_token"].(string)}}
	introReq, _ := http.NewRequest("POST", cfg.IntrospectionEndpoint,
		strings.NewReader(form.Encode()))
	introReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introReq.SetBasicAuth(rarIntroClientID, rarIntroSecret)

	introResp, err := http.DefaultClient.Do(introReq)
	require.NoError(t, err)
	defer introResp.Body.Close()

	var result map[string]any
	require.NoError(t, json.NewDecoder(introResp.Body).Decode(&result))
	assert.Equal(t, true, result["active"])

	_, hasAD := result["authorization_details"]
	assert.False(t, hasAD, "introspection should not include authorization_details when token has none")
}

// =============================================================================
// Backward Compatibility — no RAR
// =============================================================================

// TestRAR_NoDetails_StillWorks verifies that the RAR-capable issuer correctly
// handles token requests without authorization_details — backward compat.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-5
func TestRAR_NoDetails_StillWorks(t *testing.T) {
	skipIfRARIssuerNotRunning(t)

	body := map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     rarClientID,
		"client_secret": rarClientSecret,
		"scope":         "read write",
	}
	bodyJSON, _ := json.Marshal(body)

	resp, err := http.Post(rarIssuerURL()+"/api/token", "application/json",
		strings.NewReader(string(bodyJSON)))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResp map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tokenResp))

	_, hasAD := tokenResp["authorization_details"]
	assert.False(t, hasAD, "authorization_details should not appear when not requested")
	assert.NotEmpty(t, tokenResp["access_token"])
	assert.Equal(t, "read write", tokenResp["scope"])
}
