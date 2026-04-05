package admin_test

// Tests for the Dynamic Client Registration endpoint (RFC 7591).
// The DCR handler wraps AppRegistrar, accepting standard registration
// requests and returning RFC 7591 responses.
//
// References:
//   - RFC 7591 (https://www.rfc-editor.org/rfc/rfc7591):
//     "OAuth 2.0 Dynamic Client Registration Protocol"
//   - See: https://github.com/panyam/oneauth/issues/48

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDCR_SymmetricRegistration verifies that a client can register via DCR
// with client_secret_post auth method (default). The response should include
// client_id, client_secret, and client_id_issued_at per RFC 7591 §3.2.1.
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1
func TestDCR_SymmetricRegistration(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	handler := registrar.Handler()

	body := `{"client_name":"My CLI App","client_uri":"https://myapp.com","grant_types":["client_credentials"]}`
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp["client_id"], "should return client_id")
	assert.NotEmpty(t, resp["client_secret"], "should return client_secret for symmetric")
	assert.NotNil(t, resp["client_id_issued_at"], "should include issued_at timestamp")
	assert.Equal(t, "My CLI App", resp["client_name"])
	assert.Equal(t, "https://myapp.com", resp["client_uri"])
	assert.Equal(t, "client_secret_post", resp["token_endpoint_auth_method"])

	// Verify the key was stored
	clientID := resp["client_id"].(string)
	rec, err := ks.GetKey(clientID)
	require.NoError(t, err)
	assert.Equal(t, "HS256", rec.Algorithm)
}

// TestDCR_AsymmetricRegistration verifies that a client can register with
// a JWK public key (private_key_jwt auth method). No client_secret should
// be returned — the client keeps its private key.
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-2
func TestDCR_AsymmetricRegistration(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	handler := registrar.Handler()

	// Use a real RSA JWK
	body := `{
		"client_name": "Asymmetric App",
		"token_endpoint_auth_method": "private_key_jwt",
		"jwks": {
			"keys": [{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				"e": "AQAB"
			}]
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp["client_id"])
	assert.Nil(t, resp["client_secret"], "no secret for asymmetric registration")
	assert.Equal(t, "private_key_jwt", resp["token_endpoint_auth_method"])
}

// TestDCR_MissingJWKSForAsymmetric verifies that private_key_jwt without
// jwks is rejected with 400.
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-2
func TestDCR_MissingJWKSForAsymmetric(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	handler := registrar.Handler()

	body := `{"client_name":"No Keys","token_endpoint_auth_method":"private_key_jwt"}`
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestDCR_MethodNotAllowed verifies that non-POST requests to /apps/dcr
// are rejected with 405 Method Not Allowed. The DCR endpoint handles all
// methods and explicitly rejects anything other than POST.
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-3.1
func TestDCR_MethodNotAllowed(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	handler := registrar.Handler()

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/apps/dcr", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code,
			"Method %s should return 405", method)
	}
}

// TestDCR_WithAuth verifies that DCR respects AdminAuth when configured.
// An unauthenticated request should be rejected.
func TestDCR_WithAuth(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewAPIKeyAuth("admin-secret"))
	handler := registrar.Handler()

	// Without auth — rejected
	body := `{"client_name":"Unauthenticated"}`
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	// With auth — accepted
	req2 := httptest.NewRequest(http.MethodPost, "/apps/dcr", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Admin-Key", "admin-secret")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusCreated, rr2.Code)
}

// TestDCR_AppRegistrarIntegration verifies that DCR-registered clients
// appear in the AppRegistrar list (metadata is synchronized).
func TestDCR_AppRegistrarIntegration(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	handler := registrar.Handler()

	body := `{"client_name":"DCR App","client_uri":"https://dcrapp.com"}`
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code)

	var resp map[string]any
	json.Unmarshal(rr.Body.Bytes(), &resp)
	clientID := resp["client_id"].(string)

	// Verify app appears in the list
	listReq := httptest.NewRequest(http.MethodGet, "/apps", nil)
	listRR := httptest.NewRecorder()
	handler.ServeHTTP(listRR, listReq)

	var listResp map[string]any
	json.Unmarshal(listRR.Body.Bytes(), &listResp)
	apps := listResp["apps"].([]any)

	found := false
	for _, app := range apps {
		if app.(map[string]any)["client_id"] == clientID {
			found = true
			break
		}
	}
	assert.True(t, found, "DCR-registered client should appear in AppRegistrar list")
}
