package apiauth_test

// Tests for the Token Introspection endpoint (RFC 7662).
// The introspection endpoint allows resource servers to validate tokens
// by querying the auth server, as an alternative to local JWT validation.
//
// The endpoint:
//   - Accepts POST with application/x-www-form-urlencoded body (token=...)
//   - Requires caller authentication (ClientKeyStore lookup)
//   - Returns {"active": true, ...claims} for valid tokens
//   - Returns {"active": false} for invalid/expired/blacklisted tokens
//   - Never returns an error for invalid tokens — always {"active": false}
//
// References:
//   - RFC 7662 (https://www.rfc-editor.org/rfc/rfc7662):
//     "OAuth 2.0 Token Introspection"
//   - See: https://github.com/panyam/oneauth/issues/47

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupIntrospection creates an IntrospectionHandler with an APIAuth that can
// mint and validate tokens, a KeyStore with a registered resource server client,
// and an optional blacklist.
func setupIntrospection(t *testing.T) (*apiauth.IntrospectionHandler, *apiauth.APIAuth, *keys.InMemoryKeyStore, *core.InMemoryBlacklist) {
	t.Helper()
	ks := keys.NewInMemoryKeyStore()
	// Register a resource server client that can call introspection
	ks.PutKey(&keys.KeyRecord{
		ClientID:  "resource-server",
		Key:       []byte("rs-secret"),
		Algorithm: "HS256",
	})

	blacklist := core.NewInMemoryBlacklist()

	auth := &apiauth.APIAuth{
		JWTSecretKey: "introspection-test-secret-32ch!",
		JWTIssuer:    "test-issuer",
		Blacklist:    blacklist,
	}

	handler := apiauth.NewIntrospectionHandler(auth, ks)

	return handler, auth, ks, blacklist
}

// postIntrospect sends a form-encoded POST to the introspection handler
// with optional Basic auth credentials.
func postIntrospect(t *testing.T, handler http.Handler, token, clientID, clientSecret string) *httptest.ResponseRecorder {
	t.Helper()
	data := url.Values{"token": {token}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect",
		strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// mintIntrospectionToken creates a signed access token for testing.
func mintIntrospectionToken(t *testing.T, auth *apiauth.APIAuth, userID string, scopes []string) string {
	t.Helper()
	token, _, err := auth.CreateAccessToken(userID, scopes, nil)
	require.NoError(t, err)
	return token
}

// =============================================================================
// Active Token Tests
// =============================================================================

// TestIntrospection_ActiveToken verifies that a valid access token returns
// active=true with the expected claims (sub, scope, iss, exp, iat, token_type).
// This is the happy path for introspection.
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.2
func TestIntrospection_ActiveToken(t *testing.T) {
	handler, auth, _, _ := setupIntrospection(t)
	token := mintIntrospectionToken(t, auth, "user-42", []string{"read", "write"})

	rr := postIntrospect(t, handler, token, "resource-server", "rs-secret")

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, true, resp["active"])
	assert.Equal(t, "user-42", resp["sub"])
	assert.Equal(t, "test-issuer", resp["iss"])
	assert.Equal(t, "access_token", resp["token_type"])
	assert.NotNil(t, resp["exp"])
	assert.NotNil(t, resp["iat"])

	// Scope should be space-separated string (RFC 7662 §2.2)
	scope, ok := resp["scope"].(string)
	require.True(t, ok, "scope should be a string")
	assert.Contains(t, scope, "read")
	assert.Contains(t, scope, "write")
}

// =============================================================================
// Inactive Token Tests
// =============================================================================

// TestIntrospection_ExpiredToken verifies that an expired token returns
// active=false. The response must not include any claims — just {active: false}.
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.2
func TestIntrospection_ExpiredToken(t *testing.T) {
	handler, _, _, _ := setupIntrospection(t)

	// Mint an expired token manually
	claims := jwt.MapClaims{
		"sub":    "user-42",
		"type":   "access",
		"scopes": []string{"read"},
		"jti":    "expired-jti",
		"iat":    time.Now().Add(-2 * time.Hour).Unix(),
		"exp":    time.Now().Add(-1 * time.Hour).Unix(), // expired 1 hour ago
		"iss":    "test-issuer",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := tok.SignedString([]byte("introspection-test-secret-32ch!"))

	rr := postIntrospect(t, handler, tokenStr, "resource-server", "rs-secret")

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, false, resp["active"])
	// No other claims should be present for inactive tokens
	assert.Nil(t, resp["sub"])
}

// TestIntrospection_BlacklistedToken verifies that a blacklisted (revoked)
// token returns active=false, even though the JWT signature is valid.
// This is a key advantage of introspection over local JWKS validation.
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.2
func TestIntrospection_BlacklistedToken(t *testing.T) {
	handler, auth, _, blacklist := setupIntrospection(t)
	token := mintIntrospectionToken(t, auth, "user-42", []string{"read"})

	// Extract jti and blacklist it
	claims := parseJWTClaimsForIntrospection(t, token)
	jti := claims["jti"].(string)
	blacklist.Revoke(jti, time.Now().Add(time.Hour))

	rr := postIntrospect(t, handler, token, "resource-server", "rs-secret")

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, false, resp["active"],
		"blacklisted token should be inactive")
}

// TestIntrospection_InvalidToken verifies that a completely invalid token
// (not a JWT at all) returns active=false, NOT an error. RFC 7662 requires
// that introspection never reveals why a token is invalid.
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.2
func TestIntrospection_InvalidToken(t *testing.T) {
	handler, _, _, _ := setupIntrospection(t)

	rr := postIntrospect(t, handler, "not-a-jwt", "resource-server", "rs-secret")

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, false, resp["active"])
}

// TestIntrospection_TamperedToken verifies that a tampered JWT returns
// active=false (signature verification fails).
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.2
func TestIntrospection_TamperedToken(t *testing.T) {
	handler, auth, _, _ := setupIntrospection(t)
	token := mintIntrospectionToken(t, auth, "user-42", []string{"read"})
	tampered := token[:len(token)-5] + "XXXXX"

	rr := postIntrospect(t, handler, tampered, "resource-server", "rs-secret")

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, false, resp["active"])
}

// =============================================================================
// Authentication Tests
// =============================================================================

// TestIntrospection_UnauthenticatedCaller verifies that callers without
// credentials are rejected with 401. Only registered resource servers
// should be able to introspect tokens.
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.1
func TestIntrospection_UnauthenticatedCaller(t *testing.T) {
	handler, auth, _, _ := setupIntrospection(t)
	token := mintIntrospectionToken(t, auth, "user-42", []string{"read"})

	rr := postIntrospect(t, handler, token, "", "")

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestIntrospection_WrongCallerSecret verifies that callers with wrong
// credentials are rejected with 401.
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.1
func TestIntrospection_WrongCallerSecret(t *testing.T) {
	handler, auth, _, _ := setupIntrospection(t)
	token := mintIntrospectionToken(t, auth, "user-42", []string{"read"})

	rr := postIntrospect(t, handler, token, "resource-server", "wrong-secret")

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// =============================================================================
// Request Format Tests
// =============================================================================

// TestIntrospection_MissingToken verifies that a request without a token
// parameter returns 400 Bad Request.
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.1
func TestIntrospection_MissingToken(t *testing.T) {
	handler, _, _, _ := setupIntrospection(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect",
		strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("resource-server", "rs-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestIntrospection_MethodNotAllowed verifies that GET requests are rejected.
// RFC 7662 requires POST.
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.1
func TestIntrospection_MethodNotAllowed(t *testing.T) {
	handler, _, _, _ := setupIntrospection(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth/introspect", nil)
	req.SetBasicAuth("resource-server", "rs-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

// =============================================================================
// Helpers
// =============================================================================

// parseJWTClaimsForIntrospection is a test-only helper to extract claims
// from a JWT without signature verification.
func parseJWTClaimsForIntrospection(t *testing.T, tokenStr string) jwt.MapClaims {
	t.Helper()
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	require.NoError(t, err)
	return token.Claims.(jwt.MapClaims)
}
