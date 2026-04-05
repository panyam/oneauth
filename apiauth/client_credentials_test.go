package apiauth_test

// Tests for the client_credentials grant type (RFC 6749 §4.4).
// Machine-to-machine authentication: a client authenticates with its
// client_id + client_secret and receives an access token with sub=client_id.
// No user context, no refresh token.
//
// References:
//   - RFC 6749 §4.4 (https://www.rfc-editor.org/rfc/rfc6749#section-4.4):
//     "The client credentials grant type MUST only be used by confidential clients."
//   - See: https://github.com/panyam/oneauth/issues/53

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupClientCredentialsAuth creates an APIAuth configured for client_credentials
// testing with a KeyStore containing a registered client.
func setupClientCredentialsAuth(t *testing.T) (*apiauth.APIAuth, *keys.InMemoryKeyStore) {
	t.Helper()
	ks := keys.NewInMemoryKeyStore()
	// Register a client with HS256 secret
	ks.PutKey(&keys.KeyRecord{
		ClientID:  "test-service",
		Key:       []byte("service-secret-key"),
		Algorithm: "HS256",
	})
	auth := &apiauth.APIAuth{
		JWTSecretKey:   "server-jwt-secret-key-32chars!!",
		JWTIssuer:      "test-issuer",
		ClientKeyStore: ks,
	}
	return auth, ks
}

// postTokenRequest sends a POST to the token endpoint with the given JSON body.
func postTokenRequest(t *testing.T, handler http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// TestClientCredentials_Success verifies that a client can obtain an access
// token by presenting valid client_id + client_secret via client_secret_post.
// The response should contain an access token with sub=client_id and no
// refresh token (machine clients re-authenticate instead of refreshing).
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
func TestClientCredentials_Success(t *testing.T) {
	auth, _ := setupClientCredentialsAuth(t)

	rr := postTokenRequest(t, http.HandlerFunc(auth.ServeHTTP),
		`{"grant_type":"client_credentials","client_id":"test-service","client_secret":"service-secret-key"}`)

	assert.Equal(t, http.StatusOK, rr.Code, "should return 200 for valid client credentials")

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp["access_token"], "should return access_token")
	assert.Equal(t, "Bearer", resp["token_type"], "token_type should be Bearer")
	assert.Nil(t, resp["refresh_token"], "client_credentials should not return refresh_token")

	// Validate the JWT claims
	token := resp["access_token"].(string)
	userID, _, err := auth.ValidateAccessToken(token)
	require.NoError(t, err, "minted token should be valid")
	assert.Equal(t, "test-service", userID, "sub should be the client_id")
}

// TestClientCredentials_WrongSecret verifies that an incorrect client_secret
// is rejected with 401 Unauthorized.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
func TestClientCredentials_WrongSecret(t *testing.T) {
	auth, _ := setupClientCredentialsAuth(t)

	rr := postTokenRequest(t, http.HandlerFunc(auth.ServeHTTP),
		`{"grant_type":"client_credentials","client_id":"test-service","client_secret":"wrong-secret"}`)

	assert.Equal(t, http.StatusUnauthorized, rr.Code, "should reject wrong secret")

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "invalid_client", resp["error"])
}

// TestClientCredentials_UnknownClient verifies that an unregistered client_id
// is rejected with 401 Unauthorized.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
func TestClientCredentials_UnknownClient(t *testing.T) {
	auth, _ := setupClientCredentialsAuth(t)

	rr := postTokenRequest(t, http.HandlerFunc(auth.ServeHTTP),
		`{"grant_type":"client_credentials","client_id":"unknown-service","client_secret":"any-secret"}`)

	assert.Equal(t, http.StatusUnauthorized, rr.Code, "should reject unknown client")
}

// TestClientCredentials_MissingClientID verifies that a request without
// client_id is rejected with 400 Bad Request.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
func TestClientCredentials_MissingClientID(t *testing.T) {
	auth, _ := setupClientCredentialsAuth(t)

	rr := postTokenRequest(t, http.HandlerFunc(auth.ServeHTTP),
		`{"grant_type":"client_credentials","client_secret":"service-secret-key"}`)

	assert.Equal(t, http.StatusBadRequest, rr.Code, "should reject missing client_id")
}

// TestClientCredentials_MissingSecret verifies that a request without
// client_secret is rejected with 400 Bad Request.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
func TestClientCredentials_MissingSecret(t *testing.T) {
	auth, _ := setupClientCredentialsAuth(t)

	rr := postTokenRequest(t, http.HandlerFunc(auth.ServeHTTP),
		`{"grant_type":"client_credentials","client_id":"test-service"}`)

	assert.Equal(t, http.StatusBadRequest, rr.Code, "should reject missing client_secret")
}

// TestClientCredentials_NoKeyStore verifies that client_credentials is rejected
// when no ClientKeyStore is configured on APIAuth. This prevents accidental
// enablement — the server admin must explicitly configure a KeyStore.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
func TestClientCredentials_NoKeyStore(t *testing.T) {
	auth := &apiauth.APIAuth{
		JWTSecretKey: "server-jwt-secret",
		// ClientKeyStore not set
	}

	rr := postTokenRequest(t, http.HandlerFunc(auth.ServeHTTP),
		`{"grant_type":"client_credentials","client_id":"test-service","client_secret":"secret"}`)

	assert.Equal(t, http.StatusBadRequest, rr.Code, "should reject when ClientKeyStore not configured")
}

// TestClientCredentials_WithScopes verifies that requested scopes are included
// in the access token.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
func TestClientCredentials_WithScopes(t *testing.T) {
	auth, _ := setupClientCredentialsAuth(t)

	rr := postTokenRequest(t, http.HandlerFunc(auth.ServeHTTP),
		`{"grant_type":"client_credentials","client_id":"test-service","client_secret":"service-secret-key","scope":"read write"}`)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

	token := resp["access_token"].(string)
	_, scopes, err := auth.ValidateAccessToken(token)
	require.NoError(t, err)
	assert.Contains(t, scopes, "read")
	assert.Contains(t, scopes, "write")
}

// TestClientCredentials_BasicAuth verifies that client credentials can be
// provided via HTTP Basic authentication (client_secret_basic) as an
// alternative to client_secret_post.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
func TestClientCredentials_BasicAuth(t *testing.T) {
	auth, _ := setupClientCredentialsAuth(t)

	body := `{"grant_type":"client_credentials"}`
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("test-service", "service-secret-key")
	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "should accept Basic auth credentials")

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp["access_token"])
}
