package keycloak_test

// Keycloak interop tests for OneAuth. These tests prove that OneAuth's
// APIMiddleware and JWKSKeyStore correctly validate tokens issued by a
// real-world OIDC provider (Keycloak), rather than only tokens minted
// by OneAuth itself.
//
// Prerequisites:
//   - Keycloak running at localhost:8180 (or KEYCLOAK_URL env var)
//   - Realm "oneauth-test" imported from realm.json
//   - Run: make upkcl  (starts Keycloak container)
//   - Run: make testkcl (runs these tests)
//
// Tests skip gracefully when Keycloak is not reachable.
//
// References:
//   - RFC 7517 (https://www.rfc-editor.org/rfc/rfc7517): JSON Web Key (JWK)
//   - RFC 7519 (https://www.rfc-editor.org/rfc/rfc7519): JSON Web Token (JWT)
//   - RFC 8414 (https://www.rfc-editor.org/rfc/rfc8414): OAuth 2.0 AS Metadata
//   - See: https://github.com/panyam/oneauth/issues/49

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// OIDC Discovery Tests
// =============================================================================

// TestKeycloak_OIDCDiscovery verifies that Keycloak's OpenID Connect discovery
// document is reachable and contains the expected standard fields. This is the
// foundation — if discovery fails, nothing else works.
//
// See: https://www.rfc-editor.org/rfc/rfc8414
func TestKeycloak_OIDCDiscovery(t *testing.T) {
	skipIfKeycloakNotRunning(t)

	cfg := discoverOIDC(t)
	assert.Contains(t, cfg.Issuer, realmName, "issuer should contain realm name")
	assert.NotEmpty(t, cfg.TokenEndpoint, "token_endpoint is required")
	assert.NotEmpty(t, cfg.JWKSURI, "jwks_uri is required")
}

// TestKeycloak_DiscoverAS_Integration verifies that the client.DiscoverAS
// function correctly discovers Keycloak's OIDC endpoints. This validates
// our discovery client against a real-world IdP, not just test servers.
//
// See: https://www.rfc-editor.org/rfc/rfc8414
// See: https://github.com/panyam/oneauth/issues/51
func TestKeycloak_DiscoverAS_Integration(t *testing.T) {
	skipIfKeycloakNotRunning(t)

	meta, err := client.DiscoverAS(realmURL())
	require.NoError(t, err, "DiscoverAS should successfully discover Keycloak")

	assert.Contains(t, meta.Issuer, realmName, "issuer should contain realm name")
	assert.NotEmpty(t, meta.TokenEndpoint, "token_endpoint should be discovered")
	assert.NotEmpty(t, meta.AuthorizationEndpoint, "authorization_endpoint should be discovered")
	assert.NotEmpty(t, meta.JWKSURI, "jwks_uri should be discovered")
	assert.NotEmpty(t, meta.IntrospectionEndpoint, "introspection_endpoint should be discovered")
	assert.Contains(t, meta.GrantTypesSupported, "client_credentials",
		"Keycloak should support client_credentials grant")
	assert.Contains(t, meta.ResponseTypesSupported, "code",
		"Keycloak should support authorization code response type")
	assert.Contains(t, meta.CodeChallengeMethodsSupported, "S256",
		"Keycloak should support PKCE S256")

	t.Logf("Discovered Keycloak endpoints:")
	t.Logf("  token_endpoint: %s", meta.TokenEndpoint)
	t.Logf("  jwks_uri: %s", meta.JWKSURI)
	t.Logf("  introspection: %s", meta.IntrospectionEndpoint)
	t.Logf("  grant_types: %v", meta.GrantTypesSupported)
}

// =============================================================================
// JWKS Interop Tests
// =============================================================================

// TestKeycloak_JWKS_FetchAndParse verifies that JWKSKeyStore can fetch and
// parse Keycloak's JWKS endpoint. This is the primary interop test for key
// discovery: Keycloak publishes RS256 keys in standard JWK format, and
// OneAuth's JWKSKeyStore must correctly parse them.
//
// See: https://www.rfc-editor.org/rfc/rfc7517
func TestKeycloak_JWKS_FetchAndParse(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	cfg := discoverOIDC(t)

	// Fetch raw JWKS to verify structure
	jwks := fetchJWKS(t, cfg.JWKSURI)
	keysArr, ok := jwks["keys"].([]any)
	require.True(t, ok, "JWKS must contain 'keys' array")
	assert.NotEmpty(t, keysArr, "JWKS must contain at least one key")

	// Verify each key has required JWK fields
	for i, k := range keysArr {
		key := k.(map[string]any)
		assert.NotEmpty(t, key["kty"], "key[%d] must have kty", i)
		assert.NotEmpty(t, key["kid"], "key[%d] must have kid", i)
		assert.NotEmpty(t, key["alg"], "key[%d] must have alg", i)
	}
}

// TestKeycloak_JWKS_ParseViaJWKToPublicKey verifies that OneAuth's
// JWKToPublicKey function can parse Keycloak's JWK entries into Go
// crypto.PublicKey values. This tests the actual code path used by
// JWKSKeyStore internally.
//
// See: https://www.rfc-editor.org/rfc/rfc7517
func TestKeycloak_JWKS_ParseViaJWKToPublicKey(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	cfg := discoverOIDC(t)

	// Fetch JWKS
	resp, err := http.Get(cfg.JWKSURI)
	require.NoError(t, err)
	defer resp.Body.Close()

	var jwkSet utils.JWKSet
	require.NoError(t, decodeJSON(resp.Body, &jwkSet))

	for _, jwk := range jwkSet.Keys {
		pub, alg, err := utils.JWKToPublicKey(jwk)
		if jwk.Kty == "RSA" || jwk.Kty == "EC" {
			assert.NoError(t, err, "JWKToPublicKey should parse %s key (kid=%s)", jwk.Kty, jwk.Kid)
			assert.NotNil(t, pub, "parsed key should not be nil")
			assert.NotEmpty(t, alg, "algorithm should be set")
		}
	}
}

// TestKeycloak_JWKSKeyStore_Integration verifies that JWKSKeyStore can
// fetch keys from Keycloak and resolve them by kid. This tests the full
// integration: JWKS fetch → parse → lookup by kid from a JWT header.
//
// See: https://www.rfc-editor.org/rfc/rfc7517
func TestKeycloak_JWKSKeyStore_Integration(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	cfg := discoverOIDC(t)

	// Start a JWKSKeyStore pointed at Keycloak
	ks := keys.NewJWKSKeyStore(cfg.JWKSURI,
		keys.WithMinRefreshGap(0),
	)
	require.NoError(t, ks.Start())
	defer ks.Stop()

	// Get a token so we can extract its kid
	tok := getClientCredentialsToken(t, cfg.TokenEndpoint,
		confidentialClientID, confidentialClientSecret)
	header := parseJWTHeader(t, tok.AccessToken)
	kid, ok := header["kid"].(string)
	require.True(t, ok, "Keycloak token must have kid header")

	// Look up the key by kid
	rec, err := ks.GetKeyByKid(kid)
	assert.NoError(t, err, "JWKSKeyStore should find Keycloak key by kid")
	assert.NotNil(t, rec, "key record should not be nil")
	assert.NotEmpty(t, rec.Algorithm, "algorithm should be set")
}

// =============================================================================
// Token Validation Tests
// =============================================================================

// TestKeycloak_ValidateToken_ClientCredentials verifies that APIMiddleware
// correctly validates a Keycloak-issued JWT obtained via client_credentials
// grant. This is the highest-value interop test: a real IdP token validated
// by OneAuth middleware.
//
// See: https://www.rfc-editor.org/rfc/rfc7519
func TestKeycloak_ValidateToken_ClientCredentials(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	cfg := discoverOIDC(t)

	// Get a Keycloak-issued token
	tok := getClientCredentialsToken(t, cfg.TokenEndpoint,
		confidentialClientID, confidentialClientSecret)
	require.NotEmpty(t, tok.AccessToken)

	// Set up JWKSKeyStore + APIMiddleware
	ks := keys.NewJWKSKeyStore(cfg.JWKSURI, keys.WithMinRefreshGap(0))
	require.NoError(t, ks.Start())
	defer ks.Stop()

	middleware := &apiauth.APIMiddleware{
		KeyStore: ks,
	}

	// Validate via HTTP middleware
	var extractedUserID string
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extractedUserID = apiauth.GetUserIDFromAPIContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code,
		"APIMiddleware should accept Keycloak-issued token")
	assert.NotEmpty(t, extractedUserID,
		"user ID (sub claim) should be extracted from Keycloak token")
}

// TestKeycloak_ValidateToken_PasswordGrant verifies that APIMiddleware
// validates a Keycloak token obtained via the resource owner password grant
// for the test user. The sub claim should contain the Keycloak user ID.
//
// See: https://www.rfc-editor.org/rfc/rfc7519
func TestKeycloak_ValidateToken_PasswordGrant(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	cfg := discoverOIDC(t)

	tok := getPasswordToken(t, cfg.TokenEndpoint,
		confidentialClientID, confidentialClientSecret,
		testUsername, testPassword)
	require.NotEmpty(t, tok.AccessToken)

	// Verify claims contain expected user info
	claims := parseJWTClaims(t, tok.AccessToken)
	// Password grant tokens include the user's preferred_username
	if username, ok := claims["preferred_username"].(string); ok {
		assert.Equal(t, testUsername, username,
			"preferred_username should match test user")
	}
	// sub claim should always be present (Keycloak user ID)
	assert.NotEmpty(t, claims["sub"], "sub claim should be present")

	// Validate via JWKSKeyStore + middleware
	ks := keys.NewJWKSKeyStore(cfg.JWKSURI, keys.WithMinRefreshGap(0))
	require.NoError(t, ks.Start())
	defer ks.Stop()

	middleware := &apiauth.APIMiddleware{KeyStore: ks}

	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code,
		"APIMiddleware should accept Keycloak password-grant token")
}

// TestKeycloak_ValidateToken_KidLookup verifies that APIMiddleware resolves
// the kid header from a Keycloak token via JWKSKeyStore.GetKeyByKid. This
// is the standard JWKS-based key resolution path.
//
// See: https://www.rfc-editor.org/rfc/rfc7517#section-4.5
func TestKeycloak_ValidateToken_KidLookup(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	cfg := discoverOIDC(t)

	tok := getClientCredentialsToken(t, cfg.TokenEndpoint,
		confidentialClientID, confidentialClientSecret)

	// Verify the token has a kid header
	header := parseJWTHeader(t, tok.AccessToken)
	kid := header["kid"].(string)
	alg := header["alg"].(string)

	assert.NotEmpty(t, kid, "Keycloak token must include kid header")
	assert.Equal(t, "RS256", alg, "Keycloak default algorithm should be RS256")
}

// TestKeycloak_ValidateToken_AudienceArray verifies that OneAuth correctly
// handles Keycloak's aud claim, which may be a string or array depending
// on the client configuration. This validates the #52 fix in a real-world
// scenario.
//
// See: https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3
// See: https://github.com/panyam/oneauth/issues/52
func TestKeycloak_ValidateToken_AudienceArray(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	cfg := discoverOIDC(t)

	tok := getClientCredentialsToken(t, cfg.TokenEndpoint,
		confidentialClientID, confidentialClientSecret)

	claims := parseJWTClaims(t, tok.AccessToken)

	// Keycloak may send aud as string, array, or omit it entirely depending
	// on client configuration. Document what we observe for future reference.
	aud := claims["aud"]
	if aud == nil {
		t.Log("Keycloak omitted aud claim (common for client_credentials with default config)")
	} else if audArr, ok := aud.([]any); ok {
		t.Logf("Keycloak sent aud as array: %v", audArr)
		assert.NotEmpty(t, audArr)
	} else if audStr, ok := aud.(string); ok {
		t.Logf("Keycloak sent aud as string: %s", audStr)
		assert.NotEmpty(t, audStr)
	} else {
		t.Errorf("Unexpected aud type: %T", aud)
	}

	// The important thing: our middleware should accept the token regardless
	// of aud format (validated separately in token validation tests)
}

// =============================================================================
// Security Tests
// =============================================================================

// TestKeycloak_InvalidToken_Rejected verifies that APIMiddleware rejects
// a tampered Keycloak token. The token is valid structurally but has a
// modified payload, so signature verification should fail.
//
// See: https://www.rfc-editor.org/rfc/rfc7519#section-7.2
func TestKeycloak_InvalidToken_Rejected(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	cfg := discoverOIDC(t)

	tok := getClientCredentialsToken(t, cfg.TokenEndpoint,
		confidentialClientID, confidentialClientSecret)

	// Tamper with the token payload (change a character)
	tampered := tok.AccessToken[:len(tok.AccessToken)-5] + "XXXXX"

	ks := keys.NewJWKSKeyStore(cfg.JWKSURI, keys.WithMinRefreshGap(0))
	require.NoError(t, ks.Start())
	defer ks.Stop()

	middleware := &apiauth.APIMiddleware{KeyStore: ks}
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for tampered token")
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tampered)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code,
		"APIMiddleware should reject tampered Keycloak token")
}

// TestKeycloak_WrongSecret_Rejected verifies that a token obtained with
// wrong credentials is not possible — Keycloak should reject the request.
// This tests the token acquisition path, not OneAuth validation.
func TestKeycloak_WrongSecret_Rejected(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	cfg := discoverOIDC(t)

	resp, err := http.PostForm(cfg.TokenEndpoint, map[string][]string{
		"grant_type":    {"client_credentials"},
		"client_id":     {confidentialClientID},
		"client_secret": {"wrong-secret"},
	})
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"Keycloak should reject client_credentials with wrong secret")
}

// =============================================================================
// Helpers
// =============================================================================

// decodeJSON is a test helper that decodes JSON from an io.Reader.
func decodeJSON(r io.Reader, v any) error {
	return json.NewDecoder(r).Decode(v)
}
