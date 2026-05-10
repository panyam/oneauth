package testutil_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewTestAuthServer_Starts verifies that NewTestAuthServer creates a
// running server whose health endpoint responds with 200 OK.
//
// See: https://www.rfc-editor.org/rfc/rfc7230 (HTTP/1.1)
func TestNewTestAuthServer_Starts(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)

	resp, err := http.Get(srv.URL() + "/_ah/health")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "ok", string(body))
}

// TestMintToken_ValidRS256JWT verifies that MintToken produces a valid RS256
// JWT with the correct standard claims: sub, iss, type, scopes, iat, exp,
// jti. The JWT header must include alg=RS256 and a kid matching the server's
// JWKS key.
//
// See: https://www.rfc-editor.org/rfc/rfc7519 (JWT)
// See: https://www.rfc-editor.org/rfc/rfc7515 (JWS — alg header)
// See: https://www.rfc-editor.org/rfc/rfc7638 (JWK Thumbprint — kid)
func TestMintToken_ValidRS256JWT(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)

	token, err := srv.MintToken("user-42", []string{"read", "write"})
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Verify header
	hdr := testutil.ParseJWTHeader(t, token)
	assert.Equal(t, "RS256", hdr["alg"])
	assert.NotEmpty(t, hdr["kid"], "kid header must be set")

	// Verify claims
	claims := testutil.ParseJWTClaims(t, token)
	assert.Equal(t, "user-42", claims["sub"])
	assert.Equal(t, srv.Issuer(), claims["iss"])
	assert.Equal(t, "access", claims["type"])
	assert.NotEmpty(t, claims["jti"], "jti must be set")
	assert.NotNil(t, claims["iat"], "iat must be set")
	assert.NotNil(t, claims["exp"], "exp must be set")

	// Scopes should be a list
	scopes, ok := claims["scopes"].([]any)
	require.True(t, ok, "scopes should be an array")
	assert.Equal(t, 2, len(scopes))
	assert.Equal(t, "read", scopes[0])
	assert.Equal(t, "write", scopes[1])
}

// TestMintToken_WithAudience verifies that the WithAudience option causes
// MintToken to include the aud claim in the JWT.
//
// See: https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3 (aud claim)
func TestMintToken_WithAudience(t *testing.T) {
	srv := testutil.NewTestAuthServer(t, testutil.WithAudience("my-api"))

	token, err := srv.MintToken("user-1", []string{"read"})
	require.NoError(t, err)

	claims := testutil.ParseJWTClaims(t, token)
	assert.Equal(t, "my-api", claims["aud"])
}

// TestMintToken_NoAudienceByDefault verifies that when WithAudience is not
// set, MintToken does not include the aud claim.
//
// See: https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3 (aud claim)
func TestMintToken_NoAudienceByDefault(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)

	token, err := srv.MintToken("user-1", []string{"read"})
	require.NoError(t, err)

	claims := testutil.ParseJWTClaims(t, token)
	_, hasAud := claims["aud"]
	assert.False(t, hasAud, "aud should not be present when WithAudience is not used")
}

// TestMintTokenWithClaims_CustomClaims verifies that MintTokenWithClaims
// includes arbitrary custom claims and allows overriding standard defaults
// like iss and exp.
//
// See: https://www.rfc-editor.org/rfc/rfc7519#section-4 (JWT Claims)
func TestMintTokenWithClaims_CustomClaims(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)

	token, err := srv.MintTokenWithClaims(jwt.MapClaims{
		"sub":       "custom-user",
		"iss":       "custom-issuer",
		"exp":       float64(9999999999),
		"my_claim":  "my_value",
		"room_id":   "room-42",
	})
	require.NoError(t, err)

	claims := testutil.ParseJWTClaims(t, token)
	assert.Equal(t, "custom-user", claims["sub"])
	assert.Equal(t, "custom-issuer", claims["iss"], "caller should be able to override iss")
	assert.Equal(t, float64(9999999999), claims["exp"], "caller should be able to override exp")
	assert.Equal(t, "my_value", claims["my_claim"])
	assert.Equal(t, "room-42", claims["room_id"])
}

// TestMintTokenWithClaims_DefaultsApplied verifies that MintTokenWithClaims
// sets iss, iat, and exp as defaults when the caller does not provide them.
//
// See: https://www.rfc-editor.org/rfc/rfc7519#section-4.1 (Registered Claims)
func TestMintTokenWithClaims_DefaultsApplied(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)

	token, err := srv.MintTokenWithClaims(jwt.MapClaims{
		"sub": "user-1",
	})
	require.NoError(t, err)

	claims := testutil.ParseJWTClaims(t, token)
	assert.Equal(t, srv.Issuer(), claims["iss"], "default iss should be server issuer")
	assert.NotNil(t, claims["iat"], "default iat should be set")
	assert.NotNil(t, claims["exp"], "default exp should be set")
}

// TestJWKSEndpoint_ReturnsRSAKey verifies that the JWKS endpoint serves
// a valid JWK Set containing an RSA public key with a kid that matches
// the kid used in minted tokens.
//
// See: https://www.rfc-editor.org/rfc/rfc7517 (JWK)
// See: https://www.rfc-editor.org/rfc/rfc7638 (JWK Thumbprint)
func TestJWKSEndpoint_ReturnsRSAKey(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)

	jwks := testutil.FetchJWKS(t, srv.JWKSURL())
	keysArr, ok := jwks["keys"].([]any)
	require.True(t, ok, "JWKS should contain a 'keys' array")
	require.GreaterOrEqual(t, len(keysArr), 1, "JWKS should have at least one key")

	key := keysArr[0].(map[string]any)
	assert.Equal(t, "RSA", key["kty"], "key type should be RSA")
	assert.NotEmpty(t, key["kid"], "kid should be set")
	assert.NotEmpty(t, key["n"], "RSA modulus should be present")
	assert.NotEmpty(t, key["e"], "RSA exponent should be present")

	// Verify kid matches the one in minted tokens
	token, err := srv.MintToken("user-1", nil)
	require.NoError(t, err)
	hdr := testutil.ParseJWTHeader(t, token)
	assert.Equal(t, key["kid"], hdr["kid"], "JWKS kid should match token kid")
}

// TestOIDCDiscovery_ReturnsMetadata verifies that the AS metadata endpoint
// returns a valid RFC 8414 document with correct endpoint URLs.
//
// See: https://www.rfc-editor.org/rfc/rfc8414 (OAuth 2.0 Authorization Server Metadata)
func TestOIDCDiscovery_ReturnsMetadata(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)

	resp, err := http.Get(srv.URL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var meta map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))

	assert.Equal(t, srv.URL(), meta["issuer"])
	assert.Equal(t, srv.TokenEndpoint(), meta["token_endpoint"])
	assert.Equal(t, srv.JWKSURL(), meta["jwks_uri"])
	assert.Contains(t, meta, "introspection_endpoint")
	assert.Contains(t, meta, "registration_endpoint")
	assert.Contains(t, meta, "scopes_supported")
}

// TestDiscoverOIDC_Helper verifies that the DiscoverOIDC helper function
// correctly parses the AS metadata from a TestAuthServer.
//
// See: https://www.rfc-editor.org/rfc/rfc8414 (OAuth 2.0 Authorization Server Metadata)
func TestDiscoverOIDC_Helper(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)

	cfg := testutil.DiscoverOIDC(t, srv.URL())
	assert.Equal(t, srv.URL(), cfg.Issuer)
	assert.Equal(t, srv.TokenEndpoint(), cfg.TokenEndpoint)
	assert.Equal(t, srv.JWKSURL(), cfg.JWKSURI)
	assert.NotEmpty(t, cfg.IntrospectionEndpoint)
	assert.NotEmpty(t, cfg.RegistrationEndpoint)
}

// TestClientCredentialsGrant_ViaHTTP verifies the full client_credentials
// flow: register an app via /apps/register, then obtain a token via POST
// /api/token with grant_type=client_credentials using the standard
// form-encoded helper (RFC 6749 §4.4).
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4 (Client Credentials Grant)
func TestClientCredentialsGrant_ViaHTTP(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)

	// Register an app
	clientID, clientSecret := registerTestApp(t, srv, "test-app.example.com")

	// Get token via standard form-encoded client_credentials grant
	tok := testutil.GetClientCredentialsToken(t, srv.TokenEndpoint(), clientID, clientSecret)
	require.NotEmpty(t, tok.AccessToken)
	assert.Equal(t, "Bearer", tok.TokenType)

	// Verify the token is a valid JWT
	claims := testutil.ParseJWTClaims(t, tok.AccessToken)
	assert.Equal(t, clientID, claims["sub"])
}

// TestClientCredentialsGrant_WithScopes verifies that scopes can be
// requested via the client_credentials grant and appear in the token.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4.2 (Access Token Request)
func TestClientCredentialsGrant_WithScopes(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)

	clientID, clientSecret := registerTestApp(t, srv, "scoped-app.example.com")
	tok := testutil.GetClientCredentialsToken(t, srv.TokenEndpoint(), clientID, clientSecret, "read", "write")
	require.NotEmpty(t, tok.AccessToken)

	claims := testutil.ParseJWTClaims(t, tok.AccessToken)
	scopes, ok := claims["scopes"].([]any)
	require.True(t, ok, "scopes should be an array in the token")
	assert.Contains(t, scopes, "read")
	assert.Contains(t, scopes, "write")
}

// TestDCREndpoint_Works verifies that the Dynamic Client Registration
// endpoint (RFC 7591) creates a client and returns credentials.
//
// See: https://www.rfc-editor.org/rfc/rfc7591 (OAuth 2.0 Dynamic Client Registration)
func TestDCREndpoint_Works(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)

	body := `{"client_name": "dcr-test-app", "token_endpoint_auth_method": "client_secret_post"}`
	req, err := http.NewRequest("POST", srv.URL()+"/apps/dcr", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Key", srv.AdminKey())

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.NotEmpty(t, result["client_id"], "DCR should return client_id")
	assert.NotEmpty(t, result["client_secret"], "DCR should return client_secret for symmetric auth")
}

// TestWithIssuer_Option verifies that WithIssuer sets a custom issuer in
// both minted tokens and the AS discovery metadata.
//
// See: https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1 (iss claim)
func TestWithIssuer_Option(t *testing.T) {
	srv := testutil.NewTestAuthServer(t, testutil.WithIssuer("https://custom-issuer.example.com"))

	// Check token
	token, err := srv.MintToken("user-1", nil)
	require.NoError(t, err)
	claims := testutil.ParseJWTClaims(t, token)
	assert.Equal(t, "https://custom-issuer.example.com", claims["iss"])

	// Check discovery
	cfg := testutil.DiscoverOIDC(t, srv.URL())
	assert.Equal(t, "https://custom-issuer.example.com", cfg.Issuer)
}

// TestWithScopes_Option verifies that WithScopes sets the scopes_supported
// field in AS discovery metadata.
//
// See: https://www.rfc-editor.org/rfc/rfc8414#section-2 (scopes_supported)
func TestWithScopes_Option(t *testing.T) {
	srv := testutil.NewTestAuthServer(t, testutil.WithScopes([]string{"openid", "profile", "email"}))

	resp, err := http.Get(srv.URL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	var meta map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))

	scopes, ok := meta["scopes_supported"].([]any)
	require.True(t, ok)
	assert.Equal(t, 3, len(scopes))
	assert.Equal(t, "openid", scopes[0])
	assert.Equal(t, "profile", scopes[1])
	assert.Equal(t, "email", scopes[2])
}

// TestDiscoveryAdvertisesScopesAndClaims verifies the issue 200 acceptance
// criterion: the default TestAuthServer's discovery document advertises
// non-empty scopes_supported AND claims_supported. Both fields are required
// by the OpenID Foundation conformance suite (oidcc-discovery-endpoint-
// verification — CheckDiscEndpointScopesSupportedContainsOpenId,
// CheckDiscEndpointClaimsSupported).
//
// See: OpenID Connect Discovery 1.0 §3
func TestDiscoveryAdvertisesScopesAndClaims(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)

	resp, err := http.Get(srv.URL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	var meta map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))

	scopes, ok := meta["scopes_supported"].([]any)
	require.True(t, ok, "scopes_supported must be present")
	assert.NotEmpty(t, scopes)

	claims, ok := meta["claims_supported"].([]any)
	require.True(t, ok, "claims_supported must be present")
	assert.NotEmpty(t, claims)
	assert.Contains(t, claims, "sub", "claims_supported should include sub")
}

// TestWithClaimsSupported_Option verifies that WithClaimsSupported overrides
// the default `claims_supported` advertised in AS discovery metadata.
//
// See: OpenID Connect Discovery 1.0 §3
func TestWithClaimsSupported_Option(t *testing.T) {
	srv := testutil.NewTestAuthServer(t, testutil.WithClaimsSupported([]string{"sub", "email"}))

	resp, err := http.Get(srv.URL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	var meta map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))

	claims, ok := meta["claims_supported"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"sub", "email"}, claims)
}

// TestWithAdminKey_Option verifies that WithAdminKey configures the admin
// API key required for app registration. Requests with the wrong key
// should be rejected.
//
// See: https://owasp.org/www-project-web-security-testing-guide/ (authentication testing)
func TestWithAdminKey_Option(t *testing.T) {
	srv := testutil.NewTestAuthServer(t, testutil.WithAdminKey("my-secret-key"))

	// Wrong key should fail
	body := `{"client_domain":"test.com","signing_alg":"HS256"}`
	req, _ := http.NewRequest("POST", srv.URL()+"/apps/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Key", "wrong-key")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.True(t, resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden,
		"wrong admin key should be rejected, got %d", resp.StatusCode)

	// Correct key should succeed
	req, _ = http.NewRequest("POST", srv.URL()+"/apps/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Key", "my-secret-key")
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
}

// registerTestApp registers an HS256 app via the /apps/register endpoint
// and returns the client_id and client_secret.
func registerTestApp(t *testing.T, srv *testutil.TestAuthServer, domain string) (clientID, clientSecret string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"client_domain": domain,
		"signing_alg":   "HS256",
	})
	req, err := http.NewRequest("POST", srv.URL()+"/apps/register", strings.NewReader(string(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Key", srv.AdminKey())

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "app registration should succeed")

	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result["client_id"].(string), result["client_secret"].(string)
}


// TestWithGrantTypesSupported_Override verifies that the Option replaces
// the default grant_types_supported in AS metadata.
//
// See: oneauth issue 188 (RFC 7523 §2.1 + RFC 8693 follow-up wiring)
func TestWithGrantTypesSupported_Override(t *testing.T) {
	srv := testutil.NewTestAuthServer(t, testutil.WithGrantTypesSupported([]string{
		"client_credentials",
		apiauth.JwtBearerGrantType,
		apiauth.TokenExchangeGrantType,
	}))

	resp, err := http.Get(srv.URL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	var meta map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))

	grants, ok := meta["grant_types_supported"].([]any)
	require.True(t, ok, "grant_types_supported MUST be an array")
	require.Len(t, grants, 3)
	assert.Contains(t, grants, "client_credentials")
	assert.Contains(t, grants, apiauth.JwtBearerGrantType)
	assert.Contains(t, grants, apiauth.TokenExchangeGrantType)
}

// TestWithIssParameterSupported_True verifies that RFC 9207 advertisement
// flips on with the Option (the panyam/mcpconformance Phase 3b
// auth-iss-param-as-metadata-advertises-support check flips
// SKIPPED → SUCCESS once a downstream fixture sets this).
func TestWithIssParameterSupported_True(t *testing.T) {
	srv := testutil.NewTestAuthServer(t, testutil.WithIssParameterSupported(true))

	resp, err := http.Get(srv.URL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	var meta map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))

	val, present := meta["authorization_response_iss_parameter_supported"]
	require.True(t, present, "field MUST be present when Option set")
	assert.Equal(t, true, val)
}

// TestWithIssParameterSupported_OmittedByDefault — without the Option
// the field is absent (consistent with the AS not yet implementing
// RFC 9207).
func TestWithIssParameterSupported_OmittedByDefault(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)

	resp, err := http.Get(srv.URL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	var meta map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))

	_, present := meta["authorization_response_iss_parameter_supported"]
	assert.False(t, present, "field MUST be absent without the Option")
}

// TestWithTrustedAssertionIssuers_AdvertisesGrants — when trusted
// issuers are configured, the advertised grants automatically extend
// to include jwt-bearer and token-exchange (so callers don't have to
// remember to opt into both via separate Options).
func TestWithTrustedAssertionIssuers_AdvertisesGrants(t *testing.T) {
	idpKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	srv := testutil.NewTestAuthServer(t, testutil.WithTrustedAssertionIssuers([]apiauth.TrustedAssertionIssuer{{
		Issuer:    "https://corp-idp.example.com",
		PublicKey: &idpKey.PublicKey,
	}}))

	resp, err := http.Get(srv.URL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	var meta map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))

	grants, ok := meta["grant_types_supported"].([]any)
	require.True(t, ok)
	assert.Contains(t, grants, "client_credentials",
		"default grant retained alongside the new ones")
	assert.Contains(t, grants, apiauth.JwtBearerGrantType)
	assert.Contains(t, grants, apiauth.TokenExchangeGrantType)
}

// TestWithTrustedAssertionIssuers_HandlerActive — the trusted-issuer
// registry wires through to APIAuth so jwt-bearer is actually accepted
// at the token endpoint (not just advertised). Smoke-tests by minting
// an upstream-IdP-style assertion and exchanging it.
func TestWithTrustedAssertionIssuers_HandlerActive(t *testing.T) {
	idpKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	idpIssuer := "https://corp-idp.example.com"

	asAudience := "test-as"
	srv := testutil.NewTestAuthServer(t,
		testutil.WithAudience(asAudience),
		testutil.WithTrustedAssertionIssuers([]apiauth.TrustedAssertionIssuer{{
			Issuer:             idpIssuer,
			PublicKey:          &idpKey.PublicKey,
			Audiences:          []string{asAudience},
			AcceptedAlgorithms: []string{"RS256"},
		}}),
	)

	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": idpIssuer,
		"sub": "alice",
		"aud": asAudience,
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
		"nbf": now.Add(-1 * time.Second).Unix(),
	})
	signed, err := tok.SignedString(idpKey)
	require.NoError(t, err)

	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", signed)
	resp, err := http.Post(srv.URL()+"/api/token",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"jwt-bearer grant MUST be accepted; got %d: %s", resp.StatusCode, body)
	var out map[string]any
	require.NoError(t, json.Unmarshal(body, &out))
	assert.NotEmpty(t, out["access_token"])
}
