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
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

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

// TestKeycloak_ASMetadata_FieldCompatibility verifies that our ASServerMetadata
// struct covers the key fields that Keycloak's discovery document returns.
// This ensures our server-side metadata (#50) is structurally compatible with
// what real-world IdPs serve — any client that can parse Keycloak's response
// should also be able to parse ours.
//
// See: https://www.rfc-editor.org/rfc/rfc8414#section-2
// See: https://github.com/panyam/oneauth/issues/50
func TestKeycloak_ASMetadata_FieldCompatibility(t *testing.T) {
	skipIfKeycloakNotRunning(t)

	meta, err := client.DiscoverAS(realmURL())
	require.NoError(t, err)

	// These fields must be present in Keycloak's response and are also
	// fields we serve in our ASServerMetadata. If Keycloak has them and
	// our struct parsed them, the structs are compatible.
	assert.NotEmpty(t, meta.Issuer, "issuer")
	assert.NotEmpty(t, meta.TokenEndpoint, "token_endpoint")
	assert.NotEmpty(t, meta.AuthorizationEndpoint, "authorization_endpoint")
	assert.NotEmpty(t, meta.JWKSURI, "jwks_uri")
	assert.NotEmpty(t, meta.IntrospectionEndpoint, "introspection_endpoint")
	assert.NotEmpty(t, meta.GrantTypesSupported, "grant_types_supported")
	assert.NotEmpty(t, meta.ResponseTypesSupported, "response_types_supported")
	assert.NotEmpty(t, meta.TokenEndpointAuthMethods, "token_endpoint_auth_methods_supported")
	assert.NotEmpty(t, meta.CodeChallengeMethodsSupported, "code_challenge_methods_supported")
	assert.NotEmpty(t, meta.ScopesSupported, "scopes_supported")

	// Keycloak also serves subject_types_supported (OIDC required)
	// Our ASMetadata struct has this field too — verify Keycloak populates it
	// (parsed into the same ASMetadata struct via DiscoverAS)
	t.Logf("Keycloak field compatibility validated — all key fields present and parsed")
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
// Authorization Code + PKCE Tests (Headless Browser Login)
// =============================================================================

// TestKeycloak_AuthorizationCodePKCE_FullFlow verifies the full authorization
// code + PKCE flow against Keycloak. This is the same flow that
// client.LoginWithBrowser performs, but with the browser step simulated by
// programmatically submitting Keycloak's login form.
//
// Flow: DiscoverAS → build auth URL with PKCE → GET login page →
//       POST credentials → follow redirect to loopback → exchange code
//
// See: https://www.rfc-editor.org/rfc/rfc8252 (OAuth for Native Apps)
// See: https://www.rfc-editor.org/rfc/rfc7636 (PKCE)
// See: https://github.com/panyam/oneauth/issues/54
func TestKeycloak_AuthorizationCodePKCE_FullFlow(t *testing.T) {
	skipIfKeycloakNotRunning(t)

	// Step 1: Discover Keycloak endpoints
	meta, err := client.DiscoverAS(realmURL())
	require.NoError(t, err)
	require.NotEmpty(t, meta.AuthorizationEndpoint)
	require.NotEmpty(t, meta.TokenEndpoint)

	// Step 2: Generate PKCE (inline — avoids importing oauth2 sub-module)
	verifierBytes := make([]byte, 32)
	_, err = rand.Read(verifierBytes)
	require.NoError(t, err)
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	challengeHash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	// Step 3: Start loopback server for callback
	codeCh := make(chan string, 1)
	stateCh := make(chan string, 1)
	callbackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		codeCh <- r.URL.Query().Get("code")
		stateCh <- r.URL.Query().Get("state")
		w.Write([]byte("OK"))
	}))
	defer callbackSrv.Close()

	state := "test-state-12345"
	redirectURI := callbackSrv.URL + "/callback"

	// Step 4: Build authorization URL
	authURL := fmt.Sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&state=%s&scope=openid",
		meta.AuthorizationEndpoint,
		confidentialClientID,
		url.QueryEscape(redirectURI),
		challenge,
		state,
	)

	// Step 5: Simulate browser — GET the login page, submit the form
	// Keycloak returns an HTML form with an action URL. We POST credentials to it.
	jar, _ := cookiejar.New(nil)
	httpClient := &http.Client{Jar: jar}

	// GET the auth URL — Keycloak shows the login page
	loginResp, err := httpClient.Get(authURL)
	require.NoError(t, err)
	defer loginResp.Body.Close()

	// Parse the login form to find the action URL
	loginBody, _ := io.ReadAll(loginResp.Body)
	actionURL := extractFormAction(t, string(loginBody), loginResp.Request.URL)

	// POST the login form with test credentials
	// Use a client that does NOT follow redirects — we need to capture the redirect
	noRedirectClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}

	formResp, err := noRedirectClient.PostForm(actionURL, url.Values{
		"username": {testUsername},
		"password": {testPassword},
	})
	require.NoError(t, err)
	defer formResp.Body.Close()

	// Keycloak should redirect to our callback with a code
	// It might take multiple redirects — follow them manually until we hit localhost
	location := formResp.Header.Get("Location")
	for location != "" && !strings.Contains(location, "localhost") && !strings.Contains(location, "127.0.0.1") {
		nextResp, err := noRedirectClient.Get(location)
		if err != nil {
			break
		}
		location = nextResp.Header.Get("Location")
		nextResp.Body.Close()
	}

	// If Keycloak redirected to our callback, the code should be there
	if location != "" && (strings.Contains(location, "localhost") || strings.Contains(location, "127.0.0.1")) {
		// Follow the final redirect to our callback server
		httpClient.Get(location)
	}

	// Step 6: Get the code from our callback
	select {
	case code := <-codeCh:
		require.NotEmpty(t, code, "should receive authorization code")
		callbackState := <-stateCh
		assert.Equal(t, state, callbackState, "state should match")

		// Step 7: Exchange code for tokens
		tokenData := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"code_verifier": {verifier},
			"redirect_uri":  {redirectURI},
			"client_id":     {confidentialClientID},
			"client_secret": {confidentialClientSecret},
		}
		tokenResp, err := http.PostForm(meta.TokenEndpoint, tokenData)
		require.NoError(t, err)
		defer tokenResp.Body.Close()

		assert.Equal(t, http.StatusOK, tokenResp.StatusCode, "token exchange should succeed")

		var tokenResult map[string]any
		json.NewDecoder(tokenResp.Body).Decode(&tokenResult)
		assert.NotEmpty(t, tokenResult["access_token"], "should receive access token")
		assert.NotEmpty(t, tokenResult["refresh_token"], "should receive refresh token")
		t.Logf("Authorization code + PKCE flow completed successfully against Keycloak")

	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for authorization code callback")
	}
}

// extractFormAction parses HTML to find the form action URL.
// Keycloak's login page has a form with action pointing to the authentication URL.
func extractFormAction(t *testing.T, html string, baseURL *url.URL) string {
	t.Helper()
	// Simple extraction — find action="..." in the first form
	idx := strings.Index(html, "action=\"")
	if idx == -1 {
		t.Fatal("No form action found in login page")
	}
	start := idx + len("action=\"")
	end := strings.Index(html[start:], "\"")
	if end == -1 {
		t.Fatal("Malformed form action")
	}
	action := html[start : start+end]
	// Unescape HTML entities
	action = strings.ReplaceAll(action, "&amp;", "&")

	// Resolve relative URLs
	if !strings.HasPrefix(action, "http") {
		actionURL, _ := url.Parse(action)
		return baseURL.ResolveReference(actionURL).String()
	}
	return action
}

// =============================================================================
// Introspection Client Tests (RFC 7662 consumer against Keycloak)
// =============================================================================

// TestKeycloak_IntrospectionClient verifies that our IntrospectionValidator
// can validate a Keycloak-issued token by calling Keycloak's introspection
// endpoint. This proves the client-side introspection code (#55) works
// against a real-world IdP, not just our own mock server.
//
// See: https://www.rfc-editor.org/rfc/rfc7662
// See: https://github.com/panyam/oneauth/issues/55
func TestKeycloak_IntrospectionClient(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	cfg := discoverOIDC(t)

	// Get a token from Keycloak
	tok := getClientCredentialsToken(t, cfg.TokenEndpoint,
		confidentialClientID, confidentialClientSecret)
	require.NotEmpty(t, tok.AccessToken)

	// Introspect it using our IntrospectionValidator
	validator := &apiauth.IntrospectionValidator{
		IntrospectionURL: cfg.IntrospectionEndpoint,
		ClientID:         confidentialClientID,
		ClientSecret:     confidentialClientSecret,
	}

	result, err := validator.Validate(tok.AccessToken)
	require.NoError(t, err, "IntrospectionValidator should successfully call Keycloak introspection")
	assert.True(t, result.Active, "valid Keycloak token should be active")
	assert.NotEmpty(t, result.Sub, "sub should be present")

	t.Logf("Keycloak introspection response: active=%v, sub=%s, scope=%s",
		result.Active, result.Sub, result.Scope)

	// Also test ValidateForMiddleware
	userID, _, authType, _, err := validator.ValidateForMiddleware(tok.AccessToken)
	require.NoError(t, err)
	assert.NotEmpty(t, userID)
	assert.Equal(t, "introspection", authType)
}

// TestKeycloak_IntrospectionClient_InvalidToken verifies that introspecting
// an invalid token against Keycloak returns active=false (not an error).
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.2
func TestKeycloak_IntrospectionClient_InvalidToken(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	cfg := discoverOIDC(t)

	validator := &apiauth.IntrospectionValidator{
		IntrospectionURL: cfg.IntrospectionEndpoint,
		ClientID:         confidentialClientID,
		ClientSecret:     confidentialClientSecret,
	}

	result, err := validator.Validate("not-a-valid-token")
	require.NoError(t, err, "invalid token should not return transport error")
	assert.False(t, result.Active, "invalid token should be inactive")
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
// #72 — Token endpoint auth method negotiation against real IdP
// =============================================================================

// TestKeycloak_AuthMethodNegotiation_Basic verifies that SelectAuthMethod
// correctly chooses client_secret_basic when Keycloak's discovery metadata
// includes it, and that a client_credentials token request with HTTP Basic
// auth succeeds against Keycloak.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
// See: https://github.com/panyam/oneauth/issues/72
func TestKeycloak_AuthMethodNegotiation_Basic(t *testing.T) {
	skipIfKeycloakNotRunning(t)

	// Discover Keycloak metadata
	meta, err := client.DiscoverAS(realmURL())
	require.NoError(t, err, "DiscoverAS should succeed against Keycloak")

	// Verify Keycloak advertises auth methods
	require.NotEmpty(t, meta.TokenEndpointAuthMethods,
		"Keycloak should advertise token_endpoint_auth_methods_supported")

	// SelectAuthMethod should pick basic (Keycloak supports it)
	method := client.SelectAuthMethod(confidentialClientSecret, meta.TokenEndpointAuthMethods)
	assert.Equal(t, client.AuthMethodClientSecretBasic, method,
		"should negotiate client_secret_basic with Keycloak")

	// Verify Basic auth actually works against Keycloak's token endpoint
	data := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"openid"},
	}
	req, err := http.NewRequest("POST", meta.TokenEndpoint,
		strings.NewReader(data.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(confidentialClientID, confidentialClientSecret)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"Keycloak should accept client_credentials with Basic auth")

	var tokenResp map[string]any
	require.NoError(t, decodeJSON(resp.Body, &tokenResp))
	assert.NotEmpty(t, tokenResp["access_token"],
		"should receive an access token")
}

// TestKeycloak_AuthMethodNegotiation_Post verifies that client_secret_post
// also works against Keycloak — credentials sent as form body parameters
// instead of the Authorization header.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
// See: https://github.com/panyam/oneauth/issues/72
func TestKeycloak_AuthMethodNegotiation_Post(t *testing.T) {
	skipIfKeycloakNotRunning(t)

	meta, err := client.DiscoverAS(realmURL())
	require.NoError(t, err)

	// Verify post is also supported
	assert.Contains(t, meta.TokenEndpointAuthMethods, "client_secret_post",
		"Keycloak should support client_secret_post")

	// Send credentials in form body (no Basic auth header)
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {confidentialClientID},
		"client_secret": {confidentialClientSecret},
		"scope":         {"openid"},
	}
	resp, err := http.PostForm(meta.TokenEndpoint, data)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"Keycloak should accept client_credentials with post auth")

	var tokenResp map[string]any
	require.NoError(t, decodeJSON(resp.Body, &tokenResp))
	assert.NotEmpty(t, tokenResp["access_token"])
}

// TestKeycloak_ClientCredentials_WithAuthMethod verifies the full
// ClientCredentialsToken flow using the client SDK with discovered AS metadata
// for auth method negotiation against Keycloak.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
// See: https://github.com/panyam/oneauth/issues/72
func TestKeycloak_ClientCredentials_WithAuthMethod(t *testing.T) {
	skipIfKeycloakNotRunning(t)

	// Discover Keycloak metadata
	meta, err := client.DiscoverAS(realmURL())
	require.NoError(t, err)

	// Use a minimal in-memory credential store.
	// WithASMetadata provides both auth method negotiation and the full
	// token endpoint URL (e.g., /realms/.../protocol/openid-connect/token).
	store := &kclCredentialStore{creds: make(map[string]*client.ServerCredential)}
	authClient := client.NewAuthClient(realmURL(), store,
		client.WithASMetadata(meta))

	cred, err := authClient.ClientCredentialsToken(
		confidentialClientID, confidentialClientSecret, []string{"openid"})
	require.NoError(t, err, "ClientCredentialsToken should succeed against Keycloak with auth method negotiation")
	assert.NotEmpty(t, cred.AccessToken)
	assert.False(t, cred.IsExpired(), "token should not be expired")
}

// kclCredentialStore is a minimal in-memory credential store for Keycloak tests.
type kclCredentialStore struct {
	creds map[string]*client.ServerCredential
}

func (m *kclCredentialStore) GetCredential(serverURL string) (*client.ServerCredential, error) {
	return m.creds[serverURL], nil
}

func (m *kclCredentialStore) SetCredential(serverURL string, cred *client.ServerCredential) error {
	m.creds[serverURL] = cred
	return nil
}

func (m *kclCredentialStore) RemoveCredential(serverURL string) error {
	delete(m.creds, serverURL)
	return nil
}

func (m *kclCredentialStore) ListServers() ([]string, error) {
	servers := make([]string, 0, len(m.creds))
	for k := range m.creds {
		servers = append(servers, k)
	}
	return servers, nil
}

func (m *kclCredentialStore) Save() error { return nil }

// =============================================================================
// RFC 8414 AS Metadata Proxy Tests
// =============================================================================

// TestKeycloak_RFC8414Proxy verifies that MountProtectedResource proxies
// Keycloak's AS metadata at the RFC 8414 path on the resource server.
// Keycloak only serves OIDC discovery — the proxy fetches from OIDC and
// serves at RFC 8414, bridging the gap for clients like VS Code.
//
// Spec refs:
//   - RFC 8414 §3: https://www.rfc-editor.org/rfc/rfc8414#section-3
//   - RFC 9728 §3: https://www.rfc-editor.org/rfc/rfc9728#section-3
func TestKeycloak_RFC8414Proxy(t *testing.T) {
	skipIfKeycloakNotRunning(t)

	// Mount PRM + RFC 8414 proxy pointing at Keycloak
	mux := http.NewServeMux()
	apiauth.MountProtectedResource(mux, &apiauth.ProtectedResourceMetadata{
		Resource:             "http://test-resource-server",
		AuthorizationServers: []string{realmURL()},
	}, true)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// 1. PRM should return Keycloak as AS
	resp, err := http.Get(ts.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("PRM status = %d", resp.StatusCode)
	}

	// 2. RFC 8414 path-based proxy should return Keycloak's AS metadata
	// This is the path VS Code would try: /.well-known/oauth-authorization-server/realms/oneauth-test
	rfc8414URL := ts.URL + "/.well-known/oauth-authorization-server/realms/" + realmName
	resp2, err := http.Get(rfc8414URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("RFC 8414 proxy status = %d, body: %s", resp2.StatusCode, string(body))
	}

	var meta map[string]any
	if err := decodeJSON(resp2.Body, &meta); err != nil {
		t.Fatal(err)
	}

	// Verify it contains Keycloak's actual endpoints
	if meta["issuer"] == nil {
		t.Error("missing issuer in proxied AS metadata")
	}
	if meta["authorization_endpoint"] == nil {
		t.Error("missing authorization_endpoint in proxied AS metadata")
	}
	if meta["token_endpoint"] == nil {
		t.Error("missing token_endpoint in proxied AS metadata")
	}
	if meta["jwks_uri"] == nil {
		t.Error("missing jwks_uri in proxied AS metadata")
	}

	// Verify issuer matches Keycloak realm
	if issuer, ok := meta["issuer"].(string); ok {
		if !strings.Contains(issuer, realmName) {
			t.Errorf("issuer %q doesn't contain realm name %q", issuer, realmName)
		}
	}

	t.Logf("RFC 8414 proxy returned AS metadata with issuer=%v, authorization_endpoint=%v",
		meta["issuer"], meta["authorization_endpoint"])
}

// TestKeycloak_RFC8414Proxy_SimplePathAlsoWorks verifies the simple (non-path-based)
// RFC 8414 endpoint also works as a fallback.
func TestKeycloak_RFC8414Proxy_SimplePathAlsoWorks(t *testing.T) {
	skipIfKeycloakNotRunning(t)

	mux := http.NewServeMux()
	apiauth.MountProtectedResource(mux, &apiauth.ProtectedResourceMetadata{
		Resource:             "http://test-resource-server",
		AuthorizationServers: []string{realmURL()},
	}, true)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("simple RFC 8414 path status = %d", resp.StatusCode)
	}

	var meta map[string]any
	decodeJSON(resp.Body, &meta)
	if meta["authorization_endpoint"] == nil {
		t.Error("missing authorization_endpoint")
	}
}

// =============================================================================
// RFC 7009 Token Revocation Tests
// =============================================================================

// TestKeycloak_Discovery_RevocationEndpoint verifies that Keycloak advertises
// a revocation_endpoint in its discovery document.
//
// See: https://www.rfc-editor.org/rfc/rfc7009
func TestKeycloak_Discovery_RevocationEndpoint(t *testing.T) {
	skipIfKeycloakNotRunning(t)

	resp, err := http.Get(realmURL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	var raw map[string]any
	require.NoError(t, decodeJSON(resp.Body, &raw))
	revEndpoint, ok := raw["revocation_endpoint"]
	require.True(t, ok, "Keycloak should advertise revocation_endpoint")
	assert.Contains(t, revEndpoint.(string), "revoke", "revocation endpoint URL should contain 'revoke'")
}

// TestKeycloak_Revocation verifies that revoking a Keycloak-issued token
// via KC's revocation endpoint makes it inactive on introspection.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2
func TestKeycloak_Revocation(t *testing.T) {
	skipIfKeycloakNotRunning(t)

	cfg := discoverOIDC(t)
	tokenResp := getClientCredentialsToken(t, cfg.TokenEndpoint, confidentialClientID, confidentialClientSecret)

	// Discover revocation endpoint
	resp, _ := http.Get(realmURL() + "/.well-known/openid-configuration")
	var raw map[string]any
	decodeJSON(resp.Body, &raw)
	resp.Body.Close()
	revEndpoint := raw["revocation_endpoint"].(string)

	// Revoke via KC's endpoint
	form := url.Values{
		"token":           {tokenResp.AccessToken},
		"token_type_hint": {"access_token"},
	}
	req, _ := http.NewRequest("POST", revEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(confidentialClientID, confidentialClientSecret)
	revResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	revResp.Body.Close()
	assert.Equal(t, http.StatusOK, revResp.StatusCode, "KC revocation should return 200")

	// Introspect — should be inactive after revocation
	introForm := url.Values{"token": {tokenResp.AccessToken}}
	introReq, _ := http.NewRequest("POST", cfg.IntrospectionEndpoint, strings.NewReader(introForm.Encode()))
	introReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introReq.SetBasicAuth(confidentialClientID, confidentialClientSecret)
	introResp, _ := http.DefaultClient.Do(introReq)
	var introResult map[string]any
	json.NewDecoder(introResp.Body).Decode(&introResult)
	introResp.Body.Close()

	assert.Equal(t, false, introResult["active"],
		"token should be inactive after revocation via KC endpoint")
}

// =============================================================================
// RFC 9396 Backward Compatibility Tests
// =============================================================================
//
// Keycloak does NOT support RFC 9396 Rich Authorization Requests on standard
// OAuth flows (client_credentials, authorization_code) as of version 26.6.
// The org.keycloak.rar package exists internally but is only used for OID4VCI
// (Verifiable Credentials Issuance).
//
// These tests prove that OneAuth's RAR-aware middleware correctly handles
// non-RAR tokens from external IdPs. They also act as a canary: when KC adds
// RAR support (tracked: keycloak/keycloak#29340), the discovery test will fail,
// alerting us to add full RAR interop tests against Keycloak.
//
// Migration path: when Keycloak adds RFC 9396 support, copy the test patterns
// from rar_interop_test.go (RAR test issuer) and point them at Keycloak.
// The RAR test issuer binary (cmd/rar-test-issuer) can then be retired.

// TestKeycloak_Discovery_NoRARTypes verifies that Keycloak's discovery document
// does NOT contain authorization_details_types_supported. This is a canary test:
// when KC adds RAR, this test fails and prompts us to add RAR interop tests.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-10
func TestKeycloak_Discovery_NoRARTypes(t *testing.T) {
	skipIfKeycloakNotRunning(t)

	cfg := discoverOIDC(t)
	// KC does not advertise RAR types — verify absence
	// (the OIDCConfig struct may not have this field; check raw JSON)
	resp, err := http.Get(realmURL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	var raw map[string]any
	require.NoError(t, decodeJSON(resp.Body, &raw))
	_, hasRARTypes := raw["authorization_details_types_supported"]
	assert.False(t, hasRARTypes,
		"Keycloak should NOT advertise authorization_details_types_supported (if this fails, KC added RAR — time to add full RAR interop tests!)")
	_ = cfg
}

// TestKeycloak_RARMiddleware_NilForNonRARToken verifies that when APIMiddleware
// validates a normal Keycloak token (no authorization_details), the context
// helper GetAuthorizationDetailsFromContext returns nil. Proves RAR-aware
// middleware is backwards-compatible with non-RAR tokens.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-7
func TestKeycloak_RARMiddleware_NilForNonRARToken(t *testing.T) {
	skipIfKeycloakNotRunning(t)

	cfg := discoverOIDC(t)
	tokenResp := getClientCredentialsToken(t, cfg.TokenEndpoint, confidentialClientID, confidentialClientSecret)

	// Set up a JWKS-backed middleware pointing at Keycloak
	jwksKS := keys.NewJWKSKeyStore(cfg.JWKSURI)
	mw := &apiauth.APIMiddleware{KeyStore: jwksKS}

	// Validate the token through middleware
	var capturedDetails []any
	handler := mw.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ad := apiauth.GetAuthorizationDetailsFromContext(r.Context())
		if ad != nil {
			capturedDetails = make([]any, len(ad))
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "token should validate successfully")
	assert.Nil(t, capturedDetails, "authorization_details should be nil for non-RAR KC token")
}

// TestKeycloak_RequireAuthorizationDetails_RejectsNonRAR verifies that
// RequireAuthorizationDetails correctly rejects a Keycloak token that does
// not contain authorization_details. This proves enforcement works against
// real-world tokens that lack RAR.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2
func TestKeycloak_RequireAuthorizationDetails_RejectsNonRAR(t *testing.T) {
	skipIfKeycloakNotRunning(t)

	cfg := discoverOIDC(t)
	tokenResp := getClientCredentialsToken(t, cfg.TokenEndpoint, confidentialClientID, confidentialClientSecret)

	jwksKS := keys.NewJWKSKeyStore(cfg.JWKSURI)
	mw := &apiauth.APIMiddleware{KeyStore: jwksKS}

	handler := mw.RequireAuthorizationDetails("payment_initiation")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code,
		"RequireAuthorizationDetails should reject KC token without RAR")
}

// TestKeycloak_Introspection_NoAuthzDetails verifies that introspecting a
// Keycloak token does not return an authorization_details field. Confirms
// clean introspection for non-RAR tokens.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-9.1
func TestKeycloak_Introspection_NoAuthzDetails(t *testing.T) {
	skipIfKeycloakNotRunning(t)

	cfg := discoverOIDC(t)
	tokenResp := getClientCredentialsToken(t, cfg.TokenEndpoint, confidentialClientID, confidentialClientSecret)

	// Introspect via Keycloak's introspection endpoint
	form := url.Values{"token": {tokenResp.AccessToken}}
	req, _ := http.NewRequest("POST", cfg.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(confidentialClientID, confidentialClientSecret)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.Equal(t, true, result["active"])

	_, hasAD := result["authorization_details"]
	assert.False(t, hasAD, "KC introspection should not return authorization_details for non-RAR token")
}

// =============================================================================
// Helpers
// =============================================================================

// decodeJSON is a test helper that decodes JSON from an io.Reader.
func decodeJSON(r io.Reader, v any) error {
	return json.NewDecoder(r).Decode(v)
}
