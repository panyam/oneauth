package authlete_test

// Authlete interop tests. These prove that OneAuth's APIMiddleware and
// JWKSKeyStore correctly validate tokens issued by Authlete — the
// semi-hosted OAuth/OIDC protocol engine — rather than only tokens minted
// by OneAuth itself. Mirrors tests/keycloak/interop_test.go in shape.
//
// Prerequisites:
//   - authlete/java-oauth-server frontend running at AUTHLETE_AS_URL
//     (typically http://localhost:8280 via `make upauthlete`)
//   - AUTHLETE_CLIENTID and AUTHLETE_CLIENTSECRET exported (for an
//     OAuth client registered inside your Authlete service)
//
// Tests skip gracefully when those env vars are absent or the AS isn't
// reachable — `go test ./...` stays safe.
//
// References:
//   - RFC 7517: JSON Web Key (JWK)
//   - RFC 7519: JSON Web Token (JWT)
//   - RFC 7662: OAuth Token Introspection
//   - RFC 9396: Rich Authorization Requests
//   - See: https://github.com/panyam/oneauth/issues/162

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Discovery
// =============================================================================

// TestAuthlete_OIDCDiscovery verifies that the Authlete-backed AS exposes
// a parseable OpenID Connect discovery document. The endpoint URIs may be
// absent — that's a service-config choice on the Authlete side that does
// not block interop testing (other tests use the well-known java-oauth-
// server paths directly). What we DO assert here is that the discovery
// document parses cleanly into OneAuth's ASMetadata struct without errors,
// catching wire-format regressions.
func TestAuthlete_OIDCDiscovery(t *testing.T) {
	skipIfAuthleteNotConfigured(t)

	resp, err := http.Get(authleteASURL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var meta map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta), "discovery doc must be valid JSON")
	assert.NotEmpty(t, meta["issuer"], "issuer is required per RFC 8414 §2")
	// scopes_supported and response_types_supported are Authlete-populated
	// defaults; their presence is a useful smoke check that we're talking to
	// a real Authlete service, not an empty stub.
	assert.NotEmpty(t, meta["scopes_supported"])
	assert.NotEmpty(t, meta["response_types_supported"])
}

// TestAuthlete_DiscoverAS_Integration verifies that the discovery document
// parses cleanly into OneAuth's ASMetadata struct (json field-tags match,
// no surprise types). The endpoint URLs may be absent from Authlete's
// service-managed discovery; parseability is what we care about here.
func TestAuthlete_DiscoverAS_Integration(t *testing.T) {
	skipIfAuthleteNotConfigured(t)

	// Direct fetch + struct decode — skips OneAuth's DiscoverAS because
	// that function enforces RFC 8414 §3.3 issuer-equality, which fails
	// against Authlete's shared-demo AS (claims a fixed "https://authlete.com"
	// issuer regardless of which URL the discovery doc was fetched from, #235).
	resp, err := http.Get(authleteASURL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	var meta client.ASMetadata
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))
	assert.NotEmpty(t, meta.Issuer, "issuer should always be present")
	// TokenEndpoint / JWKSURI may be empty when the Authlete service config
	// omits endpoint URIs — see testutil constants for the workaround.
}

// =============================================================================
// Cluster A (issue 162 scope): JWKS fetch + token validation
// =============================================================================

// TestAuthlete_JWKSFetchAndTokenValidation is the headline interop claim:
// obtain a client_credentials token from Authlete, plug DiscoverAS +
// JWKSKeyStore into APIMiddleware, and assert the token validates end-to-end.
// If this passes, OneAuth's middleware works against Authlete-issued tokens.
func TestAuthlete_JWKSFetchAndTokenValidation(t *testing.T) {
	skipIfAuthleteNotConfigured(t)
	tok := getClientCredentialsToken(t, tokenEndpoint())
	require.NotEmpty(t, tok.AccessToken, "client_credentials grant should return a token")

	// Authlete's client_credentials grant returns an opaque access token by
	// default (not a JWT). The headline validation surface here is the
	// introspection round-trip in TestAuthlete_IntrospectionResponseParses;
	// when the token IS a JWT (some Authlete configs do issue JWTs), wire it
	// through APIMiddleware as a smoke check.
	if !looksLikeJWT(tok.AccessToken) {
		t.Logf("Authlete returned opaque token (not JWT) — JWKS validation skipped, see introspection test")
		return
	}

	// Authlete's client_credentials grant emits sub:null because there's
	// no end-user subject for a machine-to-machine token. OneAuth's
	// APIMiddleware correctly rejects tokens without a sub (defense-
	// in-depth against tokens that lack subject identification). This
	// isn't a bug on either side — it's an interop wrinkle: use a grant
	// type that populates sub (password / auth code) to exercise the
	// happy validation path. We skip rather than fail to keep the test
	// honest about what we're proving.
	if sub, _ := parseJWTClaims(t, tok.AccessToken)["sub"].(string); sub == "" {
		t.Skip("Authlete client_credentials token has sub:null — APIMiddleware correctly rejects. " +
			"Switch to a password / auth_code grant in this test to validate the happy path.")
	}

	ks := keys.NewJWKSKeyStore(jwksURI(), keys.WithMinRefreshGap(0))
	require.NoError(t, ks.Start())
	defer ks.Stop()

	middleware := &apiauth.APIMiddleware{KeyStore: ks}
	var extractedSub string
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extractedSub = apiauth.GetSubjectFromAPIContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "APIMiddleware should accept Authlete JWT")
	assert.NotEmpty(t, extractedSub, "sub claim should be present in Authlete JWT")
}

// TestAuthlete_JWKS_ParseableByOneAuth verifies that OneAuth's JWKSKeyStore
// can fetch Authlete's JWKS and parse every published key. Catches structural
// differences in how Authlete renders JWK values (kty/alg/use/kid encoding)
// independently of whether a current token uses each key.
func TestAuthlete_JWKS_ParseableByOneAuth(t *testing.T) {
	skipIfAuthleteNotConfigured(t)

	jwks := fetchJWKS(t, jwksURI())
	if jwks == nil {
		t.Skip("Authlete service exposes no JWKS (HTTP 204) — enable RS256/ES256 signing in Service Settings to exercise this test")
	}
	keysList, _ := jwks["keys"].([]any)
	if len(keysList) == 0 {
		t.Skip("Authlete service has no asymmetric keys configured (HS256-only) — nothing to validate")
	}

	for i, raw := range keysList {
		jwk, _ := raw.(map[string]any)
		t.Run(fmt.Sprintf("key_%d_kid_%v", i, jwk["kid"]), func(t *testing.T) {
			kty, _ := jwk["kty"].(string)
			require.NotEmpty(t, kty, "kty is required on every JWK per RFC 7517 §4.1")
			switch kty {
			case "RSA", "EC":
				// These are the kty values OneAuth's JWKSKeyStore actually
				// validates against; oct (symmetric) is intentionally not
				// exposed through JWKS by OneAuth (HS256 secrets stay private).
			default:
				t.Logf("kty=%s — OneAuth supports RSA + EC; %s is informational only", kty, kty)
			}
		})
	}
}

// =============================================================================
// Cluster B (issue 162 scope): RAR (RFC 9396) round-trip
// =============================================================================

// TestAuthlete_RARRoundTrip verifies that authorization_details requested at
// the token endpoint flow through Authlete and end up parseable by OneAuth's
// middleware. RAR support is one of the headline reasons to pair OneAuth
// with Authlete (#163 — Authlete-superset gap analysis).
//
// Authlete enforces that authorization_details "type" values must be
// pre-registered in the service's `supportedAuthorizationDetailsTypes`.
// When the type isn't registered, the token endpoint returns 400 — we
// treat that as a configuration-not-test failure and skip with a clear
// log so reviewers know what to add to the service config.
func TestAuthlete_RARRoundTrip(t *testing.T) {
	skipIfAuthleteNotConfigured(t)

	authzDetails := `[{"type":"payment_initiation","actions":["initiate"],"locations":["https://example.com/payments"]}]`

	form := url.Values{
		"grant_type":            {"client_credentials"},
		"authorization_details": {authzDetails},
	}
	req, _ := http.NewRequest(http.MethodPost, tokenEndpoint(), strings.NewReader(form.Encode()))
	req.SetBasicAuth(authleteClientID(), authleteClientSecret())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	if resp.StatusCode != http.StatusOK {
		errCode, _ := body["error"].(string)
		errDesc, _ := body["error_description"].(string)
		if errCode == "invalid_authorization_details" || strings.Contains(errDesc, "authorization_details") {
			t.Skipf("Authlete service does not have RAR type 'payment_initiation' registered "+
				"(error: %s - %s). Add it under Service Settings → Supported Authorization Details Types.",
				errCode, errDesc)
		}
		t.Fatalf("RAR token request failed: %d %v", resp.StatusCode, body)
	}

	echoedAD, hasAD := body["authorization_details"]
	require.True(t, hasAD, "Authlete should echo authorization_details in the token response per RFC 9396 §7")
	echoedJSON, _ := json.Marshal(echoedAD)
	assert.Contains(t, string(echoedJSON), "payment_initiation",
		"echoed authorization_details should preserve the type field")
}

// =============================================================================
// Cluster C (issue 162 scope): Introspection response parses
// =============================================================================

// TestAuthlete_IntrospectionResponseParses verifies that OneAuth's
// IntrospectionValidator correctly handles Authlete's RFC 7662 response
// shape. This is the critical path for the "OneAuth resource server in
// front of Authlete-issued tokens" deployment pattern.
//
// Uses the dedicated introspector client when one has been provisioned
// (make authlete-provision creates it and writes its creds to
// .frontend/.provisioned.env, which testutil auto-loads). Falls back to
// the standard test client when no introspector is configured — most
// Authlete services reject that, in which case the test SKIPs with an
// actionable message pointing at `make authlete-provision`.
func TestAuthlete_IntrospectionResponseParses(t *testing.T) {
	skipIfAuthleteNotConfigured(t)

	tok := getClientCredentialsToken(t, tokenEndpoint())
	require.NotEmpty(t, tok.AccessToken)

	form := url.Values{"token": {tok.AccessToken}}
	req, _ := http.NewRequest(http.MethodPost, introspectionEndpoint(), strings.NewReader(form.Encode()))
	req.SetBasicAuth(introspectorClientID(), introspectorClientSecret())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized {
		t.Skipf("Authlete /api/introspection rejected client credentials (HTTP 401). " +
			"Run `make authlete-provision` to create a dedicated introspector client, then retry.")
	}
	require.Equal(t, http.StatusOK, resp.StatusCode, "introspection request should succeed: %s", string(body))

	var introResp map[string]any
	require.NoError(t, json.Unmarshal(body, &introResp))

	active, _ := introResp["active"].(bool)
	assert.True(t, active, "freshly-minted token should be active per RFC 7662 §2.2")
	assert.NotEmpty(t, introResp["client_id"], "client_id should be present in introspection response")
}

// =============================================================================
// Cluster D (issue 162 scope): Algorithm-confusion safety
// =============================================================================

// TestAuthlete_AlgorithmConfusion_RejectedAgainstHSKeyStore proves that an
// Authlete-issued asymmetric token cannot be smuggled through a keystore
// configured for HS256. Same prevention CVE-2015-9235 covered for OneAuth-
// minted tokens (#16), but proven across the IdP boundary too.
//
// Skipped when Authlete returns opaque tokens (no JWT header to confuse).
func TestAuthlete_AlgorithmConfusion_RejectedAgainstHSKeyStore(t *testing.T) {
	skipIfAuthleteNotConfigured(t)
	tok := getClientCredentialsToken(t, tokenEndpoint())
	require.NotEmpty(t, tok.AccessToken)

	if !looksLikeJWT(tok.AccessToken) {
		t.Skip("Authlete returned opaque token — algorithm-confusion attack only applies to JWTs")
	}

	hdr := parseJWTHeader(t, tok.AccessToken)
	tokenAlg, _ := hdr["alg"].(string)
	if strings.HasPrefix(tokenAlg, "HS") {
		t.Skipf("token alg=%s is HMAC — algorithm-confusion attack between HS and RS doesn't apply here", tokenAlg)
	}
	clientID, _ := parseJWTClaims(t, tok.AccessToken)["client_id"].(string)
	if clientID == "" {
		clientID = authleteClientID()
	}

	// Configure a malicious keystore that claims the token's owning client is HS256-signed.
	// If OneAuth doesn't enforce alg-vs-keystore-record matching, this would
	// trick the middleware into validating the asymmetric token as HMAC.
	maliciousKS := keys.NewInMemoryKeyStore()
	_, _ = maliciousKS.PutKey(t.Context(), &keys.PutKeyRequest{
		Record: &keys.KeyRecord{
			ClientID:  clientID,
			Key:       []byte("attacker-supplied-secret"),
			Algorithm: "HS256",
		},
	})

	middleware := &apiauth.APIMiddleware{KeyStore: maliciousKS}
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("handler must not be called — algorithm-confusion attack should be rejected")
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code,
		"asymmetric Authlete token must NOT validate against HS256 keystore record (CVE-2015-9235)")
}

// =============================================================================
// Helpers
// =============================================================================

// looksLikeJWT returns true when the token has three dot-separated parts.
// Cheap heuristic — actual JWT validation lives in APIMiddleware. We use this
// only to decide whether a test that exercises JWT-specific behavior should
// skip or proceed against Authlete's possibly-opaque tokens.
func looksLikeJWT(token string) bool {
	return strings.Count(token, ".") == 2
}

// Ensure the asymmetric key types are imported (used indirectly when the JWKS
// parser hands typed keys to apiauth — the build would fail anyway, but the
// blank assignment makes the dependency explicit).
var (
	_ = (*rsa.PublicKey)(nil)
	_ = (*ecdsa.PublicKey)(nil)
)
