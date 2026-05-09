package keycloak_test

// Keycloak interop for `private_key_jwt` token-endpoint client
// authentication (RFC 7521 §4.2 + RFC 7523 §2.2 + OIDC Core §9).
//
// Proves the OneAuth client SDK's private_key_jwt path produces an
// assertion that a real-world AS (Keycloak) accepts.
//
// Setup: realm.json registers the `test-pkjwt` client with
// clientAuthenticatorType=client-jwt and the matching public key from
// tests/keycloak/testdata/client-jwt.public.pem (PEM body, base64).
// The private key (testdata/client-jwt.private.pem) is checked into
// the repo as a TEST-ONLY fixture — never use this key in production.
// Tooling false-positive: secret scanners will flag the file; allow
// it explicitly.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/testutil"
	"github.com/panyam/oneauth/utils"
)

const pkjwtClientID = "test-pkjwt"

// loadTestPrivateKey reads the test-only RSA private key shipped under
// tests/keycloak/testdata/. Mirrors the exact public key embedded in
// realm.json's `test-pkjwt` client config.
func loadTestPrivateKey(t *testing.T) any {
	t.Helper()
	pemBytes, err := os.ReadFile(filepath.Join("testdata", "client-jwt.private.pem"))
	require.NoError(t, err, "load test private key")
	priv, err := utils.ParsePrivateKeyPEM(pemBytes)
	require.NoError(t, err, "parse test private key")
	return priv
}

// TestKeycloak_PrivateKeyJWT_ClientCredentials proves a OneAuth-minted
// `client_assertion` authenticates against Keycloak's token endpoint
// for the client_credentials grant, and that the issued token is in
// turn validatable by APIMiddleware backed by Keycloak's JWKS — the
// full round-trip a Go service would run in production.
func TestKeycloak_PrivateKeyJWT_ClientCredentials(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	cfg := discoverOIDC(t)

	priv := loadTestPrivateKey(t)
	assertion, err := client.MintClientAssertion(pkjwtClientID, cfg.TokenEndpoint, client.ClientAssertionConfig{
		PrivateKey: priv,
		SigningAlg: "RS256",
	})
	require.NoError(t, err)

	// POST to Keycloak's token endpoint exactly as the SDK does.
	form := "grant_type=client_credentials" +
		"&client_id=" + pkjwtClientID +
		"&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" +
		"&client_assertion=" + assertion
	resp, err := http.Post(cfg.TokenEndpoint, "application/x-www-form-urlencoded", strings.NewReader(form))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "Keycloak should accept private_key_jwt; check realm.json public key matches testdata key")

	var tok testutil.TokenResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tok))
	require.NotEmpty(t, tok.AccessToken)

	// Round-trip: validate the Keycloak-issued token through OneAuth's
	// APIMiddleware backed by Keycloak's JWKS — this is what a real
	// resource server would do.
	ks := keys.NewJWKSKeyStore(cfg.JWKSURI, keys.WithMinRefreshGap(0))
	require.NoError(t, ks.Start())
	defer ks.Stop()

	middleware := &apiauth.APIMiddleware{KeyStore: ks}
	var extractedUserID string
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extractedUserID = apiauth.GetUserIDFromAPIContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "APIMiddleware should accept the Keycloak-issued token")
	assert.NotEmpty(t, extractedUserID, "sub should be present (Keycloak service-account user id)")
}

// TestKeycloak_PrivateKeyJWT_AuthMethodAdvertised — sanity check that
// Keycloak's discovery metadata advertises private_key_jwt for callers
// that auto-negotiate based on the AS metadata.
func TestKeycloak_PrivateKeyJWT_AuthMethodAdvertised(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	cfg := discoverOIDC(t)
	assert.Contains(t, cfg.TokenEndpointAuthMethodsSupported, "private_key_jwt",
		"Keycloak realm should advertise private_key_jwt so SelectAuthMethod can choose it")
}
