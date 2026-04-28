package keycloak_test

// Test utilities for Keycloak interop tests. Provides helpers to:
//   - Detect whether Keycloak is running and skip tests if not
//   - Acquire tokens via client_credentials and password grants
//   - Discover OIDC endpoints from the well-known configuration
//
// The generic OAuth helpers (token acquisition, OIDC discovery, JWT parsing)
// delegate to github.com/panyam/oneauth/testutil. Keycloak-specific helpers
// (skip detection, realm URL construction, constants) remain here.
//
// The Keycloak URL defaults to http://localhost:8180 but can be overridden
// via the KEYCLOAK_URL environment variable. Tests skip gracefully when
// Keycloak is not reachable.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/panyam/oneauth/testutil"
)

// RAR test client credentials — registered via DCR on first use.
var (
	rarClientID      string
	rarClientSecret  string
	rarIntroClientID string
	rarIntroSecret   string
	rarClientsOnce   sync.Once
)

const (
	defaultKeycloakURL  = "http://localhost:8180"
	defaultRARIssuerURL = "http://localhost:8181"
	realmName           = "oneauth-test"

	// Clients defined in realm.json (Keycloak)
	confidentialClientID     = "test-confidential"
	confidentialClientSecret = "test-secret-for-confidential-client"
	audienceClientID         = "test-audience"
	audienceClientSecret     = "test-audience-secret"

	// Test user defined in realm.json
	testUsername = "testuser"
	testPassword = "testpassword"
)

// keycloakURL returns the Keycloak base URL from env or default.
func keycloakURL() string {
	if u := os.Getenv("KEYCLOAK_URL"); u != "" {
		return u
	}
	return defaultKeycloakURL
}

// realmURL returns the full realm URL (e.g., http://localhost:8180/realms/oneauth-test).
func realmURL() string {
	return keycloakURL() + "/realms/" + realmName
}

// skipIfKeycloakNotRunning checks if Keycloak is reachable and skips the test
// if not. This allows the test suite to be run without Docker — tests simply
// skip instead of failing.
func skipIfKeycloakNotRunning(t *testing.T) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(realmURL())
	if err != nil {
		t.Skipf("Keycloak not reachable at %s: %v (run 'make upkcl' to start)", keycloakURL(), err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("Keycloak realm not ready (status %d)", resp.StatusCode)
	}
}

// discoverOIDC fetches the OpenID Connect discovery document from Keycloak.
// Delegates to testutil.DiscoverOIDC with the realm URL.
func discoverOIDC(t *testing.T) testutil.OIDCConfig {
	t.Helper()
	return testutil.DiscoverOIDC(t, realmURL())
}

// getClientCredentialsToken acquires a token using the client_credentials grant.
// Delegates to testutil.GetClientCredentialsToken.
func getClientCredentialsToken(t *testing.T, tokenEndpoint, clientID, clientSecret string, scopes ...string) testutil.TokenResponse {
	t.Helper()
	return testutil.GetClientCredentialsToken(t, tokenEndpoint, clientID, clientSecret, scopes...)
}

// getPasswordToken acquires a token using the resource owner password grant.
// Delegates to testutil.GetPasswordToken.
func getPasswordToken(t *testing.T, tokenEndpoint, clientID, clientSecret, username, password string) testutil.TokenResponse {
	t.Helper()
	return testutil.GetPasswordToken(t, tokenEndpoint, clientID, clientSecret, username, password)
}

// fetchJWKS fetches the raw JWKS JSON from the given URL.
// Delegates to testutil.FetchJWKS.
func fetchJWKS(t *testing.T, jwksURI string) map[string]any {
	t.Helper()
	return testutil.FetchJWKS(t, jwksURI)
}

// parseJWTClaims decodes the payload of a JWT without verifying the signature.
// Delegates to testutil.ParseJWTClaims.
func parseJWTClaims(t *testing.T, tokenStr string) map[string]any {
	t.Helper()
	return testutil.ParseJWTClaims(t, tokenStr)
}

// parseJWTHeader decodes the header of a JWT without verifying the signature.
// Delegates to testutil.ParseJWTHeader.
func parseJWTHeader(t *testing.T, tokenStr string) map[string]any {
	t.Helper()
	return testutil.ParseJWTHeader(t, tokenStr)
}

// =============================================================================
// RAR Test Issuer helpers
// =============================================================================

// rarIssuerURL returns the RAR test issuer URL from env or default.
func rarIssuerURL() string {
	if u := os.Getenv("RAR_ISSUER_URL"); u != "" {
		return u
	}
	return defaultRARIssuerURL
}

// skipIfRARIssuerNotRunning checks if the RAR test issuer is reachable,
// skips if not, and registers test clients via DCR on first call.
func skipIfRARIssuerNotRunning(t *testing.T) {
	t.Helper()
	httpClient := &http.Client{Timeout: 2 * time.Second}
	resp, err := httpClient.Get(rarIssuerURL() + "/_ah/health")
	if err != nil {
		t.Skipf("RAR issuer not reachable at %s: %v (run 'make uprar' to start)", rarIssuerURL(), err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("RAR issuer not ready (status %d)", resp.StatusCode)
	}
	// Register test clients via DCR (once per test run)
	ensureRARClients(t)
}

// ensureRARClients registers test clients via DCR on first call.
// Subsequent calls are no-ops (sync.Once).
func ensureRARClients(t *testing.T) {
	t.Helper()
	rarClientsOnce.Do(func() {
		base := rarIssuerURL()

		// Register main test client
		resp := dcrRegister(t, base, "rar-test-client")
		rarClientID = resp["client_id"].(string)
		rarClientSecret = resp["client_secret"].(string)

		// Register introspection client
		resp = dcrRegister(t, base, "rar-introspect-client")
		rarIntroClientID = resp["client_id"].(string)
		rarIntroSecret = resp["client_secret"].(string)

		t.Logf("Registered RAR clients: %s, %s", rarClientID, rarIntroClientID)
	})
}

// dcrRegister registers a client via the DCR endpoint and returns the response.
func dcrRegister(t *testing.T, baseURL, clientName string) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"client_name": clientName,
		"grant_types": []string{"client_credentials"},
		"token_endpoint_auth_method": "client_secret_post",
	})
	resp, err := http.Post(baseURL+"/apps/dcr", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("DCR registration failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("DCR returned %d", resp.StatusCode)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return result
}

// discoverRARIssuer fetches OIDC discovery from the RAR test issuer.
func discoverRARIssuer(t *testing.T) testutil.OIDCConfig {
	t.Helper()
	return testutil.DiscoverOIDC(t, rarIssuerURL())
}
