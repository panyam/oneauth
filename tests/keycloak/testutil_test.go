package keycloak_test

// Test utilities for Keycloak interop tests. Provides helpers to:
//   - Detect whether Keycloak is running and skip tests if not
//   - Acquire tokens via client_credentials and password grants
//   - Discover OIDC endpoints from the well-known configuration
//
// The Keycloak URL defaults to http://localhost:8180 but can be overridden
// via the KEYCLOAK_URL environment variable. Tests skip gracefully when
// Keycloak is not reachable.

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	defaultKeycloakURL = "http://localhost:8180"
	realmName          = "oneauth-test"

	// Clients defined in realm.json
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

// oidcConfig holds the discovered OIDC endpoints from Keycloak.
type oidcConfig struct {
	Issuer                string `json:"issuer"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
}

// discoverOIDC fetches the OpenID Connect discovery document from Keycloak.
func discoverOIDC(t *testing.T) oidcConfig {
	t.Helper()
	resp, err := http.Get(realmURL() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("Failed to fetch OIDC discovery: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("OIDC discovery returned %d: %s", resp.StatusCode, body)
	}
	var cfg oidcConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		t.Fatalf("Failed to decode OIDC discovery: %v", err)
	}
	return cfg
}

// tokenResponse holds the token endpoint response fields we care about.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// getClientCredentialsToken acquires a token using the client_credentials grant.
// This is the simplest way to get a Keycloak-issued JWT for testing.
func getClientCredentialsToken(t *testing.T, tokenEndpoint, clientID, clientSecret string, scopes ...string) tokenResponse {
	t.Helper()
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}
	return postToken(t, tokenEndpoint, data)
}

// getPasswordToken acquires a token using the resource owner password grant.
// Used to get tokens for the test user.
func getPasswordToken(t *testing.T, tokenEndpoint, clientID, clientSecret, username, password string) tokenResponse {
	t.Helper()
	data := url.Values{
		"grant_type":    {"password"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"username":      {username},
		"password":      {password},
	}
	return postToken(t, tokenEndpoint, data)
}

// postToken sends a POST to the token endpoint and decodes the response.
func postToken(t *testing.T, tokenEndpoint string, data url.Values) tokenResponse {
	t.Helper()
	resp, err := http.PostForm(tokenEndpoint, data)
	if err != nil {
		t.Fatalf("Token request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Token endpoint returned %d: %s", resp.StatusCode, string(body))
	}
	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		t.Fatalf("Failed to decode token response: %v", err)
	}
	return tok
}

// fetchJWKS fetches the raw JWKS JSON from the given URL.
func fetchJWKS(t *testing.T, jwksURI string) map[string]any {
	t.Helper()
	resp, err := http.Get(jwksURI)
	if err != nil {
		t.Fatalf("JWKS fetch failed: %v", err)
	}
	defer resp.Body.Close()
	var jwks map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("Failed to decode JWKS: %v", err)
	}
	return jwks
}

// parseJWTClaims decodes the payload of a JWT without verifying the signature.
// For test introspection only — never use in production.
func parseJWTClaims(t *testing.T, tokenStr string) map[string]any {
	t.Helper()
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("Invalid JWT: expected 3 parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to base64url decode JWT payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("Failed to unmarshal JWT claims: %v", err)
	}
	return claims
}

// parseJWTHeader decodes the header of a JWT without verifying the signature.
func parseJWTHeader(t *testing.T, tokenStr string) map[string]any {
	t.Helper()
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("Invalid JWT: expected 3 parts, got %d", len(parts))
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("Failed to base64url decode JWT header: %v", err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(header, &hdr); err != nil {
		t.Fatalf("Failed to unmarshal JWT header: %v", err)
	}
	return hdr
}
