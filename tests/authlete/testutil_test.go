package authlete_test

// Test utilities for Authlete interop tests. Mirrors tests/keycloak/testutil_test.go:
// skip-detection, env-var-driven config, thin wrappers over the shared
// github.com/panyam/oneauth/testutil helpers.
//
// The Authlete-backed AS frontend (authlete/java-oauth-server) is reached
// at AUTHLETE_AS_URL — usually http://localhost:8280 set by the Makefile's
// testauthlete target. The OAuth client credentials (AUTHLETE_CLIENTID /
// AUTHLETE_CLIENTSECRET) identify a confidential client registered inside
// the Authlete service via the cloud console.
//
// Tests skip cleanly when any of the four env vars (AS URL, client ID,
// client secret, plus the AS itself being reachable) is missing, so the
// suite stays safe under the default `go test ./...` invocation.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/testutil"
)

const (
	defaultAuthleteASURL = "http://localhost:8280"

	// Endpoint paths exposed by authlete/java-oauth-server. These are stable
	// across the upstream codebase. We construct full URLs from AUTHLETE_AS_URL
	// + these paths rather than reading from Authlete's discovery document,
	// because Authlete's service-managed discovery is only populated when the
	// operator has filled in endpoint URIs in the service config — which is
	// optional and orthogonal to interop testing.
	pathToken          = "/api/token"
	pathIntrospection  = "/api/introspection"
	pathJWKS           = "/api/jwks"
	pathAuthorization  = "/api/authorization"
)

// tokenEndpoint returns the full token endpoint URL for the running
// java-oauth-server frontend. Bypasses discovery — see the path constants.
func tokenEndpoint() string { return authleteASURL() + pathToken }

// introspectionEndpoint returns the full introspection endpoint URL.
func introspectionEndpoint() string { return authleteASURL() + pathIntrospection }

// jwksURI returns the full JWKS URI for the running frontend.
func jwksURI() string { return authleteASURL() + pathJWKS }

// authleteASURL returns the Authlete AS frontend URL from env or default.
// Set by the Makefile's testauthlete target; can be overridden for ad-hoc runs.
func authleteASURL() string {
	if u := os.Getenv("AUTHLETE_AS_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return defaultAuthleteASURL
}

// authleteClientID returns the OAuth client_id our tests use to fetch tokens.
// Empty when AUTHLETE_CLIENTID is unset — callers should use
// skipIfAuthleteNotConfigured to bail before reading.
//
// Gotcha: when an Authlete client has a clientIdAlias set, the OAuth wire
// layer requires the alias, not the numeric clientId. Set this env var to
// the alias when one exists (e.g., "TestClientId"), not Authlete's internal
// numeric ID. The numeric ID stays useful for management-API calls but is
// rejected at /api/token.
func authleteClientID() string {
	return os.Getenv("AUTHLETE_CLIENTID")
}

// authleteClientSecret returns the OAuth client_secret paired with the
// client_id above. Empty when AUTHLETE_CLIENTSECRET is unset.
func authleteClientSecret() string {
	return os.Getenv("AUTHLETE_CLIENTSECRET")
}

// skipIfAuthleteNotConfigured skips the test unless:
//   - AUTHLETE_CLIENTID and AUTHLETE_CLIENTSECRET are set in env, AND
//   - the AS frontend at AUTHLETE_AS_URL responds to discovery.
//
// This is the same "skip when not running" pattern as tests/keycloak —
// the suite must stay safe under `go test ./...` even on machines
// without an Authlete account or a running container.
func skipIfAuthleteNotConfigured(t *testing.T) {
	t.Helper()
	if authleteClientID() == "" || authleteClientSecret() == "" {
		t.Skip("AUTHLETE_CLIENTID and AUTHLETE_CLIENTSECRET not set — run 'make testauthlete' with the env exported")
	}
	httpClient := &http.Client{Timeout: 3 * time.Second}
	resp, err := httpClient.Get(authleteASURL() + "/.well-known/openid-configuration")
	if err != nil {
		t.Skipf("Authlete AS not reachable at %s: %v (run 'make upauthlete')", authleteASURL(), err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("Authlete AS discovery returned status %d (run 'make upauthlete')", resp.StatusCode)
	}
}

// discoverOIDC fetches the OpenID Connect discovery document from the
// Authlete-backed AS via the shared testutil helper.
func discoverOIDC(t *testing.T) testutil.OIDCConfig {
	t.Helper()
	return testutil.DiscoverOIDC(t, authleteASURL())
}

// getClientCredentialsToken acquires a token via the client_credentials
// grant against the Authlete AS using HTTP Basic auth (the auth method
// our test client is configured for). Bypasses testutil.GetClientCredentials
// Token because that helper sends credentials in the POST body (client_secret_post),
// which Authlete rejects with A157357 for clients configured as client_secret_basic.
func getClientCredentialsToken(t *testing.T, tokenEndpoint string, scopes ...string) testutil.TokenResponse {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	req, err := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(authleteClientID(), authleteClientSecret())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	var tr testutil.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token endpoint returned %d: %+v", resp.StatusCode, tr)
	}
	return tr
}

// fetchJWKS fetches the raw JWKS JSON from the given URL. Returns nil
// when the endpoint responds 204 No Content — Authlete returns 204 when
// the service has no asymmetric keys configured, which is a valid (if
// not useful for our tests) state.
func fetchJWKS(t *testing.T, jwksURI string) map[string]any {
	t.Helper()
	resp, err := http.Get(jwksURI)
	if err != nil {
		t.Fatalf("fetch JWKS: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("JWKS endpoint returned %d", resp.StatusCode)
	}
	var jwks map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	return jwks
}

// parseJWTClaims decodes the payload of a JWT without verifying the signature.
func parseJWTClaims(t *testing.T, tokenStr string) map[string]any {
	t.Helper()
	return testutil.ParseJWTClaims(t, tokenStr)
}

// parseJWTHeader decodes the header of a JWT without verifying the signature.
func parseJWTHeader(t *testing.T, tokenStr string) map[string]any {
	t.Helper()
	return testutil.ParseJWTHeader(t, tokenStr)
}
