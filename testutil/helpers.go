// Package testutil provides reusable test infrastructure for oneauth
// integration tests. It is intended to be imported by downstream projects
// (mcpkit, relay, etc.) as well as oneauth's own test suites.
//
// Two categories of helpers:
//
//  1. TestAuthServer — an in-process authorization server with RSA keys,
//     JWKS, token endpoint, and AS metadata (RFC 8414).
//
//  2. Shared OAuth helpers — standalone functions that work against any
//     RFC-compliant OAuth server (TestAuthServer, Keycloak, Auth0, etc.).
//
// Note: The client/ package has production-grade equivalents (client.DiscoverAS,
// client.AuthClient.ClientCredentialsToken) with proper error handling, retries,
// and credential storage. These testutil helpers are intentionally simpler:
// they take *testing.T, call t.Fatal on error, and return plain structs for
// test ergonomics. They also include test-only functions (ParseJWTClaims,
// GetPasswordToken) that have no production equivalent.
package testutil

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// OIDCConfig holds discovered OIDC / OAuth Authorization Server endpoints.
// See: https://www.rfc-editor.org/rfc/rfc8414#section-2
type OIDCConfig struct {
	Issuer                string   `json:"issuer"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	AuthorizationEndpoint string   `json:"authorization_endpoint,omitempty"`
	IntrospectionEndpoint string   `json:"introspection_endpoint,omitempty"`
	RegistrationEndpoint  string   `json:"registration_endpoint,omitempty"`
	ScopesSupported       []string `json:"scopes_supported,omitempty"`
}

// TokenResponse holds the token endpoint response fields.
// See: https://www.rfc-editor.org/rfc/rfc6749#section-5.1
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// DiscoverOIDC fetches and parses the OpenID Connect / OAuth Authorization
// Server Metadata document from issuerURL/.well-known/openid-configuration.
// Calls t.Fatal on any error.
//
// See: https://www.rfc-editor.org/rfc/rfc8414
func DiscoverOIDC(t *testing.T, issuerURL string) OIDCConfig {
	t.Helper()
	wellKnown := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"
	resp, err := http.Get(wellKnown)
	if err != nil {
		t.Fatalf("DiscoverOIDC: failed to fetch %s: %v", wellKnown, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("DiscoverOIDC: %s returned %d: %s", wellKnown, resp.StatusCode, body)
	}
	var cfg OIDCConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		t.Fatalf("DiscoverOIDC: failed to decode response: %v", err)
	}
	return cfg
}

// GetClientCredentialsToken acquires a token using the OAuth 2.0
// client_credentials grant. Works against any RFC 6749-compliant token
// endpoint. Calls t.Fatal on any error.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
func GetClientCredentialsToken(t *testing.T, tokenEndpoint, clientID, clientSecret string, scopes ...string) TokenResponse {
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

// GetPasswordToken acquires a token using the OAuth 2.0 resource owner
// password credentials grant. Works against any RFC 6749-compliant token
// endpoint. Calls t.Fatal on any error.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.3
func GetPasswordToken(t *testing.T, tokenEndpoint, clientID, clientSecret, username, password string) TokenResponse {
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

// postToken sends a POST request to the token endpoint with the given form
// data and decodes the JSON response. Calls t.Fatal on HTTP or decode errors.
func postToken(t *testing.T, tokenEndpoint string, data url.Values) TokenResponse {
	t.Helper()
	resp, err := http.PostForm(tokenEndpoint, data)
	if err != nil {
		t.Fatalf("postToken: request to %s failed: %v", tokenEndpoint, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("postToken: %s returned %d: %s", tokenEndpoint, resp.StatusCode, string(body))
	}
	var tok TokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		t.Fatalf("postToken: failed to decode response: %v", err)
	}
	return tok
}

// FetchJWKS fetches the raw JWKS JSON from the given URI and returns
// it as a map. Calls t.Fatal on any error.
//
// See: https://www.rfc-editor.org/rfc/rfc7517
func FetchJWKS(t *testing.T, jwksURI string) map[string]any {
	t.Helper()
	resp, err := http.Get(jwksURI)
	if err != nil {
		t.Fatalf("FetchJWKS: request to %s failed: %v", jwksURI, err)
	}
	defer resp.Body.Close()
	var jwks map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("FetchJWKS: failed to decode JWKS from %s: %v", jwksURI, err)
	}
	return jwks
}

// ParseJWTClaims decodes the payload (claims) of a JWT without verifying
// the signature. For test introspection only — never use in production.
// Calls t.Fatal on any error.
func ParseJWTClaims(t *testing.T, tokenStr string) map[string]any {
	t.Helper()
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("ParseJWTClaims: invalid JWT: expected 3 parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("ParseJWTClaims: failed to base64url-decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("ParseJWTClaims: failed to unmarshal claims: %v", err)
	}
	return claims
}

// ParseJWTHeader decodes the header of a JWT without verifying the signature.
// For test introspection only — never use in production.
// Calls t.Fatal on any error.
func ParseJWTHeader(t *testing.T, tokenStr string) map[string]any {
	t.Helper()
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("ParseJWTHeader: invalid JWT: expected 3 parts, got %d", len(parts))
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("ParseJWTHeader: failed to base64url-decode header: %v", err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(header, &hdr); err != nil {
		t.Fatalf("ParseJWTHeader: failed to unmarshal header: %v", err)
	}
	return hdr
}
