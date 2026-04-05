package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ASMetadata holds OAuth 2.0 Authorization Server metadata discovered from
// a well-known endpoint. Fields follow RFC 8414 and OpenID Connect Discovery 1.0.
//
// See: https://www.rfc-editor.org/rfc/rfc8414#section-2
type ASMetadata struct {
	// Required
	Issuer        string `json:"issuer"`
	TokenEndpoint string `json:"token_endpoint"`

	// Recommended
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	JWKSURI               string `json:"jwks_uri,omitempty"`

	// Optional
	RegistrationEndpoint  string `json:"registration_endpoint,omitempty"`
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint    string `json:"revocation_endpoint,omitempty"`
	UserinfoEndpoint      string `json:"userinfo_endpoint,omitempty"`

	// Supported features
	ScopesSupported               []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported        []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported           []string `json:"grant_types_supported,omitempty"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
	TokenEndpointAuthMethods      []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

// DiscoveryOption configures the discovery request.
type DiscoveryOption func(*discoveryConfig)

type discoveryConfig struct {
	httpClient *http.Client
}

// WithHTTPClientForDiscovery sets a custom HTTP client for the discovery request.
// Useful for testing (httptest) and custom TLS configuration.
func WithHTTPClientForDiscovery(client *http.Client) DiscoveryOption {
	return func(cfg *discoveryConfig) {
		cfg.httpClient = client
	}
}

// DiscoverAS fetches OAuth Authorization Server metadata from well-known endpoints.
//
// It tries the following URLs in order (per RFC 8414 + OIDC Discovery):
//
// For issuer "https://auth.example.com" (no path):
//  1. https://auth.example.com/.well-known/oauth-authorization-server
//  2. https://auth.example.com/.well-known/openid-configuration
//
// For issuer "https://auth.example.com/tenant1" (with path):
//  1. https://auth.example.com/.well-known/oauth-authorization-server/tenant1
//  2. https://auth.example.com/tenant1/.well-known/openid-configuration
//
// Returns the first successful response. Returns an error if all attempts fail.
//
// See: https://www.rfc-editor.org/rfc/rfc8414#section-3
func DiscoverAS(issuerURL string, opts ...DiscoveryOption) (*ASMetadata, error) {
	cfg := &discoveryConfig{
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// Normalize: strip trailing slash
	issuerURL = strings.TrimRight(issuerURL, "/")

	// Build discovery URLs based on whether the issuer has a path
	urls := buildDiscoveryURLs(issuerURL)

	var lastErr error
	for _, u := range urls {
		meta, err := fetchMetadata(cfg.httpClient, u)
		if err == nil {
			return meta, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("AS discovery failed for %s: %w", issuerURL, lastErr)
}

// buildDiscoveryURLs constructs the ordered list of well-known URLs to try.
func buildDiscoveryURLs(issuerURL string) []string {
	// Split into origin and path
	// e.g., "https://auth.example.com/tenant1" → origin="https://auth.example.com", path="/tenant1"
	origin, path := splitOriginPath(issuerURL)

	if path == "" {
		// No path — simple case
		return []string{
			origin + "/.well-known/oauth-authorization-server",
			origin + "/.well-known/openid-configuration",
		}
	}

	// Path-based issuer — try RFC 8414 path format + OIDC path format
	return []string{
		origin + "/.well-known/oauth-authorization-server" + path,
		origin + path + "/.well-known/openid-configuration",
	}
}

// splitOriginPath splits a URL into origin (scheme + host) and path.
func splitOriginPath(rawURL string) (origin, path string) {
	// Find the scheme + host boundary
	// "https://auth.example.com/tenant1" → after "https://" find the next "/"
	schemeEnd := strings.Index(rawURL, "://")
	if schemeEnd == -1 {
		return rawURL, ""
	}
	rest := rawURL[schemeEnd+3:] // "auth.example.com/tenant1"
	slashIdx := strings.Index(rest, "/")
	if slashIdx == -1 {
		return rawURL, ""
	}
	origin = rawURL[:schemeEnd+3+slashIdx] // "https://auth.example.com"
	path = rest[slashIdx:]                  // "/tenant1"
	return origin, path
}

// fetchMetadata fetches and parses AS metadata from a single URL.
// Returns an error for non-200 responses or JSON parse failures.
func fetchMetadata(client *http.Client, url string) (*ASMetadata, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}

	var meta ASMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("GET %s: invalid JSON: %w", url, err)
	}

	if meta.Issuer == "" && meta.TokenEndpoint == "" {
		return nil, fmt.Errorf("GET %s: empty metadata (no issuer or token_endpoint)", url)
	}

	return &meta, nil
}
