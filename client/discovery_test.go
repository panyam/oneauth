package client

// Tests for OAuth Authorization Server metadata discovery (RFC 8414 / OIDC Discovery).
// The DiscoverAS function fetches and parses well-known metadata from an
// authorization server, enabling clients to auto-discover endpoints without
// hardcoding URLs.
//
// The fallback chain (per RFC 8414 + OIDC):
//   For issuer https://auth.example.com:
//     1. GET /.well-known/oauth-authorization-server
//     2. GET /.well-known/openid-configuration (OIDC fallback)
//   For issuer https://auth.example.com/tenant1 (path-based):
//     1. GET /.well-known/oauth-authorization-server/tenant1
//     2. GET /.well-known/openid-configuration (with path appended)
//     3. GET /tenant1/.well-known/openid-configuration
//
// References:
//   - RFC 8414 (https://www.rfc-editor.org/rfc/rfc8414):
//     "OAuth 2.0 Authorization Server Metadata"
//   - OpenID Connect Discovery 1.0 §4
//   - See: https://github.com/panyam/oneauth/issues/51

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newDiscoveryServer creates a test HTTP server that serves AS metadata
// at the given path with the given metadata fields.
func newDiscoveryServer(t *testing.T, path string, meta map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestDiscoverAS_OIDCEndpoint verifies that DiscoverAS correctly fetches
// and parses an OIDC discovery document at /.well-known/openid-configuration.
// This is the most common case — Keycloak, Auth0, Okta all serve this.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func TestDiscoverAS_OIDCEndpoint(t *testing.T) {
	meta := map[string]any{
		"issuer":                 "https://auth.example.com",
		"token_endpoint":         "https://auth.example.com/token",
		"authorization_endpoint": "https://auth.example.com/authorize",
		"jwks_uri":               "https://auth.example.com/.well-known/jwks.json",
		"introspection_endpoint": "https://auth.example.com/introspect",
		"scopes_supported":       []string{"openid", "read", "write"},
		"grant_types_supported":  []string{"authorization_code", "client_credentials"},
		"response_types_supported":              []string{"code"},
		"code_challenge_methods_supported":       []string{"S256"},
		"token_endpoint_auth_methods_supported":  []string{"client_secret_basic", "client_secret_post"},
	}
	srv := newDiscoveryServer(t, "/.well-known/openid-configuration", meta)

	result, err := DiscoverAS(srv.URL, WithHTTPClientForDiscovery(srv.Client()))
	require.NoError(t, err)

	assert.Equal(t, "https://auth.example.com", result.Issuer)
	assert.Equal(t, "https://auth.example.com/token", result.TokenEndpoint)
	assert.Equal(t, "https://auth.example.com/authorize", result.AuthorizationEndpoint)
	assert.Equal(t, "https://auth.example.com/.well-known/jwks.json", result.JWKSURI)
	assert.Equal(t, "https://auth.example.com/introspect", result.IntrospectionEndpoint)
	assert.Contains(t, result.ScopesSupported, "read")
	assert.Contains(t, result.GrantTypesSupported, "client_credentials")
	assert.Contains(t, result.ResponseTypesSupported, "code")
	assert.Contains(t, result.CodeChallengeMethodsSupported, "S256")
	assert.Contains(t, result.TokenEndpointAuthMethods, "client_secret_basic")
}

// TestDiscoverAS_RFC8414Endpoint verifies that DiscoverAS tries the RFC 8414
// path first (/.well-known/oauth-authorization-server) before falling back
// to OIDC Discovery.
//
// See: https://www.rfc-editor.org/rfc/rfc8414#section-3
func TestDiscoverAS_RFC8414Endpoint(t *testing.T) {
	meta := map[string]any{
		"issuer":         "https://auth.example.com",
		"token_endpoint": "https://auth.example.com/token",
	}
	srv := newDiscoveryServer(t, "/.well-known/oauth-authorization-server", meta)

	result, err := DiscoverAS(srv.URL, WithHTTPClientForDiscovery(srv.Client()))
	require.NoError(t, err)
	assert.Equal(t, "https://auth.example.com/token", result.TokenEndpoint)
}

// TestDiscoverAS_FallbackToOIDC verifies that when the RFC 8414 endpoint
// returns 404, DiscoverAS falls back to /.well-known/openid-configuration.
//
// See: https://www.rfc-editor.org/rfc/rfc8414#section-3
func TestDiscoverAS_FallbackToOIDC(t *testing.T) {
	// Only serve OIDC endpoint, not RFC 8414
	meta := map[string]any{
		"issuer":         "https://auth.example.com",
		"token_endpoint": "https://auth.example.com/token",
	}
	srv := newDiscoveryServer(t, "/.well-known/openid-configuration", meta)

	result, err := DiscoverAS(srv.URL, WithHTTPClientForDiscovery(srv.Client()))
	require.NoError(t, err)
	assert.Equal(t, "https://auth.example.com/token", result.TokenEndpoint)
}

// TestDiscoverAS_PathBasedIssuer verifies that discovery works for
// path-based issuers (e.g., https://auth.example.com/tenant1).
// RFC 8414 §3.1 defines the URL construction for these cases.
//
// See: https://www.rfc-editor.org/rfc/rfc8414#section-3.1
func TestDiscoverAS_PathBasedIssuer(t *testing.T) {
	meta := map[string]any{
		"issuer":         "https://auth.example.com/tenant1",
		"token_endpoint": "https://auth.example.com/tenant1/token",
	}
	// Keycloak-style: /tenant1/.well-known/openid-configuration
	srv := newDiscoveryServer(t, "/tenant1/.well-known/openid-configuration", meta)

	result, err := DiscoverAS(srv.URL+"/tenant1", WithHTTPClientForDiscovery(srv.Client()))
	require.NoError(t, err)
	assert.Equal(t, "https://auth.example.com/tenant1/token", result.TokenEndpoint)
}

// TestDiscoverAS_Unreachable verifies that DiscoverAS returns an error
// when the server is unreachable, not a panic or nil result.
func TestDiscoverAS_Unreachable(t *testing.T) {
	_, err := DiscoverAS("http://localhost:1")
	assert.Error(t, err, "should return error for unreachable server")
}

// TestDiscoverAS_InvalidJSON verifies that DiscoverAS returns an error
// when the response is not valid JSON.
func TestDiscoverAS_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	t.Cleanup(srv.Close)

	_, err := DiscoverAS(srv.URL, WithHTTPClientForDiscovery(srv.Client()))
	assert.Error(t, err)
}

// TestDiscoverAS_404OnAllEndpoints verifies that DiscoverAS returns an error
// when none of the well-known endpoints are found.
func TestDiscoverAS_404OnAllEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)

	_, err := DiscoverAS(srv.URL, WithHTTPClientForDiscovery(srv.Client()))
	assert.Error(t, err)
}

// TestDiscoverAS_MinimalMetadata verifies that DiscoverAS works with
// minimal metadata (only required fields). Optional fields should be
// zero-valued, not cause errors.
func TestDiscoverAS_MinimalMetadata(t *testing.T) {
	meta := map[string]any{
		"issuer":         "https://auth.example.com",
		"token_endpoint": "https://auth.example.com/token",
	}
	srv := newDiscoveryServer(t, "/.well-known/openid-configuration", meta)

	result, err := DiscoverAS(srv.URL, WithHTTPClientForDiscovery(srv.Client()))
	require.NoError(t, err)
	assert.Equal(t, "https://auth.example.com", result.Issuer)
	assert.Equal(t, "https://auth.example.com/token", result.TokenEndpoint)
	assert.Empty(t, result.JWKSURI)
	assert.Empty(t, result.IntrospectionEndpoint)
	assert.Empty(t, result.ScopesSupported)
}
