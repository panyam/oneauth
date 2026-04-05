package apiauth_test

// Tests for the Protected Resource Metadata endpoint (RFC 9728).
// This endpoint allows OAuth clients to auto-discover what a resource server
// expects: which authorization servers it trusts, supported scopes, token
// formats, and signing algorithms.
//
// References:
//   - RFC 9728 (https://www.rfc-editor.org/rfc/rfc9728):
//     "OAuth 2.0 Protected Resource Metadata" — defines the well-known
//     endpoint and response format for resource server discovery.
//   - Related: #47 (Token Introspection — PRM can advertise introspection_endpoint)
//   - Related: #49 (Keycloak interop — PRM enables standards-based discovery)
//
// See: https://github.com/panyam/oneauth/issues/46

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/panyam/oneauth/apiauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPRM_FullMetadata verifies that a fully-populated ProtectedResourceMetadata
// is served as JSON with correct content-type and cache headers. This is the
// happy path: a resource server advertising all its capabilities.
//
// See: https://www.rfc-editor.org/rfc/rfc9728#section-3
func TestPRM_FullMetadata(t *testing.T) {
	meta := &apiauth.ProtectedResourceMetadata{
		Resource:             "https://relay.example.com",
		AuthorizationServers: []string{"https://auth.example.com"},
		ScopesSupported:      []string{"relay:connect", "relay:publish"},
		TokenFormatsSupported: []string{"jwt"},
		SigningAlgsSupported:  []string{"RS256", "ES256"},
		DocumentationURI:     "https://docs.example.com/api",
	}

	handler := apiauth.NewProtectedResourceHandler(meta)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	assert.Contains(t, rr.Header().Get("Cache-Control"), "max-age=")

	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "https://relay.example.com", body["resource"])
	assert.Equal(t, []any{"https://auth.example.com"}, body["authorization_servers"])
	assert.Equal(t, []any{"relay:connect", "relay:publish"}, body["scopes_supported"])
	assert.Equal(t, []any{"jwt"}, body["token_formats_supported"])
	assert.Equal(t, []any{"RS256", "ES256"}, body["resource_signing_alg_values_supported"])
	assert.Equal(t, "https://docs.example.com/api", body["resource_documentation"])
}

// TestPRM_OmitsEmptyFields verifies that optional fields with zero values
// are omitted from the JSON response (omitempty). RFC 9728 only requires
// "resource" and "authorization_servers"; all other fields are optional.
//
// See: https://www.rfc-editor.org/rfc/rfc9728#section-3
func TestPRM_OmitsEmptyFields(t *testing.T) {
	meta := &apiauth.ProtectedResourceMetadata{
		Resource:             "https://api.example.com",
		AuthorizationServers: []string{"https://auth.example.com"},
	}

	handler := apiauth.NewProtectedResourceHandler(meta)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))

	// Required fields present
	assert.Contains(t, body, "resource")
	assert.Contains(t, body, "authorization_servers")

	// Optional fields omitted
	assert.NotContains(t, body, "scopes_supported")
	assert.NotContains(t, body, "token_formats_supported")
	assert.NotContains(t, body, "resource_signing_alg_values_supported")
	assert.NotContains(t, body, "resource_documentation")
	assert.NotContains(t, body, "introspection_endpoint")
}

// TestPRM_IntrospectionEndpoint verifies that the introspection_endpoint
// field is included when set. This enables clients to discover the token
// introspection URL without hardcoding it.
//
// See: https://www.rfc-editor.org/rfc/rfc9728#section-3
// See: https://github.com/panyam/oneauth/issues/47
func TestPRM_IntrospectionEndpoint(t *testing.T) {
	meta := &apiauth.ProtectedResourceMetadata{
		Resource:              "https://api.example.com",
		AuthorizationServers:  []string{"https://auth.example.com"},
		IntrospectionEndpoint: "https://auth.example.com/oauth/introspect",
	}

	handler := apiauth.NewProtectedResourceHandler(meta)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "https://auth.example.com/oauth/introspect", body["introspection_endpoint"])
}

// TestPRM_MethodNotAllowed verifies that non-GET requests are rejected
// with 405 Method Not Allowed. The PRM endpoint is read-only.
//
// See: https://www.rfc-editor.org/rfc/rfc9728#section-3
func TestPRM_MethodNotAllowed(t *testing.T) {
	meta := &apiauth.ProtectedResourceMetadata{
		Resource:             "https://api.example.com",
		AuthorizationServers: []string{"https://auth.example.com"},
	}

	handler := apiauth.NewProtectedResourceHandler(meta)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/.well-known/oauth-protected-resource", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code, "Method %s should be rejected", method)
	}
}

// TestPRM_CacheControl verifies that the response includes Cache-Control
// headers for efficient client caching. Resource metadata rarely changes,
// so caching reduces unnecessary requests.
//
// See: https://www.rfc-editor.org/rfc/rfc9728#section-3.3
func TestPRM_CacheControl(t *testing.T) {
	meta := &apiauth.ProtectedResourceMetadata{
		Resource:             "https://api.example.com",
		AuthorizationServers: []string{"https://auth.example.com"},
	}

	handler := apiauth.NewProtectedResourceHandler(meta)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	cc := rr.Header().Get("Cache-Control")
	assert.Contains(t, cc, "public")
	assert.Contains(t, cc, "max-age=")
}

// TestPRM_CustomCacheMaxAge verifies that the cache max-age can be customized
// via the CacheMaxAge field on ProtectedResourceMetadata.
//
// See: https://www.rfc-editor.org/rfc/rfc9728#section-3.3
func TestPRM_CustomCacheMaxAge(t *testing.T) {
	meta := &apiauth.ProtectedResourceMetadata{
		Resource:             "https://api.example.com",
		AuthorizationServers: []string{"https://auth.example.com"},
		CacheMaxAge:          7200,
	}

	handler := apiauth.NewProtectedResourceHandler(meta)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Contains(t, rr.Header().Get("Cache-Control"), "max-age=7200")
}

// TestPRM_MultipleAuthorizationServers verifies that multiple authorization
// servers can be listed. This supports resource servers that accept tokens
// from multiple issuers (e.g., internal + external IdP).
//
// See: https://www.rfc-editor.org/rfc/rfc9728#section-3
func TestPRM_MultipleAuthorizationServers(t *testing.T) {
	meta := &apiauth.ProtectedResourceMetadata{
		Resource: "https://api.example.com",
		AuthorizationServers: []string{
			"https://auth1.example.com",
			"https://auth2.example.com",
		},
	}

	handler := apiauth.NewProtectedResourceHandler(meta)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	servers := body["authorization_servers"].([]any)
	assert.Len(t, servers, 2)
	assert.Equal(t, "https://auth1.example.com", servers[0])
	assert.Equal(t, "https://auth2.example.com", servers[1])
}
