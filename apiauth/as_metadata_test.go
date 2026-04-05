package apiauth_test

// Tests for the OAuth Authorization Server Metadata endpoint (RFC 8414).
// The auth server serves this at GET /.well-known/openid-configuration
// so OIDC-aware clients can auto-discover endpoints.
//
// This is metadata-only — OneAuth is not a full OIDC server. It advertises
// what endpoints exist (token, JWKS, introspection, registration) so
// standard client libraries can discover them.
//
// References:
//   - RFC 8414 (https://www.rfc-editor.org/rfc/rfc8414):
//     "OAuth 2.0 Authorization Server Metadata"
//   - OpenID Connect Discovery 1.0 §4
//   - See: https://github.com/panyam/oneauth/issues/50

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/panyam/oneauth/apiauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestASMetadata_FullResponse verifies that a fully-populated AS metadata
// config is served as JSON with all expected fields. This is the happy path
// for a fully-configured auth server.
//
// See: https://www.rfc-editor.org/rfc/rfc8414#section-2
func TestASMetadata_FullResponse(t *testing.T) {
	meta := &apiauth.ASServerMetadata{
		Issuer:                "https://auth.example.com",
		TokenEndpoint:         "https://auth.example.com/api/token",
		JWKSURI:               "https://auth.example.com/.well-known/jwks.json",
		IntrospectionEndpoint: "https://auth.example.com/oauth/introspect",
		RegistrationEndpoint:  "https://auth.example.com/apps/register",
		ScopesSupported:       []string{"read", "write", "admin"},
		GrantTypesSupported:   []string{"password", "refresh_token", "client_credentials"},
		ResponseTypesSupported:        []string{"token"},
		TokenEndpointAuthMethods:      []string{"client_secret_post", "client_secret_basic"},
		CodeChallengeMethodsSupported: []string{"S256"},
	}

	handler := apiauth.NewASMetadataHandler(meta)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	assert.Contains(t, rr.Header().Get("Cache-Control"), "max-age=")

	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "https://auth.example.com", body["issuer"])
	assert.Equal(t, "https://auth.example.com/api/token", body["token_endpoint"])
	assert.Equal(t, "https://auth.example.com/.well-known/jwks.json", body["jwks_uri"])
	assert.Equal(t, "https://auth.example.com/oauth/introspect", body["introspection_endpoint"])
	assert.Equal(t, "https://auth.example.com/apps/register", body["registration_endpoint"])
	assert.Equal(t, []any{"read", "write", "admin"}, body["scopes_supported"])
	assert.Equal(t, []any{"password", "refresh_token", "client_credentials"}, body["grant_types_supported"])
	assert.Equal(t, []any{"token"}, body["response_types_supported"])
	assert.Equal(t, []any{"client_secret_post", "client_secret_basic"}, body["token_endpoint_auth_methods_supported"])
	assert.Equal(t, []any{"S256"}, body["code_challenge_methods_supported"])
}

// TestASMetadata_OmitsEmptyFields verifies that optional fields are omitted
// when not configured. Only issuer and token_endpoint are required.
//
// See: https://www.rfc-editor.org/rfc/rfc8414#section-2
func TestASMetadata_OmitsEmptyFields(t *testing.T) {
	meta := &apiauth.ASServerMetadata{
		Issuer:        "https://auth.example.com",
		TokenEndpoint: "https://auth.example.com/api/token",
	}

	handler := apiauth.NewASMetadataHandler(meta)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))

	assert.Contains(t, body, "issuer")
	assert.Contains(t, body, "token_endpoint")
	assert.NotContains(t, body, "jwks_uri")
	assert.NotContains(t, body, "introspection_endpoint")
	assert.NotContains(t, body, "registration_endpoint")
	assert.NotContains(t, body, "scopes_supported")
}

// TestASMetadata_CacheControl verifies that the response includes
// Cache-Control headers for efficient caching. AS metadata rarely changes.
//
// See: https://www.rfc-editor.org/rfc/rfc8414#section-3
func TestASMetadata_CacheControl(t *testing.T) {
	meta := &apiauth.ASServerMetadata{
		Issuer:        "https://auth.example.com",
		TokenEndpoint: "https://auth.example.com/api/token",
	}

	handler := apiauth.NewASMetadataHandler(meta)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	cc := rr.Header().Get("Cache-Control")
	assert.Contains(t, cc, "public")
	assert.Contains(t, cc, "max-age=")
}

// TestASMetadata_CustomCacheMaxAge verifies that the cache max-age can
// be customized via the CacheMaxAge field.
func TestASMetadata_CustomCacheMaxAge(t *testing.T) {
	meta := &apiauth.ASServerMetadata{
		Issuer:        "https://auth.example.com",
		TokenEndpoint: "https://auth.example.com/api/token",
		CacheMaxAge:   7200,
	}

	handler := apiauth.NewASMetadataHandler(meta)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Contains(t, rr.Header().Get("Cache-Control"), "max-age=7200")
}

// TestASMetadata_MethodNotAllowed verifies that non-GET requests are rejected.
//
// See: https://www.rfc-editor.org/rfc/rfc8414#section-3
func TestASMetadata_MethodNotAllowed(t *testing.T) {
	meta := &apiauth.ASServerMetadata{
		Issuer:        "https://auth.example.com",
		TokenEndpoint: "https://auth.example.com/api/token",
	}

	handler := apiauth.NewASMetadataHandler(meta)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/.well-known/openid-configuration", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code, "Method %s should be rejected", method)
	}
}

// TestASMetadata_SubjectTypesSupported verifies that subject_types_supported
// is included when set. Required by OIDC Discovery.
func TestASMetadata_SubjectTypesSupported(t *testing.T) {
	meta := &apiauth.ASServerMetadata{
		Issuer:               "https://auth.example.com",
		TokenEndpoint:        "https://auth.example.com/api/token",
		SubjectTypesSupported: []string{"public"},
	}

	handler := apiauth.NewASMetadataHandler(meta)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, []any{"public"}, body["subject_types_supported"])
}
