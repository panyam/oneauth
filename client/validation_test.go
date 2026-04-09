package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- ValidateHTTPS tests ---

// TestValidateHTTPS_RejectsHTTP verifies that non-HTTPS AS endpoints are
// rejected. Per RFC 6749 §3.1.2.1, authorization server endpoints MUST use
// TLS (HTTPS) to protect credentials in transit.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2.1
func TestValidateHTTPS_RejectsHTTP(t *testing.T) {
	meta := &ASMetadata{
		AuthorizationEndpoint: "http://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
	}
	err := ValidateHTTPS(meta)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTPS")
}

// TestValidateHTTPS_AcceptsHTTPS verifies that HTTPS endpoints pass validation.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2.1
func TestValidateHTTPS_AcceptsHTTPS(t *testing.T) {
	meta := &ASMetadata{
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
	}
	err := ValidateHTTPS(meta)
	assert.NoError(t, err)
}

// TestValidateHTTPS_LocalhostExempt verifies that localhost endpoints are
// exempt from HTTPS enforcement. This allows local development and testing
// without TLS certificates.
//
// See: https://www.rfc-editor.org/rfc/rfc8252#section-8.3
func TestValidateHTTPS_LocalhostExempt(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{"localhost", "http://localhost:8080/authorize"},
		{"127.0.0.1", "http://127.0.0.1:9090/token"},
		{"IPv6 loopback", "http://[::1]:8080/authorize"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			meta := &ASMetadata{
				AuthorizationEndpoint: tc.url,
				TokenEndpoint:         tc.url,
			}
			assert.NoError(t, ValidateHTTPS(meta))
		})
	}
}

// TestValidateHTTPS_NilMetadata verifies that nil AS metadata does not cause
// a panic and returns no error (nothing to validate).
func TestValidateHTTPS_NilMetadata(t *testing.T) {
	assert.NoError(t, ValidateHTTPS(nil))
}

// TestValidateHTTPS_EmptyEndpoints verifies that empty endpoint strings are
// skipped without error (the endpoint is simply not configured).
func TestValidateHTTPS_EmptyEndpoints(t *testing.T) {
	meta := &ASMetadata{}
	assert.NoError(t, ValidateHTTPS(meta))
}

// --- IsLocalhost tests ---

// TestIsLocalhost verifies detection of loopback addresses. This is used to
// exempt local development servers from HTTPS enforcement.
//
// See: https://www.rfc-editor.org/rfc/rfc8252#section-8.3
func TestIsLocalhost(t *testing.T) {
	cases := []struct {
		name     string
		url      string
		expected bool
	}{
		{"localhost", "http://localhost:8080/path", true},
		{"127.0.0.1", "https://127.0.0.1/path", true},
		{"IPv6 loopback", "http://[::1]:3000", true},
		{"external host", "https://auth.example.com", false},
		{"empty string", "", false},
		{"invalid URL", "://bad", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsLocalhost(tc.url))
		})
	}
}

// --- ValidateCIMDURL tests ---

// TestValidateCIMDURL_Valid verifies that a well-formed CIMD URL passes
// validation. Per draft-ietf-oauth-client-id-metadata-document, the URL
// MUST use HTTPS and MUST contain a non-root path.
//
// See: https://drafts.aaronpk.com/draft-parecki-oauth-client-id-metadata-document/draft-parecki-oauth-client-id-metadata-document.html
func TestValidateCIMDURL_Valid(t *testing.T) {
	assert.NoError(t, ValidateCIMDURL("https://client.example.com/.well-known/oauth-client"))
}

// TestValidateCIMDURL_RejectsHTTP verifies that non-HTTPS CIMD URLs are
// rejected (HTTPS is required by the spec).
func TestValidateCIMDURL_RejectsHTTP(t *testing.T) {
	err := ValidateCIMDURL("http://client.example.com/metadata")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

// TestValidateCIMDURL_RejectsNoPath verifies that CIMD URLs without a path
// (or with only a root "/" path) are rejected. The URL must point to a
// specific metadata document, not a bare domain.
func TestValidateCIMDURL_RejectsNoPath(t *testing.T) {
	err := ValidateCIMDURL("https://client.example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path")

	err = ValidateCIMDURL("https://client.example.com/")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path")
}

// TestValidateCIMDURL_LocalhostExempt verifies that localhost CIMD URLs are
// exempt from the HTTPS requirement, allowing local development.
func TestValidateCIMDURL_LocalhostExempt(t *testing.T) {
	assert.NoError(t, ValidateCIMDURL("http://localhost:8080/metadata"))
	assert.NoError(t, ValidateCIMDURL("http://127.0.0.1:3000/client-meta"))
}

// TestValidateCIMDURL_InvalidURL verifies that unparseable URLs return an error.
func TestValidateCIMDURL_InvalidURL(t *testing.T) {
	err := ValidateCIMDURL("://bad-url")
	require.Error(t, err)
}
