package httpauth_test

// Tests for security headers middleware.
//
// References:
//   - OWASP Secure Headers (https://owasp.org/www-project-secure-headers/):
//     Comprehensive guide to HTTP security headers
//   - RFC 6797 (https://datatracker.ietf.org/doc/html/rfc6797):
//     HTTP Strict Transport Security (HSTS)
//   - CWE-1021 (https://cwe.mitre.org/data/definitions/1021.html):
//     Improper Restriction of Rendered UI Layers (clickjacking)

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/panyam/oneauth/httpauth"
	"github.com/stretchr/testify/assert"
)

// TestSecurityHeaders_DefaultHeaders verifies that the default configuration
// sets all standard security headers on every response.
//
// See: https://owasp.org/www-project-secure-headers/
func TestSecurityHeaders_DefaultHeaders(t *testing.T) {
	handler := httpauth.SecurityHeaders()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", rr.Header().Get("X-Frame-Options"))
	assert.Equal(t, "default-src 'self'", rr.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "strict-origin-when-cross-origin", rr.Header().Get("Referrer-Policy"))
	assert.Contains(t, rr.Header().Get("Strict-Transport-Security"), "max-age=31536000")
	assert.Contains(t, rr.Header().Get("Strict-Transport-Security"), "includeSubDomains")
	assert.Contains(t, rr.Header().Get("Permissions-Policy"), "camera=()")
	assert.Equal(t, "credentialless", rr.Header().Get("Cross-Origin-Embedder-Policy"))
	assert.Equal(t, "same-origin", rr.Header().Get("Cross-Origin-Opener-Policy"))
	assert.Equal(t, "same-origin", rr.Header().Get("Cross-Origin-Resource-Policy"))
}

// TestSecurityHeaders_HSTS verifies HSTS header format per RFC 6797.
//
// See: https://datatracker.ietf.org/doc/html/rfc6797
func TestSecurityHeaders_HSTS(t *testing.T) {
	handler := httpauth.SecurityHeaders()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	hsts := rr.Header().Get("Strict-Transport-Security")
	assert.Equal(t, "max-age=31536000; includeSubDomains", hsts)
}

// TestSecurityHeaders_CustomConfig verifies that headers can be customized
// or disabled individually.
func TestSecurityHeaders_CustomConfig(t *testing.T) {
	cfg := httpauth.SecurityHeadersConfig{
		HSTSMaxAge:            0, // disabled
		FrameOptions:          "SAMEORIGIN",
		ContentSecurityPolicy: "default-src 'self'; script-src 'self' cdn.example.com",
		ReferrerPolicy:        "",  // disabled
		PermissionsPolicy:     "",  // disabled
	}
	handler := httpauth.SecurityHeadersWithConfig(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	// Disabled headers should not be present
	assert.Empty(t, rr.Header().Get("Strict-Transport-Security"))
	assert.Empty(t, rr.Header().Get("Referrer-Policy"))
	assert.Empty(t, rr.Header().Get("Permissions-Policy"))

	// Customized headers
	assert.Equal(t, "SAMEORIGIN", rr.Header().Get("X-Frame-Options"))
	assert.Contains(t, rr.Header().Get("Content-Security-Policy"), "cdn.example.com")

	// Always-on header
	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
}

// TestSecurityHeaders_ClickjackingPrevention verifies X-Frame-Options DENY
// prevents the page from being embedded in iframes (clickjacking defense).
//
// See: https://cwe.mitre.org/data/definitions/1021.html
func TestSecurityHeaders_ClickjackingPrevention(t *testing.T) {
	handler := httpauth.SecurityHeaders()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	assert.Equal(t, "DENY", rr.Header().Get("X-Frame-Options"),
		"X-Frame-Options: DENY prevents clickjacking via iframe embedding")
}
