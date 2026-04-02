package httpauth_test

// Tests for request body size limiting middleware.
// Prevents memory exhaustion DoS attacks via oversized JSON request bodies.
//
// References:
//   - CWE-400 (https://cwe.mitre.org/data/definitions/400.html):
//     Uncontrolled Resource Consumption
//   - OWASP DoS (https://owasp.org/www-community/attacks/Denial_of_Service):
//     Denial of Service via resource exhaustion

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/panyam/oneauth/httpauth"
	"github.com/stretchr/testify/assert"
)

// TestBodyLimit_OversizedRequest_413 verifies that a request body exceeding
// the configured limit returns 413 Request Entity Too Large. Without this
// middleware, Go's http.Server accepts arbitrarily large bodies, enabling
// memory exhaustion attacks.
//
// BEFORE FIX: no LimitBody middleware exists (compile error)
// AFTER FIX: returns 413
//
// See: https://cwe.mitre.org/data/definitions/400.html
func TestBodyLimit_OversizedRequest_413(t *testing.T) {
	handler := httpauth.LimitBody(1024)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))

	// Send 2KB body to a handler with 1KB limit
	body := strings.Repeat("x", 2048)
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.ContentLength = int64(len(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code,
		"oversized request should return 413")
}

// TestBodyLimit_NormalRequest_OK verifies that requests within the size
// limit are processed normally.
func TestBodyLimit_NormalRequest_OK(t *testing.T) {
	handler := httpauth.LimitBody(1024)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}))

	body := `{"username":"alice","password":"secret123"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, body, rr.Body.String())
}

// TestBodyLimit_ExactLimit_OK verifies that a body exactly at the limit
// is accepted (boundary condition).
func TestBodyLimit_ExactLimit_OK(t *testing.T) {
	limit := int64(100)
	handler := httpauth.LimitBody(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))

	body := strings.Repeat("x", int(limit))
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestBodyLimit_GetRequest_NoLimit verifies that GET requests are not
// affected by the body limit (they typically have no body).
func TestBodyLimit_GetRequest_NoLimit(t *testing.T) {
	handler := httpauth.LimitBody(1024)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}
