package apiauth_test

// Brute-force limits at the token endpoint and on device user-code entry.
//
// See: https://cwe.mitre.org/data/definitions/307.html
// See: https://www.rfc-editor.org/rfc/rfc8628#section-5.1 (user_code brute force)
// See: https://github.com/panyam/oneauth/issues/88

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
)

func passwordGrantFrom(fx *apiAuthFixture, password, remote, xff string) int {
	form := url.Values{"grant_type": {"password"}, "username": {"apitest@example.com"}, "password": {password}}
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = remote
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	rr := httptest.NewRecorder()
	fx.TokenEndpoint.ServeHTTP(rr, req)
	return rr.Code
}

func TestBruteForce_PasswordGrantIgnoresSpoofedXFF(t *testing.T) {
	fx, _, _, _ := setupAPIAuthTest(t)
	fx.TokenEndpoint.RateLimiter = core.NewInMemoryRateLimiter(0.001, 2)

	passwordGrantFrom(fx, "wrong", "203.0.113.5:4000", "1.1.1.1")
	passwordGrantFrom(fx, "wrong", "203.0.113.5:4000", "1.1.1.2")
	assert.Equal(t, http.StatusTooManyRequests, passwordGrantFrom(fx, "wrong", "203.0.113.5:4000", "1.1.1.3"))
}

// After enough failures the account is locked, even for the right password
// from a fresh address, until the lockout expires.
func TestBruteForce_PasswordGrantLockout(t *testing.T) {
	fx, _, _, _ := setupAPIAuthTest(t)
	fx.TokenEndpoint.Lockout = core.NewAccountLockout(3, time.Minute)

	for i := 0; i < 3; i++ {
		passwordGrantFrom(fx, "wrong", "203.0.113.5:4000", "")
	}
	assert.Equal(t, http.StatusTooManyRequests, passwordGrantFrom(fx, "password123", "198.51.100.9:4000", ""))
}

func TestBruteForce_DeviceUserCodeEntryIsLimitedByDefault(t *testing.T) {
	mux := http.NewServeMux()
	apiauth.MountDeviceFlow(mux, defaultMountCfg())

	var last int
	for i := 0; i < 30; i++ {
		req := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader(url.Values{"user_code": {"WRNG-CODE"}, "csrf_token": {"test-csrf"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "203.0.113.5:4000"
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		last = rr.Code
	}
	require.Equal(t, http.StatusTooManyRequests, last, "RFC 8628 §5.1: user_code guessing must be limited")
}
