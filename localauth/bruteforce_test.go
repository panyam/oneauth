package localauth_test

// Brute-force limits that a spoofed X-Forwarded-For can't step around, and
// limits on the endpoints that send mail or create accounts.
//
// See: https://cwe.mitre.org/data/definitions/307.html
// See: https://cwe.mitre.org/data/definitions/348.html
// See: https://cwe.mitre.org/data/definitions/770.html
// See: https://github.com/panyam/oneauth/issues/88

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/core"
)

func loginFrom(h http.Handler, remote, xff string) int {
	req := httptest.NewRequest("POST", "/login", strings.NewReader(`{"username":"alice@example.com","password":"wrong"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remote
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

func TestBruteForce_SpoofedXFFDoesNotResetTheLimit(t *testing.T) {
	auth, done := setupRateLimitAuth(t)
	defer done()
	auth.RateLimiter = core.NewInMemoryRateLimiter(0.001, 2)

	codes := []int{
		loginFrom(auth, "203.0.113.5:4000", "1.1.1.1"),
		loginFrom(auth, "203.0.113.5:4000", "1.1.1.2"),
		loginFrom(auth, "203.0.113.5:4000", "1.1.1.3"),
	}
	assert.Equal(t, http.StatusTooManyRequests, codes[2], "a new X-Forwarded-For per request must not buy a new bucket: %v", codes)
}

// Behind a configured proxy the forwarded client address is used, so two
// clients behind one proxy don't share a bucket.
func TestBruteForce_TrustedProxyForwardsTheClient(t *testing.T) {
	auth, done := setupRateLimitAuth(t)
	defer done()
	auth.RateLimiter = core.NewInMemoryRateLimiter(0.001, 1)
	tp, err := core.ParseTrustedProxies([]string{"10.0.0.0/8"})
	require.NoError(t, err)
	auth.TrustedProxies = tp

	assert.NotEqual(t, http.StatusTooManyRequests, loginFrom(auth, "10.0.0.7:4000", "198.51.100.1"))
	assert.NotEqual(t, http.StatusTooManyRequests, loginFrom(auth, "10.0.0.7:4000", "198.51.100.2"), "a different client behind the proxy")
	assert.Equal(t, http.StatusTooManyRequests, loginFrom(auth, "10.0.0.7:4000", "198.51.100.1"))
}

// Forgot-password sends mail, so it's limited per address and per client,
// or it's a free email cannon.
func TestBruteForce_ForgotPasswordIsLimited(t *testing.T) {
	auth, _, _, tmpDir := setupPasswordResetAuth(t)
	defer cleanup(t, tmpDir)
	auth.RateLimiter = core.NewInMemoryRateLimiter(0.001, 2)

	post := func(email string) int {
		req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", strings.NewReader("email="+email))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "203.0.113.5:4000"
		rr := httptest.NewRecorder()
		auth.HandleForgotPassword(rr, req)
		return rr.Code
	}
	post("reset@example.com")
	post("reset@example.com")
	assert.Equal(t, http.StatusTooManyRequests, post("reset@example.com"))
}

func TestBruteForce_SignupIsLimited(t *testing.T) {
	auth, done := setupRateLimitAuth(t)
	defer done()
	auth.RateLimiter = core.NewInMemoryRateLimiter(0.001, 2)

	signup := func(i int) int {
		body := `{"username":"u` + string(rune('a'+i)) + `","email":"u` + string(rune('a'+i)) + `@example.com","password":"long-enough-pass-1"}`
		req := httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.5:4000"
		rr := httptest.NewRecorder()
		auth.HandleSignup(rr, req)
		return rr.Code
	}
	signup(0)
	signup(1)
	assert.Equal(t, http.StatusTooManyRequests, signup(2))
}
