package localauth_test

// Tests for login rate limiting, account lockout, and timing oracle prevention.
//
// References:
//   - CWE-307 (https://cwe.mitre.org/data/definitions/307.html):
//     Improper Restriction of Excessive Authentication Attempts
//   - CWE-208 (https://cwe.mitre.org/data/definitions/208.html):
//     Observable Timing Discrepancy (timing oracle)
//   - OWASP Brute Force (https://owasp.org/www-community/attacks/Brute_force_attack)

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/localauth"
	fsstore "github.com/panyam/oneauth/stores/fs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// setupRateLimitAuth creates a LocalAuth with stores, a test user, and
// configurable rate limiter + lockout.
func setupRateLimitAuth(t *testing.T) (*localauth.LocalAuth, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ratelimit-test-*")
	require.NoError(t, err)

	userStore := fsstore.NewFSUserStore(dir)
	identityStore := fsstore.NewFSIdentityStore(dir)
	channelStore := fsstore.NewFSChannelStore(dir)

	createUser := localauth.NewCreateUserFunc(userStore, identityStore, channelStore)
	email := "alice@example.com"
	creds := &core.Credentials{
		Username: "alice",
		Email:    &email,
		Password: "correctpassword123",
	}
	_, err = createUser(creds)
	require.NoError(t, err)

	auth := &localauth.LocalAuth{
		ValidateCredentials: localauth.NewCredentialsValidator(identityStore, channelStore, userStore),
		CreateUser:          createUser,
		HandleUser: func(authtype, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"user": userInfo["email"]})
		},
	}

	return auth, func() { os.RemoveAll(dir) }
}

// postLogin sends a login request and returns the response.
func postLogin(handler http.Handler, username, password string) *httptest.ResponseRecorder {
	body := `{"username":"` + username + `","password":"` + password + `"}`
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.168.1.100:12345"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// =============================================================================
// Rate Limiting Tests
// These FAIL before the fix — LocalAuth has no RateLimiter field.
// =============================================================================

// TestRateLimit_LocalAuth_BlocksAfterBurst verifies that rapid login attempts
// are blocked after the burst limit is exhausted. Without rate limiting, an
// attacker can try thousands of passwords per second.
//
// BEFORE FIX: all requests return 200/401 (no rate limiting)
// AFTER FIX: requests after burst return 429
//
// See: https://cwe.mitre.org/data/definitions/307.html
func TestRateLimit_LocalAuth_BlocksAfterBurst(t *testing.T) {
	auth, cleanup := setupRateLimitAuth(t)
	defer cleanup()

	// Allow 3 attempts, then block
	auth.RateLimiter = core.NewInMemoryRateLimiter(0.1, 3) // very slow refill

	// First 3 attempts should go through (wrong password → 401, not 429)
	for i := 0; i < 3; i++ {
		rr := postLogin(auth, "alice@example.com", "wrongpassword")
		assert.NotEqual(t, http.StatusTooManyRequests, rr.Code,
			"attempt %d should not be rate limited", i+1)
	}

	// 4th attempt should be rate limited → 429
	rr := postLogin(auth, "alice@example.com", "wrongpassword")
	assert.Equal(t, http.StatusTooManyRequests, rr.Code,
		"attempt after burst should return 429")
}

// TestRateLimit_Returns429WithRetryAfter verifies that rate-limited responses
// include the Retry-After header per RFC 6585.
//
// See: https://datatracker.ietf.org/doc/html/rfc6585#section-4
func TestRateLimit_Returns429WithRetryAfter(t *testing.T) {
	auth, cleanup := setupRateLimitAuth(t)
	defer cleanup()

	auth.RateLimiter = core.NewInMemoryRateLimiter(0.1, 1) // 1 attempt then block

	// Exhaust the burst
	postLogin(auth, "alice@example.com", "wrong")

	// Next should be 429
	rr := postLogin(auth, "alice@example.com", "wrong")
	assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	assert.NotEmpty(t, rr.Header().Get("Retry-After"),
		"429 response should include Retry-After header")
}

// TestRateLimit_CorrectPasswordStillRateLimited verifies that rate limiting
// applies even for correct passwords — the check happens before credential
// validation to prevent timing-based bypass.
//
// See: https://owasp.org/www-community/attacks/Brute_force_attack
func TestRateLimit_CorrectPasswordStillRateLimited(t *testing.T) {
	auth, cleanup := setupRateLimitAuth(t)
	defer cleanup()

	auth.RateLimiter = core.NewInMemoryRateLimiter(0.1, 1)

	// Exhaust burst with wrong password
	postLogin(auth, "alice@example.com", "wrong")

	// Correct password should still be rate limited
	rr := postLogin(auth, "alice@example.com", "correctpassword123")
	assert.Equal(t, http.StatusTooManyRequests, rr.Code,
		"rate limiting should apply before credential validation")
}

// =============================================================================
// Account Lockout Tests
// These FAIL before the fix — no lockout mechanism exists.
// =============================================================================

// TestLockout_LocksAfterMaxFailures verifies that an account is locked after
// N consecutive failed login attempts. The response should indicate the lockout
// without revealing whether the account exists.
//
// See: https://cwe.mitre.org/data/definitions/307.html
func TestLockout_LocksAfterMaxFailures(t *testing.T) {
	auth, cleanup := setupRateLimitAuth(t)
	defer cleanup()

	auth.Lockout = core.NewAccountLockout(3, 1*time.Minute)

	// 3 failed attempts → lockout
	for i := 0; i < 3; i++ {
		rr := postLogin(auth, "alice@example.com", "wrongpassword")
		assert.NotEqual(t, http.StatusTooManyRequests, rr.Code,
			"attempt %d should not be locked yet", i+1)
	}

	// 4th attempt → locked out (even with correct password)
	rr := postLogin(auth, "alice@example.com", "correctpassword123")
	assert.Equal(t, http.StatusTooManyRequests, rr.Code,
		"account should be locked after max failures")
}

// TestLockout_UnlocksAfterDuration verifies that locked accounts automatically
// unlock after the lockout duration expires.
func TestLockout_UnlocksAfterDuration(t *testing.T) {
	auth, cleanup := setupRateLimitAuth(t)
	defer cleanup()

	auth.Lockout = core.NewAccountLockout(2, 50*time.Millisecond)

	// Lock the account
	postLogin(auth, "alice@example.com", "wrong")
	postLogin(auth, "alice@example.com", "wrong")

	// Should be locked
	rr := postLogin(auth, "alice@example.com", "correctpassword123")
	assert.Equal(t, http.StatusTooManyRequests, rr.Code)

	// Wait for lockout to expire
	time.Sleep(60 * time.Millisecond)

	// Should be unlocked now — correct password works
	rr = postLogin(auth, "alice@example.com", "correctpassword123")
	assert.Equal(t, http.StatusOK, rr.Code,
		"account should unlock after lockout duration")
}

// TestLockout_SuccessResetsCounter verifies that a successful login resets
// the failure counter, preventing accumulated failures from different sessions.
func TestLockout_SuccessResetsCounter(t *testing.T) {
	auth, cleanup := setupRateLimitAuth(t)
	defer cleanup()

	auth.Lockout = core.NewAccountLockout(3, 1*time.Minute)

	// 2 failures (not enough to lock)
	postLogin(auth, "alice@example.com", "wrong")
	postLogin(auth, "alice@example.com", "wrong")

	// Successful login resets counter
	rr := postLogin(auth, "alice@example.com", "correctpassword123")
	assert.Equal(t, http.StatusOK, rr.Code)

	// 2 more failures — should NOT be locked (counter was reset)
	postLogin(auth, "alice@example.com", "wrong")
	postLogin(auth, "alice@example.com", "wrong")

	// 3rd failure after reset — still not locked (only 2 consecutive)
	rr = postLogin(auth, "alice@example.com", "correctpassword123")
	assert.Equal(t, http.StatusOK, rr.Code,
		"success should reset failure counter")
}

// =============================================================================
// Timing Oracle Tests
// =============================================================================

// TestTimingOracle_ConstantTime verifies that login responses take similar
// time for existing and non-existing users. Before the fix, non-existing
// users return instantly (~1ms) while existing users go through bcrypt (~50ms),
// allowing attackers to enumerate valid email addresses.
//
// See: https://cwe.mitre.org/data/definitions/208.html
func TestTimingOracle_ConstantTime(t *testing.T) {
	auth, cleanup := setupRateLimitAuth(t)
	defer cleanup()

	// Time login for existing user (wrong password)
	var existingDurations []time.Duration
	for i := 0; i < 3; i++ {
		start := time.Now()
		postLogin(auth, "alice@example.com", "wrongpassword")
		existingDurations = append(existingDurations, time.Since(start))
	}

	// Time login for non-existing user
	var fakeDurations []time.Duration
	for i := 0; i < 3; i++ {
		start := time.Now()
		postLogin(auth, "nobody@fake.com", "wrongpassword")
		fakeDurations = append(fakeDurations, time.Since(start))
	}

	// Both should take similar time (within 3x — bcrypt dominates)
	avgExisting := avg(existingDurations)
	avgFake := avg(fakeDurations)

	// Before fix: fake ~1ms, existing ~50ms → 50x difference
	// After fix: both ~50ms → within 3x
	ratio := float64(avgExisting) / float64(avgFake)
	if ratio > 3.0 || ratio < 0.33 {
		t.Errorf("Timing oracle detected: existing user avg=%v, fake user avg=%v, ratio=%.1fx (should be <3x)\n"+
			"See: https://cwe.mitre.org/data/definitions/208.html",
			avgExisting, avgFake, ratio)
	}
}

func avg(durations []time.Duration) time.Duration {
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	return total / time.Duration(len(durations))
}

// =============================================================================
// Core Rate Limiter Unit Tests
// =============================================================================

// TestInMemoryRateLimiter_Basic verifies the token bucket behavior.
func TestInMemoryRateLimiter_Basic(t *testing.T) {
	rl := core.NewInMemoryRateLimiter(10, 3) // 10/sec, burst 3

	// Burst of 3 should all be allowed
	assert.True(t, rl.Allow("key1"))
	assert.True(t, rl.Allow("key1"))
	assert.True(t, rl.Allow("key1"))

	// 4th should be denied
	assert.False(t, rl.Allow("key1"))

	// Different key has its own bucket
	assert.True(t, rl.Allow("key2"))
}

// TestInMemoryRateLimiter_Refill verifies that tokens refill over time.
func TestInMemoryRateLimiter_Refill(t *testing.T) {
	rl := core.NewInMemoryRateLimiter(100, 1) // 100/sec, burst 1

	assert.True(t, rl.Allow("key1"))
	assert.False(t, rl.Allow("key1"))

	// Wait for refill
	time.Sleep(20 * time.Millisecond) // 100/sec = 1 per 10ms

	assert.True(t, rl.Allow("key1"))
}

// TestAccountLockout_Basic verifies lockout lifecycle.
func TestAccountLockout_Basic(t *testing.T) {
	lo := core.NewAccountLockout(3, 50*time.Millisecond)

	assert.False(t, lo.IsLocked("alice"))

	lo.RecordFailure("alice")
	lo.RecordFailure("alice")
	assert.False(t, lo.IsLocked("alice")) // 2 failures, not locked yet

	lo.RecordFailure("alice") // 3rd → locked
	assert.True(t, lo.IsLocked("alice"))

	// Wait for expiry
	time.Sleep(60 * time.Millisecond)
	assert.False(t, lo.IsLocked("alice"))
}

// TestAccountLockout_Reset verifies admin unlock.
func TestAccountLockout_Reset(t *testing.T) {
	lo := core.NewAccountLockout(2, 1*time.Minute)

	lo.RecordFailure("alice")
	lo.RecordFailure("alice")
	assert.True(t, lo.IsLocked("alice"))

	lo.Reset("alice")
	assert.False(t, lo.IsLocked("alice"))
}
