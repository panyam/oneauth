package main

// The reference server's brute-force limits (issue 88): on by default,
// tunable, and keyed on the real client only behind configured proxies.
//
// See: https://cwe.mitre.org/data/definitions/307.html
// See: https://cwe.mitre.org/data/definitions/348.html
// See: https://github.com/panyam/oneauth/issues/88

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBruteForce_OnByDefault(t *testing.T) {
	cfg := loadYAML(t, "jwt:\n  secret_key: x\n")
	bf, err := buildBruteForce(cfg)
	require.NoError(t, err)
	require.NotNil(t, bf.limiter)
	require.NotNil(t, bf.lockout)

	allowed := 0
	for i := 0; i < 50; i++ {
		if bf.limiter.Allow("203.0.113.5:alice") {
			allowed++
		}
	}
	assert.Less(t, allowed, 50, "the default limiter must stop a burst of guesses")
	assert.Greater(t, allowed, 0)
}

func TestBruteForce_Configurable(t *testing.T) {
	cfg := loadYAML(t, `
server:
  trusted_proxies: ["10.0.0.0/8"]
rate_limit:
  login_per_minute: 3
  lockout_attempts: 2
  lockout_duration: 1m
`)
	bf, err := buildBruteForce(cfg)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		assert.True(t, bf.limiter.Allow("k"), "attempt %d", i+1)
	}
	assert.False(t, bf.limiter.Allow("k"))

	bf.lockout.RecordFailure("alice")
	bf.lockout.RecordFailure("alice")
	assert.True(t, bf.lockout.IsLocked("alice"))

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "10.0.0.7:4000"
	r.Header.Set("X-Forwarded-For", "198.51.100.9")
	assert.Equal(t, "198.51.100.9", clientIPFor(bf, r))
}

func TestBruteForce_CanBeDisabled(t *testing.T) {
	cfg := loadYAML(t, "rate_limit:\n  disabled: true\n")
	bf, err := buildBruteForce(cfg)
	require.NoError(t, err)
	assert.Nil(t, bf.limiter)
	assert.Nil(t, bf.lockout)
}

func TestBruteForce_BadProxyFailsStartup(t *testing.T) {
	cfg := loadYAML(t, "server:\n  trusted_proxies: [\"not-a-cidr\"]\n")
	_, err := buildBruteForce(cfg)
	assert.Error(t, err)
}
