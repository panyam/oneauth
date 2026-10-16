package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/panyam/oneauth/core"
)

// RateLimitConfig is the `rate_limit:` block: brute-force limits on login,
// the password grant, signup and forgot-password. On by default.
//
//	rate_limit:
//	  login_per_minute: 10   # per client address + username; also the burst
//	  lockout_attempts: 10   # consecutive failures before a username locks
//	  lockout_duration: 15m
//
// Device user-code entry has its own limiter, always on (apiauth.MountDeviceFlow).
type RateLimitConfig struct {
	// Disabled turns the limits off. Only for load tests.
	Disabled bool `yaml:"disabled"`

	// LoginPerMinute is how many attempts one client address may make per
	// username per minute, after an initial burst of the same size. Zero
	// uses 10.
	LoginPerMinute int `yaml:"login_per_minute"`

	// LockoutAttempts is how many consecutive failures lock a username,
	// from any address. Zero uses 10.
	LockoutAttempts int `yaml:"lockout_attempts"`

	// LockoutDuration is how long a locked username stays locked. Zero
	// uses 15 minutes.
	LockoutDuration time.Duration `yaml:"lockout_duration"`
}

// bruteForce is what the server wires into LocalAuth, the token endpoint and
// the device flow. limiter and lockout are nil when the limits are disabled.
type bruteForce struct {
	limiter        *core.InMemoryRateLimiter
	lockout        *core.AccountLockout
	trustedProxies core.TrustedProxies
}

// buildBruteForce turns the config into limiters. A bad trusted_proxies
// entry fails startup, since the alternative is silently keying every
// client behind the proxy on the proxy's address.
func buildBruteForce(cfg *Config) (*bruteForce, error) {
	proxies, err := core.ParseTrustedProxies(cfg.Server.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("server.trusted_proxies: %w", err)
	}
	bf := &bruteForce{trustedProxies: proxies}
	if cfg.RateLimit.Disabled {
		return bf, nil
	}
	perMinute := cfg.RateLimit.LoginPerMinute
	if perMinute <= 0 {
		perMinute = 10
	}
	attempts := cfg.RateLimit.LockoutAttempts
	if attempts <= 0 {
		attempts = 10
	}
	duration := cfg.RateLimit.LockoutDuration
	if duration <= 0 {
		duration = 15 * time.Minute
	}
	bf.limiter = core.NewInMemoryRateLimiter(float64(perMinute)/60, perMinute)
	bf.lockout = core.NewAccountLockout(attempts, duration)
	return bf, nil
}

// clientIPFor is the address the limits key on.
func clientIPFor(bf *bruteForce, r *http.Request) string {
	return core.ClientIP(r, bf.trustedProxies)
}

// sweep drops idle limiter buckets every few minutes so the map doesn't
// grow with every address that ever connected.
func (bf *bruteForce) sweep() {
	if bf.limiter == nil {
		return
	}
	go func() {
		for range time.Tick(5 * time.Minute) {
			bf.limiter.CleanupStale(10 * time.Minute)
		}
	}()
}
