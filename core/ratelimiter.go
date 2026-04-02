package core

import (
	"sync"
	"time"
)

// RateLimiter controls the rate of operations (e.g., login attempts) per key.
// Keys are typically IP addresses, usernames, or a combination.
type RateLimiter interface {
	// Allow returns true if the operation is permitted for the given key.
	// Returns false if the rate limit has been exceeded.
	Allow(key string) bool
}

// InMemoryRateLimiter implements RateLimiter using a token bucket algorithm.
// Each key gets an independent bucket that refills at a steady rate.
// Thread-safe for concurrent use.
type InMemoryRateLimiter struct {
	rate    float64 // tokens added per second
	burst   int     // max tokens (bucket size)
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens   float64
	lastTime time.Time
}

// NewInMemoryRateLimiter creates a rate limiter that allows `rate` requests
// per second with a burst capacity of `burst`.
//
// Example: NewInMemoryRateLimiter(0.5, 5) allows 1 request per 2 seconds
// sustained, with bursts of up to 5 requests.
func NewInMemoryRateLimiter(rate float64, burst int) *InMemoryRateLimiter {
	return &InMemoryRateLimiter{
		rate:    rate,
		burst:   burst,
		buckets: make(map[string]*bucket),
	}
}

// Allow returns true if the key has tokens remaining.
func (r *InMemoryRateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	b, ok := r.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(r.burst), lastTime: now}
		r.buckets[key] = b
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * r.rate
	if b.tokens > float64(r.burst) {
		b.tokens = float64(r.burst)
	}
	b.lastTime = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// CleanupStale removes buckets that haven't been used for the given duration.
// Call periodically to prevent memory growth from abandoned keys.
func (r *InMemoryRateLimiter) CleanupStale(maxAge time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for key, b := range r.buckets {
		if b.lastTime.Before(cutoff) {
			delete(r.buckets, key)
		}
	}
}

// AccountLockout tracks consecutive authentication failures per key and
// locks accounts after a configurable number of attempts. Lockouts expire
// automatically after LockDuration. Thread-safe.
type AccountLockout struct {
	MaxAttempts  int           // consecutive failures before lockout (default: 5)
	LockDuration time.Duration // how long the lockout lasts (default: 15 min)

	mu       sync.Mutex
	failures map[string]*lockoutEntry
}

type lockoutEntry struct {
	count    int
	lockedAt time.Time // zero if not locked
}

// NewAccountLockout creates an AccountLockout with the given thresholds.
func NewAccountLockout(maxAttempts int, lockDuration time.Duration) *AccountLockout {
	return &AccountLockout{
		MaxAttempts:  maxAttempts,
		LockDuration: lockDuration,
		failures:     make(map[string]*lockoutEntry),
	}
}

// IsLocked returns true if the key is currently locked out.
func (l *AccountLockout) IsLocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.failures[key]
	if !ok {
		return false
	}
	if e.lockedAt.IsZero() {
		return false
	}
	// Check if lockout has expired
	if time.Since(e.lockedAt) > l.LockDuration {
		delete(l.failures, key)
		return false
	}
	return true
}

// RecordFailure records a failed authentication attempt. Returns true if
// the account is now locked (threshold reached).
func (l *AccountLockout) RecordFailure(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.failures[key]
	if !ok {
		e = &lockoutEntry{}
		l.failures[key] = e
	}
	e.count++
	if e.count >= l.MaxAttempts {
		e.lockedAt = time.Now()
		return true
	}
	return false
}

// RecordSuccess resets the failure counter for a key (successful login).
func (l *AccountLockout) RecordSuccess(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

// Reset unlocks an account (admin action).
func (l *AccountLockout) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}
