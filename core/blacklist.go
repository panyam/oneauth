package core

import (
	"sync"
	"time"
)

// TokenBlacklist tracks revoked JWT access tokens by their jti (JWT ID) claim.
// Entries auto-expire when the original token would have expired, preventing
// unbounded growth. Pluggable: in-memory for single-node, Redis for distributed.
//
// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
type TokenBlacklist interface {
	// Revoke adds a token ID to the blacklist. The entry should be kept
	// until expiry (when the token would naturally expire anyway).
	Revoke(jti string, expiry time.Time) error

	// IsRevoked returns true if the token ID has been revoked and hasn't expired.
	IsRevoked(jti string) bool
}

// BlacklistIssuedAccessTokens revokes each token in blacklist until its
// expiry, which is what a refresh-store revocation hands back
// (RevokeTokenFamilyResponse, RevokeSubjectTokensResponse). A nil
// blacklist does nothing, and an entry with no expiry is kept for the
// default access-token lifetime. Errors from the blacklist are dropped:
// the refresh tokens are already revoked, so failing here would leave
// the caller nothing to retry.
func BlacklistIssuedAccessTokens(blacklist TokenBlacklist, tokens []IssuedAccessToken) {
	if blacklist == nil {
		return
	}
	for _, t := range tokens {
		if t.TokenID == "" {
			continue
		}
		expiresAt := t.ExpiresAt
		if expiresAt.IsZero() {
			expiresAt = time.Now().Add(TokenExpiryAccessToken)
		}
		_ = blacklist.Revoke(t.TokenID, expiresAt)
	}
}

// InMemoryBlacklist is a thread-safe in-memory TokenBlacklist.
// Suitable for single-process deployments. For distributed deployments,
// use a Redis-backed implementation with the same interface.
type InMemoryBlacklist struct {
	mu      sync.RWMutex
	entries map[string]time.Time // jti → expiry
}

// NewInMemoryBlacklist creates a new in-memory blacklist.
func NewInMemoryBlacklist() *InMemoryBlacklist {
	return &InMemoryBlacklist{
		entries: make(map[string]time.Time),
	}
}

// Revoke adds a token ID to the blacklist until its expiry time.
func (b *InMemoryBlacklist) Revoke(jti string, expiry time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries[jti] = expiry
	return nil
}

// IsRevoked returns true if the token ID is in the blacklist and hasn't expired.
func (b *InMemoryBlacklist) IsRevoked(jti string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	expiry, ok := b.entries[jti]
	if !ok {
		return false
	}
	// Entry expired — treat as not revoked (will be cleaned up)
	if time.Now().After(expiry) {
		return false
	}
	return true
}

// CleanupExpired removes entries whose tokens have naturally expired.
// Call periodically (e.g., every minute) to prevent memory growth.
func (b *InMemoryBlacklist) CleanupExpired() {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	for jti, expiry := range b.entries {
		if now.After(expiry) {
			delete(b.entries, jti)
		}
	}
}

// Len returns the number of entries (including expired ones not yet cleaned).
func (b *InMemoryBlacklist) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.entries)
}
