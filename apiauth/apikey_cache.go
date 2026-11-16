package apiauth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/panyam/oneauth/core"
)

// Defaults for APIKeyCacheConfig fields left zero.
const (
	DefaultAPIKeyCacheTTL         = time.Minute
	DefaultAPIKeyLastUsedInterval = time.Minute
)

// APIKeyCacheConfig turns on caching of validated API keys in APIMiddleware.
//
// Without it, every request carrying an API key calls
// APIKeyStore.ValidateAPIKey, which runs a bcrypt compare (tens of
// milliseconds at the default cost), and records last use in the store. With
// it, a key that validated within TTL is accepted from memory, and last use
// is written at most once per key per LastUsedInterval.
//
// The cost is revocation latency. A key revoked through the store keeps
// working until its cache entry ages out, so TTL bounds how long a revoked
// key stays usable. A caller that revokes in the same process can drop the
// entry at once with APIMiddleware.InvalidateAPIKey. A key's own ExpiresAt
// still holds exactly: an entry is never served past it.
//
// Only successful validations are cached. A wrong secret for a cached key ID
// goes to the store like any other miss.
type APIKeyCacheConfig struct {
	// TTL is how long a validated key is served from memory. Zero means
	// DefaultAPIKeyCacheTTL.
	TTL time.Duration

	// LastUsedInterval is the least time between two UpdateAPIKeyLastUsed
	// calls for one key. Zero means DefaultAPIKeyLastUsedInterval. The store's
	// LastUsedAt is then accurate to within this interval.
	LastUsedInterval time.Duration

	// Now is the clock. Nil means time.Now.
	Now func() time.Time
}

// apiKeyCache holds validated keys by key ID. Each entry keeps the full key,
// and a lookup compares it in constant time, so the secret is never hashed
// or used as a map key.
type apiKeyCache struct {
	ttl              time.Duration
	lastUsedInterval time.Duration
	now              func() time.Time

	mu        sync.Mutex
	entries   map[string]*apiKeyCacheEntry
	lastUsed  map[string]time.Time
	lastSweep time.Time
}

type apiKeyCacheEntry struct {
	fullKey string
	info    TokenInfo
	until   time.Time
}

func newAPIKeyCache(cfg *APIKeyCacheConfig) *apiKeyCache {
	c := &apiKeyCache{
		ttl:              cfg.TTL,
		lastUsedInterval: cfg.LastUsedInterval,
		now:              cfg.Now,
		entries:          make(map[string]*apiKeyCacheEntry),
		lastUsed:         make(map[string]time.Time),
	}
	if c.ttl <= 0 {
		c.ttl = DefaultAPIKeyCacheTTL
	}
	if c.lastUsedInterval <= 0 {
		c.lastUsedInterval = DefaultAPIKeyLastUsedInterval
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c
}

// apiKeyID returns the public key ID of a full key "oa_<id>_<secret>", the
// format every store in this repo parses.
func apiKeyID(fullKey string) (string, bool) {
	parts := strings.SplitN(fullKey, "_", 3)
	if len(parts) != 3 || parts[0] != "oa" || parts[1] == "" || parts[2] == "" {
		return "", false
	}
	return parts[0] + "_" + parts[1], true
}

// get returns a copy of the cached TokenInfo when fullKey matches a live
// entry.
func (c *apiKeyCache) get(fullKey string) (*TokenInfo, bool) {
	keyID, ok := apiKeyID(fullKey)
	if !ok {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[keyID]
	if !ok {
		return nil, false
	}
	if !c.now().Before(e.until) {
		delete(c.entries, keyID)
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(e.fullKey), []byte(fullKey)) != 1 {
		return nil, false
	}
	info := e.info
	info.Scopes = append([]string(nil), e.info.Scopes...)
	return &info, true
}

// put caches a key the store just validated. An entry never outlives the
// key's own expiry. A key whose ID doesn't match the full key's prefix comes
// from a store with another format, and is not cached.
func (c *apiKeyCache) put(fullKey string, apiKey *core.APIKey, info *TokenInfo) {
	keyID, ok := apiKeyID(fullKey)
	if !ok || keyID != apiKey.KeyID {
		return
	}
	now := c.now()
	until := now.Add(c.ttl)
	if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(until) {
		until = *apiKey.ExpiresAt
	}
	if !now.Before(until) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(now)
	e := &apiKeyCacheEntry{fullKey: fullKey, info: *info, until: until}
	e.info.Scopes = append([]string(nil), info.Scopes...)
	c.entries[keyID] = e
}

// shouldRecordUse reports whether last use is due for keyID, and if so marks
// it recorded now.
func (c *apiKeyCache) shouldRecordUse(keyID string) bool {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if last, ok := c.lastUsed[keyID]; ok && now.Sub(last) < c.lastUsedInterval {
		return false
	}
	c.lastUsed[keyID] = now
	return true
}

func (c *apiKeyCache) invalidate(keyID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, keyID)
}

// sweepLocked drops aged-out entries at most once per TTL, so the maps hold
// only keys used recently.
func (c *apiKeyCache) sweepLocked(now time.Time) {
	if now.Sub(c.lastSweep) < c.ttl {
		return
	}
	c.lastSweep = now
	for id, e := range c.entries {
		if !now.Before(e.until) {
			delete(c.entries, id)
		}
	}
	for id, t := range c.lastUsed {
		if now.Sub(t) >= c.lastUsedInterval {
			delete(c.lastUsed, id)
		}
	}
}

func (m *APIMiddleware) apiKeyCacheFor() *apiKeyCache {
	if m.APIKeyCache == nil {
		return nil
	}
	m.apiKeyCacheOnce.Do(func() {
		m.apiKeyCacheImpl = newAPIKeyCache(m.APIKeyCache)
	})
	return m.apiKeyCacheImpl
}

// InvalidateAPIKey drops keyID from the API key cache, so the next request
// with that key goes to the store. Call it after revoking a key in the same
// process, or a revoked key keeps working until its entry ages out (at most
// APIKeyCacheConfig.TTL). It does nothing when APIKeyCache is nil.
func (m *APIMiddleware) InvalidateAPIKey(keyID string) {
	if c := m.apiKeyCacheFor(); c != nil {
		c.invalidate(keyID)
	}
}

func (m *APIMiddleware) validateAPIKey(ctx context.Context, fullKey string) (*TokenInfo, error) {
	cache := m.apiKeyCacheFor()
	if cache != nil {
		if info, ok := cache.get(fullKey); ok {
			if keyID, _ := apiKeyID(fullKey); cache.shouldRecordUse(keyID) {
				m.recordAPIKeyUse(keyID)
			}
			return info, nil
		}
	}

	validateResp, err := m.APIKeyStore.ValidateAPIKey(ctx, &core.ValidateAPIKeyRequest{FullKey: fullKey})
	if err != nil {
		return nil, fmt.Errorf("invalid API key: %w", err)
	}
	apiKey := validateResp.APIKey

	info := &TokenInfo{Subject: apiKey.Subject, Scopes: apiKey.Scopes, AuthType: "api_key"}
	if apiKey.ExpiresAt != nil {
		info.ExpiresAt = *apiKey.ExpiresAt
	}
	if cache == nil || cache.shouldRecordUse(apiKey.KeyID) {
		m.recordAPIKeyUse(apiKey.KeyID)
	}
	if cache != nil {
		cache.put(fullKey, apiKey, info)
	}
	return info, nil
}

func (m *APIMiddleware) recordAPIKeyUse(keyID string) {
	go func() {
		if _, err := m.APIKeyStore.UpdateAPIKeyLastUsed(context.Background(), &core.UpdateAPIKeyLastUsedRequest{KeyID: keyID}); err != nil {
			log.Printf("Failed to update API key last used: %v", err)
		}
	}()
}
