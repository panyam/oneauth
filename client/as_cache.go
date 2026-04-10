package client

import (
	"sync"
	"time"
)

// DefaultASCacheTTL is the default time-to-live for cached AS metadata entries.
// AS metadata changes rarely (endpoint rotations, scope additions), so a 1-hour
// TTL balances freshness against redundant HTTP fetches.
const DefaultASCacheTTL = 1 * time.Hour

// ASMetadataStore caches OAuth Authorization Server metadata by issuer URL.
// Implementations must be safe for concurrent use by multiple goroutines.
//
// A store is typically shared across multiple [OAuthTokenSource] instances in
// the same process, so that N resource servers sharing one AS only trigger one
// discovery fetch instead of N.
//
// The store is a hot-path optimization: discovery is cheap (one HTTP fetch) but
// redundant across concurrent token sources. Callers opt in by passing a store
// to [WithASMetadataStore].
type ASMetadataStore interface {
	// Get returns the cached metadata for an issuer if present and not expired.
	// Returns (nil, false) on cache miss or expiry.
	Get(issuer string) (*ASMetadata, bool)

	// Put stores metadata for an issuer with the given TTL. A TTL of 0 means
	// use the store's default. Put replaces any existing entry for the issuer.
	Put(issuer string, md *ASMetadata, ttl time.Duration)
}

// MemoryASMetadataStore is an in-memory [ASMetadataStore] backed by a
// sync.RWMutex-protected map. Suitable for single-process deployments where
// all token sources run in the same binary.
//
// Entries expire lazily on Get — there is no background eviction goroutine.
// Expired entries stay in the map until a Get or Put touches them, which
// is fine for bounded-size workloads (one entry per unique issuer URL).
type MemoryASMetadataStore struct {
	mu         sync.RWMutex
	cache      map[string]*cachedAS
	defaultTTL time.Duration
}

// cachedAS wraps metadata with an expiry time for lazy TTL eviction.
type cachedAS struct {
	md     *ASMetadata
	expiry time.Time
}

// NewMemoryASMetadataStore creates a new in-memory AS metadata store.
// If defaultTTL is 0, [DefaultASCacheTTL] is used.
func NewMemoryASMetadataStore(defaultTTL time.Duration) *MemoryASMetadataStore {
	if defaultTTL <= 0 {
		defaultTTL = DefaultASCacheTTL
	}
	return &MemoryASMetadataStore{
		cache:      make(map[string]*cachedAS),
		defaultTTL: defaultTTL,
	}
}

// Get returns cached metadata for an issuer if present and not expired.
// Expired entries are removed lazily on access.
func (s *MemoryASMetadataStore) Get(issuer string) (*ASMetadata, bool) {
	s.mu.RLock()
	entry, ok := s.cache[issuer]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiry) {
		// Expired — remove and return miss
		s.mu.Lock()
		delete(s.cache, issuer)
		s.mu.Unlock()
		return nil, false
	}
	return entry.md, true
}

// Put stores metadata for an issuer with the given TTL. If ttl is 0, the
// store's default TTL is used.
func (s *MemoryASMetadataStore) Put(issuer string, md *ASMetadata, ttl time.Duration) {
	if ttl <= 0 {
		ttl = s.defaultTTL
	}
	s.mu.Lock()
	s.cache[issuer] = &cachedAS{
		md:     md,
		expiry: time.Now().Add(ttl),
	}
	s.mu.Unlock()
}

// Compile-time interface compliance check.
var _ ASMetadataStore = (*MemoryASMetadataStore)(nil)
