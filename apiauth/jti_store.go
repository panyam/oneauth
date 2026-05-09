package apiauth

import (
	"sync"
	"time"
)

// JTIStore tracks JWT IDs (the `jti` claim) of recently-validated client
// assertions to prevent replay (RFC 7523 §3 item 7, OIDC Core §10.1).
//
// The store has at-most-once semantics: SeenWithin(jti, ttl) returns
// true if `jti` has been seen within the lifetime, false otherwise. The
// caller atomically marks `jti` as seen on the false branch.
//
// Implementations must be goroutine-safe.
type JTIStore interface {
	// SeenWithin reports whether `jti` was already marked seen within
	// the given lifetime. When false is returned the implementation
	// MUST also record `jti` as seen for at least `lifetime`. Single
	// call, atomic check-and-set — callers do not invoke a separate
	// Mark method.
	SeenWithin(jti string, lifetime time.Duration) bool
}

// inMemoryJTIStore is a TTL-based, goroutine-safe JTIStore. Suitable
// for single-process deployments. For multi-node deployments wire a
// distributed implementation (Redis SETNX with EX, etc.) — the
// interface is intentionally narrow so swap-in is one method.
//
// Memory bound: O(N * peak-assertion-rate * max-lifetime). Client
// assertion lifetimes are short (RFC recommends <=60s), so this is
// small in practice. A background sweep amortizes cleanup across
// SeenWithin calls; no goroutine is started.
type inMemoryJTIStore struct {
	mu      sync.Mutex
	entries map[string]time.Time // jti → expiry
	lastGC  time.Time
}

// NewInMemoryJTIStore returns an in-memory JTIStore backed by a map
// with lazy eviction. Safe default for single-process deployments.
func NewInMemoryJTIStore() JTIStore {
	return &inMemoryJTIStore{entries: make(map[string]time.Time)}
}

// gcInterval bounds how often we sweep expired entries. Set so that
// even under steady high-throughput auth the sweep cost is negligible.
const jtiGCInterval = 30 * time.Second

func (s *inMemoryJTIStore) SeenWithin(jti string, lifetime time.Duration) bool {
	if jti == "" {
		// Defensive: empty jti is the caller's bug, but treat as "not
		// seen" so we don't admit a same-empty-jti pair as duplicates.
		return false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	if exp, ok := s.entries[jti]; ok && exp.After(now) {
		return true
	}

	s.entries[jti] = now.Add(lifetime)

	if now.Sub(s.lastGC) >= jtiGCInterval {
		for k, exp := range s.entries {
			if !exp.After(now) {
				delete(s.entries, k)
			}
		}
		s.lastGC = now
	}
	return false
}
