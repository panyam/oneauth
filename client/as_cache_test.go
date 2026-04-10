package client

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestMemoryASMetadataStorePutGet verifies basic round-trip: Put stores
// metadata, Get returns it within the TTL window. This is the foundation
// for caching AS discovery across multiple consumers.
func TestMemoryASMetadataStorePutGet(t *testing.T) {
	store := NewMemoryASMetadataStore(0) // use default TTL

	md := &ASMetadata{
		Issuer:        "https://auth.example.com",
		TokenEndpoint: "https://auth.example.com/token",
	}
	store.Put("https://auth.example.com", md, 0)

	got, ok := store.Get("https://auth.example.com")
	if !ok {
		t.Fatal("expected cache hit, got miss")
	}
	if got.Issuer != md.Issuer {
		t.Errorf("Issuer mismatch: got %q, want %q", got.Issuer, md.Issuer)
	}
	if got.TokenEndpoint != md.TokenEndpoint {
		t.Errorf("TokenEndpoint mismatch: got %q, want %q", got.TokenEndpoint, md.TokenEndpoint)
	}
}

// TestMemoryASMetadataStoreMiss verifies that Get returns (nil, false) for
// issuers that haven't been Put, ensuring no false positives for cold cache.
func TestMemoryASMetadataStoreMiss(t *testing.T) {
	store := NewMemoryASMetadataStore(0)
	md, ok := store.Get("https://never-cached.example.com")
	if ok {
		t.Error("expected cache miss, got hit")
	}
	if md != nil {
		t.Error("expected nil metadata on miss")
	}
}

// TestMemoryASMetadataStoreExpiry verifies that entries expire after their
// TTL and are evicted on the next Get. This is the lazy eviction contract:
// no background goroutine, expiry happens on access.
func TestMemoryASMetadataStoreExpiry(t *testing.T) {
	store := NewMemoryASMetadataStore(0)

	md := &ASMetadata{Issuer: "https://auth.example.com"}
	store.Put("https://auth.example.com", md, 10*time.Millisecond)

	// Immediate Get should hit
	if _, ok := store.Get("https://auth.example.com"); !ok {
		t.Error("expected immediate hit")
	}

	// Wait for expiry
	time.Sleep(20 * time.Millisecond)

	// Should be a miss (and evicted)
	if _, ok := store.Get("https://auth.example.com"); ok {
		t.Error("expected miss after TTL expiry")
	}
}

// TestMemoryASMetadataStoreDefaultTTL verifies that Put with ttl=0 uses
// the store's default TTL, allowing callers to opt out of per-call TTL.
func TestMemoryASMetadataStoreDefaultTTL(t *testing.T) {
	store := NewMemoryASMetadataStore(50 * time.Millisecond)

	md := &ASMetadata{Issuer: "https://auth.example.com"}
	store.Put("https://auth.example.com", md, 0) // use default

	// Should hit immediately
	if _, ok := store.Get("https://auth.example.com"); !ok {
		t.Error("expected hit with default TTL")
	}

	// Should expire after default TTL
	time.Sleep(100 * time.Millisecond)
	if _, ok := store.Get("https://auth.example.com"); ok {
		t.Error("expected miss after default TTL expiry")
	}
}

// TestDiscoverASUsesCache verifies that DiscoverAS with WithASMetadataStore
// hits the cache on the second call instead of making an HTTP request.
// This is the primary value of the cache: avoiding redundant discovery
// fetches across multiple resource servers sharing one AS.
func TestDiscoverASUsesCache(t *testing.T) {
	var fetchCount atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"issuer":"http://test","token_endpoint":"http://test/token"}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	store := NewMemoryASMetadataStore(0)

	// First call — should fetch
	md1, err := DiscoverAS(ts.URL, WithASMetadataStore(store))
	if err != nil {
		t.Fatalf("first DiscoverAS failed: %v", err)
	}
	if md1.Issuer != "http://test" {
		t.Errorf("unexpected issuer: %q", md1.Issuer)
	}
	if got := fetchCount.Load(); got != 1 {
		t.Errorf("expected 1 fetch after first call, got %d", got)
	}

	// Second call — should hit cache
	md2, err := DiscoverAS(ts.URL, WithASMetadataStore(store))
	if err != nil {
		t.Fatalf("second DiscoverAS failed: %v", err)
	}
	if md2.Issuer != "http://test" {
		t.Errorf("unexpected issuer on second call: %q", md2.Issuer)
	}
	if got := fetchCount.Load(); got != 1 {
		t.Errorf("expected still 1 fetch (cache hit), got %d", got)
	}
}

// TestDiscoverASCacheMissOnExpiry verifies that expired cache entries
// trigger a fresh HTTP fetch, ensuring stale metadata doesn't persist
// beyond its TTL.
func TestDiscoverASCacheMissOnExpiry(t *testing.T) {
	var fetchCount atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"issuer":"http://test","token_endpoint":"http://test/token"}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	store := NewMemoryASMetadataStore(10 * time.Millisecond)

	// First call fetches and caches
	_, err := DiscoverAS(ts.URL, WithASMetadataStore(store))
	if err != nil {
		t.Fatalf("first DiscoverAS failed: %v", err)
	}
	if got := fetchCount.Load(); got != 1 {
		t.Errorf("expected 1 fetch, got %d", got)
	}

	// Wait for cache expiry
	time.Sleep(20 * time.Millisecond)

	// Second call should fetch again (cache expired)
	_, err = DiscoverAS(ts.URL, WithASMetadataStore(store))
	if err != nil {
		t.Fatalf("second DiscoverAS failed: %v", err)
	}
	if got := fetchCount.Load(); got != 2 {
		t.Errorf("expected 2 fetches after expiry, got %d", got)
	}
}

// TestDiscoverASNoCache verifies that DiscoverAS without a store continues
// to fetch on every call, preserving backward compatibility for callers
// that don't opt into caching.
func TestDiscoverASNoCache(t *testing.T) {
	var fetchCount atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"issuer":"http://test","token_endpoint":"http://test/token"}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	_, _ = DiscoverAS(ts.URL)
	_, _ = DiscoverAS(ts.URL)
	_, _ = DiscoverAS(ts.URL)

	if got := fetchCount.Load(); got != 3 {
		t.Errorf("expected 3 fetches without cache, got %d", got)
	}
}
