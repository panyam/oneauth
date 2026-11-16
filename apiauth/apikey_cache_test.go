package apiauth_test

// The API key cache in APIMiddleware: a cached key skips the store's bcrypt
// compare, an entry never outlives the key's own expiry, a revoked key is
// refused within the documented bound (TTL, or at once after
// InvalidateAPIKey), and last-used writes are throttled per key.
//
// See: https://cwe.mitre.org/data/definitions/613.html
// See: https://github.com/panyam/oneauth/issues/462

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/stores/fs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// countingKeyStore is an in-memory API key store on the test clock. It counts
// ValidateAPIKey calls and reports each last-used write on a channel.
type countingKeyStore struct {
	core.APIKeyStore
	clock *fakeClock

	mu      sync.Mutex
	keys    map[string]*core.APIKey
	secrets map[string]string

	validations atomic.Int32
	lastUsed    chan string
}

func newCountingKeyStore(clock *fakeClock) *countingKeyStore {
	return &countingKeyStore{
		clock:    clock,
		keys:     map[string]*core.APIKey{},
		secrets:  map[string]string{},
		lastUsed: make(chan string, 1024),
	}
}

func (s *countingKeyStore) add(id, secret string, expiresAt *time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	keyID := "oa_" + id
	s.keys[keyID] = &core.APIKey{KeyID: keyID, Subject: "alice", Scopes: []string{"read"}, ExpiresAt: expiresAt}
	s.secrets[keyID] = secret
	return keyID + "_" + secret
}

func (s *countingKeyStore) ValidateAPIKey(_ context.Context, req *core.ValidateAPIKeyRequest) (*core.ValidateAPIKeyResponse, error) {
	s.validations.Add(1)
	parts := strings.SplitN(req.FullKey, "_", 3)
	if len(parts) != 3 {
		return nil, core.ErrAPIKeyNotFound
	}
	keyID := parts[0] + "_" + parts[1]
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyID]
	switch {
	case !ok || s.secrets[keyID] != parts[2]:
		return nil, core.ErrAPIKeyNotFound
	case k.Revoked:
		return nil, core.ErrTokenRevoked
	case k.ExpiresAt != nil && !s.clock.Now().Before(*k.ExpiresAt):
		return nil, core.ErrTokenExpired
	}
	cp := *k
	return &core.ValidateAPIKeyResponse{APIKey: &cp}, nil
}

func (s *countingKeyStore) RevokeAPIKey(_ context.Context, req *core.RevokeAPIKeyRequest) (*core.RevokeAPIKeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[req.KeyID].Revoked = true
	return &core.RevokeAPIKeyResponse{}, nil
}

func (s *countingKeyStore) UpdateAPIKeyLastUsed(_ context.Context, req *core.UpdateAPIKeyLastUsedRequest) (*core.UpdateAPIKeyLastUsedResponse, error) {
	s.lastUsed <- req.KeyID
	return &core.UpdateAPIKeyLastUsedResponse{}, nil
}

// waitLastUsed waits for exactly n last-used writes, then checks no more
// arrive shortly after.
func (s *countingKeyStore) waitLastUsed(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-s.lastUsed:
		case <-time.After(2 * time.Second):
			t.Fatalf("got %d last-used writes, want %d", i, n)
		}
	}
	select {
	case id := <-s.lastUsed:
		t.Fatalf("unexpected extra last-used write for %s (want %d)", id, n)
	case <-time.After(50 * time.Millisecond):
	}
}

func cachedMiddleware(store core.APIKeyStore, clock *fakeClock) *apiauth.APIMiddleware {
	return &apiauth.APIMiddleware{
		APIKeyStore: store,
		APIKeyCache: &apiauth.APIKeyCacheConfig{TTL: time.Minute, LastUsedInterval: time.Minute, Now: clock.Now},
	}
}

func validateKey(mw *apiauth.APIMiddleware, key string) (*apiauth.TokenInfo, error) {
	resp, err := mw.ValidateBearer(context.Background(), &apiauth.ValidateBearerRequest{Token: key})
	if err != nil {
		return nil, err
	}
	return resp.Info, nil
}

func TestAPIKeyCache_HitSkipsStore(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newCountingKeyStore(clock)
	key := store.add("k1", "s3cret", nil)
	mw := cachedMiddleware(store, clock)

	for i := 0; i < 5; i++ {
		info, err := validateKey(mw, key)
		require.NoError(t, err)
		assert.Equal(t, "alice", info.Subject)
		assert.Equal(t, []string{"read"}, info.Scopes)
		assert.Equal(t, "api_key", info.AuthType)
	}
	assert.Equal(t, int32(1), store.validations.Load())
	store.waitLastUsed(t, 1)
}

func TestAPIKeyCache_NilConfigValidatesEveryCall(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newCountingKeyStore(clock)
	key := store.add("k1", "s3cret", nil)
	mw := &apiauth.APIMiddleware{APIKeyStore: store}

	for i := 0; i < 3; i++ {
		_, err := validateKey(mw, key)
		require.NoError(t, err)
	}
	assert.Equal(t, int32(3), store.validations.Load())
	store.waitLastUsed(t, 3)
}

func TestAPIKeyCache_RefusesKeyExpiredWhileCached(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newCountingKeyStore(clock)
	exp := clock.Now().Add(10 * time.Second)
	key := store.add("k1", "s3cret", &exp)
	mw := cachedMiddleware(store, clock)

	_, err := validateKey(mw, key)
	require.NoError(t, err)

	clock.Advance(10 * time.Second)
	_, err = validateKey(mw, key)
	require.Error(t, err)
	assert.ErrorIs(t, err, core.ErrTokenExpired)
}

func TestAPIKeyCache_RevokedKeyRefusedAfterTTL(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newCountingKeyStore(clock)
	key := store.add("k1", "s3cret", nil)
	mw := cachedMiddleware(store, clock)

	_, err := validateKey(mw, key)
	require.NoError(t, err)
	_, err = store.RevokeAPIKey(context.Background(), &core.RevokeAPIKeyRequest{KeyID: "oa_k1"})
	require.NoError(t, err)

	clock.Advance(59 * time.Second)
	_, err = validateKey(mw, key)
	require.NoError(t, err, "within TTL the cached entry still answers; that is the documented bound")

	clock.Advance(time.Second)
	_, err = validateKey(mw, key)
	require.Error(t, err)
	assert.ErrorIs(t, err, core.ErrTokenRevoked)
}

func TestAPIKeyCache_InvalidateRefusesRevokedKeyAtOnce(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newCountingKeyStore(clock)
	key := store.add("k1", "s3cret", nil)
	mw := cachedMiddleware(store, clock)

	_, err := validateKey(mw, key)
	require.NoError(t, err)
	_, err = store.RevokeAPIKey(context.Background(), &core.RevokeAPIKeyRequest{KeyID: "oa_k1"})
	require.NoError(t, err)
	mw.InvalidateAPIKey("oa_k1")

	_, err = validateKey(mw, key)
	require.Error(t, err)
	assert.ErrorIs(t, err, core.ErrTokenRevoked)
}

func TestAPIKeyCache_WrongSecretForCachedIDGoesToStore(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newCountingKeyStore(clock)
	key := store.add("k1", "s3cret", nil)
	mw := cachedMiddleware(store, clock)

	_, err := validateKey(mw, key)
	require.NoError(t, err)

	_, err = validateKey(mw, "oa_k1_guess")
	require.Error(t, err)
	assert.Equal(t, int32(2), store.validations.Load())

	_, err = validateKey(mw, key)
	require.NoError(t, err, "a failed guess must not evict the good entry")
	assert.Equal(t, int32(2), store.validations.Load())
}

func TestAPIKeyCache_LastUsedThrottledPerKey(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newCountingKeyStore(clock)
	k1 := store.add("k1", "s3cret", nil)
	k2 := store.add("k2", "s3cret", nil)
	mw := &apiauth.APIMiddleware{
		APIKeyStore: store,
		APIKeyCache: &apiauth.APIKeyCacheConfig{TTL: time.Minute, LastUsedInterval: 5 * time.Minute, Now: clock.Now},
	}

	for i := 0; i < 10; i++ {
		_, err := validateKey(mw, k1)
		require.NoError(t, err)
		_, err = validateKey(mw, k2)
		require.NoError(t, err)
	}
	store.waitLastUsed(t, 2)

	// The entry ages out and the key revalidates, but last use is still
	// inside its interval, so no write.
	clock.Advance(2 * time.Minute)
	_, err := validateKey(mw, k1)
	require.NoError(t, err)
	store.waitLastUsed(t, 0)

	clock.Advance(3 * time.Minute)
	_, err = validateKey(mw, k1)
	require.NoError(t, err)
	store.waitLastUsed(t, 1)
}

func TestAPIKeyCache_Concurrent(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newCountingKeyStore(clock)
	key := store.add("k1", "s3cret", nil)
	mw := cachedMiddleware(store, clock)

	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if _, err := validateKey(mw, key); err != nil {
					t.Error(err)
					return
				}
				if i%10 == 0 {
					mw.InvalidateAPIKey("oa_k1")
				}
			}
		}()
	}
	wg.Wait()
	assert.Less(t, store.validations.Load(), int32(20*50))
}

// BenchmarkAPIKey compares a cached call with an uncached one against the FS
// store, whose ValidateAPIKey runs bcrypt at the default cost.
func BenchmarkAPIKey(b *testing.B) {
	for _, tc := range []struct {
		name  string
		cache *apiauth.APIKeyCacheConfig
	}{
		{"Uncached", nil},
		{"Cached", &apiauth.APIKeyCacheConfig{}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			store := fs.NewFSAPIKeyStore(b.TempDir())
			created, err := store.CreateAPIKey(context.Background(), &core.CreateAPIKeyRequest{Subject: "alice", Name: "bench"})
			require.NoError(b, err)
			mw := &apiauth.APIMiddleware{APIKeyStore: store, APIKeyCache: tc.cache}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := validateKey(mw, created.FullKey); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			time.Sleep(50 * time.Millisecond) // let the last-used goroutines finish before TempDir removal
		})
	}
}
