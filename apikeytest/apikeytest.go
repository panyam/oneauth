// Package apikeytest is the shared contract suite for core.APIKeyAdmin,
// the optional interface for listing every API key and deleting the
// expired ones. Each backend runs RunAdmin with a factory that returns a
// fresh, empty store.
package apikeytest

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/panyam/oneauth/core"
)

// Store is an APIKeyStore that also implements APIKeyAdmin.
type Store interface {
	core.APIKeyStore
	core.APIKeyAdmin
}

// Backend is one fresh, empty store. Reopen returns a second handle on the
// same data, the way another process would see it. For fs that's a store
// with its own mutex on the same directory.
type Backend struct {
	Store  Store
	Reopen func() Store
}

// Factory returns a fresh, empty backend for one subtest.
type Factory func(t *testing.T) Backend

// RunAdmin runs every APIKeyAdmin contract test against factory.
func RunAdmin(t *testing.T, factory Factory) {
	t.Run("ListEmpty", func(t *testing.T) { TestListEmpty(t, factory) })
	t.Run("ListEverySubjectWithoutHashes", func(t *testing.T) { TestListEverySubjectWithoutHashes(t, factory) })
	t.Run("CleanupDeletesExpiredRevokedOrNot", func(t *testing.T) { TestCleanupDeletesExpiredRevokedOrNot(t, factory) })
	t.Run("CleanupHonorsNow", func(t *testing.T) { TestCleanupHonorsNow(t, factory) })
	t.Run("CleanupIsRepeatable", func(t *testing.T) { TestCleanupIsRepeatable(t, factory) })
	t.Run("ListDuringCleanup", func(t *testing.T) { TestListDuringCleanup(t, factory) })
}

func create(t *testing.T, s core.APIKeyStore, subject string, expiresAt *time.Time) string {
	t.Helper()
	resp, err := s.CreateAPIKey(context.Background(), &core.CreateAPIKeyRequest{Subject: subject, Name: "k", ExpiresAt: expiresAt})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	return resp.APIKey.KeyID
}

func revoke(t *testing.T, s core.APIKeyStore, keyID string) {
	t.Helper()
	if _, err := s.RevokeAPIKey(context.Background(), &core.RevokeAPIKeyRequest{KeyID: keyID}); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
}

func list(t *testing.T, s core.APIKeyAdmin) []*core.APIKey {
	t.Helper()
	resp, err := s.ListAPIKeys(context.Background(), &core.ListAPIKeysRequest{})
	if err != nil {
		t.Fatalf("ListAPIKeys: %v", err)
	}
	return resp.APIKeys
}

func listIDs(t *testing.T, s core.APIKeyAdmin) []string {
	t.Helper()
	var ids []string
	for _, k := range list(t, s) {
		ids = append(ids, k.KeyID)
	}
	sort.Strings(ids)
	return ids
}

func cleanup(t *testing.T, s core.APIKeyAdmin, now time.Time) int {
	t.Helper()
	resp, err := s.CleanupExpiredAPIKeys(context.Background(), &core.CleanupExpiredAPIKeysRequest{Now: now})
	if err != nil {
		t.Fatalf("CleanupExpiredAPIKeys: %v", err)
	}
	return resp.Removed
}

func sorted(ids ...string) []string {
	sort.Strings(ids)
	return ids
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func at(t time.Time) *time.Time { return &t }

// TestListEmpty: an empty store lists no keys and no error.
func TestListEmpty(t *testing.T, factory Factory) {
	if got := list(t, factory(t).Store); len(got) != 0 {
		t.Fatalf("want no keys, got %d", len(got))
	}
}

// TestListEverySubjectWithoutHashes: the listing covers every subject,
// and no listed key carries its bcrypt hash.
func TestListEverySubjectWithoutHashes(t *testing.T, factory Factory) {
	s := factory(t).Store
	a := create(t, s, "alice", nil)
	b := create(t, s, "bob", at(time.Now().Add(time.Hour)))
	keys := list(t, s)
	var ids []string
	for _, k := range keys {
		if k.KeyHash != "" {
			t.Errorf("key %s listed with its hash", k.KeyID)
		}
		ids = append(ids, k.KeyID)
	}
	sort.Strings(ids)
	if want := sorted(a, b); !equal(ids, want) {
		t.Fatalf("want %v, got %v", want, ids)
	}
}

// TestCleanupDeletesExpiredRevokedOrNot: cleanup deletes every expired
// key, revoked or not, and keeps live keys and keys with no expiry, even
// a revoked one.
func TestCleanupDeletesExpiredRevokedOrNot(t *testing.T, factory Factory) {
	s := factory(t).Store
	now := time.Now()
	noExpiry := create(t, s, "alice", nil)
	noExpiryRevoked := create(t, s, "alice", nil)
	revoke(t, s, noExpiryRevoked)
	live := create(t, s, "alice", at(now.Add(time.Hour)))
	expired := create(t, s, "bob", at(now.Add(-time.Hour)))
	expiredRevoked := create(t, s, "bob", at(now.Add(-time.Hour)))
	revoke(t, s, expiredRevoked)

	if n := cleanup(t, s, now); n != 2 {
		t.Errorf("want 2 removed, got %d", n)
	}
	if got, want := listIDs(t, s), sorted(noExpiry, noExpiryRevoked, live); !equal(got, want) {
		t.Fatalf("want %v left, got %v", want, got)
	}
	for _, id := range []string{expired, expiredRevoked} {
		if _, err := s.GetAPIKeyByID(context.Background(), &core.GetAPIKeyByIDRequest{KeyID: id}); err == nil {
			t.Errorf("key %s still readable after cleanup", id)
		}
	}
}

// TestCleanupHonorsNow: cleanup measures expiry against req.Now, not the
// wall clock, and a key expiring exactly at Now is expired.
func TestCleanupHonorsNow(t *testing.T, factory Factory) {
	s := factory(t).Store
	// Datastore and Postgres keep microseconds; truncate so "exactly at
	// Now" survives the round trip.
	edge := time.Now().Add(time.Hour).Truncate(time.Millisecond)
	later := create(t, s, "alice", at(edge.Add(time.Hour)))
	atEdge := create(t, s, "alice", at(edge))
	if n := cleanup(t, s, edge.Add(-time.Minute)); n != 0 {
		t.Fatalf("want 0 removed before either expiry, got %d", n)
	}
	if n := cleanup(t, s, edge); n != 1 {
		t.Fatalf("want 1 removed at the edge, got %d", n)
	}
	if got := listIDs(t, s); !equal(got, []string{later}) {
		t.Fatalf("want only %s left (removed %s), got %v", later, atEdge, got)
	}
}

// TestCleanupIsRepeatable: a second cleanup at the same Now removes 0.
func TestCleanupIsRepeatable(t *testing.T, factory Factory) {
	s := factory(t).Store
	now := time.Now()
	create(t, s, "alice", at(now.Add(-time.Hour)))
	if n := cleanup(t, s, now); n != 1 {
		t.Fatalf("first cleanup: want 1, got %d", n)
	}
	if n := cleanup(t, s, now); n != 0 {
		t.Fatalf("second cleanup: want 0, got %d", n)
	}
}

// TestListDuringCleanup: a cleanup on one handle deletes keys while
// another handle lists. No listing fails, and none returns a deleted key
// half-read. Agni hit an error here on fs (agni issue 1796).
func TestListDuringCleanup(t *testing.T, factory Factory) {
	b := factory(t)
	now := time.Now()
	keep := create(t, b.Store, "alice", nil)
	for i := 0; i < 20; i++ {
		create(t, b.Store, "bob", at(now.Add(-time.Hour)))
	}
	other := b.Reopen()

	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, 64)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 10; j++ {
				resp, err := b.Store.ListAPIKeys(context.Background(), &core.ListAPIKeysRequest{})
				if err != nil {
					errs <- err
					return
				}
				for _, k := range resp.APIKeys {
					if k.KeyID == "" {
						errs <- errEmptyKey
						return
					}
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		if _, err := other.CleanupExpiredAPIKeys(context.Background(), &core.CleanupExpiredAPIKeysRequest{Now: now}); err != nil {
			errs <- err
		}
	}()
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent call failed: %v", err)
	}
	if got := listIDs(t, b.Store); !equal(got, []string{keep}) {
		t.Fatalf("want only %s left, got %v", keep, got)
	}
}

type suiteError string

func (e suiteError) Error() string { return string(e) }

const errEmptyKey = suiteError("listing returned a key with no KeyID")
