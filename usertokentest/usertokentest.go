// Package usertokentest is the shared contract suite for
// outbound.UserTokenStore. Each backend runs RunAll with a factory that
// returns a fresh, empty store.
package usertokentest

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/panyam/oneauth/outbound"
)

// Factory returns a fresh, empty store for one subtest.
type Factory func(t *testing.T) outbound.UserTokenStore

// RunAll runs every contract test against factory.
func RunAll(t *testing.T, factory Factory) {
	t.Run("GetMissing", func(t *testing.T) { TestGetMissing(t, factory) })
	t.Run("CreateThenGet", func(t *testing.T) { TestCreateThenGet(t, factory) })
	t.Run("CreateWhenPresentConflicts", func(t *testing.T) { TestCreateWhenPresentConflicts(t, factory) })
	t.Run("UpdateNeedsCurrentVersion", func(t *testing.T) { TestUpdateNeedsCurrentVersion(t, factory) })
	t.Run("UpdateMissingConflicts", func(t *testing.T) { TestUpdateMissingConflicts(t, factory) })
	t.Run("KeysAreIndependent", func(t *testing.T) { TestKeysAreIndependent(t, factory) })
	t.Run("DeleteIsIdempotent", func(t *testing.T) { TestDeleteIsIdempotent(t, factory) })
	t.Run("ConcurrentWritersOneWins", func(t *testing.T) { TestConcurrentWritersOneWins(t, factory) })
}

func put(t *testing.T, s outbound.UserTokenStore, provider, subject string, sealed []byte, expected int64) (int64, error) {
	t.Helper()
	resp, err := s.PutUserToken(context.Background(), &outbound.PutUserTokenRequest{Provider: provider, Subject: subject, Sealed: sealed, ExpectedVersion: expected})
	if err != nil {
		return 0, err
	}
	return resp.Version, nil
}

func get(t *testing.T, s outbound.UserTokenStore, provider, subject string) (*outbound.UserTokenRecord, error) {
	t.Helper()
	resp, err := s.GetUserToken(context.Background(), &outbound.GetUserTokenRequest{Provider: provider, Subject: subject})
	if err != nil {
		return nil, err
	}
	return resp.Record, nil
}

// TestGetMissing: no record is ErrUserTokenNotFound.
func TestGetMissing(t *testing.T, factory Factory) {
	if _, err := get(t, factory(t), "github", "nobody"); !errors.Is(err, outbound.ErrUserTokenNotFound) {
		t.Fatalf("want ErrUserTokenNotFound, got %v", err)
	}
}

// TestCreateThenGet: a create is version 1 and reads back byte for byte.
func TestCreateThenGet(t *testing.T, factory Factory) {
	s := factory(t)
	v, err := put(t, s, "github", "alice", []byte("sealed-1"), 0)
	if err != nil || v != 1 {
		t.Fatalf("create: v=%d err=%v", v, err)
	}
	rec, err := get(t, s, "github", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Provider != "github" || rec.Subject != "alice" || rec.Version != 1 || !bytes.Equal(rec.Sealed, []byte("sealed-1")) || rec.UpdatedAt.IsZero() {
		t.Fatalf("read back %+v", rec)
	}
}

// TestCreateWhenPresentConflicts: ExpectedVersion 0 means create only.
func TestCreateWhenPresentConflicts(t *testing.T, factory Factory) {
	s := factory(t)
	if _, err := put(t, s, "github", "alice", []byte("a"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := put(t, s, "github", "alice", []byte("b"), 0); !errors.Is(err, outbound.ErrVersionConflict) {
		t.Fatalf("want ErrVersionConflict, got %v", err)
	}
	if rec, _ := get(t, s, "github", "alice"); string(rec.Sealed) != "a" {
		t.Fatalf("losing write changed the record: %q", rec.Sealed)
	}
}

// TestUpdateNeedsCurrentVersion: a stale version is refused, the current
// one is accepted and bumps the version.
func TestUpdateNeedsCurrentVersion(t *testing.T, factory Factory) {
	s := factory(t)
	if _, err := put(t, s, "github", "alice", []byte("a"), 0); err != nil {
		t.Fatal(err)
	}
	v, err := put(t, s, "github", "alice", []byte("b"), 1)
	if err != nil || v != 2 {
		t.Fatalf("update: v=%d err=%v", v, err)
	}
	if _, err := put(t, s, "github", "alice", []byte("c"), 1); !errors.Is(err, outbound.ErrVersionConflict) {
		t.Fatalf("stale version: %v", err)
	}
	if rec, _ := get(t, s, "github", "alice"); string(rec.Sealed) != "b" || rec.Version != 2 {
		t.Fatalf("record after stale write: %+v", rec)
	}
}

// TestUpdateMissingConflicts: a non-zero version on a missing record is a
// conflict, not a create, so a deleted record isn't revived by a refresh.
func TestUpdateMissingConflicts(t *testing.T, factory Factory) {
	if _, err := put(t, factory(t), "github", "alice", []byte("a"), 3); !errors.Is(err, outbound.ErrVersionConflict) {
		t.Fatalf("want ErrVersionConflict, got %v", err)
	}
}

// TestKeysAreIndependent: provider and subject together are the key,
// including subjects that differ only in characters a file name loses.
func TestKeysAreIndependent(t *testing.T, factory Factory) {
	s := factory(t)
	for _, k := range [][2]string{{"github", "a/b"}, {"github", "a_b"}, {"github", "a:b"}, {"gitlab", "a/b"}} {
		if _, err := put(t, s, k[0], k[1], []byte(k[0]+"|"+k[1]), 0); err != nil {
			t.Fatalf("put %v: %v", k, err)
		}
	}
	for _, k := range [][2]string{{"github", "a/b"}, {"github", "a_b"}, {"github", "a:b"}, {"gitlab", "a/b"}} {
		rec, err := get(t, s, k[0], k[1])
		if err != nil || string(rec.Sealed) != k[0]+"|"+k[1] {
			t.Fatalf("get %v: %v %v", k, rec, err)
		}
	}
}

// TestDeleteIsIdempotent: delete removes the record and a second delete
// succeeds. A create after delete starts at version 1 again.
func TestDeleteIsIdempotent(t *testing.T, factory Factory) {
	s := factory(t)
	ctx := context.Background()
	if _, err := put(t, s, "github", "alice", []byte("a"), 0); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := s.DeleteUserToken(ctx, &outbound.DeleteUserTokenRequest{Provider: "github", Subject: "alice"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := get(t, s, "github", "alice"); !errors.Is(err, outbound.ErrUserTokenNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if v, err := put(t, s, "github", "alice", []byte("b"), 0); err != nil || v != 1 {
		t.Fatalf("recreate: v=%d err=%v", v, err)
	}
}

// TestConcurrentWritersOneWins: writers racing from the same version
// produce exactly one success, which is the refresh-race guarantee
// StoredUserToken relies on.
func TestConcurrentWritersOneWins(t *testing.T, factory Factory) {
	s := factory(t)
	if _, err := put(t, s, "github", "alice", []byte("v1"), 0); err != nil {
		t.Fatal(err)
	}
	var wins, conflicts atomic.Int32
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.PutUserToken(context.Background(), &outbound.PutUserTokenRequest{Provider: "github", Subject: "alice", Sealed: []byte{byte(i)}, ExpectedVersion: 1})
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, outbound.ErrVersionConflict):
				conflicts.Add(1)
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || conflicts.Load() != 15 {
		t.Fatalf("wins=%d conflicts=%d, want 1 and 15", wins.Load(), conflicts.Load())
	}
}
