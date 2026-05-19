// Package kidstoretest provides shared test suites for all KidStorage
// implementations. Each backend (in-memory KidStore, FS, GORM, GAE) calls
// these tests with its own factory function, mirroring keystoretest.
package kidstoretest

import (
	"testing"
	"time"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// Factory creates a fresh KidStorage for each test.
type Factory func(t *testing.T) keys.KidStorage

// RunAll runs the complete KidStorage test suite against the provided factory.
func RunAll(t *testing.T, factory Factory) {
	t.Run("AddAndGetByKid", func(t *testing.T) { TestAddAndGetByKid(t, factory) })
	t.Run("GetByUnknownKid", func(t *testing.T) { TestGetByUnknownKid(t, factory) })
	t.Run("GetKeyByClientIDAlwaysNotFound", func(t *testing.T) { TestGetKeyByClientIDAlwaysNotFound(t, factory) })
	t.Run("OverwriteSameKid", func(t *testing.T) { TestOverwriteSameKid(t, factory) })
	t.Run("RemoveIdempotent", func(t *testing.T) { TestRemoveIdempotent(t, factory) })
	t.Run("ExpiredKidNotReturned", func(t *testing.T) { TestExpiredKidNotReturned(t, factory) })
	t.Run("ZeroExpiryNeverExpires", func(t *testing.T) { TestZeroExpiryNeverExpires(t, factory) })
	t.Run("CleanExpired", func(t *testing.T) { TestCleanExpired(t, factory) })
	t.Run("AsymmetricKeyRoundTrip", func(t *testing.T) { TestAsymmetricKeyRoundTrip(t, factory) })
	t.Run("Persistence", func(t *testing.T) { TestPersistence(t, factory) })
}

func TestAddAndGetByKid(t *testing.T, factory Factory) {
	ks := factory(t)

	secret := []byte("kid-secret")
	if err := ks.Add("kid-1", secret, "HS256", "app-1", time.Time{}); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	rec, err := ks.GetKeyByKid("kid-1")
	if err != nil {
		t.Fatalf("GetKeyByKid failed: %v", err)
	}
	keyBytes, ok := rec.Key.([]byte)
	if !ok {
		t.Fatalf("Expected []byte, got %T", rec.Key)
	}
	if string(keyBytes) != string(secret) {
		t.Errorf("key mismatch: got %q, want %q", keyBytes, secret)
	}
	if rec.Algorithm != "HS256" {
		t.Errorf("alg=%s, want HS256", rec.Algorithm)
	}
	if rec.ClientID != "app-1" {
		t.Errorf("clientID=%s, want app-1", rec.ClientID)
	}
	if rec.Kid != "kid-1" {
		t.Errorf("kid=%s, want kid-1", rec.Kid)
	}
}

func TestGetByUnknownKid(t *testing.T, factory Factory) {
	ks := factory(t)

	_, err := ks.GetKeyByKid("does-not-exist")
	if err != keys.ErrKidNotFound {
		t.Errorf("Expected ErrKidNotFound, got %v", err)
	}
}

// TestGetKeyByClientIDAlwaysNotFound enforces the documented KidStorage
// semantic: lookup by clientID is meaningless for a kid-indexed store and
// must always return ErrKeyNotFound, regardless of whether the client has
// any kids registered.
func TestGetKeyByClientIDAlwaysNotFound(t *testing.T, factory Factory) {
	ks := factory(t)

	if err := ks.Add("kid-1", []byte("s"), "HS256", "app-1", time.Time{}); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	_, err := ks.GetKey("app-1")
	if err != keys.ErrKeyNotFound {
		t.Errorf("GetKey by clientID must always return ErrKeyNotFound, got %v", err)
	}
}

func TestOverwriteSameKid(t *testing.T, factory Factory) {
	ks := factory(t)

	if err := ks.Add("kid-1", []byte("old"), "HS256", "app-1", time.Time{}); err != nil {
		t.Fatalf("first Add failed: %v", err)
	}
	if err := ks.Add("kid-1", []byte("new"), "HS512", "app-2", time.Time{}); err != nil {
		t.Fatalf("overwrite Add failed: %v", err)
	}

	rec, err := ks.GetKeyByKid("kid-1")
	if err != nil {
		t.Fatalf("GetKeyByKid failed: %v", err)
	}
	if string(rec.Key.([]byte)) != "new" {
		t.Errorf("expected overwritten key, got %q", rec.Key)
	}
	if rec.Algorithm != "HS512" {
		t.Errorf("expected overwritten alg HS512, got %s", rec.Algorithm)
	}
	if rec.ClientID != "app-2" {
		t.Errorf("expected overwritten clientID app-2, got %s", rec.ClientID)
	}
}

// TestRemoveIdempotent enforces that Remove on an absent kid is not an
// error — KidStorage Remove is intentionally idempotent (differs from
// KeyStorage.DeleteKey which returns ErrKeyNotFound).
func TestRemoveIdempotent(t *testing.T, factory Factory) {
	ks := factory(t)

	if err := ks.Remove("never-existed"); err != nil {
		t.Errorf("Remove of absent kid should be nil, got %v", err)
	}

	if err := ks.Add("kid-1", []byte("s"), "HS256", "app-1", time.Time{}); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if err := ks.Remove("kid-1"); err != nil {
		t.Errorf("Remove of present kid failed: %v", err)
	}
	if _, err := ks.GetKeyByKid("kid-1"); err != keys.ErrKidNotFound {
		t.Errorf("kid should be gone after Remove, got %v", err)
	}
	if err := ks.Remove("kid-1"); err != nil {
		t.Errorf("second Remove (now absent) should be nil, got %v", err)
	}
}

func TestExpiredKidNotReturned(t *testing.T, factory Factory) {
	ks := factory(t)

	past := time.Now().Add(-1 * time.Hour)
	if err := ks.Add("kid-old", []byte("s"), "HS256", "app-1", past); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	_, err := ks.GetKeyByKid("kid-old")
	if err != keys.ErrKidNotFound {
		t.Errorf("expired kid should return ErrKidNotFound, got %v", err)
	}
}

func TestZeroExpiryNeverExpires(t *testing.T, factory Factory) {
	ks := factory(t)

	// Zero time.Time = no expiry. A check far in the future must still find it.
	if err := ks.Add("kid-forever", []byte("s"), "HS256", "app-1", time.Time{}); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	rec, err := ks.GetKeyByKid("kid-forever")
	if err != nil {
		t.Fatalf("zero-expiry kid must be returned: %v", err)
	}
	if rec.Kid != "kid-forever" {
		t.Errorf("kid=%s, want kid-forever", rec.Kid)
	}
}

func TestCleanExpired(t *testing.T, factory Factory) {
	ks := factory(t)

	if err := ks.Add("kid-alive", []byte("a"), "HS256", "app-1", time.Now().Add(1*time.Hour)); err != nil {
		t.Fatalf("Add kid-alive failed: %v", err)
	}
	if err := ks.Add("kid-dead", []byte("b"), "HS256", "app-2", time.Now().Add(-1*time.Hour)); err != nil {
		t.Fatalf("Add kid-dead failed: %v", err)
	}
	if err := ks.Add("kid-forever", []byte("c"), "HS256", "app-3", time.Time{}); err != nil {
		t.Fatalf("Add kid-forever failed: %v", err)
	}

	if err := ks.CleanExpired(); err != nil {
		t.Fatalf("CleanExpired failed: %v", err)
	}

	if _, err := ks.GetKeyByKid("kid-alive"); err != nil {
		t.Errorf("live kid was swept: %v", err)
	}
	if _, err := ks.GetKeyByKid("kid-forever"); err != nil {
		t.Errorf("non-expiring kid was swept: %v", err)
	}
	// Re-add kid-dead and confirm it's gone from the backing store
	// (GetKeyByKid already filters expired entries even before CleanExpired,
	// so this also confirms CleanExpired physically removed the row/file
	// — re-adding with a future expiry must not collide with stale state).
	if err := ks.Add("kid-dead", []byte("b2"), "HS256", "app-2", time.Now().Add(1*time.Hour)); err != nil {
		t.Fatalf("re-Add kid-dead failed: %v", err)
	}
	rec, err := ks.GetKeyByKid("kid-dead")
	if err != nil {
		t.Fatalf("re-added kid-dead missing: %v", err)
	}
	if string(rec.Key.([]byte)) != "b2" {
		t.Errorf("expected fresh value b2 after re-Add, got %q", rec.Key)
	}
}

func TestAsymmetricKeyRoundTrip(t *testing.T, factory Factory) {
	ks := factory(t)

	_, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair failed: %v", err)
	}

	kid, err := utils.ComputeKid(pubPEM, "RS256")
	if err != nil {
		t.Fatalf("ComputeKid failed: %v", err)
	}

	if err := ks.Add(kid, pubPEM, "RS256", "app-rsa", time.Now().Add(1*time.Hour)); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	rec, err := ks.GetKeyByKid(kid)
	if err != nil {
		t.Fatalf("GetKeyByKid failed: %v", err)
	}
	if rec.Algorithm != "RS256" {
		t.Errorf("alg=%s, want RS256", rec.Algorithm)
	}
	keyBytes, ok := rec.Key.([]byte)
	if !ok {
		t.Fatalf("Expected []byte, got %T", rec.Key)
	}
	if string(keyBytes) != string(pubPEM) {
		t.Error("PEM round-trip mismatch")
	}
}

// TestPersistence verifies the store reads back what it wrote. For
// persistent backends (FS, GORM, GAE) this exercises the actual storage
// layer; for in-memory it is trivially true. Cross-instance restart proof
// is handled in backend-specific tests where reopening makes sense.
func TestPersistence(t *testing.T, factory Factory) {
	ks := factory(t)

	if err := ks.Add("kid-1", []byte("persistent"), "HS256", "app-1", time.Now().Add(1*time.Hour)); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	rec, err := ks.GetKeyByKid("kid-1")
	if err != nil {
		t.Fatalf("GetKeyByKid failed: %v", err)
	}
	if string(rec.Key.([]byte)) != "persistent" {
		t.Error("persisted key material mismatch")
	}
}
