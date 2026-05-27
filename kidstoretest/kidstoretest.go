package kidstoretest

import (
	"context"
	"testing"
	"time"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// Factory creates a fresh KidStorage for each test.
type Factory func(t *testing.T) keys.KidStorage

func addKid(t *testing.T, ks keys.KidStorage, req *keys.AddKidRequest) {
	t.Helper()
	if _, err := ks.Add(context.Background(), req); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
}

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
	ctx := context.Background()

	secret := []byte("kid-secret")
	addKid(t, ks, &keys.AddKidRequest{Kid: "kid-1", Key: secret, Algorithm: "HS256", ClientID: "app-1"})

	resp, err := ks.GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: "kid-1"})
	if err != nil {
		t.Fatalf("GetKeyByKid failed: %v", err)
	}
	rec := resp.Record
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
	_, err := ks.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: "does-not-exist"})
	if err != keys.ErrKidNotFound {
		t.Errorf("Expected ErrKidNotFound, got %v", err)
	}
}

func TestGetKeyByClientIDAlwaysNotFound(t *testing.T, factory Factory) {
	ks := factory(t)
	addKid(t, ks, &keys.AddKidRequest{Kid: "kid-1", Key: []byte("s"), Algorithm: "HS256", ClientID: "app-1"})

	_, err := ks.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: "app-1"})
	if err != keys.ErrKeyNotFound {
		t.Errorf("GetKey by clientID must always return ErrKeyNotFound, got %v", err)
	}
}

func TestOverwriteSameKid(t *testing.T, factory Factory) {
	ks := factory(t)
	ctx := context.Background()

	addKid(t, ks, &keys.AddKidRequest{Kid: "kid-1", Key: []byte("old"), Algorithm: "HS256", ClientID: "app-1"})
	addKid(t, ks, &keys.AddKidRequest{Kid: "kid-1", Key: []byte("new"), Algorithm: "HS512", ClientID: "app-2"})

	resp, err := ks.GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: "kid-1"})
	if err != nil {
		t.Fatalf("GetKeyByKid failed: %v", err)
	}
	rec := resp.Record
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

func TestRemoveIdempotent(t *testing.T, factory Factory) {
	ks := factory(t)
	ctx := context.Background()

	if _, err := ks.Remove(ctx, &keys.RemoveKidRequest{Kid: "never-existed"}); err != nil {
		t.Errorf("Remove of absent kid should be nil, got %v", err)
	}

	addKid(t, ks, &keys.AddKidRequest{Kid: "kid-1", Key: []byte("s"), Algorithm: "HS256", ClientID: "app-1"})
	if _, err := ks.Remove(ctx, &keys.RemoveKidRequest{Kid: "kid-1"}); err != nil {
		t.Errorf("Remove of present kid failed: %v", err)
	}
	if _, err := ks.GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: "kid-1"}); err != keys.ErrKidNotFound {
		t.Errorf("kid should be gone after Remove, got %v", err)
	}
	if _, err := ks.Remove(ctx, &keys.RemoveKidRequest{Kid: "kid-1"}); err != nil {
		t.Errorf("second Remove (now absent) should be nil, got %v", err)
	}
}

func TestExpiredKidNotReturned(t *testing.T, factory Factory) {
	ks := factory(t)
	past := time.Now().Add(-1 * time.Hour)
	addKid(t, ks, &keys.AddKidRequest{Kid: "kid-old", Key: []byte("s"), Algorithm: "HS256", ClientID: "app-1", ExpiresAt: past})

	_, err := ks.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: "kid-old"})
	if err != keys.ErrKidNotFound {
		t.Errorf("expired kid should return ErrKidNotFound, got %v", err)
	}
}

func TestZeroExpiryNeverExpires(t *testing.T, factory Factory) {
	ks := factory(t)
	addKid(t, ks, &keys.AddKidRequest{Kid: "kid-forever", Key: []byte("s"), Algorithm: "HS256", ClientID: "app-1"})

	resp, err := ks.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: "kid-forever"})
	if err != nil {
		t.Fatalf("zero-expiry kid must be returned: %v", err)
	}
	if resp.Record.Kid != "kid-forever" {
		t.Errorf("kid=%s, want kid-forever", resp.Record.Kid)
	}
}

func TestCleanExpired(t *testing.T, factory Factory) {
	ks := factory(t)
	ctx := context.Background()

	addKid(t, ks, &keys.AddKidRequest{Kid: "kid-alive", Key: []byte("a"), Algorithm: "HS256", ClientID: "app-1", ExpiresAt: time.Now().Add(1 * time.Hour)})
	addKid(t, ks, &keys.AddKidRequest{Kid: "kid-dead", Key: []byte("b"), Algorithm: "HS256", ClientID: "app-2", ExpiresAt: time.Now().Add(-1 * time.Hour)})
	addKid(t, ks, &keys.AddKidRequest{Kid: "kid-forever", Key: []byte("c"), Algorithm: "HS256", ClientID: "app-3"})

	if _, err := ks.CleanExpired(ctx, &keys.CleanExpiredRequest{}); err != nil {
		t.Fatalf("CleanExpired failed: %v", err)
	}

	if _, err := ks.GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: "kid-alive"}); err != nil {
		t.Errorf("live kid was swept: %v", err)
	}
	if _, err := ks.GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: "kid-forever"}); err != nil {
		t.Errorf("non-expiring kid was swept: %v", err)
	}
	addKid(t, ks, &keys.AddKidRequest{Kid: "kid-dead", Key: []byte("b2"), Algorithm: "HS256", ClientID: "app-2", ExpiresAt: time.Now().Add(1 * time.Hour)})
	resp, err := ks.GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: "kid-dead"})
	if err != nil {
		t.Fatalf("re-added kid-dead missing: %v", err)
	}
	if string(resp.Record.Key.([]byte)) != "b2" {
		t.Errorf("expected fresh value b2 after re-Add, got %q", resp.Record.Key)
	}
}

func TestAsymmetricKeyRoundTrip(t *testing.T, factory Factory) {
	ks := factory(t)
	ctx := context.Background()

	_, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair failed: %v", err)
	}
	kid, err := utils.ComputeKid(pubPEM, "RS256")
	if err != nil {
		t.Fatalf("ComputeKid failed: %v", err)
	}
	addKid(t, ks, &keys.AddKidRequest{Kid: kid, Key: pubPEM, Algorithm: "RS256", ClientID: "app-rsa", ExpiresAt: time.Now().Add(1 * time.Hour)})

	resp, err := ks.GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: kid})
	if err != nil {
		t.Fatalf("GetKeyByKid failed: %v", err)
	}
	rec := resp.Record
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

func TestPersistence(t *testing.T, factory Factory) {
	ks := factory(t)
	addKid(t, ks, &keys.AddKidRequest{Kid: "kid-1", Key: []byte("persistent"), Algorithm: "HS256", ClientID: "app-1", ExpiresAt: time.Now().Add(1 * time.Hour)})

	resp, err := ks.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: "kid-1"})
	if err != nil {
		t.Fatalf("GetKeyByKid failed: %v", err)
	}
	if string(resp.Record.Key.([]byte)) != "persistent" {
		t.Error("persisted key material mismatch")
	}
}
