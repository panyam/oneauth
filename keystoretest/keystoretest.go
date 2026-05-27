// Package keystoretest provides shared test suites for all KeyStore implementations.
// Each backend (inmem, gorm, fs, gae) calls these tests with its own factory function.
package keystoretest

import (
	"context"
	"crypto/rsa"
	"sort"
	"testing"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// Factory creates a fresh KeyStorage for each test.
type Factory func(t *testing.T) keys.KeyStorage

func putKey(t *testing.T, ks keys.KeyStorage, rec *keys.KeyRecord) {
	t.Helper()
	if _, err := ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: rec}); err != nil {
		t.Fatalf("PutKey failed: %v", err)
	}
}

// RunAll runs the complete KeyStore test suite against the provided factory.
func RunAll(t *testing.T, factory Factory) {
	t.Run("RegisterAndGet", func(t *testing.T) { TestRegisterAndGet(t, factory) })
	t.Run("NotFound", func(t *testing.T) { TestNotFound(t, factory) })
	t.Run("MultipleHosts", func(t *testing.T) { TestMultipleHosts(t, factory) })
	t.Run("DeleteKey", func(t *testing.T) { TestDeleteKey(t, factory) })
	t.Run("DeleteNonexistent", func(t *testing.T) { TestDeleteNonexistent(t, factory) })
	t.Run("OverwriteKey", func(t *testing.T) { TestOverwriteKey(t, factory) })
	t.Run("ListKeys", func(t *testing.T) { TestListKeys(t, factory) })
	t.Run("ListKeysEmpty", func(t *testing.T) { TestListKeysEmpty(t, factory) })
	t.Run("Persistence", func(t *testing.T) { TestPersistence(t, factory) })
	t.Run("AsymmetricKey", func(t *testing.T) { TestRegisterAndGetAsymmetricKey(t, factory) })
	t.Run("KidResolverBasic", func(t *testing.T) { TestKidResolverBasic(t, factory) })
	t.Run("KidResolverAsymmetric", func(t *testing.T) { TestKidResolverAsymmetric(t, factory) })
	t.Run("GetCurrentKid", func(t *testing.T) { TestGetCurrentKid(t, factory) })
}

func TestRegisterAndGet(t *testing.T, factory Factory) {
	ks := factory(t)
	ctx := context.Background()

	secret := []byte("host-secret-123")
	putKey(t, ks, &keys.KeyRecord{ClientID: "host-abc", Key: secret, Algorithm: "HS256"})

	resp, err := ks.GetKey(ctx, &keys.GetKeyRequest{ClientID: "host-abc"})
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	rec := resp.Record
	keyBytes, ok := rec.Key.([]byte)
	if !ok {
		t.Fatalf("Expected []byte, got %T", rec.Key)
	}
	if string(keyBytes) != string(secret) {
		t.Errorf("Expected secret %q, got %q", secret, keyBytes)
	}
	if rec.Algorithm != "HS256" {
		t.Errorf("Expected alg HS256, got %s", rec.Algorithm)
	}
}

func TestNotFound(t *testing.T, factory Factory) {
	ks := factory(t)
	_, err := ks.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: "nonexistent"})
	if err != keys.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestMultipleHosts(t *testing.T, factory Factory) {
	ks := factory(t)
	ctx := context.Background()

	secret1 := []byte("secret-for-host-1")
	secret2 := []byte("secret-for-host-2")
	putKey(t, ks, &keys.KeyRecord{ClientID: "host-1", Key: secret1, Algorithm: "HS256"})
	putKey(t, ks, &keys.KeyRecord{ClientID: "host-2", Key: secret2, Algorithm: "HS256"})

	resp1, err := ks.GetKey(ctx, &keys.GetKeyRequest{ClientID: "host-1"})
	if err != nil {
		t.Fatalf("GetKey host-1 failed: %v", err)
	}
	resp2, err := ks.GetKey(ctx, &keys.GetKeyRequest{ClientID: "host-2"})
	if err != nil {
		t.Fatalf("GetKey host-2 failed: %v", err)
	}
	if string(resp1.Record.Key.([]byte)) != string(secret1) {
		t.Errorf("host-1 key mismatch")
	}
	if string(resp2.Record.Key.([]byte)) != string(secret2) {
		t.Errorf("host-2 key mismatch")
	}
}

func TestDeleteKey(t *testing.T, factory Factory) {
	ks := factory(t)
	ctx := context.Background()
	putKey(t, ks, &keys.KeyRecord{ClientID: "host-abc", Key: []byte("secret"), Algorithm: "HS256"})
	if _, err := ks.GetKey(ctx, &keys.GetKeyRequest{ClientID: "host-abc"}); err != nil {
		t.Fatalf("Key should exist: %v", err)
	}
	if _, err := ks.DeleteKey(ctx, &keys.DeleteKeyRequest{ClientID: "host-abc"}); err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}
	if _, err := ks.GetKey(ctx, &keys.GetKeyRequest{ClientID: "host-abc"}); err != keys.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound after delete, got %v", err)
	}
}

func TestDeleteNonexistent(t *testing.T, factory Factory) {
	ks := factory(t)
	_, err := ks.DeleteKey(context.Background(), &keys.DeleteKeyRequest{ClientID: "nonexistent"})
	if err != keys.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestOverwriteKey(t *testing.T, factory Factory) {
	ks := factory(t)
	ctx := context.Background()
	putKey(t, ks, &keys.KeyRecord{ClientID: "host-abc", Key: []byte("old-secret"), Algorithm: "HS256"})
	putKey(t, ks, &keys.KeyRecord{ClientID: "host-abc", Key: []byte("new-secret"), Algorithm: "HS512"})
	resp, _ := ks.GetKey(ctx, &keys.GetKeyRequest{ClientID: "host-abc"})
	if string(resp.Record.Key.([]byte)) != "new-secret" {
		t.Error("Expected overwritten secret")
	}
	if resp.Record.Algorithm != "HS512" {
		t.Errorf("Expected overwritten alg HS512, got %s", resp.Record.Algorithm)
	}
}

func TestListKeys(t *testing.T, factory Factory) {
	ks := factory(t)
	ctx := context.Background()
	putKey(t, ks, &keys.KeyRecord{ClientID: "host-alpha", Key: []byte("secret-a"), Algorithm: "HS256"})
	putKey(t, ks, &keys.KeyRecord{ClientID: "host-beta", Key: []byte("secret-b"), Algorithm: "HS256"})
	putKey(t, ks, &keys.KeyRecord{ClientID: "host-gamma", Key: []byte("secret-g"), Algorithm: "HS512"})

	resp, err := ks.ListKeyIDs(ctx, &keys.ListKeyIDsRequest{})
	if err != nil {
		t.Fatalf("ListKeyIDs failed: %v", err)
	}
	ids := resp.ClientIDs
	if len(ids) != 3 {
		t.Fatalf("Expected 3 keys, got %d", len(ids))
	}
	sort.Strings(ids)
	expected := []string{"host-alpha", "host-beta", "host-gamma"}
	for i, e := range expected {
		if ids[i] != e {
			t.Errorf("Expected ids[%d] = %s, got %s", i, e, ids[i])
		}
	}
}

func TestListKeysEmpty(t *testing.T, factory Factory) {
	ks := factory(t)
	resp, err := ks.ListKeyIDs(context.Background(), &keys.ListKeyIDsRequest{})
	if err != nil {
		t.Fatalf("ListKeyIDs failed: %v", err)
	}
	if len(resp.ClientIDs) != 0 {
		t.Errorf("Expected 0 keys, got %d", len(resp.ClientIDs))
	}
}

func TestPersistence(t *testing.T, factory Factory) {
	ks := factory(t)
	ctx := context.Background()
	putKey(t, ks, &keys.KeyRecord{ClientID: "host-abc", Key: []byte("persistent-secret"), Algorithm: "HS256"})
	resp, err := ks.GetKey(ctx, &keys.GetKeyRequest{ClientID: "host-abc"})
	if err != nil {
		t.Fatalf("Should see persisted key: %v", err)
	}
	if string(resp.Record.Key.([]byte)) != "persistent-secret" {
		t.Error("Key material should persist")
	}
}

func TestKidResolverBasic(t *testing.T, factory Factory) {
	ks := factory(t)
	ctx := context.Background()

	secret := []byte("kid-test-secret")
	putKey(t, ks, &keys.KeyRecord{ClientID: "app-kid", Key: secret, Algorithm: "HS256"})

	expectedKid, err := utils.ComputeKid(secret, "HS256")
	if err != nil {
		t.Fatalf("ComputeKid failed: %v", err)
	}

	resp, err := ks.GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: expectedKid})
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
	if rec.ClientID != "app-kid" {
		t.Errorf("clientID=%s, want app-kid", rec.ClientID)
	}

	_, err = ks.GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: "nonexistent-kid"})
	if err != keys.ErrKidNotFound {
		t.Errorf("expected ErrKidNotFound, got %v", err)
	}
}

func TestKidResolverAsymmetric(t *testing.T, factory Factory) {
	ks := factory(t)
	ctx := context.Background()

	_, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}
	putKey(t, ks, &keys.KeyRecord{ClientID: "app-rsa-kid", Key: pubPEM, Algorithm: "RS256"})

	pubKey, _ := utils.DecodeVerifyKey(pubPEM, "RS256")
	expectedKid, _ := utils.ComputeKid(pubKey, "RS256")

	storedKid, _ := utils.ComputeKid(pubPEM, "RS256")
	if storedKid != expectedKid {
		t.Errorf("ComputeKid(PEM) should equal ComputeKid(pubKey): %s != %s", storedKid, expectedKid)
	}

	resp, err := ks.GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: expectedKid})
	if err != nil {
		t.Fatalf("GetKeyByKid failed: %v", err)
	}
	rec := resp.Record
	if rec.Algorithm != "RS256" {
		t.Errorf("alg=%s, want RS256", rec.Algorithm)
	}
	if rec.ClientID != "app-rsa-kid" {
		t.Errorf("clientID=%s, want app-rsa-kid", rec.ClientID)
	}
	if keyBytes, ok := rec.Key.([]byte); ok {
		if string(keyBytes) != string(pubPEM) {
			t.Error("key material mismatch")
		}
	}
}

func TestGetCurrentKid(t *testing.T, factory Factory) {
	ks := factory(t)
	ctx := context.Background()

	secret := []byte("kid-getter-secret")
	putKey(t, ks, &keys.KeyRecord{ClientID: "app-kg", Key: secret, Algorithm: "HS256"})

	resp, err := ks.GetKey(ctx, &keys.GetKeyRequest{ClientID: "app-kg"})
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	kid := resp.Record.Kid
	if kid == "" {
		t.Error("expected non-empty kid")
	}
	expectedKid, _ := utils.ComputeKid(secret, "HS256")
	if kid != expectedKid {
		t.Errorf("kid=%s, want %s", kid, expectedKid)
	}

	_, err = ks.GetKey(ctx, &keys.GetKeyRequest{ClientID: "nonexistent"})
	if err != keys.ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestRegisterAndGetAsymmetricKey(t *testing.T, factory Factory) {
	ks := factory(t)
	ctx := context.Background()

	_, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair failed: %v", err)
	}
	putKey(t, ks, &keys.KeyRecord{ClientID: "app-rsa", Key: pubPEM, Algorithm: "RS256"})

	resp, err := ks.GetKey(ctx, &keys.GetKeyRequest{ClientID: "app-rsa"})
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	rec := resp.Record
	keyBytes, ok := rec.Key.([]byte)
	if !ok {
		t.Fatalf("Expected []byte, got %T", rec.Key)
	}
	if string(keyBytes) != string(pubPEM) {
		t.Error("Stored PEM should match original")
	}
	if rec.Algorithm != "RS256" {
		t.Errorf("Expected alg RS256, got %s", rec.Algorithm)
	}

	decoded, err := utils.DecodeVerifyKey(rec.Key, rec.Algorithm)
	if err != nil {
		t.Fatalf("DecodeVerifyKey failed: %v", err)
	}
	if _, ok := decoded.(*rsa.PublicKey); !ok {
		t.Errorf("Expected *rsa.PublicKey, got %T", decoded)
	}
}
