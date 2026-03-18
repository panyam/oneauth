// Package keystoretest provides shared test suites for all KeyStore implementations.
// Each backend (inmem, gorm, fs, gae) calls these tests with its own factory function.
package keystoretest

import (
	"crypto/rsa"
	"sort"
	"testing"

	oa "github.com/panyam/oneauth"
	"github.com/panyam/oneauth/utils"
)

// Factory creates a fresh KeyStorage for each test.
type Factory func(t *testing.T) oa.KeyStorage

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

	secret := []byte("host-secret-123")
	if err := ks.PutKey(&oa.KeyRecord{ClientID: "host-abc", Key: secret, Algorithm: "HS256"}); err != nil {
		t.Fatalf("PutKey failed: %v", err)
	}

	// GetKey should return the secret
	rec, err := ks.GetKey("host-abc")
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	keyBytes, ok := rec.Key.([]byte)
	if !ok {
		t.Fatalf("Expected []byte, got %T", rec.Key)
	}
	if string(keyBytes) != string(secret) {
		t.Errorf("Expected secret %q, got %q", secret, keyBytes)
	}

	// For HS256, signing key and verify key are the same
	rec2, err := ks.GetKey("host-abc")
	if err != nil {
		t.Fatalf("GetKey (signing) failed: %v", err)
	}
	sigKeyBytes, ok := rec2.Key.([]byte)
	if !ok {
		t.Fatalf("Expected []byte, got %T", rec2.Key)
	}
	if string(sigKeyBytes) != string(secret) {
		t.Errorf("Expected signing key %q, got %q", secret, sigKeyBytes)
	}

	// Algorithm should be HS256
	if rec.Algorithm != "HS256" {
		t.Errorf("Expected alg HS256, got %s", rec.Algorithm)
	}
}

func TestNotFound(t *testing.T, factory Factory) {
	ks := factory(t)

	_, err := ks.GetKey("nonexistent")
	if err != oa.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestMultipleHosts(t *testing.T, factory Factory) {
	ks := factory(t)

	secret1 := []byte("secret-for-host-1")
	secret2 := []byte("secret-for-host-2")

	if err := ks.PutKey(&oa.KeyRecord{ClientID: "host-1", Key: secret1, Algorithm: "HS256"}); err != nil {
		t.Fatalf("PutKey host-1 failed: %v", err)
	}
	if err := ks.PutKey(&oa.KeyRecord{ClientID: "host-2", Key: secret2, Algorithm: "HS256"}); err != nil {
		t.Fatalf("PutKey host-2 failed: %v", err)
	}

	rec1, err := ks.GetKey("host-1")
	if err != nil {
		t.Fatalf("GetKey host-1 failed: %v", err)
	}
	rec2, err := ks.GetKey("host-2")
	if err != nil {
		t.Fatalf("GetKey host-2 failed: %v", err)
	}

	if string(rec1.Key.([]byte)) != string(secret1) {
		t.Errorf("host-1 key mismatch")
	}
	if string(rec2.Key.([]byte)) != string(secret2) {
		t.Errorf("host-2 key mismatch")
	}
	if string(rec1.Key.([]byte)) == string(rec2.Key.([]byte)) {
		t.Error("host-1 and host-2 should have different keys")
	}
}

func TestDeleteKey(t *testing.T, factory Factory) {
	ks := factory(t)

	if err := ks.PutKey(&oa.KeyRecord{ClientID: "host-abc", Key: []byte("secret"), Algorithm: "HS256"}); err != nil {
		t.Fatalf("PutKey failed: %v", err)
	}

	if _, err := ks.GetKey("host-abc"); err != nil {
		t.Fatalf("Key should exist: %v", err)
	}

	if err := ks.DeleteKey("host-abc"); err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	if _, err := ks.GetKey("host-abc"); err != oa.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound after delete, got %v", err)
	}
}

func TestDeleteNonexistent(t *testing.T, factory Factory) {
	ks := factory(t)

	err := ks.DeleteKey("nonexistent")
	if err != oa.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestOverwriteKey(t *testing.T, factory Factory) {
	ks := factory(t)

	if err := ks.PutKey(&oa.KeyRecord{ClientID: "host-abc", Key: []byte("old-secret"), Algorithm: "HS256"}); err != nil {
		t.Fatalf("PutKey failed: %v", err)
	}

	if err := ks.PutKey(&oa.KeyRecord{ClientID: "host-abc", Key: []byte("new-secret"), Algorithm: "HS512"}); err != nil {
		t.Fatalf("PutKey overwrite failed: %v", err)
	}

	rec, _ := ks.GetKey("host-abc")
	if string(rec.Key.([]byte)) != "new-secret" {
		t.Error("Expected overwritten secret")
	}

	if rec.Algorithm != "HS512" {
		t.Errorf("Expected overwritten alg HS512, got %s", rec.Algorithm)
	}
}

func TestListKeys(t *testing.T, factory Factory) {
	ks := factory(t)

	ks.PutKey(&oa.KeyRecord{ClientID: "host-alpha", Key: []byte("secret-a"), Algorithm: "HS256"})
	ks.PutKey(&oa.KeyRecord{ClientID: "host-beta", Key: []byte("secret-b"), Algorithm: "HS256"})
	ks.PutKey(&oa.KeyRecord{ClientID: "host-gamma", Key: []byte("secret-g"), Algorithm: "HS512"})

	keys, err := ks.ListKeyIDs()
	if err != nil {
		t.Fatalf("ListKeyIDs failed: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("Expected 3 keys, got %d", len(keys))
	}

	sort.Strings(keys)
	expected := []string{"host-alpha", "host-beta", "host-gamma"}
	for i, e := range expected {
		if keys[i] != e {
			t.Errorf("Expected keys[%d] = %s, got %s", i, e, keys[i])
		}
	}
}

func TestListKeysEmpty(t *testing.T, factory Factory) {
	ks := factory(t)

	keys, err := ks.ListKeyIDs()
	if err != nil {
		t.Fatalf("ListKeyIDs failed: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("Expected 0 keys, got %d", len(keys))
	}
}

func TestPersistence(t *testing.T, factory Factory) {
	// This test verifies that two store instances sharing the same backend
	// see each other's data. For InMemoryKeyStore this is trivially true
	// (same instance). For persistent stores, the factory should return
	// stores sharing the same underlying storage.
	ks := factory(t)

	ks.PutKey(&oa.KeyRecord{ClientID: "host-abc", Key: []byte("persistent-secret"), Algorithm: "HS256"})

	// Re-read from the same store — all backends must support this
	rec, err := ks.GetKey("host-abc")
	if err != nil {
		t.Fatalf("Should see persisted key: %v", err)
	}
	if string(rec.Key.([]byte)) != "persistent-secret" {
		t.Error("Key material should persist")
	}
}

func TestKidResolverBasic(t *testing.T, factory Factory) {
	ks := factory(t)

	secret := []byte("kid-test-secret")
	if err := ks.PutKey(&oa.KeyRecord{ClientID: "app-kid", Key: secret, Algorithm: "HS256"}); err != nil {
		t.Fatalf("PutKey failed: %v", err)
	}

	// Compute expected kid
	expectedKid, err := utils.ComputeKid(secret, "HS256")
	if err != nil {
		t.Fatalf("ComputeKid failed: %v", err)
	}

	// Look up by kid
	rec, err := ks.GetKeyByKid(expectedKid)
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
	if rec.ClientID != "app-kid" {
		t.Errorf("clientID=%s, want app-kid", rec.ClientID)
	}

	// Unknown kid should fail
	_, err = ks.GetKeyByKid("nonexistent-kid")
	if err != oa.ErrKidNotFound {
		t.Errorf("expected ErrKidNotFound, got %v", err)
	}
}

func TestKidResolverAsymmetric(t *testing.T, factory Factory) {
	ks := factory(t)

	_, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}

	if err := ks.PutKey(&oa.KeyRecord{ClientID: "app-rsa-kid", Key: pubPEM, Algorithm: "RS256"}); err != nil {
		t.Fatal(err)
	}

	// Compute kid from the public key
	pubKey, _ := utils.DecodeVerifyKey(pubPEM, "RS256")
	expectedKid, _ := utils.ComputeKid(pubKey, "RS256")

	// For backends that store []byte PEM, ComputeKid on []byte with RS256
	// should parse PEM and compute the same thumbprint
	storedKid, _ := utils.ComputeKid(pubPEM, "RS256")
	if storedKid != expectedKid {
		t.Errorf("ComputeKid(PEM) should equal ComputeKid(pubKey): %s != %s", storedKid, expectedKid)
	}

	rec, err := ks.GetKeyByKid(expectedKid)
	if err != nil {
		t.Fatalf("GetKeyByKid failed: %v", err)
	}
	if rec.Algorithm != "RS256" {
		t.Errorf("alg=%s, want RS256", rec.Algorithm)
	}
	if rec.ClientID != "app-rsa-kid" {
		t.Errorf("clientID=%s, want app-rsa-kid", rec.ClientID)
	}
	// Key should be the PEM bytes
	if keyBytes, ok := rec.Key.([]byte); ok {
		if string(keyBytes) != string(pubPEM) {
			t.Error("key material mismatch")
		}
	}
}

func TestGetCurrentKid(t *testing.T, factory Factory) {
	ks := factory(t)

	secret := []byte("kid-getter-secret")
	ks.PutKey(&oa.KeyRecord{ClientID: "app-kg", Key: secret, Algorithm: "HS256"})

	rec, err := ks.GetKey("app-kg")
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	kid := rec.Kid
	if kid == "" {
		t.Error("expected non-empty kid")
	}

	expectedKid, _ := utils.ComputeKid(secret, "HS256")
	if kid != expectedKid {
		t.Errorf("kid=%s, want %s", kid, expectedKid)
	}

	// Nonexistent client
	_, err = ks.GetKey("nonexistent")
	if err != oa.ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestRegisterAndGetAsymmetricKey(t *testing.T, factory Factory) {
	ks := factory(t)

	// Generate an RSA key pair and store the public key PEM
	_, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair failed: %v", err)
	}

	if err := ks.PutKey(&oa.KeyRecord{ClientID: "app-rsa", Key: pubPEM, Algorithm: "RS256"}); err != nil {
		t.Fatalf("PutKey failed: %v", err)
	}

	// GetKey should return the same PEM bytes
	rec, err := ks.GetKey("app-rsa")
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	keyBytes, ok := rec.Key.([]byte)
	if !ok {
		t.Fatalf("Expected []byte, got %T", rec.Key)
	}
	if string(keyBytes) != string(pubPEM) {
		t.Error("Stored PEM should match original")
	}

	// Algorithm should be RS256
	if rec.Algorithm != "RS256" {
		t.Errorf("Expected alg RS256, got %s", rec.Algorithm)
	}

	// DecodeVerifyKey should parse PEM into *rsa.PublicKey
	decoded, err := utils.DecodeVerifyKey(rec.Key, rec.Algorithm)
	if err != nil {
		t.Fatalf("DecodeVerifyKey failed: %v", err)
	}
	if _, ok := decoded.(*rsa.PublicKey); !ok {
		t.Errorf("Expected *rsa.PublicKey, got %T", decoded)
	}
}
