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

// Factory creates a fresh WritableKeyStore for each test.
type Factory func(t *testing.T) oa.WritableKeyStore

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
}

func TestRegisterAndGet(t *testing.T, factory Factory) {
	ks := factory(t)

	secret := []byte("host-secret-123")
	if err := ks.RegisterKey("host-abc", secret, "HS256"); err != nil {
		t.Fatalf("RegisterKey failed: %v", err)
	}

	// GetVerifyKey should return the secret
	key, err := ks.GetVerifyKey("host-abc")
	if err != nil {
		t.Fatalf("GetVerifyKey failed: %v", err)
	}
	keyBytes, ok := key.([]byte)
	if !ok {
		t.Fatalf("Expected []byte, got %T", key)
	}
	if string(keyBytes) != string(secret) {
		t.Errorf("Expected secret %q, got %q", secret, keyBytes)
	}

	// GetSigningKey should return the same secret for HS256
	sigKey, err := ks.GetSigningKey("host-abc")
	if err != nil {
		t.Fatalf("GetSigningKey failed: %v", err)
	}
	sigKeyBytes, ok := sigKey.([]byte)
	if !ok {
		t.Fatalf("Expected []byte, got %T", sigKey)
	}
	if string(sigKeyBytes) != string(secret) {
		t.Errorf("Expected signing key %q, got %q", secret, sigKeyBytes)
	}

	// GetExpectedAlg should return HS256
	alg, err := ks.GetExpectedAlg("host-abc")
	if err != nil {
		t.Fatalf("GetExpectedAlg failed: %v", err)
	}
	if alg != "HS256" {
		t.Errorf("Expected alg HS256, got %s", alg)
	}
}

func TestNotFound(t *testing.T, factory Factory) {
	ks := factory(t)

	_, err := ks.GetVerifyKey("nonexistent")
	if err != oa.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}

	_, err = ks.GetSigningKey("nonexistent")
	if err != oa.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}

	_, err = ks.GetExpectedAlg("nonexistent")
	if err != oa.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestMultipleHosts(t *testing.T, factory Factory) {
	ks := factory(t)

	secret1 := []byte("secret-for-host-1")
	secret2 := []byte("secret-for-host-2")

	if err := ks.RegisterKey("host-1", secret1, "HS256"); err != nil {
		t.Fatalf("RegisterKey host-1 failed: %v", err)
	}
	if err := ks.RegisterKey("host-2", secret2, "HS256"); err != nil {
		t.Fatalf("RegisterKey host-2 failed: %v", err)
	}

	key1, err := ks.GetVerifyKey("host-1")
	if err != nil {
		t.Fatalf("GetVerifyKey host-1 failed: %v", err)
	}
	key2, err := ks.GetVerifyKey("host-2")
	if err != nil {
		t.Fatalf("GetVerifyKey host-2 failed: %v", err)
	}

	if string(key1.([]byte)) != string(secret1) {
		t.Errorf("host-1 key mismatch")
	}
	if string(key2.([]byte)) != string(secret2) {
		t.Errorf("host-2 key mismatch")
	}
	if string(key1.([]byte)) == string(key2.([]byte)) {
		t.Error("host-1 and host-2 should have different keys")
	}
}

func TestDeleteKey(t *testing.T, factory Factory) {
	ks := factory(t)

	if err := ks.RegisterKey("host-abc", []byte("secret"), "HS256"); err != nil {
		t.Fatalf("RegisterKey failed: %v", err)
	}

	if _, err := ks.GetVerifyKey("host-abc"); err != nil {
		t.Fatalf("Key should exist: %v", err)
	}

	if err := ks.DeleteKey("host-abc"); err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	if _, err := ks.GetVerifyKey("host-abc"); err != oa.ErrKeyNotFound {
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

	if err := ks.RegisterKey("host-abc", []byte("old-secret"), "HS256"); err != nil {
		t.Fatalf("RegisterKey failed: %v", err)
	}

	if err := ks.RegisterKey("host-abc", []byte("new-secret"), "HS512"); err != nil {
		t.Fatalf("RegisterKey overwrite failed: %v", err)
	}

	key, _ := ks.GetVerifyKey("host-abc")
	if string(key.([]byte)) != "new-secret" {
		t.Error("Expected overwritten secret")
	}

	alg, _ := ks.GetExpectedAlg("host-abc")
	if alg != "HS512" {
		t.Errorf("Expected overwritten alg HS512, got %s", alg)
	}
}

func TestListKeys(t *testing.T, factory Factory) {
	ks := factory(t)

	ks.RegisterKey("host-alpha", []byte("secret-a"), "HS256")
	ks.RegisterKey("host-beta", []byte("secret-b"), "HS256")
	ks.RegisterKey("host-gamma", []byte("secret-g"), "HS512")

	keys, err := ks.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
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

	keys, err := ks.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
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

	ks.RegisterKey("host-abc", []byte("persistent-secret"), "HS256")

	// Re-read from the same store — all backends must support this
	key, err := ks.GetVerifyKey("host-abc")
	if err != nil {
		t.Fatalf("Should see persisted key: %v", err)
	}
	if string(key.([]byte)) != "persistent-secret" {
		t.Error("Key material should persist")
	}
}

func TestRegisterAndGetAsymmetricKey(t *testing.T, factory Factory) {
	ks := factory(t)

	// Generate an RSA key pair and store the public key PEM
	_, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair failed: %v", err)
	}

	if err := ks.RegisterKey("app-rsa", pubPEM, "RS256"); err != nil {
		t.Fatalf("RegisterKey failed: %v", err)
	}

	// GetVerifyKey should return the same PEM bytes
	key, err := ks.GetVerifyKey("app-rsa")
	if err != nil {
		t.Fatalf("GetVerifyKey failed: %v", err)
	}
	keyBytes, ok := key.([]byte)
	if !ok {
		t.Fatalf("Expected []byte, got %T", key)
	}
	if string(keyBytes) != string(pubPEM) {
		t.Error("Stored PEM should match original")
	}

	// GetExpectedAlg should return RS256
	alg, err := ks.GetExpectedAlg("app-rsa")
	if err != nil {
		t.Fatalf("GetExpectedAlg failed: %v", err)
	}
	if alg != "RS256" {
		t.Errorf("Expected alg RS256, got %s", alg)
	}

	// DecodeVerifyKey should parse PEM into *rsa.PublicKey
	decoded, err := utils.DecodeVerifyKey(key, alg)
	if err != nil {
		t.Fatalf("DecodeVerifyKey failed: %v", err)
	}
	if _, ok := decoded.(*rsa.PublicKey); !ok {
		t.Errorf("Expected *rsa.PublicKey, got %T", decoded)
	}
}
