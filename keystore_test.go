package oneauth_test

import (
	"testing"

	oa "github.com/panyam/oneauth"
)

// TestInMemoryKeyStore_RegisterAndGet tests basic registration and retrieval
func TestInMemoryKeyStore_RegisterAndGet(t *testing.T) {
	ks := oa.NewInMemoryKeyStore()

	secret := []byte("host-secret-123")
	err := ks.RegisterKey("host-abc", secret, "HS256")
	if err != nil {
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

// TestInMemoryKeyStore_NotFound tests error on unknown client_id
func TestInMemoryKeyStore_NotFound(t *testing.T) {
	ks := oa.NewInMemoryKeyStore()

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

// TestInMemoryKeyStore_MultipleHosts tests multiple hosts with different keys
func TestInMemoryKeyStore_MultipleHosts(t *testing.T) {
	ks := oa.NewInMemoryKeyStore()

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

// TestInMemoryKeyStore_DeleteKey tests key removal
func TestInMemoryKeyStore_DeleteKey(t *testing.T) {
	ks := oa.NewInMemoryKeyStore()

	if err := ks.RegisterKey("host-abc", []byte("secret"), "HS256"); err != nil {
		t.Fatalf("RegisterKey failed: %v", err)
	}

	// Should exist
	if _, err := ks.GetVerifyKey("host-abc"); err != nil {
		t.Fatalf("Key should exist: %v", err)
	}

	// Delete
	if err := ks.DeleteKey("host-abc"); err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	// Should not exist
	if _, err := ks.GetVerifyKey("host-abc"); err != oa.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound after delete, got %v", err)
	}
}

// TestInMemoryKeyStore_DeleteNonexistent tests deleting a key that doesn't exist
func TestInMemoryKeyStore_DeleteNonexistent(t *testing.T) {
	ks := oa.NewInMemoryKeyStore()

	err := ks.DeleteKey("nonexistent")
	if err != oa.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

// TestInMemoryKeyStore_OverwriteKey tests that re-registering overwrites
func TestInMemoryKeyStore_OverwriteKey(t *testing.T) {
	ks := oa.NewInMemoryKeyStore()

	if err := ks.RegisterKey("host-abc", []byte("old-secret"), "HS256"); err != nil {
		t.Fatalf("RegisterKey failed: %v", err)
	}

	// Overwrite with new secret and alg
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
