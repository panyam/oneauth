// Tests for the EncryptedKeyStore decorator, verifying encryption at rest,
// round-trip correctness, plaintext migration, and full interface compliance.
package oneauth_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	oa "github.com/panyam/oneauth"
	"github.com/panyam/oneauth/keystoretest"
	"github.com/panyam/oneauth/utils"
)

// testMasterKey is a fixed 32-byte hex key used across tests for determinism.
const testMasterKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// newTestEncryptedKeyStore creates an EncryptedKeyStore wrapping a fresh
// InMemoryKeyStore for isolated test use. Returns both so tests can inspect
// the inner store's raw bytes.
func newTestEncryptedKeyStore(t *testing.T) (*oa.EncryptedKeyStorage, *oa.InMemoryKeyStore) {
	t.Helper()
	inner := oa.NewInMemoryKeyStore()
	enc, err := oa.NewEncryptedKeyStorage(inner, testMasterKey)
	if err != nil {
		t.Fatalf("NewEncryptedKeyStorage failed: %v", err)
	}
	return enc, inner
}

// randomMasterKey generates a cryptographically random 64-char hex master key
// for tests that need distinct keys (e.g., cross-key failure tests).
func randomMasterKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	return hex.EncodeToString(key)
}

// TestEncryptedKeyStoreRoundTrip verifies that registering a secret via the
// encrypted wrapper and reading it back yields the original plaintext.
func TestEncryptedKeyStoreRoundTrip(t *testing.T) {
	enc, _ := newTestEncryptedKeyStore(t)
	secret := []byte("my-super-secret-key")

	if err := enc.RegisterKey("app-1", secret, "HS256"); err != nil {
		t.Fatalf("RegisterKey failed: %v", err)
	}

	got, err := enc.GetVerifyKey("app-1")
	if err != nil {
		t.Fatalf("GetVerifyKey failed: %v", err)
	}
	if !bytes.Equal(got.([]byte), secret) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, secret)
	}

	// GetSigningKey should also return the same plaintext
	sigKey, err := enc.GetSigningKey("app-1")
	if err != nil {
		t.Fatalf("GetSigningKey failed: %v", err)
	}
	if !bytes.Equal(sigKey.([]byte), secret) {
		t.Errorf("GetSigningKey round-trip mismatch: got %q, want %q", sigKey, secret)
	}
}

// TestStoredBytesAreEncrypted verifies that the inner store holds ciphertext,
// not the original plaintext secret. This is the core security guarantee:
// a database dump will not expose raw HMAC secrets.
func TestStoredBytesAreEncrypted(t *testing.T) {
	enc, inner := newTestEncryptedKeyStore(t)
	secret := []byte("plaintext-secret-value")

	if err := enc.RegisterKey("app-1", secret, "HS256"); err != nil {
		t.Fatalf("RegisterKey failed: %v", err)
	}

	// Read directly from the inner store (bypassing decryption)
	raw, err := inner.GetVerifyKey("app-1")
	if err != nil {
		t.Fatalf("inner.GetVerifyKey failed: %v", err)
	}
	rawBytes := raw.([]byte)

	if bytes.Equal(rawBytes, secret) {
		t.Error("inner store contains plaintext secret — encryption is not working")
	}

	// Ciphertext should be longer than plaintext (12-byte nonce + 16-byte GCM tag)
	if len(rawBytes) <= len(secret) {
		t.Errorf("ciphertext (%d bytes) should be longer than plaintext (%d bytes)", len(rawBytes), len(secret))
	}
}

// TestAsymmetricPassthrough verifies that asymmetric keys (RS256 public PEM)
// are stored in the inner store without modification. Public keys are not
// sensitive and should not be encrypted.
func TestAsymmetricPassthrough(t *testing.T) {
	enc, inner := newTestEncryptedKeyStore(t)

	_, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair failed: %v", err)
	}

	if err := enc.RegisterKey("app-rsa", pubPEM, "RS256"); err != nil {
		t.Fatalf("RegisterKey failed: %v", err)
	}

	// Inner store should have the exact same PEM bytes (no encryption)
	raw, err := inner.GetVerifyKey("app-rsa")
	if err != nil {
		t.Fatalf("inner.GetVerifyKey failed: %v", err)
	}
	if !bytes.Equal(raw.([]byte), pubPEM) {
		t.Error("asymmetric key was modified — should pass through unchanged")
	}

	// Reading via encrypted wrapper should also return the same PEM
	got, err := enc.GetVerifyKey("app-rsa")
	if err != nil {
		t.Fatalf("GetVerifyKey failed: %v", err)
	}
	if !bytes.Equal(got.([]byte), pubPEM) {
		t.Error("encrypted wrapper altered asymmetric key on read")
	}
}

// TestWrongMasterKeyFails verifies that a secret encrypted with one master key
// cannot be decrypted with a different master key. Due to the plaintext
// fallback, the wrong (still-encrypted) bytes are returned instead of the
// original secret.
func TestWrongMasterKeyFails(t *testing.T) {
	inner := oa.NewInMemoryKeyStore()
	secret := []byte("sensitive-secret")

	// Encrypt with key A
	encA, err := oa.NewEncryptedKeyStorage(inner, testMasterKey)
	if err != nil {
		t.Fatalf("NewEncryptedKeyStorage (A) failed: %v", err)
	}
	if err := encA.RegisterKey("app-1", secret, "HS256"); err != nil {
		t.Fatalf("RegisterKey failed: %v", err)
	}

	// Try to read with key B — GCM auth will fail, fallback returns raw ciphertext
	encB, err := oa.NewEncryptedKeyStorage(inner, randomMasterKey(t))
	if err != nil {
		t.Fatalf("NewEncryptedKeyStorage (B) failed: %v", err)
	}
	got, err := encB.GetVerifyKey("app-1")
	if err != nil {
		t.Fatalf("GetVerifyKey with wrong key should not error (fallback): %v", err)
	}

	// The returned bytes should NOT match the original secret
	if bytes.Equal(got.([]byte), secret) {
		t.Error("wrong master key returned the original plaintext — encryption is broken")
	}
}

// TestPlaintextMigration verifies backward compatibility: a key stored directly
// in the inner store (without encryption) is still readable through the
// encrypted wrapper. This is the migration path for existing deployments that
// enable encryption without re-registering all apps.
func TestPlaintextMigration(t *testing.T) {
	enc, inner := newTestEncryptedKeyStore(t)
	secret := []byte("legacy-unencrypted-secret")

	// Store directly in inner store (simulating pre-encryption data)
	if err := inner.RegisterKey("legacy-app", secret, "HS256"); err != nil {
		t.Fatalf("inner.RegisterKey failed: %v", err)
	}

	// Reading via encrypted wrapper should return the plaintext (GCM fails, fallback)
	got, err := enc.GetVerifyKey("legacy-app")
	if err != nil {
		t.Fatalf("GetVerifyKey failed: %v", err)
	}
	if !bytes.Equal(got.([]byte), secret) {
		t.Errorf("plaintext migration failed: got %q, want %q", got, secret)
	}
}

// TestInvalidMasterKey verifies that NewEncryptedKeyStore rejects master keys
// that are too short, too long, not valid hex, or empty.
func TestInvalidMasterKey(t *testing.T) {
	inner := oa.NewInMemoryKeyStore()

	tests := []struct {
		name string
		key  string
	}{
		{"too short", "abcdef"},
		{"too long", testMasterKey + "ff"},
		{"not hex", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
		{"empty", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := oa.NewEncryptedKeyStorage(inner, tc.key)
			if err == nil {
				t.Errorf("expected error for master key %q, got nil", tc.name)
			}
		})
	}
}

// TestEncryptedKeyStoreContractCompliance runs the shared WritableKeyStore
// test suite (keystoretest.RunAll) against the EncryptedKeyStore wrapper,
// verifying it correctly implements the full interface contract including
// register, get, delete, list, overwrite, and asymmetric key handling.
func TestEncryptedKeyStoreContractCompliance(t *testing.T) {
	keystoretest.RunAll(t, func(t *testing.T) oa.KeyStorage {
		enc, _ := newTestEncryptedKeyStore(t)
		return enc
	})
}

// TestGetExpectedAlgPassthrough verifies that algorithm metadata is returned
// unchanged by the encrypted wrapper (algorithms are never encrypted).
func TestGetExpectedAlgPassthrough(t *testing.T) {
	enc, _ := newTestEncryptedKeyStore(t)

	if err := enc.RegisterKey("app-1", []byte("secret"), "HS512"); err != nil {
		t.Fatalf("RegisterKey failed: %v", err)
	}

	alg, err := enc.GetExpectedAlg("app-1")
	if err != nil {
		t.Fatalf("GetExpectedAlg failed: %v", err)
	}
	if alg != "HS512" {
		t.Errorf("expected HS512, got %s", alg)
	}
}

// TestDeleteKeyPassthrough verifies that deleting a key through the encrypted
// wrapper correctly removes it from the inner store.
func TestDeleteKeyPassthrough(t *testing.T) {
	enc, inner := newTestEncryptedKeyStore(t)

	if err := enc.RegisterKey("app-1", []byte("secret"), "HS256"); err != nil {
		t.Fatalf("RegisterKey failed: %v", err)
	}
	if err := enc.DeleteKey("app-1"); err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	if _, err := inner.GetVerifyKey("app-1"); err != oa.ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound from inner store, got %v", err)
	}
}

// TestListKeysPassthrough verifies that ListKeys returns the same client IDs
// regardless of whether encryption is active.
func TestListKeysPassthrough(t *testing.T) {
	enc, _ := newTestEncryptedKeyStore(t)

	enc.RegisterKey("a", []byte("s1"), "HS256")
	enc.RegisterKey("b", []byte("s2"), "HS256")

	keys, err := enc.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}
