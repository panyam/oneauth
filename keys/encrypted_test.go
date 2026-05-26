// Tests for the EncryptedKeyStore decorator, verifying encryption at rest,
// round-trip correctness, plaintext migration, and full interface compliance.
package keys_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/keystoretest"
	"github.com/panyam/oneauth/utils"
)

const testMasterKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newTestEncryptedKeyStore(t *testing.T) (*keys.EncryptedKeyStorage, *keys.InMemoryKeyStore) {
	t.Helper()
	inner := keys.NewInMemoryKeyStore()
	enc, err := keys.NewEncryptedKeyStorage(inner, testMasterKey)
	if err != nil {
		t.Fatalf("NewEncryptedKeyStorage failed: %v", err)
	}
	return enc, inner
}

func randomMasterKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	return hex.EncodeToString(key)
}

func putKey(t *testing.T, ks keys.KeyStorage, rec *keys.KeyRecord) {
	t.Helper()
	if _, err := ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: rec}); err != nil {
		t.Fatalf("PutKey failed: %v", err)
	}
}

func getKeyBytes(t *testing.T, ks keys.KeyLookup, clientID string) []byte {
	t.Helper()
	resp, err := ks.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: clientID})
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	b, ok := resp.Record.Key.([]byte)
	if !ok {
		t.Fatalf("expected []byte, got %T", resp.Record.Key)
	}
	return b
}

// TestEncryptedKeyStoreRoundTrip verifies that storing a secret via the
// encrypted wrapper and reading it back yields the original plaintext.
func TestEncryptedKeyStoreRoundTrip(t *testing.T) {
	enc, _ := newTestEncryptedKeyStore(t)
	secret := []byte("my-super-secret-key")

	putKey(t, enc, &keys.KeyRecord{ClientID: "app-1", Key: secret, Algorithm: "HS256"})

	got := getKeyBytes(t, enc, "app-1")
	if !bytes.Equal(got, secret) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, secret)
	}
}

// TestStoredBytesAreEncrypted verifies that the inner store holds ciphertext,
// not the original plaintext secret.
func TestStoredBytesAreEncrypted(t *testing.T) {
	enc, inner := newTestEncryptedKeyStore(t)
	secret := []byte("plaintext-secret-value")

	putKey(t, enc, &keys.KeyRecord{ClientID: "app-1", Key: secret, Algorithm: "HS256"})

	rawBytes := getKeyBytes(t, inner, "app-1")
	if bytes.Equal(rawBytes, secret) {
		t.Error("inner store contains plaintext secret — encryption is not working")
	}
	if len(rawBytes) <= len(secret) {
		t.Errorf("ciphertext (%d bytes) should be longer than plaintext (%d bytes)", len(rawBytes), len(secret))
	}
}

// TestAsymmetricPassthrough verifies that asymmetric keys (RS256 public PEM)
// are stored in the inner store without modification.
func TestAsymmetricPassthrough(t *testing.T) {
	enc, inner := newTestEncryptedKeyStore(t)

	_, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair failed: %v", err)
	}

	putKey(t, enc, &keys.KeyRecord{ClientID: "app-rsa", Key: pubPEM, Algorithm: "RS256"})

	raw := getKeyBytes(t, inner, "app-rsa")
	if !bytes.Equal(raw, pubPEM) {
		t.Error("asymmetric key was modified — should pass through unchanged")
	}
	got := getKeyBytes(t, enc, "app-rsa")
	if !bytes.Equal(got, pubPEM) {
		t.Error("encrypted wrapper altered asymmetric key on read")
	}
}

// TestWrongMasterKeyFails verifies that a secret encrypted with one master key
// cannot be decrypted with a different master key.
func TestWrongMasterKeyFails(t *testing.T) {
	inner := keys.NewInMemoryKeyStore()
	secret := []byte("sensitive-secret")

	encA, err := keys.NewEncryptedKeyStorage(inner, testMasterKey)
	if err != nil {
		t.Fatalf("NewEncryptedKeyStorage (A) failed: %v", err)
	}
	putKey(t, encA, &keys.KeyRecord{ClientID: "app-1", Key: secret, Algorithm: "HS256"})

	encB, err := keys.NewEncryptedKeyStorage(inner, randomMasterKey(t))
	if err != nil {
		t.Fatalf("NewEncryptedKeyStorage (B) failed: %v", err)
	}
	got := getKeyBytes(t, encB, "app-1")
	if bytes.Equal(got, secret) {
		t.Error("wrong master key returned the original plaintext — encryption is broken")
	}
}

// TestPlaintextMigration verifies backward compatibility: a key stored directly
// in the inner store (without encryption) is still readable through the
// encrypted wrapper.
func TestPlaintextMigration(t *testing.T) {
	enc, inner := newTestEncryptedKeyStore(t)
	secret := []byte("legacy-unencrypted-secret")

	putKey(t, inner, &keys.KeyRecord{ClientID: "legacy-app", Key: secret, Algorithm: "HS256"})

	got := getKeyBytes(t, enc, "legacy-app")
	if !bytes.Equal(got, secret) {
		t.Errorf("plaintext migration failed: got %q, want %q", got, secret)
	}
}

// TestInvalidMasterKey verifies that NewEncryptedKeyStorage rejects bad keys.
func TestInvalidMasterKey(t *testing.T) {
	inner := keys.NewInMemoryKeyStore()

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
			_, err := keys.NewEncryptedKeyStorage(inner, tc.key)
			if err == nil {
				t.Errorf("expected error for master key %q, got nil", tc.name)
			}
		})
	}
}

// TestEncryptedKeyStoreContractCompliance runs the shared KeyStorage
// test suite against the EncryptedKeyStore wrapper.
func TestEncryptedKeyStoreContractCompliance(t *testing.T) {
	keystoretest.RunAll(t, func(t *testing.T) keys.KeyStorage {
		enc, _ := newTestEncryptedKeyStore(t)
		return enc
	})
}

// TestDeleteKeyPassthrough verifies that deleting a key through the encrypted
// wrapper correctly removes it from the inner store.
func TestDeleteKeyPassthrough(t *testing.T) {
	enc, inner := newTestEncryptedKeyStore(t)

	putKey(t, enc, &keys.KeyRecord{ClientID: "app-1", Key: []byte("secret"), Algorithm: "HS256"})
	if _, err := enc.DeleteKey(context.Background(), &keys.DeleteKeyRequest{ClientID: "app-1"}); err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}
	if _, err := inner.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: "app-1"}); err != keys.ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound from inner store, got %v", err)
	}
}

// TestListKeysPassthrough verifies that ListKeyIDs returns the same client IDs
// regardless of whether encryption is active.
func TestListKeysPassthrough(t *testing.T) {
	enc, _ := newTestEncryptedKeyStore(t)

	putKey(t, enc, &keys.KeyRecord{ClientID: "a", Key: []byte("s1"), Algorithm: "HS256"})
	putKey(t, enc, &keys.KeyRecord{ClientID: "b", Key: []byte("s2"), Algorithm: "HS256"})

	resp, err := enc.ListKeyIDs(context.Background(), &keys.ListKeyIDsRequest{})
	if err != nil {
		t.Fatalf("ListKeyIDs failed: %v", err)
	}
	if len(resp.ClientIDs) != 2 {
		t.Errorf("expected 2 keys, got %d", len(resp.ClientIDs))
	}
}
