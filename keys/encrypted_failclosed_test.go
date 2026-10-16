package keys_test

// EncryptedKeyStorage fails closed, issue 88's "Key Management" walk. A
// record that doesn't decrypt is an error rather than a key, a ciphertext
// only opens under the record it was written for, and plaintext secrets in
// the store are refused unless the caller is migrating.
//
// References:
//   - NIST SP 800-38D §5.2.1.1 (AAD binds context to a GCM ciphertext)
//   - CWE-311 (https://cwe.mitre.org/data/definitions/311.html)
//   - CWE-354 (https://cwe.mitre.org/data/definitions/354.html)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"

	"github.com/panyam/oneauth/keys"
)

func storedBytes(t *testing.T, inner keys.KeyLookup, clientID string) []byte {
	t.Helper()
	resp, err := inner.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: clientID})
	if err != nil {
		t.Fatalf("inner GetKey: %v", err)
	}
	return append([]byte(nil), resp.Record.Key.([]byte)...)
}

func getErr(ks keys.KeyLookup, clientID string) error {
	_, err := ks.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: clientID})
	return err
}

// See: https://cwe.mitre.org/data/definitions/354.html
func TestEncryptedFailClosed_WrongMasterKeyIsAnError(t *testing.T) {
	inner := keys.NewInMemoryKeyStore()
	encA, _ := keys.NewEncryptedKeyStorage(inner, testMasterKey)
	putKey(t, encA, &keys.KeyRecord{ClientID: "app-1", Key: []byte("sensitive-secret-32-bytes-long!!"), Algorithm: "HS256"})

	encB, _ := keys.NewEncryptedKeyStorage(inner, randomMasterKey(t))
	if err := getErr(encB, "app-1"); !errors.Is(err, keys.ErrKeyDecrypt) {
		t.Fatalf("GetKey under the wrong master key: got %v, want ErrKeyDecrypt", err)
	}
}

func TestEncryptedFailClosed_TamperedCiphertextIsAnError(t *testing.T) {
	enc, inner := newTestEncryptedKeyStore(t)
	putKey(t, enc, &keys.KeyRecord{ClientID: "app-1", Key: []byte("sensitive-secret-32-bytes-long!!"), Algorithm: "HS256"})
	ct := storedBytes(t, inner, "app-1")
	ct[len(ct)-1] ^= 1
	putKey(t, inner, &keys.KeyRecord{ClientID: "app-1", Key: ct, Algorithm: "HS256", Kid: "irrelevant"})

	if err := getErr(enc, "app-1"); !errors.Is(err, keys.ErrKeyDecrypt) {
		t.Fatalf("GetKey of a tampered record: got %v, want ErrKeyDecrypt", err)
	}
}

// Someone who can write the store copies app-1's ciphertext into app-2's
// record. Without context bound into the ciphertext, app-2 would now verify
// tokens with app-1's secret.
//
// See: https://cwe.mitre.org/data/definitions/311.html
func TestEncryptedFailClosed_CiphertextOnlyOpensForItsRecord(t *testing.T) {
	enc, inner := newTestEncryptedKeyStore(t)
	putKey(t, enc, &keys.KeyRecord{ClientID: "app-1", Key: []byte("app-1-secret-that-is-32-bytes-ok"), Algorithm: "HS256"})
	putKey(t, enc, &keys.KeyRecord{ClientID: "app-2", Key: []byte("app-2-secret-that-is-32-bytes-ok"), Algorithm: "HS256"})

	app2, err := inner.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: "app-2"})
	if err != nil {
		t.Fatal(err)
	}
	putKey(t, inner, &keys.KeyRecord{ClientID: "app-2", Key: storedBytes(t, inner, "app-1"), Algorithm: "HS256", Kid: app2.Record.Kid})

	if err := getErr(enc, "app-2"); !errors.Is(err, keys.ErrKeyDecrypt) {
		t.Fatalf("app-1's ciphertext under app-2's record: got %v, want ErrKeyDecrypt", err)
	}
}

// Swapping a ciphertext for a plaintext secret of the attacker's choosing
// would otherwise be accepted as a legacy record.
func TestEncryptedFailClosed_PlaintextNeedsTheLegacyOption(t *testing.T) {
	enc, inner := newTestEncryptedKeyStore(t)
	secret := []byte("attacker-chosen-secret-32-bytes!")
	putKey(t, inner, &keys.KeyRecord{ClientID: "app-1", Key: secret, Algorithm: "HS256"})

	if err := getErr(enc, "app-1"); !errors.Is(err, keys.ErrKeyDecrypt) {
		t.Fatalf("plaintext HMAC secret in the store: got %v, want ErrKeyDecrypt", err)
	}

	enc.AllowLegacyPlaintext = true
	if got := getKeyBytes(t, enc, "app-1"); !bytes.Equal(got, secret) {
		t.Fatalf("with AllowLegacyPlaintext: got %q, want the plaintext", got)
	}
}

// legacyV0 encrypts the way EncryptedKeyStorage did before records carried
// a version and AAD: HKDF-derived AES-256-GCM, nonce prepended, no AAD.
func legacyV0(t *testing.T, masterHex string, plaintext []byte) []byte {
	t.Helper()
	master, _ := hex.DecodeString(masterHex)
	k := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, master, nil, []byte("oneauth-keystore-encryption-v1")), k); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(k)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	return aead.Seal(nonce, nonce, plaintext, nil)
}

// Records written before this change still read, and MigrateLegacy rewrites
// them (and, when allowed, plaintext ones) in the current format.
func TestEncryptedFailClosed_LegacyRecordsReadAndMigrate(t *testing.T) {
	enc, inner := newTestEncryptedKeyStore(t)
	v0Secret := []byte("v0-encrypted-secret-32-bytes-ok!")
	plainSecret := []byte("plaintext-legacy-secret-32-bytes")
	putKey(t, inner, &keys.KeyRecord{ClientID: "v0-app", Key: legacyV0(t, testMasterKey, v0Secret), Algorithm: "HS256", Kid: "kid-v0"})
	putKey(t, inner, &keys.KeyRecord{ClientID: "plain-app", Key: plainSecret, Algorithm: "HS256", Kid: "kid-plain"})

	if got := getKeyBytes(t, enc, "v0-app"); !bytes.Equal(got, v0Secret) {
		t.Fatalf("v0 record: got %q", got)
	}

	enc.AllowLegacyPlaintext = true
	n, err := enc.MigrateLegacy(context.Background())
	if err != nil {
		t.Fatalf("MigrateLegacy: %v", err)
	}
	if n != 2 {
		t.Fatalf("MigrateLegacy rewrote %d records, want 2", n)
	}

	enc.AllowLegacyPlaintext = false
	for id, want := range map[string][]byte{"v0-app": v0Secret, "plain-app": plainSecret} {
		if got := getKeyBytes(t, enc, id); !bytes.Equal(got, want) {
			t.Fatalf("%s after migration: got %q", id, got)
		}
		if raw := storedBytes(t, inner, id); bytes.Contains(raw, want) {
			t.Fatalf("%s still stored in plaintext after migration", id)
		}
	}
}
