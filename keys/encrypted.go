package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// EncryptedKeyStorage is a KeyStorage decorator that transparently encrypts
// HMAC (HS256/HS384/HS512) client secrets at rest using AES-256-GCM.
// Asymmetric keys (RS256, ES256 public keys) pass through unencrypted.
//
// Because it wraps KeyStorage and operates on KeyRecord, it only needs to
// implement 5 methods — no manual forwarding of individual field accessors.
//
// The kid is computed from plaintext key material in PutKey before encryption,
// so kid-based lookups work correctly even though the stored bytes are encrypted.
type EncryptedKeyStorage struct {
	inner KeyStorage
	aead  cipher.AEAD
}

// NewEncryptedKeyStorage creates an EncryptedKeyStorage wrapping inner.
// masterKeyHex must be exactly 64 hex characters (32 bytes).
func NewEncryptedKeyStorage(inner KeyStorage, masterKeyHex string) (*EncryptedKeyStorage, error) {
	masterKeyHex = strings.TrimSpace(masterKeyHex)
	if len(masterKeyHex) != 64 {
		return nil, fmt.Errorf("master key must be 64 hex characters (32 bytes), got %d", len(masterKeyHex))
	}

	masterKey, err := hex.DecodeString(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("master key is not valid hex: %w", err)
	}

	hkdfReader := hkdf.New(sha256.New, masterKey, nil, []byte("oneauth-keystore-encryption-v1"))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &EncryptedKeyStorage{inner: inner, aead: aead}, nil
}

// PutKey computes kid from plaintext, then encrypts HMAC keys before storing.
func (e *EncryptedKeyStorage) PutKey(rec *KeyRecord) error {
	// Compute kid from plaintext BEFORE encryption
	if rec.Kid == "" {
		rec.Kid = computeKid(rec.Key, rec.Algorithm)
	}

	if isHMACAlgorithm(rec.Algorithm) {
		keyBytes, ok := rec.Key.([]byte)
		if !ok {
			return fmt.Errorf("HMAC key must be []byte, got %T", rec.Key)
		}
		encrypted, err := e.encrypt(keyBytes)
		if err != nil {
			return fmt.Errorf("failed to encrypt key for %s: %w", rec.ClientID, err)
		}
		// Store with encrypted key but plaintext-derived kid
		return e.inner.PutKey(&KeyRecord{
			ClientID:  rec.ClientID,
			Key:       encrypted,
			Algorithm: rec.Algorithm,
			Kid:       rec.Kid,
		})
	}
	return e.inner.PutKey(rec)
}

// GetKey retrieves and decrypts the key for the given clientID.
func (e *EncryptedKeyStorage) GetKey(clientID string) (*KeyRecord, error) {
	rec, err := e.inner.GetKey(clientID)
	if err != nil {
		return nil, err
	}
	return e.maybeDecryptRecord(rec), nil
}

// GetKeyByKid retrieves and decrypts the key matching the given kid.
func (e *EncryptedKeyStorage) GetKeyByKid(kid string) (*KeyRecord, error) {
	rec, err := e.inner.GetKeyByKid(kid)
	if err != nil {
		return nil, err
	}
	return e.maybeDecryptRecord(rec), nil
}

// DeleteKey delegates to the inner store.
func (e *EncryptedKeyStorage) DeleteKey(clientID string) error {
	return e.inner.DeleteKey(clientID)
}

// ListKeyIDs delegates to the inner store.
func (e *EncryptedKeyStorage) ListKeyIDs() ([]string, error) {
	return e.inner.ListKeyIDs()
}

// maybeDecryptRecord decrypts the Key field for HMAC algorithms.
// Falls back to plaintext if decryption fails (pre-encryption migration).
func (e *EncryptedKeyStorage) maybeDecryptRecord(rec *KeyRecord) *KeyRecord {
	if !isHMACAlgorithm(rec.Algorithm) {
		return rec
	}
	keyBytes, ok := rec.Key.([]byte)
	if !ok {
		return rec
	}
	decrypted, err := e.decrypt(keyBytes)
	if err != nil {
		log.Printf("EncryptedKeyStorage: GCM decryption failed for client %q, returning as plaintext (pre-encryption migration)", rec.ClientID)
		return rec
	}
	return &KeyRecord{
		ClientID:  rec.ClientID,
		Key:       decrypted,
		Algorithm: rec.Algorithm,
		Kid:       rec.Kid,
	}
}

// Backward-compatible aliases

// RegisterKey is a convenience method for callers using the old interface.
func (e *EncryptedKeyStorage) RegisterKey(clientID string, key any, algorithm string) error {
	return e.PutKey(&KeyRecord{ClientID: clientID, Key: key, Algorithm: algorithm})
}

// GetVerifyKey is a convenience method for callers using the old interface.
func (e *EncryptedKeyStorage) GetVerifyKey(clientID string) (any, error) {
	rec, err := e.GetKey(clientID)
	if err != nil {
		return nil, err
	}
	return rec.Key, nil
}

// GetSigningKey is a convenience method for callers using the old interface.
func (e *EncryptedKeyStorage) GetSigningKey(clientID string) (any, error) {
	return e.GetVerifyKey(clientID)
}

// GetExpectedAlg is a convenience method for callers using the old interface.
func (e *EncryptedKeyStorage) GetExpectedAlg(clientID string) (string, error) {
	rec, err := e.GetKey(clientID)
	if err != nil {
		return "", err
	}
	return rec.Algorithm, nil
}

// ListKeys is a convenience alias for ListKeyIDs.
func (e *EncryptedKeyStorage) ListKeys() ([]string, error) {
	return e.ListKeyIDs()
}

// GetCurrentKid returns the kid for the given clientID.
func (e *EncryptedKeyStorage) GetCurrentKid(clientID string) (string, error) {
	rec, err := e.GetKey(clientID)
	if err != nil {
		return "", err
	}
	return rec.Kid, nil
}

// encrypt produces AES-256-GCM ciphertext with a random 12-byte nonce prepended.
func (e *EncryptedKeyStorage) encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return e.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt extracts the prepended nonce and decrypts AES-256-GCM ciphertext.
func (e *EncryptedKeyStorage) decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := e.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes, need at least %d", len(ciphertext), nonceSize)
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return e.aead.Open(nil, nonce, ct, nil)
}

// isHMACAlgorithm reports whether alg is an HMAC-based JWT signing algorithm.
func isHMACAlgorithm(alg string) bool {
	return alg == "HS256" || alg == "HS384" || alg == "HS512"
}
