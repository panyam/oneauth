package oneauth

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

// EncryptedKeyStore is a WritableKeyStore decorator that transparently encrypts
// HMAC (HS256/HS384/HS512) client secrets at rest using AES-256-GCM envelope
// encryption. Asymmetric keys (RS256, ES256 public keys) are stored unencrypted
// since they are not sensitive.
//
// The decorator pattern means a single implementation works with any backend
// (FS, GORM, GAE, InMemory) without requiring schema changes. Encryption is
// optional — if no master key is configured, the server runs without it (with a
// log warning).
//
// Migration: if GCM decryption fails on read, the wrapper falls back to treating
// the stored bytes as plaintext. This allows transparent migration from unencrypted
// to encrypted storage without a data migration step.
type EncryptedKeyStore struct {
	inner WritableKeyStore  // the underlying store that persists key material
	aead  cipher.AEAD       // AES-256-GCM cipher derived from the master key
}

// NewEncryptedKeyStore creates an EncryptedKeyStore that wraps inner with
// AES-256-GCM encryption derived from masterKeyHex.
//
// masterKeyHex must be exactly 64 hex characters representing a 32-byte key.
// Generate one with: openssl rand -hex 32
//
// The raw master key is never used directly for encryption. Instead, HKDF-SHA256
// derives an encryption-specific key using the info string
// "oneauth-keystore-encryption-v1", allowing future key versioning without
// changing the master key.
func NewEncryptedKeyStore(inner WritableKeyStore, masterKeyHex string) (*EncryptedKeyStore, error) {
	masterKeyHex = strings.TrimSpace(masterKeyHex)
	if len(masterKeyHex) != 64 {
		return nil, fmt.Errorf("master key must be 64 hex characters (32 bytes), got %d", len(masterKeyHex))
	}

	masterKey, err := hex.DecodeString(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("master key is not valid hex: %w", err)
	}

	// Derive a purpose-specific encryption key via HKDF-SHA256.
	// Using HKDF allows the same master key to derive different keys for
	// different purposes (e.g., future key rotation or additional encryption
	// contexts) by changing the info string.
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

	return &EncryptedKeyStore{inner: inner, aead: aead}, nil
}

// RegisterKey stores a signing key for the given client. For HMAC algorithms,
// the key (which must be []byte) is encrypted with AES-256-GCM before being
// passed to the inner store. A random 12-byte nonce is prepended to the
// ciphertext. Asymmetric keys (public key PEM bytes) pass through unmodified.
func (e *EncryptedKeyStore) RegisterKey(clientID string, key any, algorithm string) error {
	if isHMACAlgorithm(algorithm) {
		keyBytes, ok := key.([]byte)
		if !ok {
			return fmt.Errorf("HMAC key must be []byte, got %T", key)
		}
		encrypted, err := e.encrypt(keyBytes)
		if err != nil {
			return fmt.Errorf("failed to encrypt key for %s: %w", clientID, err)
		}
		return e.inner.RegisterKey(clientID, encrypted, algorithm)
	}
	return e.inner.RegisterKey(clientID, key, algorithm)
}

// GetVerifyKey returns the verification key for the given client. For HMAC
// algorithms, the stored ciphertext is decrypted back to the original shared
// secret. If decryption fails (e.g., the key was stored before encryption was
// enabled), the raw bytes are returned as-is for backward compatibility.
func (e *EncryptedKeyStore) GetVerifyKey(clientID string) (any, error) {
	key, err := e.inner.GetVerifyKey(clientID)
	if err != nil {
		return nil, err
	}
	return e.maybeDecrypt(clientID, key)
}

// GetSigningKey returns the signing key for the given client. Behaves
// identically to GetVerifyKey for HMAC algorithms (same shared secret),
// with the same decryption and plaintext-fallback logic.
func (e *EncryptedKeyStore) GetSigningKey(clientID string) (any, error) {
	key, err := e.inner.GetSigningKey(clientID)
	if err != nil {
		return nil, err
	}
	return e.maybeDecrypt(clientID, key)
}

// GetExpectedAlg delegates directly to the inner store. Algorithm metadata
// is not encrypted.
func (e *EncryptedKeyStore) GetExpectedAlg(clientID string) (string, error) {
	return e.inner.GetExpectedAlg(clientID)
}

// DeleteKey delegates directly to the inner store. No decryption needed.
func (e *EncryptedKeyStore) DeleteKey(clientID string) error {
	return e.inner.DeleteKey(clientID)
}

// ListKeys delegates directly to the inner store. Returns client IDs only,
// no key material involved.
func (e *EncryptedKeyStore) ListKeys() ([]string, error) {
	return e.inner.ListKeys()
}

// maybeDecrypt checks whether the key for clientID is an HMAC secret and, if
// so, attempts AES-256-GCM decryption. If decryption fails (the data is not
// valid GCM ciphertext), the raw bytes are returned unchanged. This provides
// a seamless migration path: keys stored before encryption was enabled are
// still readable without a data migration.
func (e *EncryptedKeyStore) maybeDecrypt(clientID string, key any) (any, error) {
	keyBytes, ok := key.([]byte)
	if !ok {
		// Not []byte — asymmetric key object or other type, pass through
		return key, nil
	}

	// Only decrypt HMAC keys; asymmetric PEM bytes pass through
	alg, err := e.inner.GetExpectedAlg(clientID)
	if err != nil {
		return nil, err
	}
	if !isHMACAlgorithm(alg) {
		return key, nil
	}

	decrypted, err := e.decrypt(keyBytes)
	if err != nil {
		// Decryption failed — assume this is a pre-encryption plaintext secret.
		// Log for visibility so operators know migration is happening.
		log.Printf("EncryptedKeyStore: GCM decryption failed for client %q, returning as plaintext (pre-encryption migration)", clientID)
		return key, nil
	}
	return decrypted, nil
}

// encrypt produces AES-256-GCM ciphertext with a random 12-byte nonce prepended.
// Output format: [nonce (12 bytes)][ciphertext+tag].
func (e *EncryptedKeyStore) encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return e.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt extracts the prepended nonce and decrypts AES-256-GCM ciphertext.
// Returns an error if the ciphertext is too short or authentication fails.
func (e *EncryptedKeyStore) decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := e.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes, need at least %d", len(ciphertext), nonceSize)
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return e.aead.Open(nil, nonce, ct, nil)
}

// isHMACAlgorithm reports whether alg is an HMAC-based JWT signing algorithm
// (HS256, HS384, or HS512). These algorithms use a shared secret that must
// be encrypted at rest, unlike asymmetric algorithms where only the public
// key is stored.
func isHMACAlgorithm(alg string) bool {
	return alg == "HS256" || alg == "HS384" || alg == "HS512"
}
