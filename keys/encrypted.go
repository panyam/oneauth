package keys

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// EncryptedKeyStorage is a KeyStorage decorator that transparently encrypts
// sensitive key material at rest using AES-256-GCM. Two categories of input
// are encrypted on the way in (and decrypted on the way out):
//
//   - HMAC client secrets (HS256/HS384/HS512) — identified by Algorithm.
//   - PEM blocks whose header type contains "PRIVATE" — identified by
//     content (e.g., "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY",
//     "OPENSSH PRIVATE KEY"). The content-driven check matters because
//     downstream consumers may persist private keys under non-JWT
//     Algorithm strings (e.g., "ssh-ed25519" via the sshkeys submodule).
//
// Public PEMs (which back JWKS exposure) and any other plaintext pass
// through unencrypted — they are not sensitive.
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

// PutKey computes kid from plaintext, then encrypts HMAC secrets and PEM
// blocks of type "*PRIVATE*" before storing. Other inputs (notably public
// PEMs) are stored unmodified.
func (e *EncryptedKeyStorage) PutKey(ctx context.Context, req *PutKeyRequest) (*PutKeyResponse, error) {
	if req == nil || req.Record == nil {
		return nil, fmt.Errorf("PutKey: req.Record is required")
	}
	rec := req.Record
	// Compute kid from plaintext BEFORE encryption
	if rec.Kid == "" {
		rec.Kid = computeKid(rec.Key, rec.Algorithm)
	}

	if shouldEncrypt(rec) {
		keyBytes, ok := rec.Key.([]byte)
		if !ok {
			return nil, fmt.Errorf("encrypt-eligible key must be []byte, got %T", rec.Key)
		}
		encrypted, err := e.encrypt(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt key for %s: %w", rec.ClientID, err)
		}
		// Store with encrypted key but plaintext-derived kid
		return e.inner.PutKey(ctx, &PutKeyRequest{Record: &KeyRecord{
			ClientID:  rec.ClientID,
			Key:       encrypted,
			Algorithm: rec.Algorithm,
			Kid:       rec.Kid,
		}})
	}
	return e.inner.PutKey(ctx, req)
}

// GetKey retrieves and decrypts the key for the given clientID.
func (e *EncryptedKeyStorage) GetKey(ctx context.Context, req *GetKeyRequest) (*GetKeyResponse, error) {
	resp, err := e.inner.GetKey(ctx, req)
	if err != nil {
		return nil, err
	}
	return &GetKeyResponse{Record: e.maybeDecryptRecord(resp.Record)}, nil
}

// GetKeyByKid retrieves and decrypts the key matching the given kid.
func (e *EncryptedKeyStorage) GetKeyByKid(ctx context.Context, req *GetKeyByKidRequest) (*GetKeyByKidResponse, error) {
	resp, err := e.inner.GetKeyByKid(ctx, req)
	if err != nil {
		return nil, err
	}
	return &GetKeyByKidResponse{Record: e.maybeDecryptRecord(resp.Record)}, nil
}

// DeleteKey delegates to the inner store.
func (e *EncryptedKeyStorage) DeleteKey(ctx context.Context, req *DeleteKeyRequest) (*DeleteKeyResponse, error) {
	return e.inner.DeleteKey(ctx, req)
}

// ListKeyIDs delegates to the inner store.
func (e *EncryptedKeyStorage) ListKeyIDs(ctx context.Context, req *ListKeyIDsRequest) (*ListKeyIDsResponse, error) {
	return e.inner.ListKeyIDs(ctx, req)
}

// maybeDecryptRecord decrypts the Key field when the stored bytes look like
// AES-GCM ciphertext. Falls through to plaintext on either of two paths:
//
//   - The stored bytes start with "-----BEGIN", i.e., a PEM block — public
//     PEMs (always stored plaintext) and pre-encryption private/migration
//     PEMs both surface this way without an unnecessary decrypt attempt.
//   - The bytes are non-PEM and AES-GCM tag verification fails — assumed
//     to be a pre-encryption legacy HMAC secret and returned as-is. Logged
//     so accidental corruption isn't fully silent.
//
// AES-GCM output cannot itself start with "-----BEGIN" (the prepended nonce
// is random bytes), so the PEM-prefix check is a safe fast path.
func (e *EncryptedKeyStorage) maybeDecryptRecord(rec *KeyRecord) *KeyRecord {
	keyBytes, ok := rec.Key.([]byte)
	if !ok {
		return rec
	}
	if bytes.HasPrefix(keyBytes, pemPrefix) {
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

var pemPrefix = []byte("-----BEGIN")

// shouldEncrypt reports whether PutKey should encrypt rec.Key before storing.
// Content-driven for PEMs so a future consumer that persists private SSH
// keys under Algorithm="ssh-ed25519" gets covered without growing the
// algorithm allowlist.
func shouldEncrypt(rec *KeyRecord) bool {
	if isHMACAlgorithm(rec.Algorithm) {
		return true
	}
	keyBytes, ok := rec.Key.([]byte)
	if !ok {
		return false
	}
	return isPrivatePEM(keyBytes)
}

// isPrivatePEM reports whether b decodes as a PEM block whose header type
// contains "PRIVATE" (e.g., "PRIVATE KEY", "RSA PRIVATE KEY",
// "EC PRIVATE KEY", "OPENSSH PRIVATE KEY"). Anything that doesn't parse as
// a PEM block — or whose header lacks "PRIVATE" — returns false.
func isPrivatePEM(b []byte) bool {
	block, _ := pem.Decode(b)
	if block == nil {
		return false
	}
	return strings.Contains(block.Type, "PRIVATE")
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
