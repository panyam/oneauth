package keys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// Sealer encrypts small secrets for storage with AES-256-GCM. Its output
// is the `oaenc1:` format EncryptedKeyStorage writes: the prefix, a random
// 12-byte nonce, then the ciphertext and tag.
//
// The AES key is derived from a 64-hex-character master key with HKDF-SHA256
// under a purpose label, so one master key can serve several stores without
// any two sharing an AES key. Each Seal also takes associated data (AAD).
// Callers pass something naming the record (its owner, its kind), and a
// ciphertext copied into another record then fails to open.
//
// A Sealer is safe for concurrent use.
type Sealer struct {
	aead cipher.AEAD
}

// ErrSealedOpen is returned by Open when the input can't be opened: it
// lacks the `oaenc1:` prefix, it is truncated, the master key or purpose
// differs from the one it was sealed with, the bytes were altered, or the
// AAD names another record. Open never says which, and never returns any
// plaintext with it.
var ErrSealedOpen = errors.New("keys: sealed value could not be opened")

// KeyStorePurpose is the HKDF label EncryptedKeyStorage and
// EncryptedKidStorage derive their AES key with. It is fixed by the records
// already written under it.
const KeyStorePurpose = "oneauth-keystore-encryption-v1"

// NewSealer derives an AES-256-GCM key from masterKeyHex under purpose.
// masterKeyHex must be exactly 64 hex characters (32 bytes); surrounding
// whitespace is ignored, as it often comes from an env var or a file. An
// empty purpose is refused, so two callers can't share a key by accident.
func NewSealer(masterKeyHex, purpose string) (*Sealer, error) {
	if purpose == "" {
		return nil, fmt.Errorf("sealer purpose is required")
	}
	masterKeyHex = strings.TrimSpace(masterKeyHex)
	if len(masterKeyHex) != 64 {
		return nil, fmt.Errorf("master key must be 64 hex characters (32 bytes), got %d", len(masterKeyHex))
	}
	masterKey, err := hex.DecodeString(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("master key is not valid hex: %w", err)
	}
	derived := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, masterKey, nil, []byte(purpose)), derived); err != nil {
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	return &Sealer{aead: aead}, nil
}

// Seal encrypts plaintext under aad with a fresh random nonce. Sealing the
// same plaintext twice gives different bytes.
func (s *Sealer) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	out := append([]byte(nil), encV1Prefix...)
	out = append(out, nonce...)
	return s.aead.Seal(out, nonce, plaintext, aad), nil
}

// Open reverses Seal. It needs the same master key, purpose and aad, and
// answers ErrSealedOpen otherwise.
func (s *Sealer) Open(sealed, aad []byte) ([]byte, error) {
	if !IsSealed(sealed) {
		return nil, ErrSealedOpen
	}
	plain, err := s.openRaw(sealed[len(encV1Prefix):], aad)
	if err != nil {
		return nil, ErrSealedOpen
	}
	return plain, nil
}

// IsSealed reports whether b starts with the `oaenc1:` prefix. It says
// nothing about whether b opens.
func IsSealed(b []byte) bool {
	return bytes.HasPrefix(b, encV1Prefix)
}

// openRaw opens nonce||ciphertext with no prefix. EncryptedKeyStorage uses
// it for legacy records written before the prefix existed.
func (s *Sealer) openRaw(ciphertext, aad []byte) ([]byte, error) {
	nonceSize := s.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes, need at least %d", len(ciphertext), nonceSize)
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return s.aead.Open(nil, nonce, ct, aad)
}
