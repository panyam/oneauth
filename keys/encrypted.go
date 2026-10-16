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
	"errors"
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

	// AllowLegacyPlaintext accepts encrypt-eligible records (HMAC secrets,
	// private PEMs) that are stored in plaintext, as they were before
	// encryption was turned on. Off by default: with it off, a plaintext
	// secret in the store is ErrKeyDecrypt, so someone who can write the
	// store can't swap in a key of their choosing. Turn it on only to read
	// or MigrateLegacy such records.
	AllowLegacyPlaintext bool
}

// ErrKeyDecrypt is returned by GetKey and GetKeyByKid when a record that
// should be encrypted can't be opened: the master key is wrong, the bytes
// were altered, the ciphertext belongs to a different record, or it is
// plaintext and AllowLegacyPlaintext is off. The key is never returned in
// any of those cases.
var ErrKeyDecrypt = errors.New("keys: stored key could not be decrypted")

// encV1Prefix marks the current record format: AES-256-GCM with AAD that
// binds the ciphertext to its record (see recordAAD). Records without it
// are legacy: unbound ciphertext from before the prefix, or plaintext.
var encV1Prefix = []byte("oaenc1:")

// MigrateLegacy rewrites every legacy record in the current format and
// returns how many it rewrote. Unbound ciphertext from earlier versions is
// always migrated; plaintext records only when AllowLegacyPlaintext is on.
// Records already current, and public PEMs, are left alone. It stops at
// the first record it can't read or write.
func (e *EncryptedKeyStorage) MigrateLegacy(ctx context.Context) (int, error) {
	ids, err := e.inner.ListKeyIDs(ctx, &ListKeyIDsRequest{})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids.ClientIDs {
		resp, err := e.inner.GetKey(ctx, &GetKeyRequest{ClientID: id})
		if err != nil {
			return n, fmt.Errorf("migrate %q: %w", id, err)
		}
		raw, ok := resp.Record.Key.([]byte)
		if !ok || bytes.HasPrefix(raw, encV1Prefix) {
			continue
		}
		rec, err := e.decryptRecord(resp.Record)
		if err != nil {
			return n, fmt.Errorf("migrate %q: %w", id, err)
		}
		if !shouldEncrypt(rec) {
			continue
		}
		if _, err := e.PutKey(ctx, &PutKeyRequest{Record: rec}); err != nil {
			return n, fmt.Errorf("migrate %q: %w", id, err)
		}
		n++
	}
	return n, nil
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
		encrypted, err := e.encrypt(keyBytes, recordAAD(rec))
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
	rec, err := e.decryptRecord(resp.Record)
	if err != nil {
		return nil, err
	}
	return &GetKeyResponse{Record: rec}, nil
}

// GetKeyByKid retrieves and decrypts the key matching the given kid.
func (e *EncryptedKeyStorage) GetKeyByKid(ctx context.Context, req *GetKeyByKidRequest) (*GetKeyByKidResponse, error) {
	resp, err := e.inner.GetKeyByKid(ctx, req)
	if err != nil {
		return nil, err
	}
	rec, err := e.decryptRecord(resp.Record)
	if err != nil {
		return nil, err
	}
	return &GetKeyByKidResponse{Record: rec}, nil
}

// DeleteKey delegates to the inner store.
func (e *EncryptedKeyStorage) DeleteKey(ctx context.Context, req *DeleteKeyRequest) (*DeleteKeyResponse, error) {
	return e.inner.DeleteKey(ctx, req)
}

// ListKeyIDs delegates to the inner store.
func (e *EncryptedKeyStorage) ListKeyIDs(ctx context.Context, req *ListKeyIDsRequest) (*ListKeyIDsResponse, error) {
	return e.inner.ListKeyIDs(ctx, req)
}

// decryptRecord returns rec with its key decrypted, or ErrKeyDecrypt.
//
//   - Current records carry encV1Prefix and open only with their own AAD.
//   - A PEM block passes through when it's public. A private one is legacy
//     plaintext.
//   - Other bytes are tried as unbound ciphertext from before the prefix,
//     which is still accepted since only the master key could have written
//     it. Failing that they are legacy plaintext.
//
// Legacy plaintext is accepted only with AllowLegacyPlaintext, and only for
// records that PutKey would have encrypted; anything else (public keys,
// unknown algorithms) was never encrypted and passes through.
func (e *EncryptedKeyStorage) decryptRecord(rec *KeyRecord) (*KeyRecord, error) {
	keyBytes, ok := rec.Key.([]byte)
	if !ok {
		return rec, nil
	}
	withKey := func(k []byte) *KeyRecord {
		return &KeyRecord{ClientID: rec.ClientID, Key: k, Algorithm: rec.Algorithm, Kid: rec.Kid}
	}
	if bytes.HasPrefix(keyBytes, encV1Prefix) {
		plain, err := e.decrypt(keyBytes[len(encV1Prefix):], recordAAD(rec))
		if err != nil {
			return nil, fmt.Errorf("%w (client %q)", ErrKeyDecrypt, rec.ClientID)
		}
		return withKey(plain), nil
	}
	if !bytes.HasPrefix(keyBytes, pemPrefix) {
		if plain, err := e.decrypt(keyBytes, nil); err == nil {
			return withKey(plain), nil
		}
	}
	if !shouldEncrypt(rec) {
		return rec, nil
	}
	if !e.AllowLegacyPlaintext {
		return nil, fmt.Errorf("%w (client %q): not encrypted, and AllowLegacyPlaintext is off", ErrKeyDecrypt, rec.ClientID)
	}
	log.Printf("EncryptedKeyStorage: client %q is stored in plaintext; run MigrateLegacy to encrypt it", rec.ClientID)
	return rec, nil
}

// recordAAD binds a ciphertext to the record it was written for, so it
// doesn't open when copied into another client's record or one with a
// different algorithm or kid.
func recordAAD(rec *KeyRecord) []byte {
	return []byte("oneauth-key\x00" + rec.ClientID + "\x00" + rec.Algorithm + "\x00" + rec.Kid)
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

// encrypt produces encV1Prefix, a random 12-byte nonce, then the
// AES-256-GCM ciphertext of plaintext under aad.
func (e *EncryptedKeyStorage) encrypt(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	out := append([]byte(nil), encV1Prefix...)
	out = append(out, nonce...)
	return e.aead.Seal(out, nonce, plaintext, aad), nil
}

// decrypt splits off the nonce and opens the AES-256-GCM ciphertext under
// aad. The caller strips any format prefix first.
func (e *EncryptedKeyStorage) decrypt(ciphertext, aad []byte) ([]byte, error) {
	nonceSize := e.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes, need at least %d", len(ciphertext), nonceSize)
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return e.aead.Open(nil, nonce, ct, aad)
}

// isHMACAlgorithm reports whether alg is an HMAC-based JWT signing algorithm.
func isHMACAlgorithm(alg string) bool {
	return alg == "HS256" || alg == "HS384" || alg == "HS512"
}
