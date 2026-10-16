package keys

import (
	"context"
	"fmt"
)

// EncryptedKidStorage is the KidStorage counterpart of EncryptedKeyStorage.
// A retired signing key kept for its grace period is as secret as it was
// before rotation, so persistent KidStorage backends (FS, GORM, GAE) get the
// same treatment: HMAC secrets and private PEMs are stored as `oaenc1:`
// AES-256-GCM records with AAD over client, alg and kid, a record that
// won't open is ErrKeyDecrypt, and plaintext is refused unless
// AllowLegacyPlaintext is on. Public keys pass through.
//
// Use the same master key as the EncryptedKeyStorage the keys rotate out
// of; the two are independent otherwise.
type EncryptedKidStorage struct {
	inner KidStorage
	seal  *EncryptedKeyStorage

	// AllowLegacyPlaintext accepts encrypt-eligible records stored in
	// plaintext, as they were before this decorator was added. Off by
	// default, for the same reason as EncryptedKeyStorage's option.
	AllowLegacyPlaintext bool
}

// NewEncryptedKidStorage wraps inner. masterKeyHex must be exactly 64 hex
// characters (32 bytes), as for NewEncryptedKeyStorage.
func NewEncryptedKidStorage(inner KidStorage, masterKeyHex string) (*EncryptedKidStorage, error) {
	seal, err := NewEncryptedKeyStorage(nil, masterKeyHex)
	if err != nil {
		return nil, err
	}
	return &EncryptedKidStorage{inner: inner, seal: seal}, nil
}

// Add encrypts an HMAC secret or private PEM before handing the record to
// inner; other keys are stored as given. The kid is the caller's, since
// KidStorage is indexed by it.
func (k *EncryptedKidStorage) Add(ctx context.Context, req *AddKidRequest) (*AddKidResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("Add: req is required")
	}
	rec := &KeyRecord{ClientID: req.ClientID, Key: req.Key, Algorithm: req.Algorithm, Kid: req.Kid}
	if !shouldEncrypt(rec) {
		return k.inner.Add(ctx, req)
	}
	keyBytes, ok := req.Key.([]byte)
	if !ok {
		return nil, fmt.Errorf("encrypt-eligible key must be []byte, got %T", req.Key)
	}
	sealed, err := k.seal.encrypt(keyBytes, recordAAD(rec))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt retired key %s: %w", req.Kid, err)
	}
	out := *req
	out.Key = sealed
	return k.inner.Add(ctx, &out)
}

// GetKeyByKid reads through inner and decrypts, or returns ErrKeyDecrypt.
// Unknown and expired kids keep inner's error.
func (k *EncryptedKidStorage) GetKeyByKid(ctx context.Context, req *GetKeyByKidRequest) (*GetKeyByKidResponse, error) {
	resp, err := k.inner.GetKeyByKid(ctx, req)
	if err != nil {
		return nil, err
	}
	rec, err := k.seal.openRecord(resp.Record, k.AllowLegacyPlaintext)
	if err != nil {
		return nil, err
	}
	return &GetKeyByKidResponse{Record: rec}, nil
}

// GetKey delegates to inner, which answers ErrKeyNotFound: KidStorage is
// only meaningful by kid.
func (k *EncryptedKidStorage) GetKey(ctx context.Context, req *GetKeyRequest) (*GetKeyResponse, error) {
	return k.inner.GetKey(ctx, req)
}

// Remove delegates to inner; nothing to decrypt.
func (k *EncryptedKidStorage) Remove(ctx context.Context, req *RemoveKidRequest) (*RemoveKidResponse, error) {
	return k.inner.Remove(ctx, req)
}

// CleanExpired delegates to inner; expiry is stored in the clear.
func (k *EncryptedKidStorage) CleanExpired(ctx context.Context, req *CleanExpiredRequest) (*CleanExpiredResponse, error) {
	return k.inner.CleanExpired(ctx, req)
}

var _ KidStorage = (*EncryptedKidStorage)(nil)
