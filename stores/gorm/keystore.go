//go:build !wasm
// +build !wasm

package gorm

import (
	"context"
	"fmt"
	"time"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
	"gorm.io/gorm"
)

// SigningKeyModel is the GORM model for per-client signing keys.
type SigningKeyModel struct {
	ClientID  string    `gorm:"primaryKey;size:128"`
	Key       []byte    `gorm:"not null"`
	Algorithm string    `gorm:"size:16;not null"`
	Kid       string    `gorm:"size:128;index:idx_kid,unique"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

func (SigningKeyModel) TableName() string {
	return "signing_keys"
}

// KeyStore implements keys.KeyStorage using GORM.
type KeyStore struct {
	db *gorm.DB
}

// NewKeyStore creates a new GORM-backed KeyStore.
func NewKeyStore(db *gorm.DB) *KeyStore {
	return &KeyStore{db: db}
}

func (s *KeyStore) PutKey(ctx context.Context, req *keys.PutKeyRequest) (*keys.PutKeyResponse, error) {
	if req == nil || req.Record == nil {
		return nil, fmt.Errorf("PutKey: req.Record is required")
	}
	rec := req.Record
	keyBytes, ok := rec.Key.([]byte)
	if !ok {
		return nil, keys.ErrAlgorithmMismatch
	}
	kid := rec.Kid
	if kid == "" {
		kid, _ = utils.ComputeKid(keyBytes, rec.Algorithm)
	}
	model := &SigningKeyModel{
		ClientID:  rec.ClientID,
		Key:       keyBytes,
		Algorithm: rec.Algorithm,
		Kid:       kid,
	}
	if err := s.db.WithContext(ctx).Save(model).Error; err != nil {
		return nil, err
	}
	return &keys.PutKeyResponse{}, nil
}

func (s *KeyStore) DeleteKey(ctx context.Context, req *keys.DeleteKeyRequest) (*keys.DeleteKeyResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("DeleteKey: req is required")
	}
	result := s.db.WithContext(ctx).Delete(&SigningKeyModel{}, "client_id = ?", req.ClientID)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, keys.ErrKeyNotFound
	}
	return &keys.DeleteKeyResponse{}, nil
}

func (s *KeyStore) GetKey(ctx context.Context, req *keys.GetKeyRequest) (*keys.GetKeyResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetKey: req is required")
	}
	var model SigningKeyModel
	if err := s.db.WithContext(ctx).First(&model, "client_id = ?", req.ClientID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, keys.ErrKeyNotFound
		}
		return nil, err
	}
	return &keys.GetKeyResponse{Record: &keys.KeyRecord{
		ClientID:  model.ClientID,
		Key:       model.Key,
		Algorithm: model.Algorithm,
		Kid:       model.Kid,
	}}, nil
}

func (s *KeyStore) GetKeyByKid(ctx context.Context, req *keys.GetKeyByKidRequest) (*keys.GetKeyByKidResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetKeyByKid: req is required")
	}
	var model SigningKeyModel
	if err := s.db.WithContext(ctx).First(&model, "kid = ?", req.Kid).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, keys.ErrKidNotFound
		}
		return nil, err
	}
	return &keys.GetKeyByKidResponse{Record: &keys.KeyRecord{
		ClientID:  model.ClientID,
		Key:       model.Key,
		Algorithm: model.Algorithm,
		Kid:       model.Kid,
	}}, nil
}

func (s *KeyStore) ListKeyIDs(ctx context.Context, req *keys.ListKeyIDsRequest) (*keys.ListKeyIDsResponse, error) {
	var models []SigningKeyModel
	if err := s.db.WithContext(ctx).Select("client_id").Find(&models).Error; err != nil {
		return nil, err
	}
	ids := make([]string, len(models))
	for i, m := range models {
		ids[i] = m.ClientID
	}
	return &keys.ListKeyIDsResponse{ClientIDs: ids}, nil
}
