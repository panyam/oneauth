//go:build !wasm
// +build !wasm

package gorm

import (
	"context"
	"fmt"
	"time"

	"github.com/panyam/oneauth/keys"
	"gorm.io/gorm"
)

// KidKeyModel is the GORM model for kid→key grace entries.
type KidKeyModel struct {
	Kid       string     `gorm:"primaryKey;size:128"`
	Key       []byte     `gorm:"not null"`
	Algorithm string     `gorm:"size:16;not null"`
	ClientID  string     `gorm:"size:128;index"`
	ExpiresAt *time.Time `gorm:"index:idx_kid_expires_at"`
	CreatedAt time.Time  `gorm:"autoCreateTime"`
}

func (KidKeyModel) TableName() string {
	return "kid_keys"
}

// KidStore implements keys.KidStorage using GORM.
type KidStore struct {
	db *gorm.DB
}

var _ keys.KidStorage = (*KidStore)(nil)

// NewKidStore creates a new GORM-backed KidStorage.
func NewKidStore(db *gorm.DB) *KidStore {
	return &KidStore{db: db}
}

func (s *KidStore) Add(ctx context.Context, req *keys.AddKidRequest) (*keys.AddKidResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("Add: req is required")
	}
	keyBytes, ok := req.Key.([]byte)
	if !ok {
		return nil, keys.ErrAlgorithmMismatch
	}
	model := &KidKeyModel{
		Kid:       req.Kid,
		Key:       keyBytes,
		Algorithm: req.Algorithm,
		ClientID:  req.ClientID,
	}
	if !req.ExpiresAt.IsZero() {
		t := req.ExpiresAt
		model.ExpiresAt = &t
	}
	if err := s.db.WithContext(ctx).Save(model).Error; err != nil {
		return nil, err
	}
	return &keys.AddKidResponse{}, nil
}

func (s *KidStore) Remove(ctx context.Context, req *keys.RemoveKidRequest) (*keys.RemoveKidResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("Remove: req is required")
	}
	if err := s.db.WithContext(ctx).Delete(&KidKeyModel{}, "kid = ?", req.Kid).Error; err != nil {
		return nil, err
	}
	return &keys.RemoveKidResponse{}, nil
}

func (s *KidStore) GetKey(ctx context.Context, req *keys.GetKeyRequest) (*keys.GetKeyResponse, error) {
	return nil, keys.ErrKeyNotFound
}

func (s *KidStore) GetKeyByKid(ctx context.Context, req *keys.GetKeyByKidRequest) (*keys.GetKeyByKidResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetKeyByKid: req is required")
	}
	var model KidKeyModel
	if err := s.db.WithContext(ctx).First(&model, "kid = ?", req.Kid).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, keys.ErrKidNotFound
		}
		return nil, err
	}
	if model.ExpiresAt != nil && time.Now().After(*model.ExpiresAt) {
		return nil, keys.ErrKidNotFound
	}
	return &keys.GetKeyByKidResponse{Record: &keys.KeyRecord{
		ClientID:  model.ClientID,
		Key:       model.Key,
		Algorithm: model.Algorithm,
		Kid:       model.Kid,
	}}, nil
}

func (s *KidStore) CleanExpired(ctx context.Context, req *keys.CleanExpiredRequest) (*keys.CleanExpiredResponse, error) {
	result := s.db.WithContext(ctx).Where("expires_at IS NOT NULL AND expires_at < ?", time.Now()).
		Delete(&KidKeyModel{})
	if result.Error != nil {
		return nil, result.Error
	}
	return &keys.CleanExpiredResponse{Removed: int(result.RowsAffected)}, nil
}
