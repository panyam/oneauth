//go:build !wasm
// +build !wasm

package gorm

import (
	"time"

	"github.com/panyam/oneauth/keys"
	"gorm.io/gorm"
)

// KidKeyModel is the GORM model for kid→key grace entries. Mirrors the
// fields the in-memory KidStore tracks per kid. ExpiresAt is nullable;
// nil means "no expiry" (matches zero time.Time in the in-memory store)
// — avoiding the messy 0001-01-01 zero-date some SQL dialects produce.
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

func (s *KidStore) Add(kid string, key any, algorithm string, clientID string, expiresAt time.Time) error {
	keyBytes, ok := key.([]byte)
	if !ok {
		return keys.ErrAlgorithmMismatch
	}
	model := &KidKeyModel{
		Kid:       kid,
		Key:       keyBytes,
		Algorithm: algorithm,
		ClientID:  clientID,
	}
	if !expiresAt.IsZero() {
		t := expiresAt
		model.ExpiresAt = &t
	}
	// Save = upsert by primary key (kid), matching KidStore.Add's
	// "re-adding an existing kid overwrites it" contract.
	return s.db.Save(model).Error
}

// Remove is idempotent — deleting an absent kid is not an error.
func (s *KidStore) Remove(kid string) error {
	return s.db.Delete(&KidKeyModel{}, "kid = ?", kid).Error
}

// GetKey always returns ErrKeyNotFound — KidStorage is kid-indexed.
func (s *KidStore) GetKey(clientID string) (*keys.KeyRecord, error) {
	return nil, keys.ErrKeyNotFound
}

func (s *KidStore) GetKeyByKid(kid string) (*keys.KeyRecord, error) {
	var model KidKeyModel
	if err := s.db.First(&model, "kid = ?", kid).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, keys.ErrKidNotFound
		}
		return nil, err
	}
	// Expired entries are filtered at read time (CleanExpired physically
	// removes them); mirrors the in-memory KidStore semantics.
	if model.ExpiresAt != nil && time.Now().After(*model.ExpiresAt) {
		return nil, keys.ErrKidNotFound
	}
	return &keys.KeyRecord{
		ClientID:  model.ClientID,
		Key:       model.Key,
		Algorithm: model.Algorithm,
		Kid:       model.Kid,
	}, nil
}

func (s *KidStore) CleanExpired() error {
	// expires_at IS NOT NULL excludes zero-expiry (never-expiring) rows.
	return s.db.Where("expires_at IS NOT NULL AND expires_at < ?", time.Now()).
		Delete(&KidKeyModel{}).Error
}
