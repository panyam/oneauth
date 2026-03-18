//go:build !wasm
// +build !wasm

package gorm

import (
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

func (s *KeyStore) PutKey(rec *keys.KeyRecord) error {
	keyBytes, ok := rec.Key.([]byte)
	if !ok {
		return keys.ErrAlgorithmMismatch
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
	return s.db.Save(model).Error
}

func (s *KeyStore) DeleteKey(clientID string) error {
	result := s.db.Delete(&SigningKeyModel{}, "client_id = ?", clientID)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return keys.ErrKeyNotFound
	}
	return nil
}

func (s *KeyStore) GetKey(clientID string) (*keys.KeyRecord, error) {
	var model SigningKeyModel
	if err := s.db.First(&model, "client_id = ?", clientID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, keys.ErrKeyNotFound
		}
		return nil, err
	}
	return &keys.KeyRecord{
		ClientID:  model.ClientID,
		Key:       model.Key,
		Algorithm: model.Algorithm,
		Kid:       model.Kid,
	}, nil
}

func (s *KeyStore) GetKeyByKid(kid string) (*keys.KeyRecord, error) {
	var model SigningKeyModel
	if err := s.db.First(&model, "kid = ?", kid).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, keys.ErrKidNotFound
		}
		return nil, err
	}
	return &keys.KeyRecord{
		ClientID:  model.ClientID,
		Key:       model.Key,
		Algorithm: model.Algorithm,
		Kid:       model.Kid,
	}, nil
}

func (s *KeyStore) ListKeyIDs() ([]string, error) {
	var models []SigningKeyModel
	if err := s.db.Select("client_id").Find(&models).Error; err != nil {
		return nil, err
	}
	keys := make([]string, len(models))
	for i, m := range models {
		keys[i] = m.ClientID
	}
	return keys, nil
}

// Backward-compatible aliases

func (s *KeyStore) RegisterKey(clientID string, key any, algorithm string) error {
	return s.PutKey(&keys.KeyRecord{ClientID: clientID, Key: key, Algorithm: algorithm})
}

func (s *KeyStore) GetVerifyKey(clientID string) (any, error) {
	rec, err := s.GetKey(clientID)
	if err != nil {
		return nil, err
	}
	return rec.Key, nil
}

func (s *KeyStore) GetSigningKey(clientID string) (any, error) {
	return s.GetVerifyKey(clientID)
}

func (s *KeyStore) GetExpectedAlg(clientID string) (string, error) {
	rec, err := s.GetKey(clientID)
	if err != nil {
		return "", err
	}
	return rec.Algorithm, nil
}

func (s *KeyStore) ListKeys() ([]string, error) {
	return s.ListKeyIDs()
}

func (s *KeyStore) GetCurrentKid(clientID string) (string, error) {
	rec, err := s.GetKey(clientID)
	if err != nil {
		return "", err
	}
	return rec.Kid, nil
}
