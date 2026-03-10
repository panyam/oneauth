//go:build !wasm
// +build !wasm

package gorm

import (
	"time"

	oa "github.com/panyam/oneauth"
	"gorm.io/gorm"
)

// SigningKeyModel is the GORM model for per-client signing keys.
type SigningKeyModel struct {
	ClientID  string    `gorm:"primaryKey;size:128"`
	Key       []byte    `gorm:"type:blob;not null"`
	Algorithm string    `gorm:"size:16;not null"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

func (SigningKeyModel) TableName() string {
	return "signing_keys"
}

// KeyStore implements oa.WritableKeyStore using GORM.
type KeyStore struct {
	db *gorm.DB
}

// NewKeyStore creates a new GORM-backed KeyStore.
func NewKeyStore(db *gorm.DB) *KeyStore {
	return &KeyStore{db: db}
}

func (s *KeyStore) RegisterKey(clientID string, key any, algorithm string) error {
	keyBytes, ok := key.([]byte)
	if !ok {
		return oa.ErrAlgorithmMismatch
	}
	model := &SigningKeyModel{
		ClientID:  clientID,
		Key:       keyBytes,
		Algorithm: algorithm,
	}
	// Upsert: create or update
	return s.db.Save(model).Error
}

func (s *KeyStore) DeleteKey(clientID string) error {
	result := s.db.Delete(&SigningKeyModel{}, "client_id = ?", clientID)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return oa.ErrKeyNotFound
	}
	return nil
}

func (s *KeyStore) GetVerifyKey(clientID string) (any, error) {
	var model SigningKeyModel
	if err := s.db.First(&model, "client_id = ?", clientID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, oa.ErrKeyNotFound
		}
		return nil, err
	}
	return model.Key, nil
}

func (s *KeyStore) GetSigningKey(clientID string) (any, error) {
	return s.GetVerifyKey(clientID)
}

func (s *KeyStore) GetExpectedAlg(clientID string) (string, error) {
	var model SigningKeyModel
	if err := s.db.First(&model, "client_id = ?", clientID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", oa.ErrKeyNotFound
		}
		return "", err
	}
	return model.Algorithm, nil
}

func (s *KeyStore) ListKeys() ([]string, error) {
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
