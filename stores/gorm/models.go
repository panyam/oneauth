//go:build !wasm
// +build !wasm

package gorm

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	oa "github.com/panyam/oneauth"
)

// JSONMap is a helper type for storing JSON maps in GORM
type JSONMap map[string]any

func (m JSONMap) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

func (m *JSONMap) Scan(value any) error {
	if value == nil {
		*m = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, m)
}

// StringSlice is a helper type for storing string slices in GORM
type StringSlice []string

func (s StringSlice) Value() (driver.Value, error) {
	if s == nil {
		return nil, nil
	}
	return json.Marshal(s)
}

func (s *StringSlice) Scan(value any) error {
	if value == nil {
		*s = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, s)
}

// UserModel is the GORM model for users
type UserModel struct {
	ID        string    `gorm:"primaryKey;size:64"`
	IsActive  bool      `gorm:"default:true"`
	Profile   JSONMap   `gorm:"type:jsonb"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

func (UserModel) TableName() string {
	return "users"
}

// IdentityModel is the GORM model for identities
type IdentityModel struct {
	Type      string    `gorm:"primaryKey;size:32"`
	Value     string    `gorm:"primaryKey;size:255"`
	UserID    string    `gorm:"size:64;index"`
	Verified  bool      `gorm:"default:false"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
}

func (IdentityModel) TableName() string {
	return "identities"
}

func (m *IdentityModel) ToIdentity() *oa.Identity {
	return &oa.Identity{
		Type:      m.Type,
		Value:     m.Value,
		UserID:    m.UserID,
		Verified:  m.Verified,
		CreatedAt: m.CreatedAt,
	}
}

func IdentityToModel(i *oa.Identity) *IdentityModel {
	return &IdentityModel{
		Type:      i.Type,
		Value:     i.Value,
		UserID:    i.UserID,
		Verified:  i.Verified,
		CreatedAt: i.CreatedAt,
	}
}

// ChannelModel is the GORM model for authentication channels
type ChannelModel struct {
	Provider    string    `gorm:"primaryKey;size:32"`
	IdentityKey string    `gorm:"primaryKey;size:320"`
	Credentials JSONMap   `gorm:"type:jsonb"`
	Profile     JSONMap   `gorm:"type:jsonb"`
	CreatedAt   time.Time `gorm:"autoCreateTime"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime"`
}

func (ChannelModel) TableName() string {
	return "channels"
}

func (m *ChannelModel) ToChannel() *oa.Channel {
	return &oa.Channel{
		Provider:    m.Provider,
		IdentityKey: m.IdentityKey,
		Credentials: m.Credentials,
		Profile:     m.Profile,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
	}
}

func ChannelToModel(c *oa.Channel) *ChannelModel {
	return &ChannelModel{
		Provider:    c.Provider,
		IdentityKey: c.IdentityKey,
		Credentials: JSONMap(c.Credentials),
		Profile:     JSONMap(c.Profile),
		CreatedAt:   c.CreatedAt,
		UpdatedAt:   c.UpdatedAt,
	}
}

// AuthTokenModel is the GORM model for verification/reset tokens
type AuthTokenModel struct {
	Token     string       `gorm:"primaryKey;size:128"`
	Type      oa.TokenType `gorm:"size:32;index"`
	UserID    string       `gorm:"size:64;index"`
	Email     string       `gorm:"size:255"`
	CreatedAt time.Time    `gorm:"autoCreateTime"`
	ExpiresAt time.Time    `gorm:"index"`
}

func (AuthTokenModel) TableName() string {
	return "auth_tokens"
}

func (m *AuthTokenModel) ToAuthToken() *oa.AuthToken {
	return &oa.AuthToken{
		Token:     m.Token,
		Type:      m.Type,
		UserID:    m.UserID,
		Email:     m.Email,
		CreatedAt: m.CreatedAt,
		ExpiresAt: m.ExpiresAt,
	}
}

func AuthTokenToModel(t *oa.AuthToken) *AuthTokenModel {
	return &AuthTokenModel{
		Token:     t.Token,
		Type:      t.Type,
		UserID:    t.UserID,
		Email:     t.Email,
		CreatedAt: t.CreatedAt,
		ExpiresAt: t.ExpiresAt,
	}
}

// RefreshTokenModel is the GORM model for refresh tokens
type RefreshTokenModel struct {
	TokenHash  string      `gorm:"primaryKey;size:64"`
	Token      string      `gorm:"-"` // Not stored, only used in memory
	UserID     string      `gorm:"size:64;index"`
	ClientID   string      `gorm:"size:64"`
	DeviceInfo JSONMap     `gorm:"type:jsonb"`
	Family     string      `gorm:"size:32;index"`
	Generation int         `gorm:"default:1"`
	Scopes     StringSlice `gorm:"type:jsonb"`
	CreatedAt  time.Time   `gorm:"autoCreateTime"`
	ExpiresAt  time.Time   `gorm:"index"`
	LastUsedAt time.Time
	RevokedAt  *time.Time
	Revoked    bool `gorm:"default:false;index"`
}

func (RefreshTokenModel) TableName() string {
	return "refresh_tokens"
}

func (m *RefreshTokenModel) ToRefreshToken() *oa.RefreshToken {
	return &oa.RefreshToken{
		Token:      m.Token,
		TokenHash:  m.TokenHash,
		UserID:     m.UserID,
		ClientID:   m.ClientID,
		DeviceInfo: m.DeviceInfo,
		Family:     m.Family,
		Generation: m.Generation,
		Scopes:     m.Scopes,
		CreatedAt:  m.CreatedAt,
		ExpiresAt:  m.ExpiresAt,
		LastUsedAt: m.LastUsedAt,
		RevokedAt:  m.RevokedAt,
		Revoked:    m.Revoked,
	}
}

func RefreshTokenToModel(t *oa.RefreshToken) *RefreshTokenModel {
	return &RefreshTokenModel{
		Token:      t.Token,
		TokenHash:  t.TokenHash,
		UserID:     t.UserID,
		ClientID:   t.ClientID,
		DeviceInfo: JSONMap(t.DeviceInfo),
		Family:     t.Family,
		Generation: t.Generation,
		Scopes:     StringSlice(t.Scopes),
		CreatedAt:  t.CreatedAt,
		ExpiresAt:  t.ExpiresAt,
		LastUsedAt: t.LastUsedAt,
		RevokedAt:  t.RevokedAt,
		Revoked:    t.Revoked,
	}
}

// APIKeyModel is the GORM model for API keys
type APIKeyModel struct {
	KeyID      string      `gorm:"primaryKey;size:64"`
	KeyHash    string      `gorm:"size:128"`
	UserID     string      `gorm:"size:64;index"`
	Name       string      `gorm:"size:255"`
	Scopes     StringSlice `gorm:"type:jsonb"`
	CreatedAt  time.Time   `gorm:"autoCreateTime"`
	ExpiresAt  *time.Time
	LastUsedAt time.Time
	RevokedAt  *time.Time
	Revoked    bool `gorm:"default:false;index"`
}

func (APIKeyModel) TableName() string {
	return "api_keys"
}

func (m *APIKeyModel) ToAPIKey() *oa.APIKey {
	return &oa.APIKey{
		KeyID:      m.KeyID,
		KeyHash:    m.KeyHash,
		UserID:     m.UserID,
		Name:       m.Name,
		Scopes:     m.Scopes,
		CreatedAt:  m.CreatedAt,
		ExpiresAt:  m.ExpiresAt,
		LastUsedAt: m.LastUsedAt,
		RevokedAt:  m.RevokedAt,
		Revoked:    m.Revoked,
	}
}

func APIKeyToModel(k *oa.APIKey) *APIKeyModel {
	return &APIKeyModel{
		KeyID:      k.KeyID,
		KeyHash:    k.KeyHash,
		UserID:     k.UserID,
		Name:       k.Name,
		Scopes:     StringSlice(k.Scopes),
		CreatedAt:  k.CreatedAt,
		ExpiresAt:  k.ExpiresAt,
		LastUsedAt: k.LastUsedAt,
		RevokedAt:  k.RevokedAt,
		Revoked:    k.Revoked,
	}
}
