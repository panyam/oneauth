//go:build !wasm
// +build !wasm

package gae

import (
	"time"

	"cloud.google.com/go/datastore"
	oa "github.com/panyam/oneauth"
)

// UserEntity is the Datastore entity for users
type UserEntity struct {
	Key       *datastore.Key `datastore:"__key__"`
	IsActive  bool           `datastore:"is_active"`
	Profile   []byte         `datastore:"profile,noindex"` // JSON encoded
	CreatedAt time.Time      `datastore:"created_at"`
	UpdatedAt time.Time      `datastore:"updated_at"`
	Version   int            `datastore:"version"`
}

// IdentityEntity is the Datastore entity for identities
// Key format: Type + ":" + Value
type IdentityEntity struct {
	Key       *datastore.Key `datastore:"__key__"`
	Type      string         `datastore:"type"`
	Value     string         `datastore:"value"`
	UserID    string         `datastore:"user_id"`
	Verified  bool           `datastore:"verified"`
	CreatedAt time.Time      `datastore:"created_at"`
	UpdatedAt time.Time      `datastore:"updated_at"`
	Version   int            `datastore:"version"`
}

func (e *IdentityEntity) ToIdentity() *oa.Identity {
	return &oa.Identity{
		Type:      e.Type,
		Value:     e.Value,
		UserID:    e.UserID,
		Verified:  e.Verified,
		CreatedAt: e.CreatedAt,
		UpdatedAt: e.UpdatedAt,
		Version:   e.Version,
	}
}

func IdentityToEntity(i *oa.Identity, key *datastore.Key) *IdentityEntity {
	return &IdentityEntity{
		Key:       key,
		Type:      i.Type,
		Value:     i.Value,
		UserID:    i.UserID,
		Verified:  i.Verified,
		CreatedAt: i.CreatedAt,
		UpdatedAt: i.UpdatedAt,
		Version:   i.Version,
	}
}

// ChannelEntity is the Datastore entity for authentication channels
// Key format: Provider + ":" + IdentityKey
type ChannelEntity struct {
	Key         *datastore.Key `datastore:"__key__"`
	Provider    string         `datastore:"provider"`
	IdentityKey string         `datastore:"identity_key"`
	Credentials []byte         `datastore:"credentials,noindex"` // JSON encoded
	Profile     []byte         `datastore:"profile,noindex"`     // JSON encoded
	CreatedAt   time.Time      `datastore:"created_at"`
	UpdatedAt   time.Time      `datastore:"updated_at"`
	ExpiresAt   time.Time      `datastore:"expires_at"` // when channel auth expires
	Version     int            `datastore:"version"`
}

// AuthTokenEntity is the Datastore entity for verification/reset tokens
type AuthTokenEntity struct {
	Key       *datastore.Key `datastore:"__key__"`
	Type      oa.TokenType   `datastore:"type"`
	UserID    string         `datastore:"user_id"`
	Email     string         `datastore:"email"`
	CreatedAt time.Time      `datastore:"created_at"`
	ExpiresAt time.Time      `datastore:"expires_at"`
}

func (e *AuthTokenEntity) ToAuthToken() *oa.AuthToken {
	return &oa.AuthToken{
		Token:     e.Key.Name,
		Type:      e.Type,
		UserID:    e.UserID,
		Email:     e.Email,
		CreatedAt: e.CreatedAt,
		ExpiresAt: e.ExpiresAt,
	}
}

func AuthTokenToEntity(t *oa.AuthToken, key *datastore.Key) *AuthTokenEntity {
	return &AuthTokenEntity{
		Key:       key,
		Type:      t.Type,
		UserID:    t.UserID,
		Email:     t.Email,
		CreatedAt: t.CreatedAt,
		ExpiresAt: t.ExpiresAt,
	}
}

// RefreshTokenEntity is the Datastore entity for refresh tokens
type RefreshTokenEntity struct {
	Key        *datastore.Key `datastore:"__key__"` // Key is the token hash
	UserID     string         `datastore:"user_id"`
	ClientID   string         `datastore:"client_id,omitempty"`
	DeviceInfo []byte         `datastore:"device_info,noindex"` // JSON encoded
	Family     string         `datastore:"family"`
	Generation int            `datastore:"generation"`
	Scopes     []byte         `datastore:"scopes,noindex"` // JSON encoded
	CreatedAt  time.Time      `datastore:"created_at"`
	ExpiresAt  time.Time      `datastore:"expires_at"`
	LastUsedAt time.Time      `datastore:"last_used_at"`
	RevokedAt  time.Time      `datastore:"revoked_at,omitempty"`
	Revoked    bool           `datastore:"revoked"`
}

// APIKeyEntity is the Datastore entity for API keys
type APIKeyEntity struct {
	Key        *datastore.Key `datastore:"__key__"` // Key is the KeyID
	KeyHash    string         `datastore:"key_hash,noindex"`
	UserID     string         `datastore:"user_id"`
	Name       string         `datastore:"name"`
	Scopes     []byte         `datastore:"scopes,noindex"` // JSON encoded
	CreatedAt  time.Time      `datastore:"created_at"`
	ExpiresAt  time.Time      `datastore:"expires_at,omitempty"`
	HasExpiry  bool           `datastore:"has_expiry"`
	LastUsedAt time.Time      `datastore:"last_used_at"`
	RevokedAt  time.Time      `datastore:"revoked_at,omitempty"`
	Revoked    bool           `datastore:"revoked"`
}

// UsernameEntity is the Datastore entity for username -> userID mapping
// Key is the username (lowercased for case-insensitive lookup)
type UsernameEntity struct {
	Key       *datastore.Key `datastore:"__key__"`
	Username  string         `datastore:"username"`  // Original case-preserved username
	UserID    string         `datastore:"user_id"`
	CreatedAt time.Time      `datastore:"created_at"`
}
