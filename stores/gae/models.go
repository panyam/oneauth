//go:build !wasm
// +build !wasm

package gae

import (
	"time"

	"cloud.google.com/go/datastore"
	"github.com/panyam/oneauth/accounts"
	"github.com/panyam/oneauth/localauth"
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

// ToIdentity copies every IdentityEntity field into a new accounts.Identity.
// The Datastore Key is NOT carried over — the returned domain object has no
// pointer back to its storage row, so callers that still need the key must
// hold the entity. Used by IdentityStore methods immediately after tx.Get
// to hand domain objects back to the accounts layer.
func (e *IdentityEntity) ToIdentity() *accounts.Identity {
	return &accounts.Identity{
		Type:      e.Type,
		Value:     e.Value,
		UserID:    e.UserID,
		Verified:  e.Verified,
		CreatedAt: e.CreatedAt,
		UpdatedAt: e.UpdatedAt,
		Version:   e.Version,
	}
}

// IdentityToEntity is the write-path counterpart of ToIdentity. The caller
// supplies the namespaced datastore key — this helper does not derive it
// because the store struct (IdentityStore) owns the namespace, not this
// package-level function. The entity name follows the "<type>:<value>"
// format documented on IdentityEntity.
func IdentityToEntity(i *accounts.Identity, key *datastore.Key) *IdentityEntity {
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

// VerificationTokenEntity is the Datastore entity for localauth verification tokens.
type VerificationTokenEntity struct {
	Key       *datastore.Key            `datastore:"__key__"`
	Type      localauth.VerificationType `datastore:"type"`
	Subject   string                    `datastore:"subject"`
	Email     string                    `datastore:"email"`
	CreatedAt time.Time                 `datastore:"created_at"`
	ExpiresAt time.Time                 `datastore:"expires_at"`
}

// ToVerificationToken reconstructs the plaintext Token from e.Key.Name.
// Non-obvious invariant: the token string is the entity key name, not a
// stored property — consumers must hold the entity (not just its
// struct-tagged property bag) to recover the token. This is also why the
// helper is a method on *VerificationTokenEntity rather than a free
// function: it depends on the key, which lives on the entity, not on the
// property struct.
func (e *VerificationTokenEntity) ToVerificationToken() *localauth.VerificationToken {
	return &localauth.VerificationToken{
		Token:     e.Key.Name,
		Type:      e.Type,
		Subject:   e.Subject,
		Email:     e.Email,
		CreatedAt: e.CreatedAt,
		ExpiresAt: e.ExpiresAt,
	}
}

// VerificationTokenToEntity is the write-path counterpart of
// ToVerificationToken. Caller supplies the namespaced datastore key whose
// name carries the token string; the t.Token field is NOT persisted as a
// separate property — it lives only in the key, matching the
// ToVerificationToken contract.
func VerificationTokenToEntity(t *localauth.VerificationToken, key *datastore.Key) *VerificationTokenEntity {
	return &VerificationTokenEntity{
		Key:       key,
		Type:      t.Type,
		Subject:   t.Subject,
		Email:     t.Email,
		CreatedAt: t.CreatedAt,
		ExpiresAt: t.ExpiresAt,
	}
}

// RefreshTokenEntity is the Datastore entity for refresh tokens
type RefreshTokenEntity struct {
	Key                  *datastore.Key `datastore:"__key__"` // Key is the token hash
	Subject              string         `datastore:"subject"`
	ClientID             string         `datastore:"client_id,omitempty"`
	DeviceInfo           []byte         `datastore:"device_info,noindex"`            // JSON encoded
	Family               string         `datastore:"family"`
	Generation           int            `datastore:"generation"`
	Scopes               []byte         `datastore:"scopes,noindex"`                // JSON encoded
	AuthorizationDetails []byte         `datastore:"authorization_details,noindex"` // JSON encoded, RFC 9396
	CreatedAt            time.Time      `datastore:"created_at"`
	ExpiresAt            time.Time      `datastore:"expires_at"`
	LastUsedAt           time.Time      `datastore:"last_used_at"`
	RevokedAt            time.Time      `datastore:"revoked_at,omitempty"`
	Revoked              bool           `datastore:"revoked"`
}

// APIKeyEntity is the Datastore entity for API keys
type APIKeyEntity struct {
	Key        *datastore.Key `datastore:"__key__"` // Key is the KeyID
	KeyHash    string         `datastore:"key_hash,noindex"`
	Subject    string         `datastore:"subject"`
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
