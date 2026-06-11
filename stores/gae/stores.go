//go:build !wasm
// +build !wasm

package gae

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/api/iterator"

	"github.com/panyam/oneauth/accounts"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/localauth"
)

// Kind constants for Datastore entities
const (
	KindUser         = "User"
	KindIdentity     = "Identity"
	KindChannel      = "Channel"
	KindAuthToken    = "AuthToken"
	KindRefreshToken = "RefreshToken"
	KindAPIKey       = "APIKey"
	KindUsername     = "Username"
)

// ============================================================================
// UserStore
// ============================================================================

// GAEUser implements the accounts.User interface
type GAEUser struct {
	UserID      string         `json:"user_id"`
	Active      bool           `json:"is_active"`
	UserProfile map[string]any `json:"profile"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

func (u *GAEUser) Id() string              { return u.UserID }
func (u *GAEUser) Profile() map[string]any { return u.UserProfile }

// UserStore implements accounts.UserStore using Google Cloud Datastore
type UserStore struct {
	client    *datastore.Client
	namespace string
}

// NewUserStore creates a new Datastore-backed UserStore
func NewUserStore(client *datastore.Client, namespace string) *UserStore {
	return &UserStore{
		client:    client,
		namespace: namespace,
	}
}

func (s *UserStore) namespacedKey(kind, name string) *datastore.Key {
	key := datastore.NameKey(kind, name, nil)
	key.Namespace = s.namespace
	return key
}

// CreateUser inserts a new user keyed by req.UserID. The caller picks the
// ID — this backend doesn't generate one — and re-creating the same ID
// silently overwrites (Datastore's Put is upsert-shaped, not insert-only).
// CreatedAt and UpdatedAt are stamped from time.Now() on the way in; the
// returned GAEUser mirrors the persisted entity so callers don't have to
// re-read.
func (s *UserStore) CreateUser(ctx context.Context, req *accounts.CreateUserRequest) (*accounts.CreateUserResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("CreateUser: req is required")
	}
	key := s.namespacedKey(KindUser, req.UserID)

	var profileBytes []byte
	if req.Profile != nil {
		profileBytes, _ = json.Marshal(req.Profile)
	}

	now := time.Now()
	entity := &UserEntity{
		Key:       key,
		IsActive:  req.IsActive,
		Profile:   profileBytes,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if _, err := s.client.Put(ctx, key, entity); err != nil {
		return nil, err
	}

	return &accounts.CreateUserResponse{User: &GAEUser{
		UserID:      req.UserID,
		Active:      req.IsActive,
		UserProfile: req.Profile,
		CreatedAt:   now,
		UpdatedAt:   now,
	}}, nil
}

// GetUserById returns the user for req.UserID. Absent users surface as
// fmt.Errorf("user not found: %s", req.UserID) — not a sentinel — diverging
// from the keys.ErrKeyNotFound / core.ErrAppNotFound pattern used elsewhere
// in this package. Callers that need to distinguish "missing" from other
// failures currently match on the string prefix; introducing a sentinel is
// tracked separately (it's an interface change, not a doc fix).
func (s *UserStore) GetUserById(ctx context.Context, req *accounts.GetUserByIDRequest) (*accounts.GetUserByIDResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetUserById: req is required")
	}
	key := s.namespacedKey(KindUser, req.UserID)
	var entity UserEntity
	if err := s.client.Get(ctx, key, &entity); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, fmt.Errorf("user not found: %s", req.UserID)
		}
		return nil, err
	}

	var profile map[string]any
	if entity.Profile != nil {
		json.Unmarshal(entity.Profile, &profile)
	}

	return &accounts.GetUserByIDResponse{User: &GAEUser{
		UserID:      req.UserID,
		Active:      entity.IsActive,
		UserProfile: profile,
		CreatedAt:   entity.CreatedAt,
		UpdatedAt:   entity.UpdatedAt,
	}}, nil
}

// SaveUser writes req.User, preserving CreatedAt across overwrites (re-saving
// an existing user keeps the original create time and only bumps UpdatedAt).
// IsActive defaults to true unless the concrete *GAEUser carries an explicit
// false — the accounts.User interface has no Active() getter, so non-GAEUser
// implementations always end up active. Callers that need a different
// default should pass a *GAEUser.
func (s *UserStore) SaveUser(ctx context.Context, req *accounts.SaveUserRequest) (*accounts.SaveUserResponse, error) {
	if req == nil || req.User == nil {
		return nil, fmt.Errorf("SaveUser: req.User is required")
	}
	user := req.User
	key := s.namespacedKey(KindUser, user.Id())

	var profileBytes []byte
	if user.Profile() != nil {
		profileBytes, _ = json.Marshal(user.Profile())
	}

	var existing UserEntity
	err := s.client.Get(ctx, key, &existing)
	if err != nil && err != datastore.ErrNoSuchEntity {
		return nil, err
	}

	entity := &UserEntity{
		Key:       key,
		IsActive:  true,
		Profile:   profileBytes,
		CreatedAt: existing.CreatedAt,
		UpdatedAt: time.Now(),
	}
	if existing.CreatedAt.IsZero() {
		entity.CreatedAt = time.Now()
	}

	if gaeUser, ok := user.(*GAEUser); ok {
		entity.IsActive = gaeUser.Active
	}

	if _, err := s.client.Put(ctx, key, entity); err != nil {
		return nil, err
	}
	return &accounts.SaveUserResponse{}, nil
}

// ============================================================================
// IdentityStore
// ============================================================================

// IdentityStore implements accounts.IdentityStore using Google Cloud Datastore
type IdentityStore struct {
	client    *datastore.Client
	namespace string
}

// NewIdentityStore creates a new Datastore-backed IdentityStore
func NewIdentityStore(client *datastore.Client, namespace string) *IdentityStore {
	return &IdentityStore{
		client:    client,
		namespace: namespace,
	}
}

func (s *IdentityStore) namespacedKey(kind, name string) *datastore.Key {
	key := datastore.NameKey(kind, name, nil)
	key.Namespace = s.namespace
	return key
}

func (s *IdentityStore) identityKeyName(idType, value string) string {
	return idType + ":" + value
}

// GetIdentity returns the identity for (req.IdentityType, req.IdentityValue),
// or fmt.Errorf("identity not found") when absent. With req.CreateIfMissing
// set, an unbound identity (UserID="") is created in the same call and
// NewCreated is set in the response — pairs with the signup flow's
// "ensure-or-create" need without forcing two round trips. The entity key
// derives from "<type>:<value>" so identities of different types with the
// same value (e.g., email:foo@bar vs phone:foo@bar) are distinct rows.
func (s *IdentityStore) GetIdentity(ctx context.Context, req *accounts.GetIdentityRequest) (*accounts.GetIdentityResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetIdentity: req is required")
	}
	key := s.namespacedKey(KindIdentity, s.identityKeyName(req.IdentityType, req.IdentityValue))
	var entity IdentityEntity
	err := s.client.Get(ctx, key, &entity)

	if err == datastore.ErrNoSuchEntity {
		if req.CreateIfMissing {
			now := time.Now()
			entity = IdentityEntity{
				Key:       key,
				Type:      req.IdentityType,
				Value:     req.IdentityValue,
				UserID:    "",
				Verified:  false,
				CreatedAt: now,
				UpdatedAt: now,
				Version:   1,
			}
			if _, err := s.client.Put(ctx, key, &entity); err != nil {
				return nil, err
			}
			return &accounts.GetIdentityResponse{Identity: entity.ToIdentity(), NewCreated: true}, nil
		}
		return nil, fmt.Errorf("identity not found")
	}
	if err != nil {
		return nil, err
	}

	return &accounts.GetIdentityResponse{Identity: entity.ToIdentity()}, nil
}

// SaveIdentity writes req.Identity unconditionally — used after callers have
// mutated fields not covered by the dedicated SetUserForIdentity /
// MarkIdentityVerified helpers. Does NOT bump Version; the dedicated helpers
// do that under transaction. Callers that need version increments should
// reach for the appropriate helper instead.
func (s *IdentityStore) SaveIdentity(ctx context.Context, req *accounts.SaveIdentityRequest) (*accounts.SaveIdentityResponse, error) {
	if req == nil || req.Identity == nil {
		return nil, fmt.Errorf("SaveIdentity: req.Identity is required")
	}
	identity := req.Identity
	key := s.namespacedKey(KindIdentity, s.identityKeyName(identity.Type, identity.Value))
	entity := IdentityToEntity(identity, key)
	if _, err := s.client.Put(ctx, key, entity); err != nil {
		return nil, err
	}
	return &accounts.SaveIdentityResponse{}, nil
}

// SetUserForIdentity binds an identity to a user. Runs under a Datastore
// transaction so two concurrent calls can't observe a stale UserID and race
// each other; Version is incremented on every write for optimistic-lock
// tooling downstream. Identity must already exist — there is no
// CreateIfMissing here; pair with GetIdentity to provision first.
func (s *IdentityStore) SetUserForIdentity(ctx context.Context, req *accounts.SetUserForIdentityRequest) (*accounts.SetUserForIdentityResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("SetUserForIdentity: req is required")
	}
	key := s.namespacedKey(KindIdentity, s.identityKeyName(req.IdentityType, req.IdentityValue))

	_, err := s.client.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		var entity IdentityEntity
		if err := tx.Get(key, &entity); err != nil {
			return err
		}
		entity.UserID = req.NewUserID
		entity.UpdatedAt = time.Now()
		entity.Version++
		_, err := tx.Put(key, &entity)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &accounts.SetUserForIdentityResponse{}, nil
}

// MarkIdentityVerified flips Verified=true and bumps Version under a
// transaction. Idempotent at the result level — re-marking an already-verified
// identity still succeeds and still bumps Version (useful for audit trails
// that want to count verification attempts).
func (s *IdentityStore) MarkIdentityVerified(ctx context.Context, req *accounts.MarkIdentityVerifiedRequest) (*accounts.MarkIdentityVerifiedResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("MarkIdentityVerified: req is required")
	}
	key := s.namespacedKey(KindIdentity, s.identityKeyName(req.IdentityType, req.IdentityValue))

	_, err := s.client.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		var entity IdentityEntity
		if err := tx.Get(key, &entity); err != nil {
			return err
		}
		entity.Verified = true
		entity.UpdatedAt = time.Now()
		entity.Version++
		_, err := tx.Put(key, &entity)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &accounts.MarkIdentityVerifiedResponse{}, nil
}

// GetUserIdentities returns every identity bound to req.UserID. Backed by
// an indexed query on the user_id property — unlike most properties in this
// package, user_id is intentionally indexed because this lookup is on the
// hot path of "show me all the ways this user can log in." Returns an empty
// slice (not an error) for a user with no identities yet.
func (s *IdentityStore) GetUserIdentities(ctx context.Context, req *accounts.GetUserIdentitiesRequest) (*accounts.GetUserIdentitiesResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetUserIdentities: req is required")
	}
	query := datastore.NewQuery(KindIdentity).
		FilterField("user_id", "=", req.UserID)
	if s.namespace != "" {
		query = query.Namespace(s.namespace)
	}

	var identities []*accounts.Identity
	it := s.client.Run(ctx, query)
	for {
		var entity IdentityEntity
		_, err := it.Next(&entity)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		identities = append(identities, entity.ToIdentity())
	}
	return &accounts.GetUserIdentitiesResponse{Identities: identities}, nil
}

// ============================================================================
// ChannelStore
// ============================================================================

// ChannelStore implements accounts.ChannelStore using Google Cloud Datastore
type ChannelStore struct {
	client    *datastore.Client
	namespace string
}

// NewChannelStore creates a new Datastore-backed ChannelStore
func NewChannelStore(client *datastore.Client, namespace string) *ChannelStore {
	return &ChannelStore{
		client:    client,
		namespace: namespace,
	}
}

func (s *ChannelStore) namespacedKey(kind, name string) *datastore.Key {
	key := datastore.NameKey(kind, name, nil)
	key.Namespace = s.namespace
	return key
}

func (s *ChannelStore) channelKeyName(provider, identityKey string) string {
	return provider + ":" + identityKey
}

// GetChannel returns the (provider, identity) channel, or fmt.Errorf("channel
// not found") when absent. With req.CreateIfMissing set, an empty channel is
// created in the same call and NewCreated is set — pairs with provider-bind
// flows ("first time logging in with Google") that want a "fetch or
// provision" step without a separate write. The entity key derives from
// "<provider>:<identityKey>" so the same identity bound to two providers
// (e.g., Google and GitHub) is two distinct rows.
func (s *ChannelStore) GetChannel(ctx context.Context, req *accounts.GetChannelRequest) (*accounts.GetChannelResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetChannel: req is required")
	}
	key := s.namespacedKey(KindChannel, s.channelKeyName(req.Provider, req.IdentityKey))
	var entity ChannelEntity
	err := s.client.Get(ctx, key, &entity)

	if err == datastore.ErrNoSuchEntity {
		if req.CreateIfMissing {
			now := time.Now()
			entity = ChannelEntity{
				Key:         key,
				Provider:    req.Provider,
				IdentityKey: req.IdentityKey,
				Credentials: nil,
				Profile:     nil,
				CreatedAt:   now,
				UpdatedAt:   now,
				Version:     1,
			}
			if _, err := s.client.Put(ctx, key, &entity); err != nil {
				return nil, err
			}
			return &accounts.GetChannelResponse{Channel: &accounts.Channel{
				Provider:    req.Provider,
				IdentityKey: req.IdentityKey,
				Credentials: make(map[string]any),
				Profile:     make(map[string]any),
				CreatedAt:   now,
				UpdatedAt:   now,
				Version:     1,
			}, NewCreated: true}, nil
		}
		return nil, fmt.Errorf("channel not found")
	}
	if err != nil {
		return nil, err
	}

	var credentials, profile map[string]any
	if entity.Credentials != nil {
		json.Unmarshal(entity.Credentials, &credentials)
	}
	if entity.Profile != nil {
		json.Unmarshal(entity.Profile, &profile)
	}

	return &accounts.GetChannelResponse{Channel: &accounts.Channel{
		Provider:    entity.Provider,
		IdentityKey: entity.IdentityKey,
		Credentials: credentials,
		Profile:     profile,
		CreatedAt:   entity.CreatedAt,
		UpdatedAt:   entity.UpdatedAt,
		ExpiresAt:   entity.ExpiresAt,
		Version:     entity.Version,
	}}, nil
}

// SaveChannel upserts req.Channel and increments Version each call.
// CreatedAt is preserved across overwrites; on first write it's stamped from
// time.Now() and Version starts at 1. Credentials and Profile maps are
// JSON-encoded into noindex byte properties — Datastore's 1500-byte index
// limit makes indexing them impractical, and nothing queries by their
// contents anyway.
func (s *ChannelStore) SaveChannel(ctx context.Context, req *accounts.SaveChannelRequest) (*accounts.SaveChannelResponse, error) {
	if req == nil || req.Channel == nil {
		return nil, fmt.Errorf("SaveChannel: req.Channel is required")
	}
	channel := req.Channel
	key := s.namespacedKey(KindChannel, s.channelKeyName(channel.Provider, channel.IdentityKey))

	var credBytes, profileBytes []byte
	if channel.Credentials != nil {
		credBytes, _ = json.Marshal(channel.Credentials)
	}
	if channel.Profile != nil {
		profileBytes, _ = json.Marshal(channel.Profile)
	}

	var existing ChannelEntity
	err := s.client.Get(ctx, key, &existing)
	if err != nil && err != datastore.ErrNoSuchEntity {
		return nil, err
	}

	now := time.Now()
	entity := &ChannelEntity{
		Key:         key,
		Provider:    channel.Provider,
		IdentityKey: channel.IdentityKey,
		Credentials: credBytes,
		Profile:     profileBytes,
		CreatedAt:   existing.CreatedAt,
		UpdatedAt:   now,
		ExpiresAt:   channel.ExpiresAt,
		Version:     existing.Version + 1,
	}
	if existing.CreatedAt.IsZero() {
		entity.CreatedAt = now
		entity.Version = 1
	}

	if _, err := s.client.Put(ctx, key, entity); err != nil {
		return nil, err
	}
	return &accounts.SaveChannelResponse{}, nil
}

// GetChannelsByIdentity returns every channel for a given identity_key
// across all providers — backed by an indexed query on the identity_key
// property. Returns an empty slice (not an error) when nothing matches.
// Order is unspecified.
func (s *ChannelStore) GetChannelsByIdentity(ctx context.Context, req *accounts.GetChannelsByIdentityRequest) (*accounts.GetChannelsByIdentityResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetChannelsByIdentity: req is required")
	}
	query := datastore.NewQuery(KindChannel).
		FilterField("identity_key", "=", req.IdentityKey)
	if s.namespace != "" {
		query = query.Namespace(s.namespace)
	}

	var channels []*accounts.Channel
	it := s.client.Run(ctx, query)
	for {
		var entity ChannelEntity
		_, err := it.Next(&entity)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		var credentials, profile map[string]any
		if entity.Credentials != nil {
			json.Unmarshal(entity.Credentials, &credentials)
		}
		if entity.Profile != nil {
			json.Unmarshal(entity.Profile, &profile)
		}

		channels = append(channels, &accounts.Channel{
			Provider:    entity.Provider,
			IdentityKey: entity.IdentityKey,
			Credentials: credentials,
			Profile:     profile,
			CreatedAt:   entity.CreatedAt,
			UpdatedAt:   entity.UpdatedAt,
			ExpiresAt:   entity.ExpiresAt,
			Version:     entity.Version,
		})
	}
	return &accounts.GetChannelsByIdentityResponse{Channels: channels}, nil
}

// ============================================================================
// TokenStore (AuthToken)
// ============================================================================

// TokenStore implements core.TokenStore using Google Cloud Datastore
type TokenStore struct {
	client    *datastore.Client
	namespace string
}

// NewTokenStore creates a new Datastore-backed TokenStore
func NewTokenStore(client *datastore.Client, namespace string) *TokenStore {
	return &TokenStore{
		client:    client,
		namespace: namespace,
	}
}

func (s *TokenStore) namespacedKey(kind, name string) *datastore.Key {
	key := datastore.NameKey(kind, name, nil)
	key.Namespace = s.namespace
	return key
}

// CreateToken mints a fresh verification token via core.GenerateSecureToken
// (the token is the entity key, so collisions would manifest as overwrites;
// the secure-random width makes collision negligible). ExpiresAt is computed
// from req.ExpiryDuration at insert time — the persisted absolute time, not
// the relative duration, drives GetToken's expiry check.
func (s *TokenStore) CreateToken(ctx context.Context, req *localauth.CreateVerificationTokenRequest) (*localauth.CreateVerificationTokenResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("CreateToken: req is required")
	}
	token, err := core.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	key := s.namespacedKey(KindAuthToken, token)
	now := time.Now()
	entity := &VerificationTokenEntity{
		Key:       key,
		Type:      req.Type,
		Subject:   req.Subject,
		Email:     req.Email,
		CreatedAt: now,
		ExpiresAt: now.Add(req.ExpiryDuration),
	}

	if _, err := s.client.Put(ctx, key, entity); err != nil {
		return nil, err
	}

	return &localauth.CreateVerificationTokenResponse{Token: &localauth.VerificationToken{
		Token:     token,
		Type:      req.Type,
		Subject:   req.Subject,
		Email:     req.Email,
		CreatedAt: now,
		ExpiresAt: now.Add(req.ExpiryDuration),
	}}, nil
}

// GetToken returns the token or one of two error strings: "token not found"
// when absent, "token expired" when the entity exists but its ExpiresAt has
// passed. Expired entities are deleted on read — a single-shot self-clean so
// stale rows don't pile up between explicit DeleteSubjectTokens sweeps.
// Callers that need to distinguish the two failures match the error string
// (a sentinel introduction is tracked separately).
func (s *TokenStore) GetToken(ctx context.Context, req *localauth.GetVerificationTokenRequest) (*localauth.GetVerificationTokenResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetToken: req is required")
	}
	key := s.namespacedKey(KindAuthToken, req.Token)
	var entity VerificationTokenEntity
	if err := s.client.Get(ctx, key, &entity); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, fmt.Errorf("token not found")
		}
		return nil, err
	}

	authToken := entity.ToVerificationToken()
	if authToken.IsExpired() {
		_, _ = s.DeleteToken(ctx, &localauth.DeleteVerificationTokenRequest{Token: req.Token})
		return nil, fmt.Errorf("token expired")
	}

	return &localauth.GetVerificationTokenResponse{Token: authToken}, nil
}

// DeleteToken is idempotent — Datastore's Delete silently succeeds on
// missing keys, and verification tokens are single-use by design (delete
// after the action they unlock fires). No "not found" error.
func (s *TokenStore) DeleteToken(ctx context.Context, req *localauth.DeleteVerificationTokenRequest) (*localauth.DeleteVerificationTokenResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("DeleteToken: req is required")
	}
	key := s.namespacedKey(KindAuthToken, req.Token)
	if err := s.client.Delete(ctx, key); err != nil {
		return nil, err
	}
	return &localauth.DeleteVerificationTokenResponse{}, nil
}

// DeleteSubjectTokens removes every verification token of req.Type for
// req.Subject. Used during password-reset / email-change cleanup to
// invalidate every outstanding token a subject holds for the same action.
// Returns success (not an error) when the subject has no matching tokens —
// the no-op case is normal.
func (s *TokenStore) DeleteSubjectTokens(ctx context.Context, req *localauth.DeleteSubjectVerificationTokensRequest) (*localauth.DeleteSubjectVerificationTokensResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("DeleteSubjectTokens: req is required")
	}
	query := datastore.NewQuery(KindAuthToken).
		FilterField("subject", "=", req.Subject).
		FilterField("type", "=", string(req.Type)).
		KeysOnly()
	if s.namespace != "" {
		query = query.Namespace(s.namespace)
	}

	keys, err := s.client.GetAll(ctx, query, nil)
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		return &localauth.DeleteSubjectVerificationTokensResponse{}, nil
	}

	if err := s.client.DeleteMulti(ctx, keys); err != nil {
		return nil, err
	}
	return &localauth.DeleteSubjectVerificationTokensResponse{}, nil
}

// ============================================================================
// RefreshTokenStore
// ============================================================================

// RefreshTokenStore implements core.RefreshTokenStore using Google Cloud Datastore
type RefreshTokenStore struct {
	client    *datastore.Client
	namespace string
}

// NewRefreshTokenStore creates a new Datastore-backed RefreshTokenStore
func NewRefreshTokenStore(client *datastore.Client, namespace string) *RefreshTokenStore {
	return &RefreshTokenStore{
		client:    client,
		namespace: namespace,
	}
}

func (s *RefreshTokenStore) namespacedKey(kind, name string) *datastore.Key {
	key := datastore.NameKey(kind, name, nil)
	key.Namespace = s.namespace
	return key
}

func (s *RefreshTokenStore) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// CreateRefreshToken mints a new refresh-token row with a fresh family id
// (the first generation in its family). The token string itself is returned
// to the caller; only its SHA-256 hash is persisted as the entity key — the
// raw token must never round-trip through the database. Family is a
// 16-character prefix of a secure random; rotation chains keep this Family
// constant so RevokeTokenFamily can hit the whole lineage at once on reuse
// detection.
func (s *RefreshTokenStore) CreateRefreshToken(ctx context.Context, req *core.CreateRefreshTokenRequest) (*core.CreateRefreshTokenResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("CreateRefreshToken: req is required")
	}
	token, err := core.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	family, err := core.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	tokenHash := s.hashToken(token)
	now := time.Now()

	var deviceBytes, scopeBytes []byte
	if req.DeviceInfo != nil {
		deviceBytes, _ = json.Marshal(req.DeviceInfo)
	}
	if req.Scopes != nil {
		scopeBytes, _ = json.Marshal(req.Scopes)
	}

	key := s.namespacedKey(KindRefreshToken, tokenHash)
	entity := &RefreshTokenEntity{
		Key:        key,
		Subject:    req.Subject,
		ClientID:   req.ClientID,
		DeviceInfo: deviceBytes,
		Family:     family[:16],
		Generation: 1,
		Scopes:     scopeBytes,
		CreatedAt:  now,
		ExpiresAt:  now.Add(core.TokenExpiryRefreshToken),
		LastUsedAt: now,
		Revoked:    false,
	}

	if _, err := s.client.Put(ctx, key, entity); err != nil {
		return nil, err
	}

	return &core.CreateRefreshTokenResponse{Token: &core.RefreshToken{
		Token:      token,
		TokenHash:  tokenHash,
		Subject:    req.Subject,
		ClientID:   req.ClientID,
		DeviceInfo: req.DeviceInfo,
		Family:     family[:16],
		Generation: 1,
		Scopes:     req.Scopes,
		CreatedAt:  now,
		ExpiresAt:  now.Add(core.TokenExpiryRefreshToken),
		LastUsedAt: now,
		Revoked:    false,
	}}, nil
}

func (s *RefreshTokenStore) entityToToken(entity *RefreshTokenEntity) *core.RefreshToken {
	var deviceInfo map[string]any
	var scopes []string
	if entity.DeviceInfo != nil {
		json.Unmarshal(entity.DeviceInfo, &deviceInfo)
	}
	if entity.Scopes != nil {
		json.Unmarshal(entity.Scopes, &scopes)
	}
	var authzDetails []core.AuthorizationDetail
	if entity.AuthorizationDetails != nil {
		json.Unmarshal(entity.AuthorizationDetails, &authzDetails)
	}

	rt := &core.RefreshToken{
		TokenHash:            entity.Key.Name,
		Subject:              entity.Subject,
		ClientID:             entity.ClientID,
		DeviceInfo:           deviceInfo,
		Family:               entity.Family,
		Generation:           entity.Generation,
		Scopes:               scopes,
		AuthorizationDetails: authzDetails,
		CreatedAt:            entity.CreatedAt,
		ExpiresAt:            entity.ExpiresAt,
		LastUsedAt:           entity.LastUsedAt,
		Revoked:              entity.Revoked,
	}
	if !entity.RevokedAt.IsZero() {
		rt.RevokedAt = &entity.RevokedAt
	}
	return rt
}

// GetRefreshToken returns the token row for req.Token (looked up by SHA-256
// hash). Returns core.ErrTokenNotFound when absent. Does NOT validate
// Revoked / ExpiresAt — callers that need that should use RotateRefreshToken
// (which enforces both under transaction). This method exists for read-only
// inspection paths (admin tooling, audit).
func (s *RefreshTokenStore) GetRefreshToken(ctx context.Context, req *core.GetRefreshTokenRequest) (*core.GetRefreshTokenResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetRefreshToken: req is required")
	}
	tokenHash := s.hashToken(req.Token)
	key := s.namespacedKey(KindRefreshToken, tokenHash)

	var entity RefreshTokenEntity
	if err := s.client.Get(ctx, key, &entity); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, core.ErrTokenNotFound
		}
		return nil, err
	}

	rt := s.entityToToken(&entity)
	rt.Token = req.Token
	return &core.GetRefreshTokenResponse{Token: rt}, nil
}

// RotateRefreshToken implements OAuth refresh-token rotation with reuse
// detection. Under transaction: revoke the old token, mint a new one in the
// same Family (Generation+1), preserve Subject/ClientID/Scopes/DeviceInfo/
// AuthorizationDetails. Three error sentinels:
//
//   - core.ErrTokenNotFound — old token doesn't exist
//   - core.ErrTokenExpired — old token's ExpiresAt has passed
//   - core.ErrTokenReused — old token was already revoked (reuse attack)
//
// On reuse, the entire family is revoked OUTSIDE the transaction (Datastore
// transactions can touch at most 25 entity groups; a family can outgrow
// that). The transaction itself is best-effort: if the family revoke fails,
// the reuse is still reported to the caller, and a subsequent admin sweep
// or RevokeSubjectTokens call can finish the cleanup.
func (s *RefreshTokenStore) RotateRefreshToken(ctx context.Context, req *core.RotateRefreshTokenRequest) (*core.RotateRefreshTokenResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("RotateRefreshToken: req is required")
	}
	oldHash := s.hashToken(req.OldToken)
	key := s.namespacedKey(KindRefreshToken, oldHash)

	var newRefreshToken *core.RefreshToken

	_, err := s.client.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		var entity RefreshTokenEntity
		if err := tx.Get(key, &entity); err != nil {
			if err == datastore.ErrNoSuchEntity {
				return core.ErrTokenNotFound
			}
			return err
		}

		oldRT := s.entityToToken(&entity)

		// Check if already revoked - potential token reuse attack
		if oldRT.Revoked {
			// Revoke entire family (done outside transaction)
			return core.ErrTokenReused
		}

		// Check if expired
		if time.Now().After(oldRT.ExpiresAt) {
			return core.ErrTokenExpired
		}

		// Revoke old token
		now := time.Now()
		entity.Revoked = true
		entity.RevokedAt = now
		if _, err := tx.Put(key, &entity); err != nil {
			return err
		}

		// Create new token
		newTokenStr, err := core.GenerateSecureToken()
		if err != nil {
			return fmt.Errorf("failed to generate token: %w", err)
		}

		newHash := s.hashToken(newTokenStr)
		newKey := s.namespacedKey(KindRefreshToken, newHash)

		var deviceBytes, scopeBytes, authzDetailsBytes []byte
		if oldRT.DeviceInfo != nil {
			deviceBytes, _ = json.Marshal(oldRT.DeviceInfo)
		}
		if oldRT.Scopes != nil {
			scopeBytes, _ = json.Marshal(oldRT.Scopes)
		}
		if oldRT.AuthorizationDetails != nil {
			authzDetailsBytes, _ = json.Marshal(oldRT.AuthorizationDetails)
		}

		newEntity := &RefreshTokenEntity{
			Key:                  newKey,
			Subject:              oldRT.Subject,
			ClientID:             oldRT.ClientID,
			DeviceInfo:           deviceBytes,
			Family:               oldRT.Family,
			Generation:           oldRT.Generation + 1,
			Scopes:               scopeBytes,
			AuthorizationDetails: authzDetailsBytes,
			CreatedAt:            now,
			ExpiresAt:            now.Add(core.TokenExpiryRefreshToken),
			LastUsedAt:           now,
			Revoked:              false,
		}

		if _, err := tx.Put(newKey, newEntity); err != nil {
			return err
		}

		newRefreshToken = &core.RefreshToken{
			Token:                newTokenStr,
			TokenHash:            newHash,
			Subject:              oldRT.Subject,
			ClientID:             oldRT.ClientID,
			DeviceInfo:           oldRT.DeviceInfo,
			Family:               oldRT.Family,
			Generation:           oldRT.Generation + 1,
			Scopes:               oldRT.Scopes,
			AuthorizationDetails: oldRT.AuthorizationDetails,
			CreatedAt:            now,
			ExpiresAt:            now.Add(core.TokenExpiryRefreshToken),
			LastUsedAt:           now,
			Revoked:    false,
		}

		return nil
	})

	if err == core.ErrTokenReused {
		// Revoke entire family outside the transaction
		var entity RefreshTokenEntity
		if getErr := s.client.Get(ctx, key, &entity); getErr == nil {
			s.RevokeTokenFamily(ctx, &core.RevokeTokenFamilyRequest{Family: entity.Family})
		}
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	return &core.RotateRefreshTokenResponse{Token: newRefreshToken}, nil
}

// RevokeRefreshToken flips Revoked=true under transaction. Idempotent: a
// missing or already-revoked token returns success, not an error — explicit
// logout / RFC 7009 revocation must be safe to call multiple times.
func (s *RefreshTokenStore) RevokeRefreshToken(ctx context.Context, req *core.RevokeRefreshTokenRequest) (*core.RevokeRefreshTokenResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("RevokeRefreshToken: req is required")
	}
	tokenHash := s.hashToken(req.Token)
	key := s.namespacedKey(KindRefreshToken, tokenHash)

	_, err := s.client.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		var entity RefreshTokenEntity
		if err := tx.Get(key, &entity); err != nil {
			if err == datastore.ErrNoSuchEntity {
				return nil // Already gone
			}
			return err
		}

		if entity.Revoked {
			return nil
		}

		entity.Revoked = true
		entity.RevokedAt = time.Now()
		_, err := tx.Put(key, &entity)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &core.RevokeRefreshTokenResponse{}, nil
}

// RevokeSubjectTokens revokes every active (non-revoked) refresh token for
// req.Subject — used by "log out everywhere" and admin force-revoke paths.
// Iterates the indexed subject query and stamps Revoked/RevokedAt outside a
// transaction (the working set can be larger than Datastore's per-tx limit);
// callers tolerate a brief window where some tokens are revoked and others
// aren't, since the worst case is a not-yet-revoked token getting one more
// rotation that then fails reuse detection on the next try.
func (s *RefreshTokenStore) RevokeSubjectTokens(ctx context.Context, req *core.RevokeSubjectTokensRequest) (*core.RevokeSubjectTokensResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("RevokeSubjectTokens: req is required")
	}
	query := datastore.NewQuery(KindRefreshToken).
		FilterField("subject", "=", req.Subject).
		FilterField("revoked", "=", false)
	if s.namespace != "" {
		query = query.Namespace(s.namespace)
	}

	now := time.Now()
	it := s.client.Run(ctx, query)
	for {
		var entity RefreshTokenEntity
		key, err := it.Next(&entity)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		entity.Key = key
		entity.Revoked = true
		entity.RevokedAt = now
		if _, err := s.client.Put(ctx, key, &entity); err != nil {
			return nil, err
		}
	}
	return &core.RevokeSubjectTokensResponse{}, nil
}

// RevokeTokenFamily revokes every active token in a rotation lineage. Called
// by RotateRefreshToken's reuse-attack path (also addressable from admin
// tooling). Like RevokeSubjectTokens, runs outside a transaction — the
// family can have more entities than a single transaction permits.
func (s *RefreshTokenStore) RevokeTokenFamily(ctx context.Context, req *core.RevokeTokenFamilyRequest) (*core.RevokeTokenFamilyResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("RevokeTokenFamily: req is required")
	}
	query := datastore.NewQuery(KindRefreshToken).
		FilterField("family", "=", req.Family).
		FilterField("revoked", "=", false)
	if s.namespace != "" {
		query = query.Namespace(s.namespace)
	}

	now := time.Now()
	it := s.client.Run(ctx, query)
	for {
		var entity RefreshTokenEntity
		key, err := it.Next(&entity)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		entity.Key = key
		entity.Revoked = true
		entity.RevokedAt = now
		if _, err := s.client.Put(ctx, key, &entity); err != nil {
			return nil, err
		}
	}
	return &core.RevokeTokenFamilyResponse{}, nil
}

// GetSubjectTokens returns every active (non-revoked) refresh token for
// req.Subject — backs the "list active sessions" admin / self-service flow.
// The plaintext Token field is intentionally cleared from each result; only
// the hash and metadata travel back to callers, since the store never holds
// the raw token to begin with.
func (s *RefreshTokenStore) GetSubjectTokens(ctx context.Context, req *core.GetSubjectTokensRequest) (*core.GetSubjectTokensResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetSubjectTokens: req is required")
	}
	query := datastore.NewQuery(KindRefreshToken).
		FilterField("subject", "=", req.Subject).
		FilterField("revoked", "=", false)
	if s.namespace != "" {
		query = query.Namespace(s.namespace)
	}

	var tokens []*core.RefreshToken
	it := s.client.Run(ctx, query)
	for {
		var entity RefreshTokenEntity
		key, err := it.Next(&entity)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		entity.Key = key

		rt := s.entityToToken(&entity)
		rt.Token = ""
		tokens = append(tokens, rt)
	}
	return &core.GetSubjectTokensResponse{Tokens: tokens}, nil
}

// CleanupExpiredTokens removes (a) every token whose ExpiresAt has passed
// and (b) every revoked token whose RevokedAt is older than 24 hours. The
// 24-hour grace on revoked rows lets ongoing rotation paths still detect
// reuse against recently-revoked tokens before they vanish entirely.
// Intended for a periodic background sweep, not per-request invocation.
func (s *RefreshTokenStore) CleanupExpiredTokens(ctx context.Context, req *core.CleanupExpiredTokensRequest) (*core.CleanupExpiredTokensResponse, error) {
	cutoff := time.Now().Add(-24 * time.Hour)

	query := datastore.NewQuery(KindRefreshToken).
		FilterField("expires_at", "<", time.Now()).
		KeysOnly()
	if s.namespace != "" {
		query = query.Namespace(s.namespace)
	}

	keys, err := s.client.GetAll(ctx, query, nil)
	if err != nil {
		return nil, err
	}

	if len(keys) > 0 {
		if err := s.client.DeleteMulti(ctx, keys); err != nil {
			return nil, err
		}
	}

	query = datastore.NewQuery(KindRefreshToken).
		FilterField("revoked", "=", true).
		FilterField("revoked_at", "<", cutoff).
		KeysOnly()
	if s.namespace != "" {
		query = query.Namespace(s.namespace)
	}

	keys, err = s.client.GetAll(ctx, query, nil)
	if err != nil {
		return nil, err
	}

	if len(keys) > 0 {
		if err := s.client.DeleteMulti(ctx, keys); err != nil {
			return nil, err
		}
	}

	return &core.CleanupExpiredTokensResponse{}, nil
}

// ============================================================================
// APIKeyStore
// ============================================================================

// APIKeyStore implements core.APIKeyStore using Google Cloud Datastore
type APIKeyStore struct {
	client    *datastore.Client
	namespace string
}

// NewAPIKeyStore creates a new Datastore-backed APIKeyStore
func NewAPIKeyStore(client *datastore.Client, namespace string) *APIKeyStore {
	return &APIKeyStore{
		client:    client,
		namespace: namespace,
	}
}

func (s *APIKeyStore) namespacedKey(kind, name string) *datastore.Key {
	key := datastore.NameKey(kind, name, nil)
	key.Namespace = s.namespace
	return key
}

// CreateAPIKey mints a new key. The KeyID (the entity key) is returned in
// FullKey concatenated with the secret as "<keyID>_<secret>" — only the
// bcrypt hash of the secret is persisted, so the raw secret can never be
// retrieved again. Callers must surface FullKey to the end-user
// immediately; losing it means rotating. HasExpiry tracks whether the
// caller supplied an ExpiresAt — needed because Datastore stores a zero
// time.Time identically to a not-set value, but the contract distinguishes
// "never expires" from "set to 1970-01-01."
func (s *APIKeyStore) CreateAPIKey(ctx context.Context, req *core.CreateAPIKeyRequest) (*core.CreateAPIKeyResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("CreateAPIKey: req is required")
	}
	keyID, err := core.GenerateAPIKeyID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key ID: %w", err)
	}

	secret, err := core.GenerateAPIKeySecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key secret: %w", err)
	}

	keyHash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash key: %w", err)
	}

	now := time.Now()
	key := s.namespacedKey(KindAPIKey, keyID)

	var scopeBytes []byte
	if req.Scopes != nil {
		scopeBytes, _ = json.Marshal(req.Scopes)
	}

	entity := &APIKeyEntity{
		Key:        key,
		KeyHash:    string(keyHash),
		Subject:    req.Subject,
		Name:       req.Name,
		Scopes:     scopeBytes,
		CreatedAt:  now,
		HasExpiry:  req.ExpiresAt != nil,
		LastUsedAt: now,
		Revoked:    false,
	}
	if req.ExpiresAt != nil {
		entity.ExpiresAt = *req.ExpiresAt
	}

	if _, err := s.client.Put(ctx, key, entity); err != nil {
		return nil, err
	}

	fullKey := keyID + "_" + secret
	return &core.CreateAPIKeyResponse{
		FullKey: fullKey,
		APIKey: &core.APIKey{
			KeyID:      keyID,
			KeyHash:    string(keyHash),
			Subject:    req.Subject,
			Name:       req.Name,
			Scopes:     req.Scopes,
			CreatedAt:  now,
			ExpiresAt:  req.ExpiresAt,
			LastUsedAt: now,
			Revoked:    false,
		},
	}, nil
}

func (s *APIKeyStore) entityToAPIKey(entity *APIKeyEntity) *core.APIKey {
	var scopes []string
	if entity.Scopes != nil {
		json.Unmarshal(entity.Scopes, &scopes)
	}

	apiKey := &core.APIKey{
		KeyID:      entity.Key.Name,
		KeyHash:    entity.KeyHash,
		Subject:    entity.Subject,
		Name:       entity.Name,
		Scopes:     scopes,
		CreatedAt:  entity.CreatedAt,
		LastUsedAt: entity.LastUsedAt,
		Revoked:    entity.Revoked,
	}
	if entity.HasExpiry {
		apiKey.ExpiresAt = &entity.ExpiresAt
	}
	if !entity.RevokedAt.IsZero() {
		apiKey.RevokedAt = &entity.RevokedAt
	}
	return apiKey
}

// GetAPIKeyByID returns the metadata row for req.KeyID, or
// core.ErrAPIKeyNotFound when absent. Does NOT validate secret, revocation,
// or expiry — use ValidateAPIKey for the full check.
func (s *APIKeyStore) GetAPIKeyByID(ctx context.Context, req *core.GetAPIKeyByIDRequest) (*core.GetAPIKeyByIDResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetAPIKeyByID: req is required")
	}
	key := s.namespacedKey(KindAPIKey, req.KeyID)

	var entity APIKeyEntity
	if err := s.client.Get(ctx, key, &entity); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, core.ErrAPIKeyNotFound
		}
		return nil, err
	}

	return &core.GetAPIKeyByIDResponse{APIKey: s.entityToAPIKey(&entity)}, nil
}

// ValidateAPIKey performs the full check that GetAPIKeyByID skips. Three
// error sentinels: core.ErrAPIKeyNotFound for "no such key, malformed input,
// or wrong secret" (collapsed deliberately so a probe can't distinguish);
// core.ErrTokenRevoked for revoked keys; core.ErrTokenExpired for expired
// keys. The FullKey format is "oa_<idTail>_<secret>" — first segment fixed,
// second the id tail, third the secret. Any deviation maps to
// ErrAPIKeyNotFound.
func (s *APIKeyStore) ValidateAPIKey(ctx context.Context, req *core.ValidateAPIKeyRequest) (*core.ValidateAPIKeyResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("ValidateAPIKey: req is required")
	}
	parts := strings.SplitN(req.FullKey, "_", 3)
	if len(parts) != 3 || parts[0] != "oa" {
		return nil, core.ErrAPIKeyNotFound
	}

	keyID := parts[0] + "_" + parts[1]
	secret := parts[2]

	getResp, err := s.GetAPIKeyByID(ctx, &core.GetAPIKeyByIDRequest{KeyID: keyID})
	if err != nil {
		return nil, err
	}
	apiKey := getResp.APIKey

	if apiKey.Revoked {
		return nil, core.ErrTokenRevoked
	}

	if apiKey.IsExpired() {
		return nil, core.ErrTokenExpired
	}

	if err := bcrypt.CompareHashAndPassword([]byte(apiKey.KeyHash), []byte(secret)); err != nil {
		return nil, core.ErrAPIKeyNotFound
	}

	return &core.ValidateAPIKeyResponse{APIKey: apiKey}, nil
}

// RevokeAPIKey flips Revoked=true under transaction. Returns
// core.ErrAPIKeyNotFound when the key doesn't exist; already-revoked is a
// no-op success (admin "revoke twice" calls must remain safe).
func (s *APIKeyStore) RevokeAPIKey(ctx context.Context, req *core.RevokeAPIKeyRequest) (*core.RevokeAPIKeyResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("RevokeAPIKey: req is required")
	}
	key := s.namespacedKey(KindAPIKey, req.KeyID)

	_, err := s.client.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		var entity APIKeyEntity
		if err := tx.Get(key, &entity); err != nil {
			if err == datastore.ErrNoSuchEntity {
				return core.ErrAPIKeyNotFound
			}
			return err
		}

		if entity.Revoked {
			return nil
		}

		entity.Revoked = true
		entity.RevokedAt = time.Now()
		_, err := tx.Put(key, &entity)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &core.RevokeAPIKeyResponse{}, nil
}

// ListSubjectAPIKeys returns every API key (revoked or active) for
// req.Subject. The KeyHash field is cleared from results — listing the
// hash to an admin UI would leak bcrypt-protected material that's only
// meant to live inside validation. Order is unspecified.
func (s *APIKeyStore) ListSubjectAPIKeys(ctx context.Context, req *core.ListSubjectAPIKeysRequest) (*core.ListSubjectAPIKeysResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("ListSubjectAPIKeys: req is required")
	}
	query := datastore.NewQuery(KindAPIKey).
		FilterField("subject", "=", req.Subject)
	if s.namespace != "" {
		query = query.Namespace(s.namespace)
	}

	var keys []*core.APIKey
	it := s.client.Run(ctx, query)
	for {
		var entity APIKeyEntity
		key, err := it.Next(&entity)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		entity.Key = key
		apiKey := s.entityToAPIKey(&entity)
		apiKey.KeyHash = ""
		keys = append(keys, apiKey)
	}
	return &core.ListSubjectAPIKeysResponse{APIKeys: keys}, nil
}

// UpdateAPIKeyLastUsed bumps LastUsedAt to time.Now() under transaction.
// Returns an unwrapped datastore.ErrNoSuchEntity (not core.ErrAPIKeyNotFound)
// when the key is missing — this is on the validation hot path and a
// missing key already implies an upstream lookup bug rather than user-facing
// flow. Callers may swallow this error since the bump is advisory.
func (s *APIKeyStore) UpdateAPIKeyLastUsed(ctx context.Context, req *core.UpdateAPIKeyLastUsedRequest) (*core.UpdateAPIKeyLastUsedResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("UpdateAPIKeyLastUsed: req is required")
	}
	key := s.namespacedKey(KindAPIKey, req.KeyID)

	_, err := s.client.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		var entity APIKeyEntity
		if err := tx.Get(key, &entity); err != nil {
			return err
		}

		entity.LastUsedAt = time.Now()
		_, err := tx.Put(key, &entity)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &core.UpdateAPIKeyLastUsedResponse{}, nil
}

// ============================================================================
// UsernameStore
// ============================================================================

// UsernameStore implements accounts.UsernameStore using Google Cloud Datastore
type UsernameStore struct {
	client    *datastore.Client
	namespace string
}

// NewUsernameStore creates a new Datastore-backed UsernameStore
func NewUsernameStore(client *datastore.Client, namespace string) *UsernameStore {
	return &UsernameStore{
		client:    client,
		namespace: namespace,
	}
}

func (s *UsernameStore) namespacedKey(kind, name string) *datastore.Key {
	key := datastore.NameKey(kind, name, nil)
	key.Namespace = s.namespace
	return key
}

// normalizeUsername converts username to lowercase for case-insensitive lookup
func (s *UsernameStore) normalizeUsername(username string) string {
	return strings.ToLower(username)
}

// ReserveUsername binds req.Username to req.UserID. The entity key is the
// lowercased form (case-insensitive uniqueness); the Username field
// preserves the original casing for display. Idempotent for the same
// (username, user) pair — re-reserving by the owner refreshes the display
// casing but doesn't error. A reservation owned by a different user returns
// fmt.Errorf("username already taken"). Runs under transaction to close the
// check-then-write race between two concurrent reservations.
func (s *UsernameStore) ReserveUsername(ctx context.Context, req *accounts.ReserveUsernameRequest) (*accounts.ReserveUsernameResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("ReserveUsername: req is required")
	}
	normalizedUsername := s.normalizeUsername(req.Username)
	key := s.namespacedKey(KindUsername, normalizedUsername)

	_, err := s.client.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		var existing UsernameEntity
		err := tx.Get(key, &existing)
		if err == nil {
			if existing.UserID == req.UserID {
				existing.Username = req.Username
				_, err = tx.Put(key, &existing)
				return err
			}
			return fmt.Errorf("username already taken")
		}
		if err != datastore.ErrNoSuchEntity {
			return err
		}

		entity := &UsernameEntity{
			Key:       key,
			Username:  req.Username,
			UserID:    req.UserID,
			CreatedAt: time.Now(),
		}
		_, err = tx.Put(key, entity)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &accounts.ReserveUsernameResponse{}, nil
}

// GetUserByUsername resolves a username (case-insensitively) to its UserID.
// Returns fmt.Errorf("username not found") when absent — same string-error
// pattern as the other accounts-package lookups; sentinel introduction is
// tracked separately.
func (s *UsernameStore) GetUserByUsername(ctx context.Context, req *accounts.GetUserByUsernameRequest) (*accounts.GetUserByUsernameResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetUserByUsername: req is required")
	}
	normalizedUsername := s.normalizeUsername(req.Username)
	key := s.namespacedKey(KindUsername, normalizedUsername)

	var entity UsernameEntity
	if err := s.client.Get(ctx, key, &entity); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, fmt.Errorf("username not found")
		}
		return nil, err
	}
	return &accounts.GetUserByUsernameResponse{UserID: entity.UserID}, nil
}

// ReleaseUsername drops the reservation. Idempotent — Datastore's Delete
// silently succeeds on missing keys, and account-cleanup paths must remain
// safe to retry. Does NOT verify ownership; callers gating release on
// "the right user is asking" must check upstream (account deletion, admin
// release).
func (s *UsernameStore) ReleaseUsername(ctx context.Context, req *accounts.ReleaseUsernameRequest) (*accounts.ReleaseUsernameResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("ReleaseUsername: req is required")
	}
	normalizedUsername := s.normalizeUsername(req.Username)
	key := s.namespacedKey(KindUsername, normalizedUsername)
	if err := s.client.Delete(ctx, key); err != nil {
		return nil, err
	}
	return &accounts.ReleaseUsernameResponse{}, nil
}

// ChangeUsername atomically moves a reservation from OldUsername to
// NewUsername. Two paths:
//
//   - Case-only change (lowercased forms equal) — single-entity transaction
//     that just updates the display Username; ownership is verified before
//     write ("username not owned by user").
//   - True rename — multi-entity transaction that asserts the new lowercased
//     form is free, deletes the old entity, and inserts the new one in the
//     same transaction so concurrent reservers can't win the race in the
//     gap.
//
// Error strings: "old username not found", "old username not owned by
// user", "new username already taken". CreatedAt resets to now on the new
// row — the reservation is conceptually fresh for the new username.
func (s *UsernameStore) ChangeUsername(ctx context.Context, req *accounts.ChangeUsernameRequest) (*accounts.ChangeUsernameResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("ChangeUsername: req is required")
	}
	oldNormalized := s.normalizeUsername(req.OldUsername)
	newNormalized := s.normalizeUsername(req.NewUsername)

	if oldNormalized == newNormalized {
		key := s.namespacedKey(KindUsername, oldNormalized)
		_, err := s.client.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
			var entity UsernameEntity
			if err := tx.Get(key, &entity); err != nil {
				return err
			}
			if entity.UserID != req.UserID {
				return fmt.Errorf("username not owned by user")
			}
			entity.Username = req.NewUsername
			_, err := tx.Put(key, &entity)
			return err
		})
		if err != nil {
			return nil, err
		}
		return &accounts.ChangeUsernameResponse{}, nil
	}

	oldKey := s.namespacedKey(KindUsername, oldNormalized)
	newKey := s.namespacedKey(KindUsername, newNormalized)

	_, err := s.client.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		var oldEntity UsernameEntity
		if err := tx.Get(oldKey, &oldEntity); err != nil {
			if err == datastore.ErrNoSuchEntity {
				return fmt.Errorf("old username not found")
			}
			return err
		}
		if oldEntity.UserID != req.UserID {
			return fmt.Errorf("old username not owned by user")
		}

		var newEntity UsernameEntity
		err := tx.Get(newKey, &newEntity)
		if err == nil {
			return fmt.Errorf("new username already taken")
		}
		if err != datastore.ErrNoSuchEntity {
			return err
		}

		if err := tx.Delete(oldKey); err != nil {
			return err
		}

		newEntity = UsernameEntity{
			Key:       newKey,
			Username:  req.NewUsername,
			UserID:    req.UserID,
			CreatedAt: time.Now(),
		}
		_, err = tx.Put(newKey, &newEntity)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &accounts.ChangeUsernameResponse{}, nil
}
