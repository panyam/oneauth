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

	oa "github.com/panyam/oneauth"
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

// GAEUser implements the oa.User interface
type GAEUser struct {
	UserID      string         `json:"user_id"`
	Active      bool           `json:"is_active"`
	UserProfile map[string]any `json:"profile"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

func (u *GAEUser) Id() string              { return u.UserID }
func (u *GAEUser) Profile() map[string]any { return u.UserProfile }

// UserStore implements oa.UserStore using Google Cloud Datastore
type UserStore struct {
	client    *datastore.Client
	namespace string
	ctx       context.Context
}

// NewUserStore creates a new Datastore-backed UserStore
func NewUserStore(client *datastore.Client, namespace string) *UserStore {
	return &UserStore{
		client:    client,
		namespace: namespace,
		ctx:       context.Background(),
	}
}

// WithContext returns a copy of the store with the given context
func (s *UserStore) WithContext(ctx context.Context) *UserStore {
	return &UserStore{
		client:    s.client,
		namespace: s.namespace,
		ctx:       ctx,
	}
}

func (s *UserStore) namespacedKey(kind, name string) *datastore.Key {
	key := datastore.NameKey(kind, name, nil)
	key.Namespace = s.namespace
	return key
}

func (s *UserStore) CreateUser(userId string, isActive bool, profile map[string]any) (oa.User, error) {
	key := s.namespacedKey(KindUser, userId)

	var profileBytes []byte
	if profile != nil {
		profileBytes, _ = json.Marshal(profile)
	}

	now := time.Now()
	entity := &UserEntity{
		Key:       key,
		IsActive:  isActive,
		Profile:   profileBytes,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if _, err := s.client.Put(s.ctx, key, entity); err != nil {
		return nil, err
	}

	return &GAEUser{
		UserID:      userId,
		Active:      isActive,
		UserProfile: profile,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

func (s *UserStore) GetUserById(userId string) (oa.User, error) {
	key := s.namespacedKey(KindUser, userId)
	var entity UserEntity
	if err := s.client.Get(s.ctx, key, &entity); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, fmt.Errorf("user not found: %s", userId)
		}
		return nil, err
	}

	var profile map[string]any
	if entity.Profile != nil {
		json.Unmarshal(entity.Profile, &profile)
	}

	return &GAEUser{
		UserID:      userId,
		Active:      entity.IsActive,
		UserProfile: profile,
		CreatedAt:   entity.CreatedAt,
		UpdatedAt:   entity.UpdatedAt,
	}, nil
}

func (s *UserStore) SaveUser(user oa.User) error {
	key := s.namespacedKey(KindUser, user.Id())

	var profileBytes []byte
	if user.Profile() != nil {
		profileBytes, _ = json.Marshal(user.Profile())
	}

	// Get existing to preserve CreatedAt
	var existing UserEntity
	err := s.client.Get(s.ctx, key, &existing)
	if err != nil && err != datastore.ErrNoSuchEntity {
		return err
	}

	entity := &UserEntity{
		Key:       key,
		IsActive:  true, // Default to true if not specified
		Profile:   profileBytes,
		CreatedAt: existing.CreatedAt,
		UpdatedAt: time.Now(),
	}
	if existing.CreatedAt.IsZero() {
		entity.CreatedAt = time.Now()
	}

	// Check if user implements an isActive method via profile
	if gaeUser, ok := user.(*GAEUser); ok {
		entity.IsActive = gaeUser.Active
	}

	_, err = s.client.Put(s.ctx, key, entity)
	return err
}

// ============================================================================
// IdentityStore
// ============================================================================

// IdentityStore implements oa.IdentityStore using Google Cloud Datastore
type IdentityStore struct {
	client    *datastore.Client
	namespace string
	ctx       context.Context
}

// NewIdentityStore creates a new Datastore-backed IdentityStore
func NewIdentityStore(client *datastore.Client, namespace string) *IdentityStore {
	return &IdentityStore{
		client:    client,
		namespace: namespace,
		ctx:       context.Background(),
	}
}

func (s *IdentityStore) WithContext(ctx context.Context) *IdentityStore {
	return &IdentityStore{
		client:    s.client,
		namespace: s.namespace,
		ctx:       ctx,
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

func (s *IdentityStore) GetIdentity(identityType, identityValue string, createIfMissing bool) (*oa.Identity, bool, error) {
	key := s.namespacedKey(KindIdentity, s.identityKeyName(identityType, identityValue))
	var entity IdentityEntity
	err := s.client.Get(s.ctx, key, &entity)

	if err == datastore.ErrNoSuchEntity {
		if createIfMissing {
			now := time.Now()
			entity = IdentityEntity{
				Key:       key,
				Type:      identityType,
				Value:     identityValue,
				UserID:    "",
				Verified:  false,
				CreatedAt: now,
				UpdatedAt: now,
				Version:   1,
			}
			if _, err := s.client.Put(s.ctx, key, &entity); err != nil {
				return nil, false, err
			}
			return entity.ToIdentity(), true, nil
		}
		return nil, false, fmt.Errorf("identity not found")
	}
	if err != nil {
		return nil, false, err
	}

	return entity.ToIdentity(), false, nil
}

func (s *IdentityStore) SaveIdentity(identity *oa.Identity) error {
	key := s.namespacedKey(KindIdentity, s.identityKeyName(identity.Type, identity.Value))
	entity := IdentityToEntity(identity, key)
	_, err := s.client.Put(s.ctx, key, entity)
	return err
}

func (s *IdentityStore) SetUserForIdentity(identityType, identityValue string, newUserId string) error {
	key := s.namespacedKey(KindIdentity, s.identityKeyName(identityType, identityValue))

	_, err := s.client.RunInTransaction(s.ctx, func(tx *datastore.Transaction) error {
		var entity IdentityEntity
		if err := tx.Get(key, &entity); err != nil {
			return err
		}
		entity.UserID = newUserId
		entity.UpdatedAt = time.Now()
		entity.Version++
		_, err := tx.Put(key, &entity)
		return err
	})
	return err
}

func (s *IdentityStore) MarkIdentityVerified(identityType, identityValue string) error {
	key := s.namespacedKey(KindIdentity, s.identityKeyName(identityType, identityValue))

	_, err := s.client.RunInTransaction(s.ctx, func(tx *datastore.Transaction) error {
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
	return err
}

func (s *IdentityStore) GetUserIdentities(userId string) ([]*oa.Identity, error) {
	query := datastore.NewQuery(KindIdentity).
		FilterField("user_id", "=", userId)
	if s.namespace != "" {
		query = query.Namespace(s.namespace)
	}

	var identities []*oa.Identity
	it := s.client.Run(s.ctx, query)
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
	return identities, nil
}

// ============================================================================
// ChannelStore
// ============================================================================

// ChannelStore implements oa.ChannelStore using Google Cloud Datastore
type ChannelStore struct {
	client    *datastore.Client
	namespace string
	ctx       context.Context
}

// NewChannelStore creates a new Datastore-backed ChannelStore
func NewChannelStore(client *datastore.Client, namespace string) *ChannelStore {
	return &ChannelStore{
		client:    client,
		namespace: namespace,
		ctx:       context.Background(),
	}
}

func (s *ChannelStore) WithContext(ctx context.Context) *ChannelStore {
	return &ChannelStore{
		client:    s.client,
		namespace: s.namespace,
		ctx:       ctx,
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

func (s *ChannelStore) GetChannel(provider string, identityKey string, createIfMissing bool) (*oa.Channel, bool, error) {
	key := s.namespacedKey(KindChannel, s.channelKeyName(provider, identityKey))
	var entity ChannelEntity
	err := s.client.Get(s.ctx, key, &entity)

	if err == datastore.ErrNoSuchEntity {
		if createIfMissing {
			now := time.Now()
			entity = ChannelEntity{
				Key:         key,
				Provider:    provider,
				IdentityKey: identityKey,
				Credentials: nil,
				Profile:     nil,
				CreatedAt:   now,
				UpdatedAt:   now,
				Version:     1,
			}
			if _, err := s.client.Put(s.ctx, key, &entity); err != nil {
				return nil, false, err
			}
			return &oa.Channel{
				Provider:    provider,
				IdentityKey: identityKey,
				Credentials: make(map[string]any),
				Profile:     make(map[string]any),
				CreatedAt:   now,
				UpdatedAt:   now,
				Version:     1,
			}, true, nil
		}
		return nil, false, fmt.Errorf("channel not found")
	}
	if err != nil {
		return nil, false, err
	}

	var credentials, profile map[string]any
	if entity.Credentials != nil {
		json.Unmarshal(entity.Credentials, &credentials)
	}
	if entity.Profile != nil {
		json.Unmarshal(entity.Profile, &profile)
	}

	return &oa.Channel{
		Provider:    entity.Provider,
		IdentityKey: entity.IdentityKey,
		Credentials: credentials,
		Profile:     profile,
		CreatedAt:   entity.CreatedAt,
		UpdatedAt:   entity.UpdatedAt,
		ExpiresAt:   entity.ExpiresAt,
		Version:     entity.Version,
	}, false, nil
}

func (s *ChannelStore) SaveChannel(channel *oa.Channel) error {
	key := s.namespacedKey(KindChannel, s.channelKeyName(channel.Provider, channel.IdentityKey))

	var credBytes, profileBytes []byte
	if channel.Credentials != nil {
		credBytes, _ = json.Marshal(channel.Credentials)
	}
	if channel.Profile != nil {
		profileBytes, _ = json.Marshal(channel.Profile)
	}

	// Get existing to preserve CreatedAt and increment Version
	var existing ChannelEntity
	err := s.client.Get(s.ctx, key, &existing)
	if err != nil && err != datastore.ErrNoSuchEntity {
		return err
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

	_, err = s.client.Put(s.ctx, key, entity)
	return err
}

func (s *ChannelStore) GetChannelsByIdentity(identityKey string) ([]*oa.Channel, error) {
	query := datastore.NewQuery(KindChannel).
		FilterField("identity_key", "=", identityKey)
	if s.namespace != "" {
		query = query.Namespace(s.namespace)
	}

	var channels []*oa.Channel
	it := s.client.Run(s.ctx, query)
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

		channels = append(channels, &oa.Channel{
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
	return channels, nil
}

// ============================================================================
// TokenStore (AuthToken)
// ============================================================================

// TokenStore implements oa.TokenStore using Google Cloud Datastore
type TokenStore struct {
	client    *datastore.Client
	namespace string
	ctx       context.Context
}

// NewTokenStore creates a new Datastore-backed TokenStore
func NewTokenStore(client *datastore.Client, namespace string) *TokenStore {
	return &TokenStore{
		client:    client,
		namespace: namespace,
		ctx:       context.Background(),
	}
}

func (s *TokenStore) WithContext(ctx context.Context) *TokenStore {
	return &TokenStore{
		client:    s.client,
		namespace: s.namespace,
		ctx:       ctx,
	}
}

func (s *TokenStore) namespacedKey(kind, name string) *datastore.Key {
	key := datastore.NameKey(kind, name, nil)
	key.Namespace = s.namespace
	return key
}

func (s *TokenStore) CreateToken(userID, email string, tokenType oa.TokenType, expiryDuration time.Duration) (*oa.AuthToken, error) {
	token, err := oa.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	key := s.namespacedKey(KindAuthToken, token)
	now := time.Now()
	entity := &AuthTokenEntity{
		Key:       key,
		Type:      tokenType,
		UserID:    userID,
		Email:     email,
		CreatedAt: now,
		ExpiresAt: now.Add(expiryDuration),
	}

	if _, err := s.client.Put(s.ctx, key, entity); err != nil {
		return nil, err
	}

	return &oa.AuthToken{
		Token:     token,
		Type:      tokenType,
		UserID:    userID,
		Email:     email,
		CreatedAt: now,
		ExpiresAt: now.Add(expiryDuration),
	}, nil
}

func (s *TokenStore) GetToken(token string) (*oa.AuthToken, error) {
	key := s.namespacedKey(KindAuthToken, token)
	var entity AuthTokenEntity
	if err := s.client.Get(s.ctx, key, &entity); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, fmt.Errorf("token not found")
		}
		return nil, err
	}

	authToken := entity.ToAuthToken()
	if authToken.IsExpired() {
		_ = s.DeleteToken(token)
		return nil, fmt.Errorf("token expired")
	}

	return authToken, nil
}

func (s *TokenStore) DeleteToken(token string) error {
	key := s.namespacedKey(KindAuthToken, token)
	return s.client.Delete(s.ctx, key)
}

func (s *TokenStore) DeleteUserTokens(userID string, tokenType oa.TokenType) error {
	query := datastore.NewQuery(KindAuthToken).
		FilterField("user_id", "=", userID).
		FilterField("type", "=", string(tokenType)).
		KeysOnly()
	if s.namespace != "" {
		query = query.Namespace(s.namespace)
	}

	keys, err := s.client.GetAll(s.ctx, query, nil)
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		return nil
	}

	return s.client.DeleteMulti(s.ctx, keys)
}

// ============================================================================
// RefreshTokenStore
// ============================================================================

// RefreshTokenStore implements oa.RefreshTokenStore using Google Cloud Datastore
type RefreshTokenStore struct {
	client    *datastore.Client
	namespace string
	ctx       context.Context
}

// NewRefreshTokenStore creates a new Datastore-backed RefreshTokenStore
func NewRefreshTokenStore(client *datastore.Client, namespace string) *RefreshTokenStore {
	return &RefreshTokenStore{
		client:    client,
		namespace: namespace,
		ctx:       context.Background(),
	}
}

func (s *RefreshTokenStore) WithContext(ctx context.Context) *RefreshTokenStore {
	return &RefreshTokenStore{
		client:    s.client,
		namespace: s.namespace,
		ctx:       ctx,
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

func (s *RefreshTokenStore) CreateRefreshToken(userID, clientID string, deviceInfo map[string]any, scopes []string) (*oa.RefreshToken, error) {
	token, err := oa.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	family, err := oa.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	tokenHash := s.hashToken(token)
	now := time.Now()

	var deviceBytes, scopeBytes []byte
	if deviceInfo != nil {
		deviceBytes, _ = json.Marshal(deviceInfo)
	}
	if scopes != nil {
		scopeBytes, _ = json.Marshal(scopes)
	}

	key := s.namespacedKey(KindRefreshToken, tokenHash)
	entity := &RefreshTokenEntity{
		Key:        key,
		UserID:     userID,
		ClientID:   clientID,
		DeviceInfo: deviceBytes,
		Family:     family[:16],
		Generation: 1,
		Scopes:     scopeBytes,
		CreatedAt:  now,
		ExpiresAt:  now.Add(oa.TokenExpiryRefreshToken),
		LastUsedAt: now,
		Revoked:    false,
	}

	if _, err := s.client.Put(s.ctx, key, entity); err != nil {
		return nil, err
	}

	return &oa.RefreshToken{
		Token:      token,
		TokenHash:  tokenHash,
		UserID:     userID,
		ClientID:   clientID,
		DeviceInfo: deviceInfo,
		Family:     family[:16],
		Generation: 1,
		Scopes:     scopes,
		CreatedAt:  now,
		ExpiresAt:  now.Add(oa.TokenExpiryRefreshToken),
		LastUsedAt: now,
		Revoked:    false,
	}, nil
}

func (s *RefreshTokenStore) entityToToken(entity *RefreshTokenEntity) *oa.RefreshToken {
	var deviceInfo map[string]any
	var scopes []string
	if entity.DeviceInfo != nil {
		json.Unmarshal(entity.DeviceInfo, &deviceInfo)
	}
	if entity.Scopes != nil {
		json.Unmarshal(entity.Scopes, &scopes)
	}

	rt := &oa.RefreshToken{
		TokenHash:  entity.Key.Name,
		UserID:     entity.UserID,
		ClientID:   entity.ClientID,
		DeviceInfo: deviceInfo,
		Family:     entity.Family,
		Generation: entity.Generation,
		Scopes:     scopes,
		CreatedAt:  entity.CreatedAt,
		ExpiresAt:  entity.ExpiresAt,
		LastUsedAt: entity.LastUsedAt,
		Revoked:    entity.Revoked,
	}
	if !entity.RevokedAt.IsZero() {
		rt.RevokedAt = &entity.RevokedAt
	}
	return rt
}

func (s *RefreshTokenStore) GetRefreshToken(token string) (*oa.RefreshToken, error) {
	tokenHash := s.hashToken(token)
	key := s.namespacedKey(KindRefreshToken, tokenHash)

	var entity RefreshTokenEntity
	if err := s.client.Get(s.ctx, key, &entity); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, oa.ErrTokenNotFound
		}
		return nil, err
	}

	rt := s.entityToToken(&entity)
	rt.Token = token
	return rt, nil
}

func (s *RefreshTokenStore) RotateRefreshToken(oldToken string) (*oa.RefreshToken, error) {
	oldHash := s.hashToken(oldToken)
	key := s.namespacedKey(KindRefreshToken, oldHash)

	var newRefreshToken *oa.RefreshToken

	_, err := s.client.RunInTransaction(s.ctx, func(tx *datastore.Transaction) error {
		var entity RefreshTokenEntity
		if err := tx.Get(key, &entity); err != nil {
			if err == datastore.ErrNoSuchEntity {
				return oa.ErrTokenNotFound
			}
			return err
		}

		oldRT := s.entityToToken(&entity)

		// Check if already revoked - potential token reuse attack
		if oldRT.Revoked {
			// Revoke entire family (done outside transaction)
			return oa.ErrTokenReused
		}

		// Check if expired
		if time.Now().After(oldRT.ExpiresAt) {
			return oa.ErrTokenExpired
		}

		// Revoke old token
		now := time.Now()
		entity.Revoked = true
		entity.RevokedAt = now
		if _, err := tx.Put(key, &entity); err != nil {
			return err
		}

		// Create new token
		newTokenStr, err := oa.GenerateSecureToken()
		if err != nil {
			return fmt.Errorf("failed to generate token: %w", err)
		}

		newHash := s.hashToken(newTokenStr)
		newKey := s.namespacedKey(KindRefreshToken, newHash)

		var deviceBytes, scopeBytes []byte
		if oldRT.DeviceInfo != nil {
			deviceBytes, _ = json.Marshal(oldRT.DeviceInfo)
		}
		if oldRT.Scopes != nil {
			scopeBytes, _ = json.Marshal(oldRT.Scopes)
		}

		newEntity := &RefreshTokenEntity{
			Key:        newKey,
			UserID:     oldRT.UserID,
			ClientID:   oldRT.ClientID,
			DeviceInfo: deviceBytes,
			Family:     oldRT.Family,
			Generation: oldRT.Generation + 1,
			Scopes:     scopeBytes,
			CreatedAt:  now,
			ExpiresAt:  now.Add(oa.TokenExpiryRefreshToken),
			LastUsedAt: now,
			Revoked:    false,
		}

		if _, err := tx.Put(newKey, newEntity); err != nil {
			return err
		}

		newRefreshToken = &oa.RefreshToken{
			Token:      newTokenStr,
			TokenHash:  newHash,
			UserID:     oldRT.UserID,
			ClientID:   oldRT.ClientID,
			DeviceInfo: oldRT.DeviceInfo,
			Family:     oldRT.Family,
			Generation: oldRT.Generation + 1,
			Scopes:     oldRT.Scopes,
			CreatedAt:  now,
			ExpiresAt:  now.Add(oa.TokenExpiryRefreshToken),
			LastUsedAt: now,
			Revoked:    false,
		}

		return nil
	})

	if err == oa.ErrTokenReused {
		// Revoke entire family outside the transaction
		var entity RefreshTokenEntity
		if getErr := s.client.Get(s.ctx, key, &entity); getErr == nil {
			s.RevokeTokenFamily(entity.Family)
		}
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	return newRefreshToken, nil
}

func (s *RefreshTokenStore) RevokeRefreshToken(token string) error {
	tokenHash := s.hashToken(token)
	key := s.namespacedKey(KindRefreshToken, tokenHash)

	_, err := s.client.RunInTransaction(s.ctx, func(tx *datastore.Transaction) error {
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
	return err
}

func (s *RefreshTokenStore) RevokeUserTokens(userID string) error {
	query := datastore.NewQuery(KindRefreshToken).
		FilterField("user_id", "=", userID).
		FilterField("revoked", "=", false)
	if s.namespace != "" {
		query = query.Namespace(s.namespace)
	}

	now := time.Now()
	it := s.client.Run(s.ctx, query)
	for {
		var entity RefreshTokenEntity
		key, err := it.Next(&entity)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}

		entity.Key = key
		entity.Revoked = true
		entity.RevokedAt = now
		if _, err := s.client.Put(s.ctx, key, &entity); err != nil {
			return err
		}
	}
	return nil
}

func (s *RefreshTokenStore) RevokeTokenFamily(family string) error {
	query := datastore.NewQuery(KindRefreshToken).
		FilterField("family", "=", family).
		FilterField("revoked", "=", false)
	if s.namespace != "" {
		query = query.Namespace(s.namespace)
	}

	now := time.Now()
	it := s.client.Run(s.ctx, query)
	for {
		var entity RefreshTokenEntity
		key, err := it.Next(&entity)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}

		entity.Key = key
		entity.Revoked = true
		entity.RevokedAt = now
		if _, err := s.client.Put(s.ctx, key, &entity); err != nil {
			return err
		}
	}
	return nil
}

func (s *RefreshTokenStore) GetUserTokens(userID string) ([]*oa.RefreshToken, error) {
	query := datastore.NewQuery(KindRefreshToken).
		FilterField("user_id", "=", userID).
		FilterField("revoked", "=", false)
	if s.namespace != "" {
		query = query.Namespace(s.namespace)
	}

	var tokens []*oa.RefreshToken
	it := s.client.Run(s.ctx, query)
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
		// Don't include the actual token value for security
		rt.Token = ""
		tokens = append(tokens, rt)
	}
	return tokens, nil
}

func (s *RefreshTokenStore) CleanupExpiredTokens() error {
	cutoff := time.Now().Add(-24 * time.Hour)

	// Delete expired tokens
	query := datastore.NewQuery(KindRefreshToken).
		FilterField("expires_at", "<", time.Now()).
		KeysOnly()
	if s.namespace != "" {
		query = query.Namespace(s.namespace)
	}

	keys, err := s.client.GetAll(s.ctx, query, nil)
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		if err := s.client.DeleteMulti(s.ctx, keys); err != nil {
			return err
		}
	}

	// Delete old revoked tokens
	query = datastore.NewQuery(KindRefreshToken).
		FilterField("revoked", "=", true).
		FilterField("revoked_at", "<", cutoff).
		KeysOnly()
	if s.namespace != "" {
		query = query.Namespace(s.namespace)
	}

	keys, err = s.client.GetAll(s.ctx, query, nil)
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		return s.client.DeleteMulti(s.ctx, keys)
	}

	return nil
}

// ============================================================================
// APIKeyStore
// ============================================================================

// APIKeyStore implements oa.APIKeyStore using Google Cloud Datastore
type APIKeyStore struct {
	client    *datastore.Client
	namespace string
	ctx       context.Context
}

// NewAPIKeyStore creates a new Datastore-backed APIKeyStore
func NewAPIKeyStore(client *datastore.Client, namespace string) *APIKeyStore {
	return &APIKeyStore{
		client:    client,
		namespace: namespace,
		ctx:       context.Background(),
	}
}

func (s *APIKeyStore) WithContext(ctx context.Context) *APIKeyStore {
	return &APIKeyStore{
		client:    s.client,
		namespace: s.namespace,
		ctx:       ctx,
	}
}

func (s *APIKeyStore) namespacedKey(kind, name string) *datastore.Key {
	key := datastore.NameKey(kind, name, nil)
	key.Namespace = s.namespace
	return key
}

func (s *APIKeyStore) CreateAPIKey(userID, name string, scopes []string, expiresAt *time.Time) (string, *oa.APIKey, error) {
	keyID, err := oa.GenerateAPIKeyID()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate key ID: %w", err)
	}

	secret, err := oa.GenerateAPIKeySecret()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate key secret: %w", err)
	}

	keyHash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, fmt.Errorf("failed to hash key: %w", err)
	}

	now := time.Now()
	key := s.namespacedKey(KindAPIKey, keyID)

	var scopeBytes []byte
	if scopes != nil {
		scopeBytes, _ = json.Marshal(scopes)
	}

	entity := &APIKeyEntity{
		Key:        key,
		KeyHash:    string(keyHash),
		UserID:     userID,
		Name:       name,
		Scopes:     scopeBytes,
		CreatedAt:  now,
		HasExpiry:  expiresAt != nil,
		LastUsedAt: now,
		Revoked:    false,
	}
	if expiresAt != nil {
		entity.ExpiresAt = *expiresAt
	}

	if _, err := s.client.Put(s.ctx, key, entity); err != nil {
		return "", nil, err
	}

	fullKey := keyID + "_" + secret
	return fullKey, &oa.APIKey{
		KeyID:      keyID,
		KeyHash:    string(keyHash),
		UserID:     userID,
		Name:       name,
		Scopes:     scopes,
		CreatedAt:  now,
		ExpiresAt:  expiresAt,
		LastUsedAt: now,
		Revoked:    false,
	}, nil
}

func (s *APIKeyStore) entityToAPIKey(entity *APIKeyEntity) *oa.APIKey {
	var scopes []string
	if entity.Scopes != nil {
		json.Unmarshal(entity.Scopes, &scopes)
	}

	apiKey := &oa.APIKey{
		KeyID:      entity.Key.Name,
		KeyHash:    entity.KeyHash,
		UserID:     entity.UserID,
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

func (s *APIKeyStore) GetAPIKeyByID(keyID string) (*oa.APIKey, error) {
	key := s.namespacedKey(KindAPIKey, keyID)

	var entity APIKeyEntity
	if err := s.client.Get(s.ctx, key, &entity); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, oa.ErrAPIKeyNotFound
		}
		return nil, err
	}

	return s.entityToAPIKey(&entity), nil
}

func (s *APIKeyStore) ValidateAPIKey(fullKey string) (*oa.APIKey, error) {
	// Parse the full key: oa_keyid_secret -> ["oa", "keyid", "secret"]
	parts := strings.SplitN(fullKey, "_", 3)
	if len(parts) != 3 || parts[0] != "oa" {
		return nil, oa.ErrAPIKeyNotFound
	}

	keyID := parts[0] + "_" + parts[1]
	secret := parts[2]

	apiKey, err := s.GetAPIKeyByID(keyID)
	if err != nil {
		return nil, err
	}

	if apiKey.Revoked {
		return nil, oa.ErrTokenRevoked
	}

	if apiKey.IsExpired() {
		return nil, oa.ErrTokenExpired
	}

	if err := bcrypt.CompareHashAndPassword([]byte(apiKey.KeyHash), []byte(secret)); err != nil {
		return nil, oa.ErrAPIKeyNotFound
	}

	return apiKey, nil
}

func (s *APIKeyStore) RevokeAPIKey(keyID string) error {
	key := s.namespacedKey(KindAPIKey, keyID)

	_, err := s.client.RunInTransaction(s.ctx, func(tx *datastore.Transaction) error {
		var entity APIKeyEntity
		if err := tx.Get(key, &entity); err != nil {
			if err == datastore.ErrNoSuchEntity {
				return oa.ErrAPIKeyNotFound
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
	return err
}

func (s *APIKeyStore) ListUserAPIKeys(userID string) ([]*oa.APIKey, error) {
	query := datastore.NewQuery(KindAPIKey).
		FilterField("user_id", "=", userID)
	if s.namespace != "" {
		query = query.Namespace(s.namespace)
	}

	var keys []*oa.APIKey
	it := s.client.Run(s.ctx, query)
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
		apiKey.KeyHash = "" // Don't expose hash in listings
		keys = append(keys, apiKey)
	}
	return keys, nil
}

func (s *APIKeyStore) UpdateAPIKeyLastUsed(keyID string) error {
	key := s.namespacedKey(KindAPIKey, keyID)

	_, err := s.client.RunInTransaction(s.ctx, func(tx *datastore.Transaction) error {
		var entity APIKeyEntity
		if err := tx.Get(key, &entity); err != nil {
			return err
		}

		entity.LastUsedAt = time.Now()
		_, err := tx.Put(key, &entity)
		return err
	})
	return err
}

// ============================================================================
// UsernameStore
// ============================================================================

// UsernameStore implements oa.UsernameStore using Google Cloud Datastore
type UsernameStore struct {
	client    *datastore.Client
	namespace string
	ctx       context.Context
}

// NewUsernameStore creates a new Datastore-backed UsernameStore
func NewUsernameStore(client *datastore.Client, namespace string) *UsernameStore {
	return &UsernameStore{
		client:    client,
		namespace: namespace,
		ctx:       context.Background(),
	}
}

func (s *UsernameStore) WithContext(ctx context.Context) *UsernameStore {
	return &UsernameStore{
		client:    s.client,
		namespace: s.namespace,
		ctx:       ctx,
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

func (s *UsernameStore) ReserveUsername(username string, userID string) error {
	normalizedUsername := s.normalizeUsername(username)
	key := s.namespacedKey(KindUsername, normalizedUsername)

	_, err := s.client.RunInTransaction(s.ctx, func(tx *datastore.Transaction) error {
		var existing UsernameEntity
		err := tx.Get(key, &existing)
		if err == nil {
			// Username already exists
			if existing.UserID == userID {
				// Same user, just update the original case
				existing.Username = username
				_, err = tx.Put(key, &existing)
				return err
			}
			return fmt.Errorf("username already taken")
		}
		if err != datastore.ErrNoSuchEntity {
			return err
		}

		// Create new username reservation
		entity := &UsernameEntity{
			Key:       key,
			Username:  username,
			UserID:    userID,
			CreatedAt: time.Now(),
		}
		_, err = tx.Put(key, entity)
		return err
	})
	return err
}

func (s *UsernameStore) GetUserByUsername(username string) (string, error) {
	normalizedUsername := s.normalizeUsername(username)
	key := s.namespacedKey(KindUsername, normalizedUsername)

	var entity UsernameEntity
	if err := s.client.Get(s.ctx, key, &entity); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return "", fmt.Errorf("username not found")
		}
		return "", err
	}
	return entity.UserID, nil
}

func (s *UsernameStore) ReleaseUsername(username string) error {
	normalizedUsername := s.normalizeUsername(username)
	key := s.namespacedKey(KindUsername, normalizedUsername)
	return s.client.Delete(s.ctx, key)
}

func (s *UsernameStore) ChangeUsername(oldUsername, newUsername, userID string) error {
	oldNormalized := s.normalizeUsername(oldUsername)
	newNormalized := s.normalizeUsername(newUsername)

	// If same normalized username, just update the case
	if oldNormalized == newNormalized {
		key := s.namespacedKey(KindUsername, oldNormalized)
		_, err := s.client.RunInTransaction(s.ctx, func(tx *datastore.Transaction) error {
			var entity UsernameEntity
			if err := tx.Get(key, &entity); err != nil {
				return err
			}
			if entity.UserID != userID {
				return fmt.Errorf("username not owned by user")
			}
			entity.Username = newUsername
			_, err := tx.Put(key, &entity)
			return err
		})
		return err
	}

	// Different username - need to atomically release old and reserve new
	oldKey := s.namespacedKey(KindUsername, oldNormalized)
	newKey := s.namespacedKey(KindUsername, newNormalized)

	_, err := s.client.RunInTransaction(s.ctx, func(tx *datastore.Transaction) error {
		// Check old username exists and belongs to user
		var oldEntity UsernameEntity
		if err := tx.Get(oldKey, &oldEntity); err != nil {
			if err == datastore.ErrNoSuchEntity {
				return fmt.Errorf("old username not found")
			}
			return err
		}
		if oldEntity.UserID != userID {
			return fmt.Errorf("old username not owned by user")
		}

		// Check new username is available
		var newEntity UsernameEntity
		err := tx.Get(newKey, &newEntity)
		if err == nil {
			return fmt.Errorf("new username already taken")
		}
		if err != datastore.ErrNoSuchEntity {
			return err
		}

		// Delete old, create new
		if err := tx.Delete(oldKey); err != nil {
			return err
		}

		newEntity = UsernameEntity{
			Key:       newKey,
			Username:  newUsername,
			UserID:    userID,
			CreatedAt: time.Now(),
		}
		_, err = tx.Put(newKey, &newEntity)
		return err
	})
	return err
}
