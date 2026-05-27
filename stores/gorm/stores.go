//go:build !wasm
// +build !wasm

package gorm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/panyam/oneauth/accounts"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/localauth"
)

// AutoMigrate runs database migrations for all oneauth tables
func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&UserModel{},
		&IdentityModel{},
		&ChannelModel{},
		&VerificationTokenModel{},
		&RefreshTokenModel{},
		&APIKeyModel{},
		&UsernameModel{},
		&SigningKeyModel{},
		&KidKeyModel{},
		&AppRegistrationModel{},
	)
}

// =============================================================================
// UserStore
// =============================================================================

// GORMUser implements the accounts.User interface
type GORMUser struct {
	model *UserModel
}

func (u *GORMUser) Id() string              { return u.model.ID }
func (u *GORMUser) Profile() map[string]any { return u.model.Profile }

// UserStore implements accounts.UserStore using GORM
type UserStore struct {
	db *gorm.DB
}

func NewUserStore(db *gorm.DB) *UserStore {
	return &UserStore{db: db}
}

func (s *UserStore) CreateUser(ctx context.Context, req *accounts.CreateUserRequest) (*accounts.CreateUserResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("CreateUser: req is required")
	}
	model := &UserModel{
		ID:       req.UserID,
		IsActive: req.IsActive,
		Profile:  req.Profile,
	}
	if err := s.db.WithContext(ctx).Create(model).Error; err != nil {
		return nil, err
	}
	return &accounts.CreateUserResponse{User: &GORMUser{model: model}}, nil
}

func (s *UserStore) GetUserById(ctx context.Context, req *accounts.GetUserByIDRequest) (*accounts.GetUserByIDResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetUserById: req is required")
	}
	var model UserModel
	if err := s.db.WithContext(ctx).First(&model, "id = ?", req.UserID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found: %s", req.UserID)
		}
		return nil, err
	}
	return &accounts.GetUserByIDResponse{User: &GORMUser{model: &model}}, nil
}

func (s *UserStore) SaveUser(ctx context.Context, req *accounts.SaveUserRequest) (*accounts.SaveUserResponse, error) {
	if req == nil || req.User == nil {
		return nil, fmt.Errorf("SaveUser: req.User is required")
	}
	model := &UserModel{
		ID:      req.User.Id(),
		Profile: req.User.Profile(),
	}
	if err := s.db.WithContext(ctx).Save(model).Error; err != nil {
		return nil, err
	}
	return &accounts.SaveUserResponse{}, nil
}

// =============================================================================
// IdentityStore
// =============================================================================

// IdentityStore implements accounts.IdentityStore using GORM
type IdentityStore struct {
	db *gorm.DB
}

func NewIdentityStore(db *gorm.DB) *IdentityStore {
	return &IdentityStore{db: db}
}

func (s *IdentityStore) GetIdentity(ctx context.Context, req *accounts.GetIdentityRequest) (*accounts.GetIdentityResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetIdentity: req is required")
	}
	var model IdentityModel
	err := s.db.WithContext(ctx).First(&model, "type = ? AND value = ?", req.IdentityType, req.IdentityValue).Error

	if err == gorm.ErrRecordNotFound {
		if req.CreateIfMissing {
			model = IdentityModel{
				Type:     req.IdentityType,
				Value:    req.IdentityValue,
				UserID:   "",
				Verified: false,
			}
			if err := s.db.WithContext(ctx).Create(&model).Error; err != nil {
				return nil, err
			}
			return &accounts.GetIdentityResponse{Identity: model.ToIdentity(), NewCreated: true}, nil
		}
		return nil, fmt.Errorf("identity not found")
	}
	if err != nil {
		return nil, err
	}

	return &accounts.GetIdentityResponse{Identity: model.ToIdentity()}, nil
}

func (s *IdentityStore) SaveIdentity(ctx context.Context, req *accounts.SaveIdentityRequest) (*accounts.SaveIdentityResponse, error) {
	if req == nil || req.Identity == nil {
		return nil, fmt.Errorf("SaveIdentity: req.Identity is required")
	}
	model := IdentityToModel(req.Identity)
	if err := s.db.WithContext(ctx).Save(model).Error; err != nil {
		return nil, err
	}
	return &accounts.SaveIdentityResponse{}, nil
}

func (s *IdentityStore) SetUserForIdentity(ctx context.Context, req *accounts.SetUserForIdentityRequest) (*accounts.SetUserForIdentityResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("SetUserForIdentity: req is required")
	}
	if err := s.db.WithContext(ctx).Model(&IdentityModel{}).
		Where("type = ? AND value = ?", req.IdentityType, req.IdentityValue).
		Update("user_id", req.NewUserID).Error; err != nil {
		return nil, err
	}
	return &accounts.SetUserForIdentityResponse{}, nil
}

func (s *IdentityStore) MarkIdentityVerified(ctx context.Context, req *accounts.MarkIdentityVerifiedRequest) (*accounts.MarkIdentityVerifiedResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("MarkIdentityVerified: req is required")
	}
	if err := s.db.WithContext(ctx).Model(&IdentityModel{}).
		Where("type = ? AND value = ?", req.IdentityType, req.IdentityValue).
		Update("verified", true).Error; err != nil {
		return nil, err
	}
	return &accounts.MarkIdentityVerifiedResponse{}, nil
}

func (s *IdentityStore) GetUserIdentities(ctx context.Context, req *accounts.GetUserIdentitiesRequest) (*accounts.GetUserIdentitiesResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetUserIdentities: req is required")
	}
	var models []IdentityModel
	if err := s.db.WithContext(ctx).Where("user_id = ?", req.UserID).Find(&models).Error; err != nil {
		return nil, err
	}

	identities := make([]*accounts.Identity, len(models))
	for i, m := range models {
		identities[i] = m.ToIdentity()
	}
	return &accounts.GetUserIdentitiesResponse{Identities: identities}, nil
}

// =============================================================================
// ChannelStore
// =============================================================================

// ChannelStore implements accounts.ChannelStore using GORM
type ChannelStore struct {
	db *gorm.DB
}

func NewChannelStore(db *gorm.DB) *ChannelStore {
	return &ChannelStore{db: db}
}

func (s *ChannelStore) GetChannel(ctx context.Context, req *accounts.GetChannelRequest) (*accounts.GetChannelResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetChannel: req is required")
	}
	var model ChannelModel
	err := s.db.WithContext(ctx).First(&model, "provider = ? AND identity_key = ?", req.Provider, req.IdentityKey).Error

	if err == gorm.ErrRecordNotFound {
		if req.CreateIfMissing {
			model = ChannelModel{
				Provider:    req.Provider,
				IdentityKey: req.IdentityKey,
				Credentials: make(JSONMap),
				Profile:     make(JSONMap),
			}
			if err := s.db.WithContext(ctx).Create(&model).Error; err != nil {
				return nil, err
			}
			return &accounts.GetChannelResponse{Channel: model.ToChannel(), NewCreated: true}, nil
		}
		return nil, fmt.Errorf("channel not found")
	}
	if err != nil {
		return nil, err
	}

	return &accounts.GetChannelResponse{Channel: model.ToChannel()}, nil
}

func (s *ChannelStore) SaveChannel(ctx context.Context, req *accounts.SaveChannelRequest) (*accounts.SaveChannelResponse, error) {
	if req == nil || req.Channel == nil {
		return nil, fmt.Errorf("SaveChannel: req.Channel is required")
	}
	model := ChannelToModel(req.Channel)
	if err := s.db.WithContext(ctx).Save(model).Error; err != nil {
		return nil, err
	}
	return &accounts.SaveChannelResponse{}, nil
}

func (s *ChannelStore) GetChannelsByIdentity(ctx context.Context, req *accounts.GetChannelsByIdentityRequest) (*accounts.GetChannelsByIdentityResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetChannelsByIdentity: req is required")
	}
	var models []ChannelModel
	if err := s.db.WithContext(ctx).Where("identity_key = ?", req.IdentityKey).Find(&models).Error; err != nil {
		return nil, err
	}

	channels := make([]*accounts.Channel, len(models))
	for i, m := range models {
		channels[i] = m.ToChannel()
	}
	return &accounts.GetChannelsByIdentityResponse{Channels: channels}, nil
}

// =============================================================================
// TokenStore (for email verification and password reset)
// =============================================================================

// TokenStore implements core.TokenStore using GORM
type TokenStore struct {
	db *gorm.DB
}

func NewTokenStore(db *gorm.DB) *TokenStore {
	return &TokenStore{db: db}
}

func (s *TokenStore) CreateToken(subject, email string, tokenType localauth.VerificationType, expiryDuration time.Duration) (*localauth.VerificationToken, error) {
	token, err := core.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	model := &VerificationTokenModel{
		Token:     token,
		Type:      tokenType,
		Subject:   subject,
		Email:     email,
		ExpiresAt: time.Now().Add(expiryDuration),
	}

	if err := s.db.Create(model).Error; err != nil {
		return nil, err
	}

	return model.ToVerificationToken(), nil
}

func (s *TokenStore) GetToken(token string) (*localauth.VerificationToken, error) {
	var model VerificationTokenModel
	if err := s.db.First(&model, "token = ?", token).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("token not found")
		}
		return nil, err
	}

	verToken := model.ToVerificationToken()
	if verToken.IsExpired() {
		_ = s.DeleteToken(token)
		return nil, fmt.Errorf("token expired")
	}

	return verToken, nil
}

func (s *TokenStore) DeleteToken(token string) error {
	return s.db.Delete(&VerificationTokenModel{}, "token = ?", token).Error
}

func (s *TokenStore) DeleteSubjectTokens(subject string, tokenType localauth.VerificationType) error {
	return s.db.Delete(&VerificationTokenModel{}, "subject = ? AND type = ?", subject, tokenType).Error
}

// =============================================================================
// RefreshTokenStore
// =============================================================================

// RefreshTokenStore implements core.RefreshTokenStore using GORM
type RefreshTokenStore struct {
	db *gorm.DB
}

func NewRefreshTokenStore(db *gorm.DB) *RefreshTokenStore {
	return &RefreshTokenStore{db: db}
}

func (s *RefreshTokenStore) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (s *RefreshTokenStore) CreateRefreshToken(ctx context.Context, req *core.CreateRefreshTokenRequest) (*core.CreateRefreshTokenResponse, error) {
	token, err := core.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	family, err := core.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	model := &RefreshTokenModel{
		TokenHash:  s.hashToken(token),
		Token:      token,
		Subject:    req.Subject,
		ClientID:   req.ClientID,
		DeviceInfo: req.DeviceInfo,
		Family:     family[:16],
		Generation: 1,
		Scopes:     req.Scopes,
		ExpiresAt:  now.Add(core.TokenExpiryRefreshToken),
		LastUsedAt: now,
		Revoked:    false,
	}

	if err := s.db.WithContext(ctx).Create(model).Error; err != nil {
		return nil, err
	}

	rt := model.ToRefreshToken()
	rt.Token = token
	return &core.CreateRefreshTokenResponse{Token: rt}, nil
}

func (s *RefreshTokenStore) GetRefreshToken(ctx context.Context, req *core.GetRefreshTokenRequest) (*core.GetRefreshTokenResponse, error) {
	tokenHash := s.hashToken(req.Token)
	var model RefreshTokenModel
	if err := s.db.WithContext(ctx).First(&model, "token_hash = ?", tokenHash).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, core.ErrTokenNotFound
		}
		return nil, err
	}

	rt := model.ToRefreshToken()
	rt.Token = req.Token
	return &core.GetRefreshTokenResponse{Token: rt}, nil
}

func (s *RefreshTokenStore) RotateRefreshToken(ctx context.Context, req *core.RotateRefreshTokenRequest) (*core.RotateRefreshTokenResponse, error) {
	oldHash := s.hashToken(req.OldToken)

	var newRefreshToken *core.RefreshToken
	var newTokenValue string

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var oldModel RefreshTokenModel
		if err := tx.First(&oldModel, "token_hash = ?", oldHash).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return core.ErrTokenNotFound
			}
			return err
		}

		if oldModel.Revoked {
			return core.ErrTokenReused
		}

		if time.Now().After(oldModel.ExpiresAt) {
			return core.ErrTokenExpired
		}

		now := time.Now()
		if err := tx.Model(&oldModel).Updates(map[string]any{
			"revoked":    true,
			"revoked_at": now,
		}).Error; err != nil {
			return err
		}

		newToken, err := core.GenerateSecureToken()
		if err != nil {
			return err
		}
		newTokenValue = newToken

		newModel := &RefreshTokenModel{
			TokenHash:            s.hashToken(newToken),
			Subject:              oldModel.Subject,
			ClientID:             oldModel.ClientID,
			DeviceInfo:           oldModel.DeviceInfo,
			Family:               oldModel.Family,
			Generation:           oldModel.Generation + 1,
			Scopes:               oldModel.Scopes,
			AuthorizationDetails: oldModel.AuthorizationDetails,
			ExpiresAt:            now.Add(core.TokenExpiryRefreshToken),
			LastUsedAt:           now,
			Revoked:              false,
		}

		if err := tx.Create(newModel).Error; err != nil {
			return err
		}

		newRefreshToken = newModel.ToRefreshToken()
		return nil
	})

	if err != nil {
		return nil, err
	}

	newRefreshToken.Token = newTokenValue
	return &core.RotateRefreshTokenResponse{Token: newRefreshToken}, nil
}

func (s *RefreshTokenStore) RevokeRefreshToken(ctx context.Context, req *core.RevokeRefreshTokenRequest) (*core.RevokeRefreshTokenResponse, error) {
	tokenHash := s.hashToken(req.Token)
	now := time.Now()
	if err := s.db.WithContext(ctx).Model(&RefreshTokenModel{}).
		Where("token_hash = ?", tokenHash).
		Updates(map[string]any{"revoked": true, "revoked_at": now}).Error; err != nil {
		return nil, err
	}
	return &core.RevokeRefreshTokenResponse{}, nil
}

func (s *RefreshTokenStore) RevokeSubjectTokens(ctx context.Context, req *core.RevokeSubjectTokensRequest) (*core.RevokeSubjectTokensResponse, error) {
	now := time.Now()
	if err := s.db.WithContext(ctx).Model(&RefreshTokenModel{}).
		Where("subject = ? AND revoked = ?", req.Subject, false).
		Updates(map[string]any{"revoked": true, "revoked_at": now}).Error; err != nil {
		return nil, err
	}
	return &core.RevokeSubjectTokensResponse{}, nil
}

func (s *RefreshTokenStore) RevokeTokenFamily(ctx context.Context, req *core.RevokeTokenFamilyRequest) (*core.RevokeTokenFamilyResponse, error) {
	now := time.Now()
	if err := s.db.WithContext(ctx).Model(&RefreshTokenModel{}).
		Where("family = ? AND revoked = ?", req.Family, false).
		Updates(map[string]any{"revoked": true, "revoked_at": now}).Error; err != nil {
		return nil, err
	}
	return &core.RevokeTokenFamilyResponse{}, nil
}

func (s *RefreshTokenStore) GetSubjectTokens(ctx context.Context, req *core.GetSubjectTokensRequest) (*core.GetSubjectTokensResponse, error) {
	var models []RefreshTokenModel
	if err := s.db.WithContext(ctx).Where("subject = ? AND revoked = ? AND expires_at > ?", req.Subject, false, time.Now()).
		Find(&models).Error; err != nil {
		return nil, err
	}

	tokens := make([]*core.RefreshToken, len(models))
	for i, m := range models {
		tokens[i] = m.ToRefreshToken()
		tokens[i].Token = ""
	}
	return &core.GetSubjectTokensResponse{Tokens: tokens}, nil
}

func (s *RefreshTokenStore) CleanupExpiredTokens(ctx context.Context, req *core.CleanupExpiredTokensRequest) (*core.CleanupExpiredTokensResponse, error) {
	cutoff := time.Now().Add(-24 * time.Hour)
	if err := s.db.WithContext(ctx).Delete(&RefreshTokenModel{},
		"expires_at < ? OR (revoked = ? AND revoked_at < ?)",
		time.Now(), true, cutoff).Error; err != nil {
		return nil, err
	}
	return &core.CleanupExpiredTokensResponse{}, nil
}

// =============================================================================
// APIKeyStore
// =============================================================================

// APIKeyStore implements core.APIKeyStore using GORM
type APIKeyStore struct {
	db *gorm.DB
}

func NewAPIKeyStore(db *gorm.DB) *APIKeyStore {
	return &APIKeyStore{db: db}
}

func (s *APIKeyStore) CreateAPIKey(ctx context.Context, req *core.CreateAPIKeyRequest) (*core.CreateAPIKeyResponse, error) {
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
	model := &APIKeyModel{
		KeyID:      keyID,
		KeyHash:    string(keyHash),
		Subject:    req.Subject,
		Name:       req.Name,
		Scopes:     req.Scopes,
		ExpiresAt:  req.ExpiresAt,
		LastUsedAt: now,
		Revoked:    false,
	}

	if err := s.db.WithContext(ctx).Create(model).Error; err != nil {
		return nil, err
	}

	fullKey := keyID + "_" + secret
	return &core.CreateAPIKeyResponse{FullKey: fullKey, APIKey: model.ToAPIKey()}, nil
}

func (s *APIKeyStore) GetAPIKeyByID(ctx context.Context, req *core.GetAPIKeyByIDRequest) (*core.GetAPIKeyByIDResponse, error) {
	var model APIKeyModel
	if err := s.db.WithContext(ctx).First(&model, "key_id = ?", req.KeyID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, core.ErrAPIKeyNotFound
		}
		return nil, err
	}
	return &core.GetAPIKeyByIDResponse{APIKey: model.ToAPIKey()}, nil
}

func (s *APIKeyStore) ValidateAPIKey(ctx context.Context, req *core.ValidateAPIKeyRequest) (*core.ValidateAPIKeyResponse, error) {
	parts := strings.SplitN(req.FullKey, "_", 3)
	if len(parts) != 3 || parts[0] != "oa" || parts[1] == "" || parts[2] == "" {
		return nil, core.ErrAPIKeyNotFound
	}

	keyID := "oa_" + parts[1]
	secret := parts[2]

	var model APIKeyModel
	if err := s.db.WithContext(ctx).First(&model, "key_id = ?", keyID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, core.ErrAPIKeyNotFound
		}
		return nil, err
	}

	if model.Revoked {
		return nil, core.ErrTokenRevoked
	}

	apiKey := model.ToAPIKey()
	if apiKey.IsExpired() {
		return nil, core.ErrTokenExpired
	}

	if err := bcrypt.CompareHashAndPassword([]byte(model.KeyHash), []byte(secret)); err != nil {
		return nil, core.ErrAPIKeyNotFound
	}

	return &core.ValidateAPIKeyResponse{APIKey: apiKey}, nil
}

func (s *APIKeyStore) RevokeAPIKey(ctx context.Context, req *core.RevokeAPIKeyRequest) (*core.RevokeAPIKeyResponse, error) {
	now := time.Now()
	if err := s.db.WithContext(ctx).Model(&APIKeyModel{}).
		Where("key_id = ?", req.KeyID).
		Updates(map[string]any{"revoked": true, "revoked_at": now}).Error; err != nil {
		return nil, err
	}
	return &core.RevokeAPIKeyResponse{}, nil
}

func (s *APIKeyStore) ListSubjectAPIKeys(ctx context.Context, req *core.ListSubjectAPIKeysRequest) (*core.ListSubjectAPIKeysResponse, error) {
	var models []APIKeyModel
	if err := s.db.WithContext(ctx).Where("subject = ?", req.Subject).Find(&models).Error; err != nil {
		return nil, err
	}

	keys := make([]*core.APIKey, len(models))
	for i, m := range models {
		keys[i] = m.ToAPIKey()
		keys[i].KeyHash = ""
	}
	return &core.ListSubjectAPIKeysResponse{APIKeys: keys}, nil
}

func (s *APIKeyStore) UpdateAPIKeyLastUsed(ctx context.Context, req *core.UpdateAPIKeyLastUsedRequest) (*core.UpdateAPIKeyLastUsedResponse, error) {
	if err := s.db.WithContext(ctx).Model(&APIKeyModel{}).
		Where("key_id = ?", req.KeyID).
		Update("last_used_at", time.Now()).Error; err != nil {
		return nil, err
	}
	return &core.UpdateAPIKeyLastUsedResponse{}, nil
}

// =============================================================================
// UsernameStore
// =============================================================================

// UsernameStore implements accounts.UsernameStore using GORM with optimistic concurrency.
//
// # Purpose
//
// Provides username uniqueness enforcement and username-based login lookup.
// This is optional - only configure it if your app needs:
//   - Username uniqueness (prevent two users from having same username)
//   - Username-based login (login with "johndoe" instead of email)
//
// # Concurrency Model
//
// Uses optimistic locking with version numbers. Updates use "WHERE version = ?"
// clauses to detect concurrent modifications. If a conflict occurs, the operation
// returns an error and can be retried.
//
// # Setup
//
//	db, _ := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
//	gorm.AutoMigrate(db) // Creates usernames table
//	usernameStore := gorm.NewUsernameStore(db)
//
//	// Use with LocalAuth
//	localAuth := &oneauth.LocalAuth{
//	    UsernameStore: usernameStore,
//	    SignupPolicy: &oneauth.SignupPolicy{
//	        RequireUsername:       true,
//	        EnforceUsernameUnique: true,
//	    },
//	}
type UsernameStore struct {
	db *gorm.DB
}

// NewUsernameStore creates a new GORM-backed UsernameStore
func NewUsernameStore(db *gorm.DB) *UsernameStore {
	return &UsernameStore{db: db}
}

// normalizeUsername converts username to lowercase for case-insensitive lookup
func (s *UsernameStore) normalizeUsername(username string) string {
	return strings.ToLower(username)
}

// ReserveUsername reserves a username for a user.
// Returns error if username is already taken by a different user.
//
// # Concurrency
//
// Uses database unique constraint on primary key. Concurrent inserts for the
// same username will have one succeed and one fail with a constraint violation.
func (s *UsernameStore) ReserveUsername(ctx context.Context, req *accounts.ReserveUsernameRequest) (*accounts.ReserveUsernameResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("ReserveUsername: req is required")
	}
	normalized := s.normalizeUsername(req.Username)

	var existing UsernameModel
	err := s.db.WithContext(ctx).First(&existing, "normalized_username = ?", normalized).Error

	if err == nil {
		if existing.UserID == req.UserID {
			if existing.Username != req.Username {
				result := s.db.WithContext(ctx).Model(&UsernameModel{}).
					Where("normalized_username = ? AND version = ?", normalized, existing.Version).
					Updates(map[string]any{
						"username": req.Username,
						"version":  existing.Version + 1,
					})
				if result.RowsAffected == 0 {
					return nil, fmt.Errorf("concurrent modification detected, please retry")
				}
			}
			return &accounts.ReserveUsernameResponse{}, nil
		}
		return nil, fmt.Errorf("username already taken")
	}

	if err != gorm.ErrRecordNotFound {
		return nil, err
	}

	model := &UsernameModel{
		NormalizedUsername: normalized,
		Username:           req.Username,
		UserID:             req.UserID,
		Version:            1,
	}
	if err := s.db.WithContext(ctx).Create(model).Error; err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "UNIQUE") {
			return nil, fmt.Errorf("username already taken")
		}
		return nil, err
	}
	return &accounts.ReserveUsernameResponse{}, nil
}

// GetUserByUsername looks up a userID by username (case-insensitive).
//
// # Usage
//
// Called by NewCredentialsValidatorWithUsername during login when
// user enters a username instead of email.
func (s *UsernameStore) GetUserByUsername(ctx context.Context, req *accounts.GetUserByUsernameRequest) (*accounts.GetUserByUsernameResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetUserByUsername: req is required")
	}
	normalized := s.normalizeUsername(req.Username)

	var model UsernameModel
	if err := s.db.WithContext(ctx).First(&model, "normalized_username = ?", normalized).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("username not found")
		}
		return nil, err
	}
	return &accounts.GetUserByUsernameResponse{UserID: model.UserID}, nil
}

func (s *UsernameStore) ReleaseUsername(ctx context.Context, req *accounts.ReleaseUsernameRequest) (*accounts.ReleaseUsernameResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("ReleaseUsername: req is required")
	}
	normalized := s.normalizeUsername(req.Username)
	if err := s.db.WithContext(ctx).Delete(&UsernameModel{}, "normalized_username = ?", normalized).Error; err != nil {
		return nil, err
	}
	return &accounts.ReleaseUsernameResponse{}, nil
}

// ChangeUsername atomically changes a username using optimistic concurrency.
// Returns error if new username is already taken or concurrent modification detected.
//
// # Usage
//
// Called from a "Change Username" profile page handler.
//
// # Concurrency
//
// Uses version check to detect concurrent modifications. If another process
// modifies the username between read and update, returns error for retry.
func (s *UsernameStore) ChangeUsername(ctx context.Context, req *accounts.ChangeUsernameRequest) (*accounts.ChangeUsernameResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("ChangeUsername: req is required")
	}
	oldNormalized := s.normalizeUsername(req.OldUsername)
	newNormalized := s.normalizeUsername(req.NewUsername)

	if oldNormalized == newNormalized {
		var existing UsernameModel
		if err := s.db.WithContext(ctx).First(&existing, "normalized_username = ?", oldNormalized).Error; err != nil {
			return nil, fmt.Errorf("username not found")
		}
		if existing.UserID != req.UserID {
			return nil, fmt.Errorf("username not owned by user")
		}

		result := s.db.WithContext(ctx).Model(&UsernameModel{}).
			Where("normalized_username = ? AND version = ?", oldNormalized, existing.Version).
			Updates(map[string]any{
				"username": req.NewUsername,
				"version":  existing.Version + 1,
			})
		if result.RowsAffected == 0 {
			return nil, fmt.Errorf("concurrent modification detected, please retry")
		}
		return &accounts.ChangeUsernameResponse{}, nil
	}

	var oldModel UsernameModel
	if err := s.db.WithContext(ctx).First(&oldModel, "normalized_username = ?", oldNormalized).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("old username not found")
		}
		return nil, err
	}
	if oldModel.UserID != req.UserID {
		return nil, fmt.Errorf("old username not owned by user")
	}

	var newModel UsernameModel
	err := s.db.WithContext(ctx).First(&newModel, "normalized_username = ?", newNormalized).Error
	if err == nil {
		return nil, fmt.Errorf("new username already taken")
	}
	if err != gorm.ErrRecordNotFound {
		return nil, err
	}

	result := s.db.WithContext(ctx).Where("normalized_username = ? AND version = ?", oldNormalized, oldModel.Version).
		Delete(&UsernameModel{})
	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("concurrent modification detected, please retry")
	}

	newModel = UsernameModel{
		NormalizedUsername: newNormalized,
		Username:           req.NewUsername,
		UserID:             req.UserID,
		Version:            1,
	}
	if err := s.db.WithContext(ctx).Create(&newModel).Error; err != nil {
		oldModel.Version++
		_ = s.db.WithContext(ctx).Create(&oldModel)
		return nil, fmt.Errorf("new username already taken")
	}

	return &accounts.ChangeUsernameResponse{}, nil
}
