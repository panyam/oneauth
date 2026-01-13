//go:build !wasm
// +build !wasm

package gorm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	oa "github.com/panyam/oneauth"
)

// AutoMigrate runs database migrations for all oneauth tables
func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&UserModel{},
		&IdentityModel{},
		&ChannelModel{},
		&AuthTokenModel{},
		&RefreshTokenModel{},
		&APIKeyModel{},
	)
}

// =============================================================================
// UserStore
// =============================================================================

// GORMUser implements the oa.User interface
type GORMUser struct {
	model *UserModel
}

func (u *GORMUser) Id() string              { return u.model.ID }
func (u *GORMUser) Profile() map[string]any { return u.model.Profile }

// UserStore implements oa.UserStore using GORM
type UserStore struct {
	db *gorm.DB
}

func NewUserStore(db *gorm.DB) *UserStore {
	return &UserStore{db: db}
}

func (s *UserStore) CreateUser(userId string, isActive bool, profile map[string]any) (oa.User, error) {
	model := &UserModel{
		ID:       userId,
		IsActive: isActive,
		Profile:  profile,
	}
	if err := s.db.Create(model).Error; err != nil {
		return nil, err
	}
	return &GORMUser{model: model}, nil
}

func (s *UserStore) GetUserById(userId string) (oa.User, error) {
	var model UserModel
	if err := s.db.First(&model, "id = ?", userId).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found: %s", userId)
		}
		return nil, err
	}
	return &GORMUser{model: &model}, nil
}

func (s *UserStore) SaveUser(user oa.User) error {
	model := &UserModel{
		ID:      user.Id(),
		Profile: user.Profile(),
	}
	return s.db.Save(model).Error
}

// =============================================================================
// IdentityStore
// =============================================================================

// IdentityStore implements oa.IdentityStore using GORM
type IdentityStore struct {
	db *gorm.DB
}

func NewIdentityStore(db *gorm.DB) *IdentityStore {
	return &IdentityStore{db: db}
}

func (s *IdentityStore) GetIdentity(identityType, identityValue string, createIfMissing bool) (*oa.Identity, bool, error) {
	var model IdentityModel
	err := s.db.First(&model, "type = ? AND value = ?", identityType, identityValue).Error

	if err == gorm.ErrRecordNotFound {
		if createIfMissing {
			model = IdentityModel{
				Type:     identityType,
				Value:    identityValue,
				UserID:   "",
				Verified: false,
			}
			if err := s.db.Create(&model).Error; err != nil {
				return nil, false, err
			}
			return model.ToIdentity(), true, nil
		}
		return nil, false, fmt.Errorf("identity not found")
	}
	if err != nil {
		return nil, false, err
	}

	return model.ToIdentity(), false, nil
}

func (s *IdentityStore) SaveIdentity(identity *oa.Identity) error {
	model := IdentityToModel(identity)
	return s.db.Save(model).Error
}

func (s *IdentityStore) SetUserForIdentity(identityType, identityValue string, newUserId string) error {
	return s.db.Model(&IdentityModel{}).
		Where("type = ? AND value = ?", identityType, identityValue).
		Update("user_id", newUserId).Error
}

func (s *IdentityStore) MarkIdentityVerified(identityType, identityValue string) error {
	return s.db.Model(&IdentityModel{}).
		Where("type = ? AND value = ?", identityType, identityValue).
		Update("verified", true).Error
}

func (s *IdentityStore) GetUserIdentities(userId string) ([]*oa.Identity, error) {
	var models []IdentityModel
	if err := s.db.Where("user_id = ?", userId).Find(&models).Error; err != nil {
		return nil, err
	}

	identities := make([]*oa.Identity, len(models))
	for i, m := range models {
		identities[i] = m.ToIdentity()
	}
	return identities, nil
}

// =============================================================================
// ChannelStore
// =============================================================================

// ChannelStore implements oa.ChannelStore using GORM
type ChannelStore struct {
	db *gorm.DB
}

func NewChannelStore(db *gorm.DB) *ChannelStore {
	return &ChannelStore{db: db}
}

func (s *ChannelStore) GetChannel(provider string, identityKey string, createIfMissing bool) (*oa.Channel, bool, error) {
	var model ChannelModel
	err := s.db.First(&model, "provider = ? AND identity_key = ?", provider, identityKey).Error

	if err == gorm.ErrRecordNotFound {
		if createIfMissing {
			model = ChannelModel{
				Provider:    provider,
				IdentityKey: identityKey,
				Credentials: make(JSONMap),
				Profile:     make(JSONMap),
			}
			if err := s.db.Create(&model).Error; err != nil {
				return nil, false, err
			}
			return model.ToChannel(), true, nil
		}
		return nil, false, fmt.Errorf("channel not found")
	}
	if err != nil {
		return nil, false, err
	}

	return model.ToChannel(), false, nil
}

func (s *ChannelStore) SaveChannel(channel *oa.Channel) error {
	model := ChannelToModel(channel)
	return s.db.Save(model).Error
}

func (s *ChannelStore) GetChannelsByIdentity(identityKey string) ([]*oa.Channel, error) {
	var models []ChannelModel
	if err := s.db.Where("identity_key = ?", identityKey).Find(&models).Error; err != nil {
		return nil, err
	}

	channels := make([]*oa.Channel, len(models))
	for i, m := range models {
		channels[i] = m.ToChannel()
	}
	return channels, nil
}

// =============================================================================
// TokenStore (for email verification and password reset)
// =============================================================================

// TokenStore implements oa.TokenStore using GORM
type TokenStore struct {
	db *gorm.DB
}

func NewTokenStore(db *gorm.DB) *TokenStore {
	return &TokenStore{db: db}
}

func (s *TokenStore) CreateToken(userID, email string, tokenType oa.TokenType, expiryDuration time.Duration) (*oa.AuthToken, error) {
	token, err := oa.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	model := &AuthTokenModel{
		Token:     token,
		Type:      tokenType,
		UserID:    userID,
		Email:     email,
		ExpiresAt: time.Now().Add(expiryDuration),
	}

	if err := s.db.Create(model).Error; err != nil {
		return nil, err
	}

	return model.ToAuthToken(), nil
}

func (s *TokenStore) GetToken(token string) (*oa.AuthToken, error) {
	var model AuthTokenModel
	if err := s.db.First(&model, "token = ?", token).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("token not found")
		}
		return nil, err
	}

	authToken := model.ToAuthToken()
	if authToken.IsExpired() {
		_ = s.DeleteToken(token)
		return nil, fmt.Errorf("token expired")
	}

	return authToken, nil
}

func (s *TokenStore) DeleteToken(token string) error {
	return s.db.Delete(&AuthTokenModel{}, "token = ?", token).Error
}

func (s *TokenStore) DeleteUserTokens(userID string, tokenType oa.TokenType) error {
	return s.db.Delete(&AuthTokenModel{}, "user_id = ? AND type = ?", userID, tokenType).Error
}

// =============================================================================
// RefreshTokenStore
// =============================================================================

// RefreshTokenStore implements oa.RefreshTokenStore using GORM
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

func (s *RefreshTokenStore) CreateRefreshToken(userID, clientID string, deviceInfo map[string]any, scopes []string) (*oa.RefreshToken, error) {
	token, err := oa.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	family, err := oa.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	model := &RefreshTokenModel{
		TokenHash:  s.hashToken(token),
		Token:      token,
		UserID:     userID,
		ClientID:   clientID,
		DeviceInfo: deviceInfo,
		Family:     family[:16],
		Generation: 1,
		Scopes:     scopes,
		ExpiresAt:  now.Add(oa.TokenExpiryRefreshToken),
		LastUsedAt: now,
		Revoked:    false,
	}

	if err := s.db.Create(model).Error; err != nil {
		return nil, err
	}

	rt := model.ToRefreshToken()
	rt.Token = token // Restore the actual token value
	return rt, nil
}

func (s *RefreshTokenStore) GetRefreshToken(token string) (*oa.RefreshToken, error) {
	tokenHash := s.hashToken(token)
	var model RefreshTokenModel
	if err := s.db.First(&model, "token_hash = ?", tokenHash).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, oa.ErrTokenNotFound
		}
		return nil, err
	}

	rt := model.ToRefreshToken()
	rt.Token = token // Restore the actual token value
	return rt, nil
}

func (s *RefreshTokenStore) RotateRefreshToken(oldToken string) (*oa.RefreshToken, error) {
	oldHash := s.hashToken(oldToken)

	var newRefreshToken *oa.RefreshToken
	var newTokenValue string

	err := s.db.Transaction(func(tx *gorm.DB) error {
		var oldModel RefreshTokenModel
		if err := tx.First(&oldModel, "token_hash = ?", oldHash).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return oa.ErrTokenNotFound
			}
			return err
		}

		if oldModel.Revoked {
			return oa.ErrTokenReused
		}

		if time.Now().After(oldModel.ExpiresAt) {
			return oa.ErrTokenExpired
		}

		// Revoke old token
		now := time.Now()
		if err := tx.Model(&oldModel).Updates(map[string]any{
			"revoked":    true,
			"revoked_at": now,
		}).Error; err != nil {
			return err
		}

		// Create new token
		newToken, err := oa.GenerateSecureToken()
		if err != nil {
			return err
		}
		newTokenValue = newToken

		newModel := &RefreshTokenModel{
			TokenHash:  s.hashToken(newToken),
			UserID:     oldModel.UserID,
			ClientID:   oldModel.ClientID,
			DeviceInfo: oldModel.DeviceInfo,
			Family:     oldModel.Family,
			Generation: oldModel.Generation + 1,
			Scopes:     oldModel.Scopes,
			ExpiresAt:  now.Add(oa.TokenExpiryRefreshToken),
			LastUsedAt: now,
			Revoked:    false,
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
	return newRefreshToken, nil
}

func (s *RefreshTokenStore) RevokeRefreshToken(token string) error {
	tokenHash := s.hashToken(token)
	now := time.Now()
	return s.db.Model(&RefreshTokenModel{}).
		Where("token_hash = ?", tokenHash).
		Updates(map[string]any{"revoked": true, "revoked_at": now}).Error
}

func (s *RefreshTokenStore) RevokeUserTokens(userID string) error {
	now := time.Now()
	return s.db.Model(&RefreshTokenModel{}).
		Where("user_id = ? AND revoked = ?", userID, false).
		Updates(map[string]any{"revoked": true, "revoked_at": now}).Error
}

func (s *RefreshTokenStore) RevokeTokenFamily(family string) error {
	now := time.Now()
	return s.db.Model(&RefreshTokenModel{}).
		Where("family = ? AND revoked = ?", family, false).
		Updates(map[string]any{"revoked": true, "revoked_at": now}).Error
}

func (s *RefreshTokenStore) GetUserTokens(userID string) ([]*oa.RefreshToken, error) {
	var models []RefreshTokenModel
	if err := s.db.Where("user_id = ? AND revoked = ? AND expires_at > ?", userID, false, time.Now()).
		Find(&models).Error; err != nil {
		return nil, err
	}

	tokens := make([]*oa.RefreshToken, len(models))
	for i, m := range models {
		tokens[i] = m.ToRefreshToken()
		tokens[i].Token = "" // Don't expose token value
	}
	return tokens, nil
}

func (s *RefreshTokenStore) CleanupExpiredTokens() error {
	cutoff := time.Now().Add(-24 * time.Hour)
	return s.db.Delete(&RefreshTokenModel{},
		"expires_at < ? OR (revoked = ? AND revoked_at < ?)",
		time.Now(), true, cutoff).Error
}

// =============================================================================
// APIKeyStore
// =============================================================================

// APIKeyStore implements oa.APIKeyStore using GORM
type APIKeyStore struct {
	db *gorm.DB
}

func NewAPIKeyStore(db *gorm.DB) *APIKeyStore {
	return &APIKeyStore{db: db}
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
	model := &APIKeyModel{
		KeyID:      keyID,
		KeyHash:    string(keyHash),
		UserID:     userID,
		Name:       name,
		Scopes:     scopes,
		ExpiresAt:  expiresAt,
		LastUsedAt: now,
		Revoked:    false,
	}

	if err := s.db.Create(model).Error; err != nil {
		return "", nil, err
	}

	fullKey := keyID + "_" + secret
	return fullKey, model.ToAPIKey(), nil
}

func (s *APIKeyStore) GetAPIKeyByID(keyID string) (*oa.APIKey, error) {
	var model APIKeyModel
	if err := s.db.First(&model, "key_id = ?", keyID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, oa.ErrAPIKeyNotFound
		}
		return nil, err
	}
	return model.ToAPIKey(), nil
}

func (s *APIKeyStore) ValidateAPIKey(fullKey string) (*oa.APIKey, error) {
	// Parse the full key: oa_keyid_secret
	parts := make([]string, 3)
	n := 0
	for i := 0; i < len(fullKey) && n < 3; i++ {
		if fullKey[i] == '_' {
			n++
		} else if n < 3 {
			parts[n] += string(fullKey[i])
		}
	}

	if parts[0] != "oa" || parts[1] == "" || parts[2] == "" {
		return nil, oa.ErrAPIKeyNotFound
	}

	keyID := "oa_" + parts[1]
	secret := parts[2]

	var model APIKeyModel
	if err := s.db.First(&model, "key_id = ?", keyID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, oa.ErrAPIKeyNotFound
		}
		return nil, err
	}

	if model.Revoked {
		return nil, oa.ErrTokenRevoked
	}

	apiKey := model.ToAPIKey()
	if apiKey.IsExpired() {
		return nil, oa.ErrTokenExpired
	}

	if err := bcrypt.CompareHashAndPassword([]byte(model.KeyHash), []byte(secret)); err != nil {
		return nil, oa.ErrAPIKeyNotFound
	}

	return apiKey, nil
}

func (s *APIKeyStore) RevokeAPIKey(keyID string) error {
	now := time.Now()
	return s.db.Model(&APIKeyModel{}).
		Where("key_id = ?", keyID).
		Updates(map[string]any{"revoked": true, "revoked_at": now}).Error
}

func (s *APIKeyStore) ListUserAPIKeys(userID string) ([]*oa.APIKey, error) {
	var models []APIKeyModel
	if err := s.db.Where("user_id = ?", userID).Find(&models).Error; err != nil {
		return nil, err
	}

	keys := make([]*oa.APIKey, len(models))
	for i, m := range models {
		keys[i] = m.ToAPIKey()
		keys[i].KeyHash = "" // Don't expose hash
	}
	return keys, nil
}

func (s *APIKeyStore) UpdateAPIKeyLastUsed(keyID string) error {
	return s.db.Model(&APIKeyModel{}).
		Where("key_id = ?", keyID).
		Update("last_used_at", time.Now()).Error
}
