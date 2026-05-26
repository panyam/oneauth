package core

import "time"

// RefreshTokenStore manages refresh tokens for API access.
type RefreshTokenStore interface {
	// CreateRefreshToken creates a new refresh token for a user.
	CreateRefreshToken(userID, clientID string, deviceInfo map[string]any, scopes []string) (*RefreshToken, error)

	// GetRefreshToken retrieves a refresh token by its value.
	GetRefreshToken(token string) (*RefreshToken, error)

	// RotateRefreshToken invalidates old token and creates new one in same family.
	// Returns ErrTokenReused if the old token was already revoked (theft detection).
	RotateRefreshToken(oldToken string) (*RefreshToken, error)

	// RevokeRefreshToken marks a token as revoked.
	RevokeRefreshToken(token string) error

	// RevokeUserTokens revokes all refresh tokens for a user.
	RevokeUserTokens(userID string) error

	// RevokeTokenFamily revokes all tokens in a family (theft detection).
	RevokeTokenFamily(family string) error

	// GetUserTokens lists all active (non-revoked, non-expired) refresh tokens for a user.
	GetUserTokens(userID string) ([]*RefreshToken, error)

	// CleanupExpiredTokens removes expired tokens (for maintenance).
	CleanupExpiredTokens() error
}

// APIKeyStore manages API keys for programmatic access.
type APIKeyStore interface {
	// CreateAPIKey creates a new API key and returns the full key (only shown once).
	// The key format is: keyID + "_" + secret.
	CreateAPIKey(userID, name string, scopes []string, expiresAt *time.Time) (fullKey string, apiKey *APIKey, err error)

	// GetAPIKeyByID retrieves an API key by its public ID.
	GetAPIKeyByID(keyID string) (*APIKey, error)

	// ValidateAPIKey validates a full API key and returns the key metadata if valid.
	// The fullKey format is: keyID + "_" + secret.
	ValidateAPIKey(fullKey string) (*APIKey, error)

	// RevokeAPIKey marks an API key as revoked.
	RevokeAPIKey(keyID string) error

	// ListUserAPIKeys returns all API keys for a user (without secrets).
	ListUserAPIKeys(userID string) ([]*APIKey, error)

	// UpdateAPIKeyLastUsed updates the last used timestamp.
	UpdateAPIKeyLastUsed(keyID string) error
}
