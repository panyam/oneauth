package oneauth

import "time"

// User represents a unified user account
type User interface {
	Id() string
	Profile() map[string]any
}

// Identity represents a contact method (email, phone) that can be verified
type Identity struct {
	Type      string    `json:"type"`       // "email", "phone"
	Value     string    `json:"value"`      // "john@example.com", "+1-555-1234"
	UserID    string    `json:"user_id"`    // which user owns this identity
	Verified  bool      `json:"verified"`   // has any channel verified this identity?
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Version   int       `json:"version"` // optimistic locking version
}

// Channel represents an authentication mechanism/provider
type Channel struct {
	Provider    string         `json:"provider"`     // "local", "google", "github"
	IdentityKey string         `json:"identity_key"` // "email:john@example.com"
	Credentials map[string]any `json:"credentials"`  // password_hash, access_token, etc.
	Profile     map[string]any `json:"profile"`      // optional data from provider
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	ExpiresAt   time.Time      `json:"expires_at"` // when channel auth expires and needs re-auth
	Version     int            `json:"version"`    // optimistic locking version
}

// IsExpired returns true if the channel has an expiration time set and it has passed
func (c *Channel) IsExpired() bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(c.ExpiresAt)
}

// UserStore manages unified user accounts
type UserStore interface {
	// CreateUser creates a new user with the given ID and profile
	CreateUser(userId string, isActive bool, profile map[string]any) (User, error)

	// GetUserById retrieves a user by their ID
	GetUserById(userId string) (User, error)

	// SaveUser creates or updates a user (upsert)
	SaveUser(user User) error
}

// IdentityStore manages contact identities (email, phone)
type IdentityStore interface {
	// GetIdentity gets or optionally creates an identity
	GetIdentity(identityType, identityValue string, createIfMissing bool) (identity *Identity, newCreated bool, err error)

	// SaveIdentity creates or updates an identity (upsert)
	SaveIdentity(identity *Identity) error

	// SetUserForIdentity associates an identity with a user
	SetUserForIdentity(identityType, identityValue string, newUserId string) error

	// MarkIdentityVerified marks an identity as verified
	MarkIdentityVerified(identityType, identityValue string) error

	// GetUserIdentities returns all identities for a user
	GetUserIdentities(userId string) ([]*Identity, error)
}

// ChannelStore manages authentication channels/providers
type ChannelStore interface {
	// GetChannel gets or optionally creates a channel
	GetChannel(provider string, identityKey string, createIfMissing bool) (channel *Channel, newCreated bool, err error)

	// SaveChannel creates or updates a channel (upsert)
	SaveChannel(channel *Channel) error

	// GetChannelsByIdentity returns all channels for an identity
	GetChannelsByIdentity(identityKey string) ([]*Channel, error)
}

// IdentityKey creates a consistent identity key from type and value
func IdentityKey(identityType, identityValue string) string {
	return identityType + ":" + identityValue
}

// RefreshTokenStore manages refresh tokens for API access
type RefreshTokenStore interface {
	// CreateRefreshToken creates a new refresh token for a user
	CreateRefreshToken(userID, clientID string, deviceInfo map[string]any, scopes []string) (*RefreshToken, error)

	// GetRefreshToken retrieves a refresh token by its value
	GetRefreshToken(token string) (*RefreshToken, error)

	// RotateRefreshToken invalidates old token and creates new one in same family
	// Returns ErrTokenReused if the old token was already revoked (theft detection)
	RotateRefreshToken(oldToken string) (*RefreshToken, error)

	// RevokeRefreshToken marks a token as revoked
	RevokeRefreshToken(token string) error

	// RevokeUserTokens revokes all refresh tokens for a user
	RevokeUserTokens(userID string) error

	// RevokeTokenFamily revokes all tokens in a family (theft detection)
	RevokeTokenFamily(family string) error

	// GetUserTokens lists all active (non-revoked, non-expired) refresh tokens for a user
	GetUserTokens(userID string) ([]*RefreshToken, error)

	// CleanupExpiredTokens removes expired tokens (for maintenance)
	CleanupExpiredTokens() error
}

// APIKeyStore manages API keys for programmatic access
type APIKeyStore interface {
	// CreateAPIKey creates a new API key and returns the full key (only shown once)
	// The key format is: keyID + "_" + secret
	CreateAPIKey(userID, name string, scopes []string, expiresAt *time.Time) (fullKey string, apiKey *APIKey, err error)

	// GetAPIKeyByID retrieves an API key by its public ID
	GetAPIKeyByID(keyID string) (*APIKey, error)

	// ValidateAPIKey validates a full API key and returns the key metadata if valid
	// The fullKey format is: keyID + "_" + secret
	ValidateAPIKey(fullKey string) (*APIKey, error)

	// RevokeAPIKey marks an API key as revoked
	RevokeAPIKey(keyID string) error

	// ListUserAPIKeys returns all API keys for a user (without secrets)
	ListUserAPIKeys(userID string) ([]*APIKey, error)

	// UpdateAPIKeyLastUsed updates the last used timestamp
	UpdateAPIKeyLastUsed(keyID string) error
}

// UsernameStore manages username uniqueness (optional - for apps that need username-based login)
// This is separate from IdentityStore because:
// - Username is a display handle, not a contact method
// - Different validation rules than email/phone
// - Username changes are more common
// - Enables O(1) username lookup for username-based login
type UsernameStore interface {
	// ReserveUsername reserves a username for a user (creates username -> userID mapping)
	// Returns error if username is already taken
	ReserveUsername(username string, userID string) error

	// GetUserByUsername looks up a userID by username
	// Returns error if username not found
	GetUserByUsername(username string) (userID string, err error)

	// ReleaseUsername removes a username reservation
	ReleaseUsername(username string) error

	// ChangeUsername atomically changes a username (release old, reserve new)
	// Returns error if new username is already taken
	ChangeUsername(oldUsername, newUsername, userID string) error
}
