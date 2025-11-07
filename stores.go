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
}

// Channel represents an authentication mechanism/provider
type Channel struct {
	Provider    string         `json:"provider"`     // "local", "google", "github"
	IdentityKey string         `json:"identity_key"` // "email:john@example.com"
	Credentials map[string]any `json:"credentials"`  // password_hash, access_token, etc.
	Profile     map[string]any `json:"profile"`      // optional data from provider
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
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
