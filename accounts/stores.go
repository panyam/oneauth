package accounts

// UserStore manages unified user accounts.
type UserStore interface {
	// CreateUser creates a new user with the given ID and profile.
	CreateUser(userId string, isActive bool, profile map[string]any) (User, error)

	// GetUserById retrieves a user by their ID.
	GetUserById(userId string) (User, error)

	// SaveUser creates or updates a user (upsert).
	SaveUser(user User) error
}

// IdentityStore manages contact identities (email, phone).
type IdentityStore interface {
	// GetIdentity gets or optionally creates an identity.
	GetIdentity(identityType, identityValue string, createIfMissing bool) (identity *Identity, newCreated bool, err error)

	// SaveIdentity creates or updates an identity (upsert).
	SaveIdentity(identity *Identity) error

	// SetUserForIdentity associates an identity with a user.
	SetUserForIdentity(identityType, identityValue string, newUserId string) error

	// MarkIdentityVerified marks an identity as verified.
	MarkIdentityVerified(identityType, identityValue string) error

	// GetUserIdentities returns all identities for a user.
	GetUserIdentities(userId string) ([]*Identity, error)
}

// ChannelStore manages authentication channels/providers.
type ChannelStore interface {
	// GetChannel gets or optionally creates a channel.
	GetChannel(provider string, identityKey string, createIfMissing bool) (channel *Channel, newCreated bool, err error)

	// SaveChannel creates or updates a channel (upsert).
	SaveChannel(channel *Channel) error

	// GetChannelsByIdentity returns all channels for an identity.
	GetChannelsByIdentity(identityKey string) ([]*Channel, error)
}

// UsernameStore manages username uniqueness (optional — for apps that need
// username-based login).
type UsernameStore interface {
	// ReserveUsername reserves a username for a user (creates username -> userID mapping).
	// Returns error if username is already taken.
	ReserveUsername(username string, userID string) error

	// GetUserByUsername looks up a userID by username.
	// Returns error if username not found.
	GetUserByUsername(username string) (userID string, err error)

	// ReleaseUsername removes a username reservation.
	ReleaseUsername(username string) error

	// ChangeUsername atomically changes a username (release old, reserve new).
	// Returns error if new username is already taken.
	ChangeUsername(oldUsername, newUsername, userID string) error
}
