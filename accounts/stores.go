package accounts

import "context"

// ----------------------------------------------------------------------------
// UserStore — request / response types and interface
// ----------------------------------------------------------------------------

// CreateUserRequest is the input to UserStore.CreateUser.
type CreateUserRequest struct {
	UserID   string
	IsActive bool
	Profile  map[string]any
}

// CreateUserResponse wraps the created user.
type CreateUserResponse struct {
	User User
}

// GetUserByIDRequest is the input to UserStore.GetUserById.
type GetUserByIDRequest struct {
	UserID string
}

// GetUserByIDResponse wraps the requested user.
type GetUserByIDResponse struct {
	User User
}

// SaveUserRequest is the input to UserStore.SaveUser.
type SaveUserRequest struct {
	User User
}

// SaveUserResponse is the output of UserStore.SaveUser.
type SaveUserResponse struct{}

// UserStore manages unified user accounts.
type UserStore interface {
	// CreateUser creates a new user with the given ID and profile.
	CreateUser(ctx context.Context, req *CreateUserRequest) (*CreateUserResponse, error)

	// GetUserById retrieves a user by their ID.
	GetUserById(ctx context.Context, req *GetUserByIDRequest) (*GetUserByIDResponse, error)

	// SaveUser creates or updates a user (upsert).
	SaveUser(ctx context.Context, req *SaveUserRequest) (*SaveUserResponse, error)
}

// ----------------------------------------------------------------------------
// IdentityStore — request / response types and interface
// ----------------------------------------------------------------------------

// GetIdentityRequest is the input to IdentityStore.GetIdentity.
type GetIdentityRequest struct {
	IdentityType    string
	IdentityValue   string
	CreateIfMissing bool
}

// GetIdentityResponse wraps the looked-up Identity and whether it was
// newly created in this call.
type GetIdentityResponse struct {
	Identity   *Identity
	NewCreated bool
}

// SaveIdentityRequest is the input to IdentityStore.SaveIdentity.
type SaveIdentityRequest struct {
	Identity *Identity
}

// SaveIdentityResponse is the output of IdentityStore.SaveIdentity.
type SaveIdentityResponse struct{}

// SetUserForIdentityRequest is the input to IdentityStore.SetUserForIdentity.
type SetUserForIdentityRequest struct {
	IdentityType  string
	IdentityValue string
	NewUserID     string
}

// SetUserForIdentityResponse is the output of IdentityStore.SetUserForIdentity.
type SetUserForIdentityResponse struct{}

// MarkIdentityVerifiedRequest is the input to IdentityStore.MarkIdentityVerified.
type MarkIdentityVerifiedRequest struct {
	IdentityType  string
	IdentityValue string
}

// MarkIdentityVerifiedResponse is the output of IdentityStore.MarkIdentityVerified.
type MarkIdentityVerifiedResponse struct{}

// GetUserIdentitiesRequest is the input to IdentityStore.GetUserIdentities.
type GetUserIdentitiesRequest struct {
	UserID string
}

// GetUserIdentitiesResponse wraps the identities owned by the user.
type GetUserIdentitiesResponse struct {
	Identities []*Identity
}

// IdentityStore manages contact identities (email, phone).
type IdentityStore interface {
	// GetIdentity gets or optionally creates an identity.
	GetIdentity(ctx context.Context, req *GetIdentityRequest) (*GetIdentityResponse, error)

	// SaveIdentity creates or updates an identity (upsert).
	SaveIdentity(ctx context.Context, req *SaveIdentityRequest) (*SaveIdentityResponse, error)

	// SetUserForIdentity associates an identity with a user.
	SetUserForIdentity(ctx context.Context, req *SetUserForIdentityRequest) (*SetUserForIdentityResponse, error)

	// MarkIdentityVerified marks an identity as verified.
	MarkIdentityVerified(ctx context.Context, req *MarkIdentityVerifiedRequest) (*MarkIdentityVerifiedResponse, error)

	// GetUserIdentities returns all identities for a user.
	GetUserIdentities(ctx context.Context, req *GetUserIdentitiesRequest) (*GetUserIdentitiesResponse, error)
}

// ----------------------------------------------------------------------------
// ChannelStore — request / response types and interface
// ----------------------------------------------------------------------------

// GetChannelRequest is the input to ChannelStore.GetChannel.
type GetChannelRequest struct {
	Provider        string
	IdentityKey     string
	CreateIfMissing bool
}

// GetChannelResponse wraps the looked-up Channel and whether it was
// newly created in this call.
type GetChannelResponse struct {
	Channel    *Channel
	NewCreated bool
}

// SaveChannelRequest is the input to ChannelStore.SaveChannel.
type SaveChannelRequest struct {
	Channel *Channel
}

// SaveChannelResponse is the output of ChannelStore.SaveChannel.
type SaveChannelResponse struct{}

// GetChannelsByIdentityRequest is the input to ChannelStore.GetChannelsByIdentity.
type GetChannelsByIdentityRequest struct {
	IdentityKey string
}

// GetChannelsByIdentityResponse wraps the channels for an identity.
type GetChannelsByIdentityResponse struct {
	Channels []*Channel
}

// ChannelStore manages authentication channels/providers.
type ChannelStore interface {
	// GetChannel gets or optionally creates a channel.
	GetChannel(ctx context.Context, req *GetChannelRequest) (*GetChannelResponse, error)

	// SaveChannel creates or updates a channel (upsert).
	SaveChannel(ctx context.Context, req *SaveChannelRequest) (*SaveChannelResponse, error)

	// GetChannelsByIdentity returns all channels for an identity.
	GetChannelsByIdentity(ctx context.Context, req *GetChannelsByIdentityRequest) (*GetChannelsByIdentityResponse, error)
}

// ----------------------------------------------------------------------------
// UsernameStore — request / response types and interface
// ----------------------------------------------------------------------------

// ReserveUsernameRequest is the input to UsernameStore.ReserveUsername.
type ReserveUsernameRequest struct {
	Username string
	UserID   string
}

// ReserveUsernameResponse is the output of UsernameStore.ReserveUsername.
type ReserveUsernameResponse struct{}

// GetUserByUsernameRequest is the input to UsernameStore.GetUserByUsername.
type GetUserByUsernameRequest struct {
	Username string
}

// GetUserByUsernameResponse wraps the userID for the queried username.
type GetUserByUsernameResponse struct {
	UserID string
}

// ReleaseUsernameRequest is the input to UsernameStore.ReleaseUsername.
type ReleaseUsernameRequest struct {
	Username string
}

// ReleaseUsernameResponse is the output of UsernameStore.ReleaseUsername.
type ReleaseUsernameResponse struct{}

// ChangeUsernameRequest is the input to UsernameStore.ChangeUsername.
type ChangeUsernameRequest struct {
	OldUsername string
	NewUsername string
	UserID      string
}

// ChangeUsernameResponse is the output of UsernameStore.ChangeUsername.
type ChangeUsernameResponse struct{}

// UsernameStore manages username uniqueness (optional — for apps that need
// username-based login).
type UsernameStore interface {
	// ReserveUsername reserves a username for a user (creates username -> userID mapping).
	// Returns error if username is already taken.
	ReserveUsername(ctx context.Context, req *ReserveUsernameRequest) (*ReserveUsernameResponse, error)

	// GetUserByUsername looks up a userID by username.
	// Returns error if username not found.
	GetUserByUsername(ctx context.Context, req *GetUserByUsernameRequest) (*GetUserByUsernameResponse, error)

	// ReleaseUsername removes a username reservation.
	ReleaseUsername(ctx context.Context, req *ReleaseUsernameRequest) (*ReleaseUsernameResponse, error)

	// ChangeUsername atomically changes a username (release old, reserve new).
	// Returns error if new username is already taken.
	ChangeUsername(ctx context.Context, req *ChangeUsernameRequest) (*ChangeUsernameResponse, error)
}
