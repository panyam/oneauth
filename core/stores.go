package core

import (
	"context"
	"time"
)

// =============================================================================
// RefreshTokenStore
// =============================================================================

// CreateRefreshTokenRequest carries the inputs for issuing a refresh token.
// Subject is the RFC 7519 `sub` (user ID for user-bound flows, client_id for
// client_credentials).
type CreateRefreshTokenRequest struct {
	Subject    string
	ClientID   string
	DeviceInfo map[string]any
	Scopes     []string

	// Confirmation binds the refresh token to a proof-of-possession key
	// (RFC 9449 §5). Non-nil means only a client that can prove possession
	// of that key may redeem it; rotation carries the binding forward.
	// Nil issues a plain bearer refresh token.
	Confirmation *Confirmation
}

type CreateRefreshTokenResponse struct {
	Token *RefreshToken
}

type GetRefreshTokenRequest struct {
	Token string
}

type GetRefreshTokenResponse struct {
	Token *RefreshToken
}

type RotateRefreshTokenRequest struct {
	OldToken string
}

type RotateRefreshTokenResponse struct {
	Token *RefreshToken
}

type RevokeRefreshTokenRequest struct {
	Token string
}

type RevokeRefreshTokenResponse struct{}

type RevokeSubjectTokensRequest struct {
	Subject string
}

type RevokeSubjectTokensResponse struct{}

type RevokeTokenFamilyRequest struct {
	Family string
}

// RevokeTokenFamilyResponse carries the access tokens the family minted
// that have not yet expired, from every generation, already-revoked ones
// included, so the caller can blacklist them (RFC 7009 §2.1, RFC 9700
// §4.14.2). The store has no blacklist of its own.
type RevokeTokenFamilyResponse struct {
	AccessTokens []IssuedAccessToken
}

// RecordAccessTokenRequest names an access token minted alongside (or
// from) the refresh token Token.
type RecordAccessTokenRequest struct {
	Token     string
	TokenID   string
	ExpiresAt time.Time
}

// RecordAccessTokenResponse reports whether Token had been revoked when
// the access token was recorded. When it had, the caller blacklists the
// access token it just minted and refuses the grant: the revocation that
// beat it never saw this token.
type RecordAccessTokenResponse struct {
	Revoked bool
}

type GetSubjectTokensRequest struct {
	Subject string
}

type GetSubjectTokensResponse struct {
	Tokens []*RefreshToken
}

type CleanupExpiredTokensRequest struct{}

type CleanupExpiredTokensResponse struct{}

// RefreshTokenStore manages refresh tokens for API access.
type RefreshTokenStore interface {
	// CreateRefreshToken creates a new refresh token for the given subject.
	CreateRefreshToken(ctx context.Context, req *CreateRefreshTokenRequest) (*CreateRefreshTokenResponse, error)

	// GetRefreshToken retrieves a refresh token by its value.
	GetRefreshToken(ctx context.Context, req *GetRefreshTokenRequest) (*GetRefreshTokenResponse, error)

	// RotateRefreshToken invalidates old token and creates new one in same family.
	// Returns ErrTokenReused if the old token was already revoked (theft detection),
	// including when a concurrent call rotated it first: only one caller may
	// get a new token. The new token keeps the old one's ExpiresAt, so a family
	// lives at most TokenExpiryRefreshToken from its first issue however often
	// it is refreshed (RFC 9700 §4.14.2).
	RotateRefreshToken(ctx context.Context, req *RotateRefreshTokenRequest) (*RotateRefreshTokenResponse, error)

	// RevokeRefreshToken marks a token as revoked.
	RevokeRefreshToken(ctx context.Context, req *RevokeRefreshTokenRequest) (*RevokeRefreshTokenResponse, error)

	// RevokeSubjectTokens revokes all refresh tokens belonging to a subject.
	RevokeSubjectTokens(ctx context.Context, req *RevokeSubjectTokensRequest) (*RevokeSubjectTokensResponse, error)

	// RecordAccessToken appends an access token's jti and expiry to the
	// refresh token it was issued with, dropping entries that have
	// expired, and reports Revoked read in the same atomic step. Paired
	// with RevokeTokenFamily, whichever of the two runs second sees the
	// other's write, so an access token minted while the family is being
	// revoked is still caught. A missing token is ErrTokenNotFound.
	RecordAccessToken(ctx context.Context, req *RecordAccessTokenRequest) (*RecordAccessTokenResponse, error)

	// RevokeTokenFamily revokes all tokens in a family (theft detection,
	// RFC 7009 revocation) and returns the access tokens the family
	// recorded that have not expired. Revoking an empty or unknown family
	// is not an error.
	RevokeTokenFamily(ctx context.Context, req *RevokeTokenFamilyRequest) (*RevokeTokenFamilyResponse, error)

	// GetSubjectTokens lists all active (non-revoked, non-expired) refresh
	// tokens for a subject.
	GetSubjectTokens(ctx context.Context, req *GetSubjectTokensRequest) (*GetSubjectTokensResponse, error)

	// CleanupExpiredTokens removes expired tokens (for maintenance).
	CleanupExpiredTokens(ctx context.Context, req *CleanupExpiredTokensRequest) (*CleanupExpiredTokensResponse, error)
}

// =============================================================================
// APIKeyStore
// =============================================================================

// CreateAPIKeyRequest carries the inputs for issuing an API key.
type CreateAPIKeyRequest struct {
	Subject   string
	Name      string
	Scopes    []string
	ExpiresAt *time.Time
}

// CreateAPIKeyResponse carries the issued key. FullKey is keyID + "_" + secret
// and is only available at creation time.
type CreateAPIKeyResponse struct {
	FullKey string
	APIKey  *APIKey
}

type GetAPIKeyByIDRequest struct {
	KeyID string
}

type GetAPIKeyByIDResponse struct {
	APIKey *APIKey
}

type ValidateAPIKeyRequest struct {
	FullKey string
}

type ValidateAPIKeyResponse struct {
	APIKey *APIKey
}

type RevokeAPIKeyRequest struct {
	KeyID string
}

type RevokeAPIKeyResponse struct{}

type ListSubjectAPIKeysRequest struct {
	Subject string
}

type ListSubjectAPIKeysResponse struct {
	APIKeys []*APIKey
}

type UpdateAPIKeyLastUsedRequest struct {
	KeyID string
}

type UpdateAPIKeyLastUsedResponse struct{}

// APIKeyStore manages API keys for programmatic access.
type APIKeyStore interface {
	// CreateAPIKey creates a new API key for the given subject. The full key
	// (keyID + "_" + secret) is only returned here.
	CreateAPIKey(ctx context.Context, req *CreateAPIKeyRequest) (*CreateAPIKeyResponse, error)

	// GetAPIKeyByID retrieves an API key by its public ID.
	GetAPIKeyByID(ctx context.Context, req *GetAPIKeyByIDRequest) (*GetAPIKeyByIDResponse, error)

	// ValidateAPIKey validates a full API key and returns the key metadata if valid.
	ValidateAPIKey(ctx context.Context, req *ValidateAPIKeyRequest) (*ValidateAPIKeyResponse, error)

	// RevokeAPIKey marks an API key as revoked.
	RevokeAPIKey(ctx context.Context, req *RevokeAPIKeyRequest) (*RevokeAPIKeyResponse, error)

	// ListSubjectAPIKeys returns all API keys owned by a subject (without secrets).
	ListSubjectAPIKeys(ctx context.Context, req *ListSubjectAPIKeysRequest) (*ListSubjectAPIKeysResponse, error)

	// UpdateAPIKeyLastUsed updates the last-used timestamp.
	UpdateAPIKeyLastUsed(ctx context.Context, req *UpdateAPIKeyLastUsedRequest) (*UpdateAPIKeyLastUsedResponse, error)
}
