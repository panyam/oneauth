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

	// OIDC is the OpenID Connect login the grant came from, stored on
	// the token so a refresh can issue an ID token (RefreshToken.OIDC).
	// Nil for a grant without the "openid" scope.
	OIDC *OIDCGrant

	// Resources are the RFC 8707 resources the grant was authorized for
	// (RefreshToken.Resources).
	Resources []string
}

// CreateRefreshTokenResponse carries the new token. Token.Token is the
// plaintext value the client must present. Every bundled store keeps
// only its hash (the FS store since issue 526), so the caller hands it to
// the client now. Token.Family
// is new, and every rotation of this token stays in it, so revoking the
// family reaches every generation.
type CreateRefreshTokenResponse struct {
	Token *RefreshToken
}

// GetRefreshTokenRequest looks a token up by the plaintext value the
// client presented. The bundled stores key tokens by its SHA-256, so the
// lookup needs the exact value and no prefix or partial match is
// possible.
type GetRefreshTokenRequest struct {
	Token string
}

// GetRefreshTokenResponse returns the stored token, revoked and expired
// ones included, so the caller can tell reuse of a rotated token
// (Revoked) from an unknown one (ErrTokenNotFound) and revoke the family
// on reuse (RFC 9700 §4.14.2).
type GetRefreshTokenResponse struct {
	Token *RefreshToken
}

// RotateRefreshTokenRequest names the token being redeemed by its
// plaintext value. The store revokes it and issues its successor in one
// atomic step, so two concurrent redemptions can't both succeed.
type RotateRefreshTokenRequest struct {
	OldToken string
}

// RotateRefreshTokenResponse carries the successor: same Family and
// Subject, Generation one higher, and the old token's ExpiresAt, so
// rotating never extends the grant past its first issue. As with
// creation, Token.Token is the plaintext the client must present next.
type RotateRefreshTokenResponse struct {
	Token *RefreshToken
}

// RevokeRefreshTokenRequest names one token by its plaintext value.
// Only that token is revoked; its family and the access tokens it
// recorded are not. Callers that want the whole session ended use
// RevokeTokenFamily, as RFC 7009 revocation does.
type RevokeRefreshTokenRequest struct {
	Token string
}

// RevokeRefreshTokenResponse is empty. Revoking an unknown or already
// revoked token is not an error, so a retried revocation succeeds.
type RevokeRefreshTokenResponse struct{}

// RevokeSubjectTokensRequest names the user (or, for client_credentials,
// the client) whose every refresh token to revoke, as logout-all and a
// password reset do. It crosses every client and device.
type RevokeSubjectTokensRequest struct {
	Subject string
}

// RevokeSubjectTokensResponse carries the unexpired access tokens
// recorded on any of the subject's refresh tokens, already-revoked ones
// included, so the caller can blacklist them. Logout-all and a password
// reset then cut off live access tokens as well as refresh tokens
// (RFC 7009 §2.1). The store has no blacklist of its own.
type RevokeSubjectTokensResponse struct {
	AccessTokens []IssuedAccessToken
}

// RevokeTokenFamilyRequest names a rotation family, the sid of one
// session. Revoking it ends that session on every generation, including
// the one a thief may hold, while the user's other sessions stay live.
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

// GetSubjectTokensRequest names the user whose live sessions to list.
type GetSubjectTokensRequest struct {
	Subject string
}

// GetSubjectTokensResponse lists the subject's tokens that are neither
// revoked nor expired, which is one per live session: rotation revokes
// the older generations. Callers read ClientID and Family from it to
// know which clients and sessions a revocation will reach, before the
// revocation makes them disappear from the list. Order is unspecified.
type GetSubjectTokensResponse struct {
	Tokens []*RefreshToken
}

// CleanupExpiredTokensRequest is empty. Cleanup is maintenance: the
// bundled stores delete expired tokens and tokens revoked more than 24
// hours ago. Neither can be redeemed, so cleanup only bounds storage.
// After it, a deleted rotated generation reads as unknown rather than as
// reuse, which is acceptable because the access tokens it recorded
// expired long before.
type CleanupExpiredTokensRequest struct{}

// CleanupExpiredTokensResponse is empty. Cleanup removes no live token,
// so callers can run it on any schedule, or never, without changing who
// can refresh.
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

	// RevokeSubjectTokens revokes all refresh tokens belonging to a
	// subject and returns the access tokens any of them recorded that
	// have not expired. Like RevokeTokenFamily it is atomic per token
	// against RecordAccessToken. A subject with no tokens is not an error.
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
