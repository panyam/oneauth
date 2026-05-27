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

type RevokeTokenFamilyResponse struct{}

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
	// Returns ErrTokenReused if the old token was already revoked (theft detection).
	RotateRefreshToken(ctx context.Context, req *RotateRefreshTokenRequest) (*RotateRefreshTokenResponse, error)

	// RevokeRefreshToken marks a token as revoked.
	RevokeRefreshToken(ctx context.Context, req *RevokeRefreshTokenRequest) (*RevokeRefreshTokenResponse, error)

	// RevokeSubjectTokens revokes all refresh tokens belonging to a subject.
	RevokeSubjectTokens(ctx context.Context, req *RevokeSubjectTokensRequest) (*RevokeSubjectTokensResponse, error)

	// RevokeTokenFamily revokes all tokens in a family (theft detection).
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
