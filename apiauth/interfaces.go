package apiauth

import (
	"context"

	"github.com/panyam/oneauth/core"
)

// Transport-independent interfaces for OneAuth operations.
//
// Each interface represents a focused capability. Implementations take only
// the dependencies they need (Option A — composed interfaces, no god objects).
//
// HTTP handlers, gRPC interceptors, and MCP auth managers are thin transport
// bindings over these interfaces. Per the convention adopted in 169 / 172
// every method follows:
//
//	MethodName(ctx context.Context, req *XRequest) (*XResponse, error)
//
// The ctx parameter is currently unused in most implementations but is the
// extension point for typed library contexts and async-store cancellation
// without changing method shapes (issue 175).
//
// See: https://github.com/panyam/oneauth/issues/110 (transport-independent core)
// See: https://github.com/panyam/oneauth/issues/175 (this convention)

// ----------------------------------------------------------------------------
// TokenIssuer — creates signed access tokens.
// ----------------------------------------------------------------------------

// TokenIssuer mints access tokens via the standard OAuth 2.0 grants.
type TokenIssuer interface {
	// CreateAccessToken mints a JWT with the given subject, scopes, and
	// optional RFC 9396 authorization_details.
	CreateAccessToken(ctx context.Context, req *CreateAccessTokenRequest) (*CreateAccessTokenResponse, error)

	// ClientCredentials performs the full client_credentials grant:
	// authenticates the client, validates scopes/details, and returns a token pair.
	ClientCredentials(ctx context.Context, req *ClientCredentialsRequest) (*ClientCredentialsResponse, error)

	// RefreshGrant rotates a refresh token and returns a new access + refresh
	// token pair. Handles theft detection (revoked token → revoke entire family).
	RefreshGrant(ctx context.Context, req *RefreshGrantRequest) (*RefreshGrantResponse, error)

	// PasswordGrant authenticates a user with username/password and returns
	// an access token. Does NOT create a refresh token — the caller's
	// responsibility (via RefreshTokenStore.CreateRefreshToken), since refresh
	// tokens may carry transport-specific metadata (device info, IP, etc.).
	PasswordGrant(ctx context.Context, req *PasswordGrantRequest) (*PasswordGrantResponse, error)
}

// CreateAccessTokenRequest is the input to TokenIssuer.CreateAccessToken.
type CreateAccessTokenRequest struct {
	Subject              string
	Scopes               []string
	AuthorizationDetails []core.AuthorizationDetail
}

// CreateAccessTokenResponse is the output of TokenIssuer.CreateAccessToken.
type CreateAccessTokenResponse struct {
	Token     string
	ExpiresIn int64
}

// ClientCredentialsRequest is the input to TokenIssuer.ClientCredentials.
type ClientCredentialsRequest struct {
	ClientID             string
	ClientSecret         string
	Scopes               []string
	AuthorizationDetails []core.AuthorizationDetail
}

// ClientCredentialsResponse wraps the issued token pair. Wrapped (rather than
// returning *core.TokenPair directly) for symmetry across the interface and
// forward-compat headroom — same rationale as ClientRegistrationManager
// response types in 168.
type ClientCredentialsResponse struct {
	Tokens *core.TokenPair
}

// RefreshGrantRequest is the input to TokenIssuer.RefreshGrant.
type RefreshGrantRequest struct {
	RefreshToken string
}

// RefreshGrantResponse wraps the rotated token pair.
type RefreshGrantResponse struct {
	Tokens *core.TokenPair
}

// PasswordGrantRequest holds the inputs for a password grant.
type PasswordGrantRequest struct {
	Username             string
	Password             string
	Scopes               []string                   // requested (intersected with allowed)
	AuthorizationDetails []core.AuthorizationDetail // RFC 9396
	ClientID             string                     // optional — associated client
}

// PasswordGrantResponse holds the output of a successful password grant.
// The caller uses UserID + GrantedScopes to create a refresh token if needed.
//
// (Renamed from PasswordGrantResult during the 175 convention port; the
// PasswordGrantResult type alias below preserves the old name for one
// release as a deprecation bridge.)
type PasswordGrantResponse struct {
	UserID               string
	AccessToken          string
	ExpiresIn            int64
	GrantedScopes        []string
	AuthorizationDetails []core.AuthorizationDetail
}

// PasswordGrantResult is the previous name of PasswordGrantResponse.
//
// Deprecated: use PasswordGrantResponse. Will be removed in a future release.
type PasswordGrantResult = PasswordGrantResponse

// ----------------------------------------------------------------------------
// TokenValidator — validates tokens and checks authorization.
// ----------------------------------------------------------------------------

// TokenValidator parses tokens, verifies their signatures and standard claims,
// and checks scope / RFC 9396 authorization_details requirements.
type TokenValidator interface {
	// ValidateToken parses and validates a token (signature, expiry, issuer,
	// audience, blacklist) and returns its claims.
	ValidateToken(ctx context.Context, req *ValidateTokenRequest) (*ValidateTokenResponse, error)

	// CheckScopes validates a token and verifies it carries every required scope.
	CheckScopes(ctx context.Context, req *CheckScopesRequest) (*CheckScopesResponse, error)

	// CheckAuthorizationDetails validates a token and verifies it carries
	// authorization_details entries for every required type (RFC 9396).
	CheckAuthorizationDetails(ctx context.Context, req *CheckAuthorizationDetailsRequest) (*CheckAuthorizationDetailsResponse, error)
}

// ValidateTokenRequest is the input to TokenValidator.ValidateToken.
type ValidateTokenRequest struct {
	Token string
}

// ValidateTokenResponse wraps the parsed token claims.
type ValidateTokenResponse struct {
	Info *TokenInfo
}

// CheckScopesRequest is the input to TokenValidator.CheckScopes.
type CheckScopesRequest struct {
	Token            string
	RequiredScopes   []string
}

// CheckScopesResponse is intentionally empty — the operation is a pure
// success/failure signal expressed via the error return. Wrapped struct
// preserves the convention shape and gives forward-compat headroom.
type CheckScopesResponse struct{}

// CheckAuthorizationDetailsRequest is the input to TokenValidator.CheckAuthorizationDetails.
type CheckAuthorizationDetailsRequest struct {
	Token         string
	RequiredTypes []string
}

// CheckAuthorizationDetailsResponse — see CheckScopesResponse rationale.
type CheckAuthorizationDetailsResponse struct{}

// ----------------------------------------------------------------------------
// TokenIntrospector — RFC 7662.
// ----------------------------------------------------------------------------

// TokenIntrospector performs RFC 7662 token introspection.
type TokenIntrospector interface {
	// Introspect checks a token's validity and returns its claims.
	// Returns {Active: false} on the wrapped result for any invalid token
	// (never reveals why — RFC 7662 §2.2 confidentiality).
	Introspect(ctx context.Context, req *IntrospectRequest) (*IntrospectResponse, error)
}

// IntrospectRequest is the input to TokenIntrospector.Introspect.
type IntrospectRequest struct {
	Token string
}

// IntrospectResponse wraps the RFC 7662 introspection result.
type IntrospectResponse struct {
	Result *IntrospectionResult
}

// ----------------------------------------------------------------------------
// TokenRevoker — RFC 7009.
// ----------------------------------------------------------------------------

// TokenRevoker invalidates tokens per RFC 7009.
type TokenRevoker interface {
	// Revoke invalidates a token. The TokenTypeHint ("access_token" or
	// "refresh_token") guides which store to check first; empty hint tries both.
	Revoke(ctx context.Context, req *RevokeRequest) (*RevokeResponse, error)
}

// RevokeRequest is the input to TokenRevoker.Revoke.
type RevokeRequest struct {
	Token         string
	TokenTypeHint string
}

// RevokeResponse — empty (success/failure via error). Wrapped per convention.
type RevokeResponse struct{}

// ----------------------------------------------------------------------------
// ClientAuthenticator — verifies client credentials.
// ----------------------------------------------------------------------------

// ClientAuthenticator verifies client_id + client_secret. Used by transport
// bindings to authenticate callers of protected endpoints (introspection,
// revocation, DCR).
type ClientAuthenticator interface {
	// AuthenticateClient verifies the client_id and client_secret.
	AuthenticateClient(ctx context.Context, req *AuthenticateClientRequest) (*AuthenticateClientResponse, error)
}

// AuthenticateClientRequest is the input to ClientAuthenticator.AuthenticateClient.
type AuthenticateClientRequest struct {
	ClientID     string
	ClientSecret string
}

// AuthenticateClientResponse — empty (success/failure via error). Wrapped per convention.
type AuthenticateClientResponse struct{}

// ----------------------------------------------------------------------------
// Result types (returned by interface methods, exported for wire compat)
// ----------------------------------------------------------------------------

// TokenInfo holds the validated claims extracted from a token.
// Returned wrapped inside ValidateTokenResponse.
type TokenInfo struct {
	// UserID is the subject (sub claim) — a user ID or client_id.
	UserID string

	// Scopes are the granted scopes from the token.
	Scopes []string

	// AuthorizationDetails are the RFC 9396 authorization_details from the token.
	// Nil if the token has no authorization_details.
	AuthorizationDetails []core.AuthorizationDetail

	// CustomClaims are non-standard JWT claims (everything not in standardClaims).
	CustomClaims map[string]any

	// AuthType is "jwt" or "api_key".
	AuthType string
}

// Note: IntrospectionResult is defined in introspection_client.go.
// TokenIntrospector.Introspect returns the same type (wrapped) used by
// IntrospectionValidator (the HTTP client). This keeps the result
// consistent regardless of whether introspection is done locally
// (via TokenIntrospector) or remotely (via IntrospectionValidator).
