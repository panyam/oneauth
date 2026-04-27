package apiauth

import (
	"github.com/panyam/oneauth/core"
)

// Transport-independent interfaces for OneAuth operations.
// Each interface represents a focused capability. Implementations take only
// the dependencies they need (Option A — composed interfaces, no god objects).
//
// HTTP handlers, gRPC interceptors, and MCP auth managers are thin transport
// bindings over these interfaces.
//
// See: https://github.com/panyam/oneauth/issues/110

// TokenIssuer creates signed access tokens.
type TokenIssuer interface {
	// CreateAccessToken mints a JWT with the given subject, scopes, and
	// optional RFC 9396 authorization_details.
	// Returns the signed token string and expiry in seconds.
	CreateAccessToken(subject string, scopes []string, details []core.AuthorizationDetail) (token string, expiresIn int64, err error)

	// ClientCredentials performs the full client_credentials grant:
	// authenticates the client, validates scopes/details, and returns a token response.
	ClientCredentials(clientID, clientSecret string, scopes []string, details []core.AuthorizationDetail) (*core.TokenPair, error)
}

// TokenValidator validates tokens and checks authorization.
type TokenValidator interface {
	// ValidateToken parses and validates a token string (JWT signature,
	// expiry, issuer, audience, blacklist). Returns the token's claims.
	ValidateToken(token string) (*TokenInfo, error)

	// CheckScopes validates a token and verifies it contains all required scopes.
	// Returns an error if the token is invalid or scopes are insufficient.
	CheckScopes(token string, required []string) error

	// CheckAuthorizationDetails validates a token and verifies it contains
	// authorization_details entries for all required types (RFC 9396).
	CheckAuthorizationDetails(token string, requiredTypes []string) error
}

// TokenIntrospector inspects tokens per RFC 7662.
type TokenIntrospector interface {
	// Introspect checks a token's validity and returns its claims.
	// Returns {Active: false} for any invalid token (never reveals why).
	Introspect(token string) (*IntrospectionResult, error)
}

// TokenRevoker revokes tokens per RFC 7009.
type TokenRevoker interface {
	// Revoke invalidates a token. The tokenTypeHint ("access_token" or
	// "refresh_token") guides which store to check first. Empty hint
	// tries both.
	Revoke(token, tokenTypeHint string) error
}

// ClientAuthenticator verifies client credentials.
// Used by transport bindings to authenticate callers of protected endpoints
// (introspection, revocation, DCR).
type ClientAuthenticator interface {
	// AuthenticateClient verifies the client_id and client_secret.
	AuthenticateClient(clientID, clientSecret string) error
}

// --- Result types ---

// TokenInfo holds the validated claims extracted from a token.
// Returned by TokenValidator.ValidateToken.
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
// TokenIntrospector.Introspect returns the same type used by
// IntrospectionValidator (the HTTP client). This keeps the result
// consistent regardless of whether introspection is done locally
// (via TokenIntrospector) or remotely (via IntrospectionValidator).
