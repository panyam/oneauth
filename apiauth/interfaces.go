package apiauth

import (
	"context"

	"github.com/panyam/oneauth/accounts"
	"github.com/panyam/oneauth/core"
)

// CredentialsValidator is re-exported from accounts as a single shared
// function shape so apiauth's password-grant validator field and localauth's
// host-supplied validator are assignable to each other without conversion.
type CredentialsValidator = accounts.CredentialsValidator

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

// TokenIssuer mints access tokens via the OAuth 2.0 grants that ship
// on by default: client_credentials, refresh_token, and the raw
// access-token mint. Password grant (ROPC) was retired in OAuth 2.1
// §7.6 and is no longer part of the default issuer surface — wire
// PasswordGranter (a peer interface) to opt in for OAuth 2.0
// deployments that need it. Per capability-gating umbrella #344.
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
// The caller uses Subject + GrantedScopes to create a refresh token if needed.
type PasswordGrantResponse struct {
	Subject              string // RFC 7519 sub — user ID for password grant
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
// AuthorizationCodeGranter — RFC 6749 §4.1.3 authorization-code grant.
// ----------------------------------------------------------------------------

// AuthorizationCodeGranter redeems an RFC 6749 §4.1 authorization
// code at the token endpoint. Separate from TokenIssuer so the
// authorization-code dependencies (AuthorizationCodeStore + AppStore +
// ClientAuthenticator + PKCE) don't leak into callers that only need
// the base TokenIssuer.
//
// The implementation looks up the stored binding, re-verifies every
// promise the AS made at /authorize time (client_id, redirect_uri,
// S256 PKCE), consumes the code (single-use per RFC 6749 §4.1.2),
// authenticates confidential clients via the wired
// ClientAuthenticator, and delegates the actual token mint to
// TokenIssuer.CreateAccessToken.
type AuthorizationCodeGranter interface {
	// AuthorizationCodeGrant trades an authorization code for an
	// access token (and optionally a refresh token).
	AuthorizationCodeGrant(ctx context.Context, req *AuthorizationCodeGrantRequest) (*AuthorizationCodeGrantResponse, error)
}

// AuthorizationCodeGrantRequest holds the inputs the token endpoint
// receives for grant_type=authorization_code.
type AuthorizationCodeGrantRequest struct {
	Code         string
	CodeVerifier string
	RedirectURI  string
	ClientID     string

	// Client authentication credentials (only one channel populated
	// per RFC 7521 / OIDC Core §9):
	ClientSecret        string
	ClientAssertionType string
	ClientAssertion     string

	// AcceptedAudiences is the set of URLs the assertion's `aud` claim
	// MUST match (used for private_key_jwt / client_secret_jwt).
	// Empty falls back to the request URL.
	AcceptedAudiences []string
}

// AuthorizationCodeGrantResponse wraps the issued token pair.
type AuthorizationCodeGrantResponse struct {
	Tokens *core.TokenPair
}

// ----------------------------------------------------------------------------
// DeviceCodeGranter — RFC 8628 §3.4 device-code grant.
// ----------------------------------------------------------------------------

// DeviceCodeGranter redeems an RFC 8628 device_code at the token
// endpoint. Separate from TokenIssuer so the device-flow dependencies
// (DeviceAuthorizationStore, polling-clock bookkeeping) don't leak
// into callers that only need the base TokenIssuer.
//
// The implementation maps the stored DeviceAuthorization's status +
// polling clock to the RFC 8628 §3.5 error taxonomy
// (authorization_pending / slow_down / access_denied / expired_token),
// enforces confidential-client authentication via AppStore +
// ClientAuthenticator when configured (issue 266), and delegates the
// token mint to TokenIssuer.CreateAccessToken on Approved status.
type DeviceCodeGranter interface {
	// DeviceCodeGrant trades a device_code (after the user has
	// approved on the verification URI) for an access token.
	DeviceCodeGrant(ctx context.Context, req *DeviceCodeGrantRequest) (*DeviceCodeGrantResponse, error)
}

// DeviceCodeGrantRequest holds the inputs the token endpoint
// receives for grant_type=urn:ietf:params:oauth:grant-type:device_code.
type DeviceCodeGrantRequest struct {
	DeviceCode string
	ClientID   string

	// Client authentication credentials (confidential clients only).
	ClientSecret        string
	ClientAssertionType string
	ClientAssertion     string

	AcceptedAudiences []string
}

// DeviceCodeGrantResponse wraps the issued token pair.
type DeviceCodeGrantResponse struct {
	Tokens *core.TokenPair
}

// ----------------------------------------------------------------------------
// JwtBearerGranter — RFC 7523 §2.1 jwt-bearer grant.
// ----------------------------------------------------------------------------

// JwtBearerGranter validates an upstream-IdP assertion and mints
// an access token bound to the assertion's subject (RFC 7523 §2.1).
// Separate from TokenIssuer so the assertion-side validation
// (trusted-issuer registry, key lookup, audience checks) doesn't
// leak into callers that only need the base TokenIssuer.
type JwtBearerGranter interface {
	// JwtBearerGrant validates the assertion against the configured
	// TrustedAssertionIssuers and issues an access token.
	JwtBearerGrant(ctx context.Context, req *JwtBearerGrantRequest) (*JwtBearerGrantResponse, error)
}

// JwtBearerGrantRequest holds the inputs the token endpoint receives
// for grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer.
type JwtBearerGrantRequest struct {
	Assertion            string
	Scopes               []string
	AuthorizationDetails []core.AuthorizationDetail
}

// JwtBearerGrantResponse wraps the issued token pair.
type JwtBearerGrantResponse struct {
	Tokens *core.TokenPair
}

// ----------------------------------------------------------------------------
// TokenExchanger — RFC 8693 token exchange.
// ----------------------------------------------------------------------------

// TokenExchanger trades one token for another per RFC 8693. Distinct
// from JwtBearerGranter because the audience / resource / actor
// semantics are token-exchange-specific.
type TokenExchanger interface {
	// TokenExchange trades subject_token for a token with the
	// requested type / audience / resource.
	TokenExchange(ctx context.Context, req *TokenExchangeRequest) (*TokenExchangeResponse, error)
}

// TokenExchangeRequest holds the inputs the token endpoint receives
// for grant_type=urn:ietf:params:oauth:grant-type:token-exchange.
type TokenExchangeRequest struct {
	SubjectToken       string
	SubjectTokenType   string
	RequestedTokenType string
	Resource           string
	Audience           string
	Scopes             []string
	AuthorizationDetails []core.AuthorizationDetail
}

// TokenExchangeResponse wraps the issued token pair. The wire
// response carries the RFC 8693 issued_token_type field; the
// implementation populates Tokens.IssuedTokenType.
type TokenExchangeResponse struct {
	Tokens *core.TokenPair
}

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

// ClientAuthenticator verifies client credentials. Used by transport
// bindings to authenticate callers of protected endpoints (token,
// introspection, revocation, DCR).
//
// Supported authentication methods (RFC 6749 §2.3.1, OIDC Core §9):
//   - client_secret_basic / client_secret_post: ClientID + ClientSecret
//   - private_key_jwt (RFC 7521 §3 + RFC 7523 §2.2): ClientAssertionType +
//     ClientAssertion. The implementation routes by which fields are set.
type ClientAuthenticator interface {
	// AuthenticateClient verifies the supplied credentials. Returns the
	// authenticated client_id and the auth method used on success.
	AuthenticateClient(ctx context.Context, req *AuthenticateClientRequest) (*AuthenticateClientResponse, error)
}

// AuthenticateClientRequest is the input to ClientAuthenticator.AuthenticateClient.
//
// Callers populate either the secret pair (ClientID + ClientSecret) or
// the assertion pair (ClientAssertionType + ClientAssertion). When both
// are populated the implementation prefers the assertion (it is the
// stronger credential per RFC 6749 §2.3.1).
type AuthenticateClientRequest struct {
	// ClientID is the OAuth client identifier. For private_key_jwt this
	// may be empty; the authenticator extracts it from the assertion's
	// `iss` / `sub` claims.
	ClientID string

	// ClientSecret is the shared secret for client_secret_basic /
	// client_secret_post. Empty when authenticating via assertion.
	ClientSecret string

	// ClientAssertionType is the OAuth assertion type URN. For
	// private_key_jwt this MUST be
	// "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	// (RFC 7521 §4.2). Empty when authenticating via secret.
	ClientAssertionType string

	// ClientAssertion is the signed JWT bearing the client's identity
	// (RFC 7523 §2.2 / OIDC Core §9). Validated against the client's
	// registered public key. Empty when authenticating via secret.
	ClientAssertion string

	// Audiences is the set of URLs the AS will accept as the assertion's
	// `aud` claim — typically the token endpoint URL AND the AS issuer
	// URL. Per OIDC Core §9 the audience SHOULD be the token endpoint
	// URL, but real-world clients (Auth0, Keycloak, Authlete) send one
	// or the other; accept both for interop. The assertion's `aud`
	// MUST match at least one entry. Required when ClientAssertion is
	// set.
	Audiences []string
}

// AuthenticateClientResponse reports the authenticated client and the
// auth method that succeeded. The method is informational (telemetry,
// logging) — handlers that only need success/failure can ignore it.
type AuthenticateClientResponse struct {
	// ClientID is the authenticated client identifier. Equals the
	// request ClientID for the secret path; extracted from the
	// assertion `iss` / `sub` for the assertion path.
	ClientID string

	// Method names the auth method that succeeded — one of
	// "client_secret_basic", "client_secret_post", "private_key_jwt".
	// Transport bindings populate Method on the way in (basic vs post)
	// when they know which channel carried the secret; the assertion
	// path always sets it to "private_key_jwt".
	Method string
}

// ----------------------------------------------------------------------------
// Result types (returned by interface methods, exported for wire compat)
// ----------------------------------------------------------------------------

// TokenInfo holds the validated claims extracted from a token.
// Returned wrapped inside ValidateTokenResponse.
type TokenInfo struct {
	// Subject is the principal the token represents (RFC 7519 sub) — a
	// user ID for human-driven flows or a client_id for
	// client_credentials.
	Subject string

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
