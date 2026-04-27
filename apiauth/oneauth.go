package apiauth

import (
	"time"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
)

// OneAuth is the transport-independent core of the authentication system.
// It composes focused interfaces (Option A — no god object) and wires
// hooks for lifecycle callbacks.
//
// Use NewOneAuth to create an instance with all dependencies wired.
// Transport bindings (HTTP handlers, gRPC interceptors, MCP auth) are
// thin wrappers over these interfaces.
//
// Library usage (no HTTP):
//
//	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{...})
//	token, _, _ := oa.Issuer.CreateAccessToken("alice", []string{"read"}, nil)
//	info, _ := oa.Validator.ValidateToken(token)
//	result, _ := oa.Introspector.Introspect(token)
//	oa.Revoker.Revoke(token, "access_token")
//
// See: https://github.com/panyam/oneauth/issues/110
type OneAuth struct {
	// Core operation interfaces — each has minimal dependencies.
	Issuer       TokenIssuer
	Validator    TokenValidator
	Introspector TokenIntrospector
	Revoker      TokenRevoker
	Authenticator ClientAuthenticator

	// Shared state — available for transport bindings that need direct access.
	KeyStore     keys.KeyStorage
	Blacklist    core.TokenBlacklist
	RefreshStore core.RefreshTokenStore

	// Hooks — lifecycle callbacks grouped by concern.
	Hooks Hooks
}

// OneAuthConfig holds the dependencies for creating a OneAuth instance.
type OneAuthConfig struct {
	// Key management
	KeyStore keys.KeyStorage // required — stores client keys

	// Signing configuration
	SigningKey any    // []byte for HS256, *rsa.PrivateKey for RS256, etc.
	SigningAlg string // "HS256", "RS256", "ES256" — default "HS256"

	// JWT configuration
	Issuer       string        // JWT iss claim
	Audience     string        // JWT aud claim (optional)
	AccessExpiry time.Duration // default 15 minutes

	// Token lifecycle
	Blacklist    core.TokenBlacklist    // for access token revocation (optional)
	RefreshStore core.RefreshTokenStore // for refresh token management (optional)

	// Password grant callbacks (optional — only needed if password grant is used)
	ValidateCredentials core.CredentialsValidator // validates username/password
	GetUserScopes       core.GetUserScopesFunc   // returns allowed scopes for a user

	// Hooks — lifecycle callbacks
	Hooks Hooks
}

// NewOneAuth creates a fully wired OneAuth instance.
// All implementations receive only the interfaces they need.
func NewOneAuth(cfg OneAuthConfig) *OneAuth {
	signingAlg := cfg.SigningAlg
	if signingAlg == "" {
		signingAlg = "HS256"
	}

	// Wire the issuer — needs signing config + client key lookup + refresh store
	issuer := NewJWTIssuer(JWTIssuerConfig{
		SigningKey:      cfg.SigningKey,
		SigningAlg:      signingAlg,
		Issuer:          cfg.Issuer,
		Audience:        cfg.Audience,
		AccessExpiry:    cfg.AccessExpiry,
		ClientKeyLookup:     cfg.KeyStore, // KeyStorage implements KeyLookup
		RefreshStore:        cfg.RefreshStore,
		ValidateCredentials: cfg.ValidateCredentials,
		GetUserScopes:       cfg.GetUserScopes,
		Hooks:               cfg.Hooks.Token,
	})

	// Wire the validator — needs read-only key lookup + blacklist
	validator := NewJWTValidator(JWTValidatorConfig{
		KeyLookup: cfg.KeyStore, // KeyStorage implements KeyLookup
		Blacklist: cfg.Blacklist,
		Issuer:    cfg.Issuer,
		Audience:  cfg.Audience,
		Hooks:     cfg.Hooks.Security,
	})

	// Wire the introspector — needs only the validator
	introspector := NewTokenIntrospector(validator)

	// Wire the revoker — needs blacklist + refresh store
	revoker := NewTokenRevoker(TokenRevokerConfig{
		Blacklist:    cfg.Blacklist,
		RefreshStore: cfg.RefreshStore,
		Hooks:        cfg.Hooks.Token,
	})

	// Wire the client authenticator — needs key lookup
	authenticator := NewClientAuthenticator(cfg.KeyStore)

	oa := &OneAuth{
		Issuer:        issuer,
		Validator:     validator,
		Introspector:  introspector,
		Revoker:       revoker,
		Authenticator: authenticator,
		KeyStore:      cfg.KeyStore,
		Blacklist:     cfg.Blacklist,
		RefreshStore:  cfg.RefreshStore,
		Hooks:         cfg.Hooks,
	}
	return oa
}

// --- HTTP Convenience Methods ---
// These create HTTP handlers wired to the OneAuth core interfaces.
// Use these when mounting endpoints on an HTTP mux.

// IntrospectionHTTPHandler returns an http.Handler for POST /oauth/introspect.
func (oa *OneAuth) IntrospectionHTTPHandler() *IntrospectionHandler {
	return &IntrospectionHandler{
		Introspector:  oa.Introspector,
		Authenticator: oa.Authenticator,
	}
}

// RevocationHTTPHandler returns an http.Handler for POST /oauth/revoke.
func (oa *OneAuth) RevocationHTTPHandler() *RevocationHandler {
	return &RevocationHandler{
		Revoker:       oa.Revoker,
		Authenticator: oa.Authenticator,
	}
}

// HTTPMiddleware returns an APIMiddleware wired to the OneAuth TokenValidator.
// Use this for protecting resource endpoints.
func (oa *OneAuth) HTTPMiddleware() *APIMiddleware {
	return &APIMiddleware{
		Validator: oa.Validator,
		Blacklist: oa.Blacklist,
		KeyStore:  oa.KeyStore,
	}
}
