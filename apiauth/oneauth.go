package apiauth

import (
	"time"

	"go.opentelemetry.io/otel/trace"

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
	Issuer        TokenIssuer
	Validator     TokenValidator
	Introspector  TokenIntrospector
	Revoker       TokenRevoker
	Authenticator ClientAuthenticator

	// Per-grant interfaces. Nil when the corresponding store / config
	// is not wired — the TokenEndpointHandler returns
	// unsupported_grant_type for any grant whose Granter is nil.
	AuthorizationCodeGranter AuthorizationCodeGranter
	DeviceCodeGranter        DeviceCodeGranter
	JwtBearerGranter         JwtBearerGranter
	TokenExchanger           TokenExchanger

	// Shared state — available for transport bindings that need direct access.
	KeyStore     keys.KeyStorage
	Blacklist    core.TokenBlacklist
	RefreshStore core.RefreshTokenStore

	// Stores backing the new grant flows. Exposed on OneAuth so
	// transport bindings (DeviceVerificationHandler, the consent
	// screens) can write to them — the granter implementations only
	// read.
	AuthorizationCodeStore core.AuthorizationCodeStore
	DeviceAuthStore        core.DeviceAuthorizationStore
	AppStore               core.AppRegistrationStore

	// AcceptedAudiences is the set of URLs the token endpoint will
	// accept as the `aud` claim of a private_key_jwt / client_secret_jwt
	// client assertion (OIDC Core §9). Echoed into the granters so they
	// can validate confidential-client assertions.
	AcceptedAudiences []string

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

	// VerifyKey is the public key for asymmetric token validation.
	// When SigningKey is a private key (RS256 / ES256), VerifyKey is
	// the matching public key handed to the validator. When SigningKey
	// is a []byte HS256 secret, VerifyKey is ignored. Nil + asymmetric
	// SigningKey causes the validator to fall back to KeyStore-based
	// key lookup.
	VerifyKey any

	// JWT configuration
	Issuer       string        // JWT iss claim
	Audience     string        // JWT aud claim (optional)
	AccessExpiry time.Duration // default 15 minutes

	// Token lifecycle
	Blacklist    core.TokenBlacklist    // for access token revocation (optional)
	RefreshStore core.RefreshTokenStore // for refresh token management (optional)

	// Password grant callbacks (optional — only needed if password grant is used)
	ValidateCredentials CredentialsValidator      // validates username/password
	GetSubjectScopes    core.GetSubjectScopesFunc // returns allowed scopes for the subject (user ID or client_id)

	// CustomClaims is called during access-token issuance to inject additional
	// non-standard claims into the JWT. Standard JWT claims (sub, iss, aud,
	// exp, iat, type, scopes, jti, authorization_details) cannot be overridden.
	CustomClaims CustomClaimsFunc

	// Authenticator overrides the default KeyStore-backed
	// ClientAuthenticator. Nil keeps the default behavior
	// (KeyStore-based secret + private_key_jwt assertion validation).
	Authenticator ClientAuthenticator

	// AcceptedAudiences is the set of URLs the token endpoint will
	// accept as the `aud` claim of a private_key_jwt / client_secret_jwt
	// client assertion. Typically the token endpoint URL plus the AS
	// issuer URL. Empty falls back to the request URL.
	AcceptedAudiences []string

	// Authorization code grant (RFC 6749 §4.1). When AuthorizationCodeStore
	// is non-nil the token endpoint accepts grant_type=authorization_code.
	AuthorizationCodeStore core.AuthorizationCodeStore

	// Device authorization grant (RFC 8628). When DeviceAuthStore is
	// non-nil the token endpoint accepts grant_type=...:device_code.
	DeviceAuthStore core.DeviceAuthorizationStore

	// AppStore drives confidential-client enforcement on the device-
	// code (issue 266) and authorization-code redemption paths.
	AppStore core.AppRegistrationStore

	// TrustedAssertionIssuers lists upstream IdPs whose JWT assertions
	// the token endpoint accepts for the jwt-bearer (RFC 7523 §2.1)
	// and token-exchange (RFC 8693) grants. Empty disables both.
	TrustedAssertionIssuers []TrustedAssertionIssuer

	// TracerProvider opts the validator's signature-verify hot path
	// into SEP-414 tracing. Nil keeps it on the no-op fast path.
	TracerProvider trace.TracerProvider

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
		GetSubjectScopes:    cfg.GetSubjectScopes,
		CustomClaims:        cfg.CustomClaims,
		Hooks:               cfg.Hooks.Token,
	})

	// Wire the validator — needs read-only key lookup + blacklist.
	// SigningKey carries through so HS256 single-tenant deployments
	// (KeyStore is nil) can still validate their own tokens. For
	// asymmetric setups VerifyKey (the public key) takes precedence
	// over SigningKey so the validator never needs the private key.
	validatorKey := any(cfg.VerifyKey)
	if validatorKey == nil {
		validatorKey = cfg.SigningKey
	}
	validator := NewJWTValidator(JWTValidatorConfig{
		KeyLookup:      cfg.KeyStore, // KeyStorage implements KeyLookup
		SigningKey:     validatorKey,
		SigningAlg:     signingAlg,
		Blacklist:      cfg.Blacklist,
		Issuer:         cfg.Issuer,
		Audience:       cfg.Audience,
		Hooks:          cfg.Hooks.Security,
		TracerProvider: cfg.TracerProvider,
	})

	// Wire the introspector — needs only the validator
	introspector := NewTokenIntrospector(validator)

	// Wire the revoker — needs blacklist + refresh store
	revoker := NewTokenRevoker(TokenRevokerConfig{
		Blacklist:    cfg.Blacklist,
		RefreshStore: cfg.RefreshStore,
		Hooks:        cfg.Hooks.Token,
	})

	// Wire the client authenticator — caller override wins so deployments
	// can swap in private_key_jwt / federated client auth.
	authenticator := cfg.Authenticator
	if authenticator == nil {
		authenticator = NewClientAuthenticator(cfg.KeyStore)
	}

	// Per-grant Granters. Nil when the corresponding store / config is
	// not wired; TokenEndpointHandler maps a nil Granter to
	// unsupported_grant_type for that grant_type.
	var authCodeGranter AuthorizationCodeGranter
	if cfg.AuthorizationCodeStore != nil {
		authCodeGranter = NewAuthorizationCodeGranter(
			cfg.AuthorizationCodeStore,
			cfg.AppStore,
			authenticator,
			issuer,
			cfg.RefreshStore,
		)
	}
	var deviceGranter DeviceCodeGranter
	if cfg.DeviceAuthStore != nil {
		deviceGranter = NewDeviceCodeGranter(
			cfg.DeviceAuthStore,
			cfg.AppStore,
			authenticator,
			issuer,
			cfg.RefreshStore,
		)
	}
	var jwtBearerGranter JwtBearerGranter
	var tokenExchanger TokenExchanger
	if len(cfg.TrustedAssertionIssuers) > 0 {
		jwtBearerGranter = NewJwtBearerGranter(cfg.TrustedAssertionIssuers, cfg.Audience, cfg.Issuer, issuer)
		tokenExchanger = NewTokenExchanger(cfg.TrustedAssertionIssuers, cfg.Audience, cfg.Issuer, issuer)
	}

	oa := &OneAuth{
		Issuer:                   issuer,
		Validator:                validator,
		Introspector:             introspector,
		Revoker:                  revoker,
		Authenticator:            authenticator,
		AuthorizationCodeGranter: authCodeGranter,
		DeviceCodeGranter:        deviceGranter,
		JwtBearerGranter:         jwtBearerGranter,
		TokenExchanger:           tokenExchanger,
		KeyStore:                 cfg.KeyStore,
		Blacklist:                cfg.Blacklist,
		RefreshStore:             cfg.RefreshStore,
		AuthorizationCodeStore:   cfg.AuthorizationCodeStore,
		DeviceAuthStore:          cfg.DeviceAuthStore,
		AppStore:                 cfg.AppStore,
		AcceptedAudiences:        cfg.AcceptedAudiences,
		Hooks:                    cfg.Hooks,
	}
	return oa
}

// --- HTTP Convenience Methods ---
// These create HTTP handlers wired to the OneAuth core interfaces.
// Use these when mounting endpoints on an HTTP mux.

// SessionsHTTPHandler returns a SessionsHandler for /api/logout,
// /api/logout-all, and /api/sessions. RefreshStore must be set on the
// OneAuth instance.
func (oa *OneAuth) SessionsHTTPHandler() *SessionsHandler {
	return NewSessionsHandler(oa.RefreshStore, oa.Hooks.Token)
}

// APIKeysHTTPHandler returns an APIKeysHandler for /api/keys{,/{id}}.
// The supplied APIKeyStore is wired into the returned handler;
// OneAuthConfig does not carry it because it isn't an OAuth concern.
func (oa *OneAuth) APIKeysHTTPHandler(store core.APIKeyStore, getSubjectScopes core.GetSubjectScopesFunc) *APIKeysHandler {
	return NewAPIKeysHandler(store, getSubjectScopes)
}

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
