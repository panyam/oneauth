package testutil

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/httpauth"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

const (
	defaultAdminKey = "testutil-admin-key"
	defaultIssuer   = "testutil-issuer"
)

// TestAuthServer is an in-process oneauth authorization server for integration
// tests. It generates an RSA 2048 key pair, serves JWKS, issues tokens via the
// client_credentials grant, and provides OAuth AS metadata (RFC 8414).
//
// The server is cleaned up automatically via t.Cleanup — callers never need
// to call Close manually.
//
// Endpoints served:
//
//	GET  /_ah/health                          — health check
//	POST /api/token                           — token endpoint (client_credentials)
//	POST /oauth/introspect                    — token introspection (RFC 7662)
//	GET  /.well-known/jwks.json               — JWKS public key (RFC 7517)
//	GET  /.well-known/openid-configuration    — AS metadata (RFC 8414)
//	POST /apps/dcr                            — dynamic client registration (RFC 7591)
type TestAuthServer struct {
	// Server is the underlying httptest.Server. Use URL() for the base URL.
	Server *httptest.Server

	// OneAuth is the configured transport-independent core (RS256).
	OneAuth *apiauth.OneAuth

	// TokenEndpointHandler is the HTTP handler mounted at /api/token.
	// Distinct name from the TokenEndpoint() method which returns the URL.
	TokenEndpointHandler *apiauth.TokenEndpointHandler

	// KeyStore holds the server's RSA key and any registered app keys.
	KeyStore keys.KeyStorage

	// Registrar manages app registrations and serves the /apps/ endpoints.
	Registrar *admin.AppRegistrar

	privateKey *rsa.PrivateKey
	cfg        config
}

// config holds TestAuthServer configuration set via functional options.
type config struct {
	adminKey                string
	issuer                  string
	audience                string
	audienceFunc            func() string
	scopes                  []string
	claimsSupported         []string                         // OIDC Discovery 1.0 §3 advertisement
	grantTypesSupported     []string                         // overrides default when non-nil
	responseTypesSupported  []string                         // overrides default when non-nil
	issParameterSupported   *bool                            // RFC 9207 advertisement (nil = omit)
	trustedAssertionIssuers []apiauth.TrustedAssertionIssuer // RFC 7523 §2.1 + RFC 8693

	// Authorize-flow configuration. authorizeEnabled gates the mount of
	// MountAuthorize + the AS-metadata advertisement extensions.
	authorizeEnabled         bool
	authorizeAutoApprove     string
	authorizeRedirectOverride func(values url.Values)
	allowPlainPKCE           bool
}

// Option configures a TestAuthServer.
type Option func(*config)

// WithAdminKey sets the admin API key required for app registration endpoints.
// Default: "testutil-admin-key".
func WithAdminKey(key string) Option {
	return func(c *config) { c.adminKey = key }
}

// WithIssuer sets the JWT issuer claim and the issuer field in AS metadata.
// Default: "testutil-issuer" (overridden to server URL after start).
func WithIssuer(iss string) Option {
	return func(c *config) { c.issuer = iss }
}

// WithAudience sets the JWT audience claim on minted tokens.
// Default: "" (no audience restriction).
func WithAudience(aud string) Option {
	return func(c *config) { c.audience = aud }
}

// WithAudienceFunc registers a closure consulted on every token mint
// and validation. A non-empty return takes precedence over the eager
// WithAudience value; an empty return falls back to it.
//
// Use this when the audience is not known at construction time — the
// canonical case is an in-process AS whose `aud` must equal a resource
// server URL only allocated after `httptest.NewServer` runs. Build the
// AS once, then teach the closure to look up the current value when
// the RS comes online. The caller owns the storage and synchronisation;
// testutil only plumbs the closure to OneAuthConfig.AudienceFunc.
//
// See docs/MIGRATION.md "Late-binding the audience" for the full
// pattern.
func WithAudienceFunc(fn func() string) Option {
	return func(c *config) { c.audienceFunc = fn }
}

// WithScopes sets the scopes_supported field in AS metadata.
// Default: ["read", "write", "admin"].
func WithScopes(scopes []string) Option {
	return func(c *config) { c.scopes = scopes }
}

// WithClaimsSupported sets the `claims_supported` field in AS metadata
// (OIDC Discovery 1.0 §3). Default: the claims OneAuth's bearer tokens
// already emit (sub, iss, aud, exp, iat, jti, scope, client_id).
func WithClaimsSupported(claims []string) Option {
	return func(c *config) { c.claimsSupported = claims }
}

// WithGrantTypesSupported overrides the `grant_types_supported` field
// advertised in AS metadata (RFC 8414). Use this when enabling a grant
// beyond the default (`client_credentials`) — e.g., advertising the
// jwt-bearer (RFC 7523 §2.1) or token-exchange (RFC 8693) grants
// alongside the default.
//
// The values supplied REPLACE the default. Callers that want to keep
// `client_credentials` and add more must include it in the slice.
//
// Note: advertising a grant in metadata does NOT enable its handler at
// the token endpoint. Pair this with WithTrustedAssertionIssuers to
// actually serve jwt-bearer / token-exchange requests.
func WithGrantTypesSupported(grants []string) Option {
	return func(c *config) { c.grantTypesSupported = grants }
}

// WithIssParameterSupported sets the
// `authorization_response_iss_parameter_supported` field in AS metadata
// (RFC 9207 §3). Mitigates mix-up attacks against clients that interact
// with multiple ASes by signaling that the AS includes an `iss`
// parameter on every authorization response.
//
// When paired with WithAuthorizeEnabled(true), this flag ALSO drives
// the wire behavior — the /authorize redirect carries `iss=<issuer>`
// per RFC 9207 §2 — so the AS's advertisement matches what callers
// observe. To simulate the misbehaving-AS scenario (advertises but
// does not emit, or emits without advertising), combine with
// WithAuthorizeRedirectOverride to mutate the redirect query
// per-scenario.
func WithIssParameterSupported(supported bool) Option {
	return func(c *config) { c.issParameterSupported = &supported }
}

// WithAuthorizeEnabled mounts the RFC 6749 §4.1 authorization-code
// flow endpoint (`GET / POST /authorize`) on the test server. When
// enabled the AS metadata advertises `authorization_endpoint`,
// extends `response_types_supported` to include "code", and adds
// "authorization_code" to `grant_types_supported`.
//
// The mounted flow auto-approves all requests with the subject set
// by WithAuthorizeAutoApproveSubject (default: "e2e-user"). This is
// suitable for conformance fixtures and in-process tests — NEVER for
// production deployments.
func WithAuthorizeEnabled(enabled bool) Option {
	return func(c *config) { c.authorizeEnabled = enabled }
}

// WithAuthorizeAutoApproveSubject sets the subject the auto-approve
// path binds to issued codes. Empty falls back to "e2e-user".
func WithAuthorizeAutoApproveSubject(subject string) Option {
	return func(c *config) { c.authorizeAutoApprove = subject }
}

// WithAllowPlainPKCE opts the test AS into OAuth 2.0 `plain` PKCE on
// the /authorize endpoint (RFC 7636 §4.4). OAuth 2.1 §7.5 retired
// plain; this option exists for conformance fixtures that need to
// exercise the OAuth 2.0 escape hatch documented under
// capability-gating umbrella #344. AS metadata
// `code_challenge_methods_supported` extends to ["S256", "plain"] when
// enabled. Production deployments never set this.
func WithAllowPlainPKCE(allow bool) Option {
	return func(c *config) { c.allowPlainPKCE = allow }
}

// WithAuthorizeRedirectOverride installs a hook that mutates the
// /authorize redirect's query values before they are URL-encoded.
// Lets conformance scenarios test misbehaving-AS branches that a
// correct production AS cannot simulate — e.g. "AS advertises
// authorization_response_iss_parameter_supported=true in metadata
// but does NOT emit iss in the redirect" — by stripping or
// corrupting individual values.
//
// Production deployments never set this. Mirrors the PR 191 pattern.
func WithAuthorizeRedirectOverride(fn func(values url.Values)) Option {
	return func(c *config) { c.authorizeRedirectOverride = fn }
}

// WithTrustedAssertionIssuers configures the AS to accept
// jwt-bearer (RFC 7523 §2.1) and token-exchange (RFC 8693) grants from
// the listed upstream IdPs. Each entry binds an issuer URL to a public
// key (or KeyFunc) so the AS can verify assertion signatures.
//
// When the supplied slice is non-empty, this Option AUTOMATICALLY
// extends the advertised `grant_types_supported` to include the two new
// grant URIs (so callers don't need to remember the pair). Callers can
// still pass WithGrantTypesSupported AFTER this option to fully replace
// the advertised list — last-option-wins for the slice.
//
// See:
//   - RFC 7523 §2.1: https://www.rfc-editor.org/rfc/rfc7523#section-2.1
//   - RFC 8693:      https://www.rfc-editor.org/rfc/rfc8693
func WithTrustedAssertionIssuers(issuers []apiauth.TrustedAssertionIssuer) Option {
	return func(c *config) {
		c.trustedAssertionIssuers = issuers
		// Extend the advertised grants unless the caller already pinned
		// a specific list. Append-don't-replace keeps client_credentials
		// alongside the new grants by default.
		if c.grantTypesSupported == nil {
			c.grantTypesSupported = []string{
				"client_credentials",
				apiauth.JwtBearerGrantType,
				apiauth.TokenExchangeGrantType,
			}
		}
	}
}

// NewTestAuthServer creates and starts an in-process authorization server
// with an RSA 2048 key pair. The server is automatically shut down via
// t.Cleanup when the test completes.
//
// The server signs JWTs with RS256 and serves the public key via JWKS.
// Apps can be registered via /apps/dcr (RFC 7591),
// and tokens can be obtained via /api/token (client_credentials grant).
// NewAuthServer creates an in-process OAuth authorization server without
// requiring *testing.T. Use this in standalone examples, benchmarks, or
// any non-test context. The caller must call Close() when done.
//
// For test code, prefer NewTestAuthServer which auto-registers cleanup.
func NewAuthServer(opts ...Option) (*TestAuthServer, error) {
	cfg := config{
		adminKey:        defaultAdminKey,
		issuer:          defaultIssuer,
		scopes:          []string{"read", "write", "admin"},
		claimsSupported: []string{"sub", "iss", "aud", "exp", "iat", "jti", "scope", "client_id"},
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("testutil: failed to generate RSA key: %w", err)
	}

	ks := keys.NewInMemoryKeyStore()
	pubPEM, err := utils.EncodePublicKeyPEM(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("testutil: failed to encode public key: %w", err)
	}
	kid, err := utils.ComputeKid(&privKey.PublicKey, "RS256")
	if err != nil {
		return nil, fmt.Errorf("testutil: failed to compute kid: %w", err)
	}
	if _, err := ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID:  cfg.issuer,
		Key:       pubPEM,
		Algorithm: "RS256",
		Kid:       kid,
	}}); err != nil {
		return nil, fmt.Errorf("testutil: failed to store RSA key: %w", err)
	}

	registrar := admin.NewAppRegistrar(ks, admin.NewAPIKeyAuth(cfg.adminKey))

	oaCfg := apiauth.OneAuthConfig{
		KeyStore:                ks,
		SigningKey:              privKey,
		VerifyKey:               &privKey.PublicKey,
		SigningAlg:              "RS256",
		Issuer:                  cfg.issuer,
		Audience:                cfg.audience,
		AudienceFunc:            cfg.audienceFunc,
		TrustedAssertionIssuers: cfg.trustedAssertionIssuers,
		AllowPlainPKCE:          cfg.allowPlainPKCE,
	}
	if cfg.authorizeEnabled {
		oaCfg.AuthorizationCodeStore = core.NewInMemoryAuthorizationCodeStore()
	}
	jwksHandler := &keys.JWKSHandler{KeyStore: ks}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /_ah/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /.well-known/jwks.json", jwksHandler.ServeHTTP)
	mux.Handle("/apps/", httpauth.LimitBody(httpauth.DefaultMaxBodySize)(registrar.Handler()))
	mux.Handle("/apps", httpauth.LimitBody(httpauth.DefaultMaxBodySize)(registrar.Handler()))

	server := httptest.NewServer(mux)

	baseURL := server.URL
	issuer := cfg.issuer
	if issuer == defaultIssuer {
		issuer = baseURL
		oaCfg.Issuer = issuer
	}

	// Build OneAuth + the handlers it wires AFTER the issuer is
	// resolved so the validator's expected iss matches what the token
	// endpoint stamps onto minted tokens.
	oa := apiauth.NewOneAuth(oaCfg)
	tokenEndpoint := apiauth.NewTokenEndpointHandler(oa)
	mux.Handle("POST /api/token", tokenEndpoint)
	mux.Handle("POST /oauth/introspect", oa.IntrospectionHTTPHandler())
	grants := cfg.grantTypesSupported
	if grants == nil {
		grants = []string{"client_credentials"}
	}
	responseTypes := cfg.responseTypesSupported
	if responseTypes == nil {
		responseTypes = []string{"token"}
	}
	authorizeEndpoint := ""
	if cfg.authorizeEnabled {
		authorizeEndpoint = baseURL + "/authorize"
		grants = appendIfMissing(grants, apiauth.AuthorizationCodeGrantType)
		responseTypes = appendIfMissing(responseTypes, "code")

		autoApprove := cfg.authorizeAutoApprove
		if autoApprove == "" {
			autoApprove = "e2e-user"
		}
		apiauth.MountAuthorize(mux, apiauth.AuthorizeMountConfig{
			OneAuth:              oa,
			IssuerURL:            issuer,
			EmitIssParameter:     cfg.issParameterSupported != nil && *cfg.issParameterSupported,
			RedirectOverride:     cfg.authorizeRedirectOverride,
			SubjectFromRequest:   func(r *http.Request) string { return "" },
			CSRFTokenFromRequest: func(r *http.Request) string { return "" },
			AutoApproveSubject:   autoApprove,
		})
	}
	apiauth.MountASMetadata(mux, &apiauth.ASServerMetadata{
		Issuer:                        issuer,
		TokenEndpoint:                 baseURL + "/api/token",
		AuthorizationEndpoint:         authorizeEndpoint,
		JWKSURI:                       baseURL + "/.well-known/jwks.json",
		IntrospectionEndpoint:         baseURL + "/oauth/introspect",
		RegistrationEndpoint:          baseURL + "/apps/dcr",
		ScopesSupported:               cfg.scopes,
		ClaimsSupported:               cfg.claimsSupported,
		GrantTypesSupported:           grants,
		ResponseTypesSupported:        responseTypes,
		TokenEndpointAuthMethods:                   []string{"client_secret_post", "client_secret_basic", "private_key_jwt"},
		TokenEndpointAuthSigningAlgValuesSupported: []string{"RS256", "ES256"},
		CodeChallengeMethodsSupported:              pkceMethodsSupported(cfg.allowPlainPKCE),
		AuthorizationResponseIssParameterSupported: cfg.issParameterSupported,
	})

	return &TestAuthServer{
		Server:               server,
		OneAuth:              oa,
		TokenEndpointHandler: tokenEndpoint,
		KeyStore:             ks,
		Registrar:            registrar,
		privateKey:           privKey,
		cfg: config{
			adminKey:     cfg.adminKey,
			issuer:       issuer,
			audience:     cfg.audience,
			audienceFunc: cfg.audienceFunc,
			scopes:       cfg.scopes,
		},
	}, nil
}

// appendIfMissing returns slice with value appended if it is not
// already present. Used by AS-metadata wiring so opt-in options
// (WithAuthorizeEnabled, WithTrustedAssertionIssuers) extend the
// advertised grant / response-type lists without duplicating values
// the caller may have already pinned via WithGrantTypesSupported.
func appendIfMissing(slice []string, value string) []string {
	for _, v := range slice {
		if v == value {
			return slice
		}
	}
	return append(slice, value)
}

// pkceMethodsSupported returns the value to advertise in AS metadata's
// `code_challenge_methods_supported` based on whether the deployment
// opted into OAuth 2.0 plain PKCE. Default is the OAuth 2.1-clean
// ["S256"]; opt-in extends to ["S256", "plain"] per RFC 7636 §4.4.
func pkceMethodsSupported(allowPlain bool) []string {
	if allowPlain {
		return []string{"S256", "plain"}
	}
	return []string{"S256"}
}

// NewTestAuthServer creates an in-process authorization server for tests.
// Cleanup is registered via t.Cleanup — the server is stopped automatically.
func NewTestAuthServer(t *testing.T, opts ...Option) *TestAuthServer {
	t.Helper()
	s, err := NewAuthServer(opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// URL returns the base URL of the test auth server (e.g., "http://127.0.0.1:PORT").
func (s *TestAuthServer) URL() string {
	return s.Server.URL
}

// JWKSURL returns the JWKS endpoint URL.
func (s *TestAuthServer) JWKSURL() string {
	return s.Server.URL + "/.well-known/jwks.json"
}

// TokenEndpoint returns the token endpoint URL.
func (s *TestAuthServer) TokenEndpoint() string {
	return s.Server.URL + "/api/token"
}

// AdminKey returns the admin API key configured for this server.
func (s *TestAuthServer) AdminKey() string {
	return s.cfg.adminKey
}

// Issuer returns the JWT issuer configured for this server.
func (s *TestAuthServer) Issuer() string {
	return s.cfg.issuer
}

// Close stops the underlying HTTP server.
func (s *TestAuthServer) Close() {
	if s.Server != nil {
		s.Server.Close()
	}
}

// MintTokenForSubject creates a valid RS256 JWT for the given subject and scopes.
// The token has iss=server issuer, aud=server audience, exp=15 min.
// Use this in standalone examples that don't have *testing.T.
func (s *TestAuthServer) MintTokenForSubject(subject string, scopes []string) (string, error) {
	claims := jwt.MapClaims{
		"sub": subject,
	}
	if s.cfg.audience != "" {
		claims["aud"] = s.cfg.audience
	}
	if len(scopes) > 0 {
		claims["scope"] = strings.Join(scopes, " ")
	}
	return s.MintTokenWithClaims(claims)
}
