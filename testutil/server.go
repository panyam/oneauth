package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
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
//	POST /apps/register                       — app registration
//	POST /apps/dcr                            — dynamic client registration (RFC 7591)
type TestAuthServer struct {
	// Server is the underlying httptest.Server. Use URL() for the base URL.
	Server *httptest.Server

	// APIAuth is the configured API authentication handler (RS256).
	APIAuth *apiauth.APIAuth

	// KeyStore holds the server's RSA key and any registered app keys.
	KeyStore keys.KeyStorage

	// Registrar manages app registrations and serves the /apps/ endpoints.
	Registrar *admin.AppRegistrar

	privateKey *rsa.PrivateKey
	cfg        config
}

// config holds TestAuthServer configuration set via functional options.
type config struct {
	adminKey string
	issuer   string
	audience string
	scopes   []string
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

// WithScopes sets the scopes_supported field in AS metadata.
// Default: ["read", "write", "admin"].
func WithScopes(scopes []string) Option {
	return func(c *config) { c.scopes = scopes }
}

// NewTestAuthServer creates and starts an in-process authorization server
// with an RSA 2048 key pair. The server is automatically shut down via
// t.Cleanup when the test completes.
//
// The server signs JWTs with RS256 and serves the public key via JWKS.
// Apps can be registered via /apps/register or /apps/dcr (RFC 7591),
// and tokens can be obtained via /api/token (client_credentials grant).
// NewAuthServer creates an in-process OAuth authorization server without
// requiring *testing.T. Use this in standalone examples, benchmarks, or
// any non-test context. The caller must call Close() when done.
//
// For test code, prefer NewTestAuthServer which auto-registers cleanup.
func NewAuthServer(opts ...Option) (*TestAuthServer, error) {
	cfg := config{
		adminKey: defaultAdminKey,
		issuer:   defaultIssuer,
		scopes:   []string{"read", "write", "admin"},
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
	if err := ks.PutKey(&keys.KeyRecord{
		ClientID:  cfg.issuer,
		Key:       pubPEM,
		Algorithm: "RS256",
		Kid:       kid,
	}); err != nil {
		return nil, fmt.Errorf("testutil: failed to store RSA key: %w", err)
	}

	registrar := admin.NewAppRegistrar(ks, admin.NewAPIKeyAuth(cfg.adminKey))

	apiAuth := &apiauth.APIAuth{
		JWTSigningAlg:  "RS256",
		JWTSigningKey:  privKey,
		JWTVerifyKey:   &privKey.PublicKey,
		JWTIssuer:      cfg.issuer,
		JWTAudience:    cfg.audience,
		ClientKeyStore: ks,
	}

	introspection := apiauth.NewIntrospectionHandler(apiAuth, ks)

	jwksHandler := &keys.JWKSHandler{KeyStore: ks}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /_ah/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("POST /api/token", apiAuth.ServeHTTP)
	mux.Handle("POST /oauth/introspect", introspection)
	mux.HandleFunc("GET /.well-known/jwks.json", jwksHandler.ServeHTTP)
	mux.Handle("/apps/", httpauth.LimitBody(httpauth.DefaultMaxBodySize)(registrar.Handler()))
	mux.Handle("/apps", httpauth.LimitBody(httpauth.DefaultMaxBodySize)(registrar.Handler()))

	server := httptest.NewServer(mux)

	baseURL := server.URL
	issuer := cfg.issuer
	if issuer == defaultIssuer {
		issuer = baseURL
		apiAuth.JWTIssuer = issuer
	}
	asMetaHandler := apiauth.NewASMetadataHandler(&apiauth.ASServerMetadata{
		Issuer:                        issuer,
		TokenEndpoint:                 baseURL + "/api/token",
		JWKSURI:                       baseURL + "/.well-known/jwks.json",
		IntrospectionEndpoint:         baseURL + "/oauth/introspect",
		RegistrationEndpoint:          baseURL + "/apps/register",
		ScopesSupported:               cfg.scopes,
		GrantTypesSupported:           []string{"client_credentials"},
		ResponseTypesSupported:        []string{"token"},
		TokenEndpointAuthMethods:      []string{"client_secret_post", "client_secret_basic"},
		CodeChallengeMethodsSupported: []string{"S256"},
	})
	mux.Handle("GET /.well-known/openid-configuration", asMetaHandler)

	return &TestAuthServer{
		Server:     server,
		APIAuth:    apiAuth,
		KeyStore:   ks,
		Registrar:  registrar,
		privateKey: privKey,
		cfg: config{
			adminKey: cfg.adminKey,
			issuer:   issuer,
			audience: cfg.audience,
			scopes:   cfg.scopes,
		},
	}, nil
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
