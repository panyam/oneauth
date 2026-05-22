// Package client is the client-side OAuth SDK for oneauth: AS discovery,
// browser/PKCE login, client-credentials and private_key_jwt token
// acquisition with caching/refresh, dynamic client registration, and an
// auth-injecting HTTP transport.
//
// <!-- design:start -->
// This package is what an application embeds to talk to an OAuth
// authorization server (AS): it discovers the AS's endpoints, drives the
// login flows that obtain tokens, caches and refreshes those tokens, and
// hands back an http.Client that injects them. It owns no server-side
// logic — every type here is a caller of remote endpoints. The central
// type is AuthClient, bound to a single server URL and a CredentialStore;
// around it sit a token-source abstraction for machine-to-machine auth, a
// discovery layer with an optional shared metadata cache, the RFC 7591/7592
// dynamic-registration helpers, and small auth-method / validation
// utilities. The gRPC-shape convention (issue 169) governs the registration
// management calls — GetRegistration / UpdateRegistration /
// DeleteRegistration all take (ctx, *Request) and return (*Response, error);
// RegisterClient predates the convention and stays as a plain HTTP helper
// (issue 175). A recurring constraint: initial token requests use the bare
// base transport rather than the auth-wrapping refreshTransport, to avoid a
// circular dependency where fetching a token would itself need a token.
//
// # ENTITIES
//
// AuthClient — HTTP client bound to one server URL with automatic token
// storage, refresh, and login flows; mutex-guarded, so OnToken callbacks
// must not re-enter its methods or they deadlock.
//
// NewAuthClient — constructs an AuthClient, normalizing the server URL and
// wrapping the base transport with refreshTransport; a nil store becomes a
// noop store so single-shot login flows work without persistence.
//
// ClientOption — functional option for AuthClient (WithTokenEndpoint,
// WithHTTPClient, WithTransport, WithASMetadata); WithASMetadata pre-seeds
// discovery so auth-method negotiation needs no extra fetch.
//
// ClientCredentialsToken — RFC 6749 §4.4 machine-to-machine grant;
// negotiates the auth method and posts form-encoded credentials via the
// base transport to dodge the auth loop.
//
// ClientCredentialsTokenWithAssertion — private_key_jwt variant of the
// client-credentials grant; mints a fresh signed assertion per call with the
// token endpoint URL as audience.
//
// LoginWithBrowser — authorization-code + PKCE flow (RFC 8252) using a
// loopback redirect server, a state CSRF check, and code exchange; enforces
// S256 support only when it performed discovery itself.
//
// BrowserLoginConfig — inputs to LoginWithBrowser; ClientAssertion and
// ClientSecret are mutually exclusive and assertion wins, switching the
// exchange to private_key_jwt.
//
// FollowRedirects — OpenBrowser replacement that GETs the authorization URL
// for headless/CI flows; works only with auto-approving AS endpoints, not
// form-login servers like Keycloak.
//
// ClientCredentialsSource — TokenSource implementing cached
// client-credentials acquisition with reactive plus optional proactive
// (background goroutine) refresh and scope step-up; OnToken fires outside the
// mutex so callbacks may safely re-enter Token().
//
// ProactiveRefresher — bundles the pre-expiry refresh Buffer with the
// background goroutine lifecycle; the goroutine starts lazily on first
// Token() and must be stopped via Close(), which guards against double-close.
//
// TokenSource — single Token() method matching mcpkit/core.TokenSource by
// structural typing, avoiding a cross-module import.
//
// ScopeAwareTokenSource — TokenSource plus TokenForScopes; merging scopes
// invalidates the cache and re-fetches with the union.
//
// ServerCredential — stored auth material for one server (access/refresh
// tokens, expiry, scope, RFC 9396 authorization_details); IsExpiringSoon
// drives proactive refresh.
//
// CredentialStore — pluggable persistence for ServerCredentials keyed by
// server URL; Save() is separate so batching backends can defer writes.
//
// DiscoverAS — fetches AS metadata trying RFC 8414 + OIDC well-known URLs in
// order, with optional caching; handles path-based (multi-tenant) issuers by
// trying both well-known layouts.
//
// ASMetadata — parsed RFC 8414 / OIDC discovery document;
// token_endpoint_auth_methods_supported feeds SelectAuthMethod and
// CodeChallengeMethodsSupported gates PKCE.
//
// DiscoveryOption — functional option for DiscoverAS
// (WithHTTPClientForDiscovery, WithASMetadataStore, WithASCacheTTL); caching
// is opt-in.
//
// ASMetadataStore — concurrency-safe Get/Put cache of AS metadata by issuer,
// shared across token sources so N resource servers on one AS trigger one
// fetch instead of N.
//
// MemoryASMetadataStore — in-memory RWMutex-backed store with lazy TTL
// eviction and no background eviction goroutine.
//
// SelectAuthMethod — picks the token-endpoint auth method from the client
// secret and AS-advertised methods, preferring client_secret_basic (creds in
// header, less likely logged) and defaulting to it for unknown/empty sets.
//
// TokenEndpointAuthMethod — named string for RFC 6749 §2.3 auth methods;
// drives applyAuthToForm, where Basic intentionally omits creds from the form
// body (set via SetBasicAuth instead).
//
// ClientAssertionConfig — signing material (key, alg, kid, lifetime) for
// private_key_jwt assertions; lifetime must be ≤ 5min for OneAuth's
// server-side cap and defaults to 60s.
//
// MintClientAssertion — produces a single-use signed JWT (RFC 7523 §3 / OIDC
// Core §9 claims) for the client_assertion parameter; fresh jti/iat/exp per
// call enforce single-use.
//
// AuthMethodPrivateKeyJWT — TokenEndpointAuthMethod value for
// private_key_jwt, the strongest standard method (no shared secret).
//
// RegisterClient — RFC 7591 Dynamic Client Registration POST returning the
// assigned client_id/secret plus RFC 7592 management credentials; kept in the
// pre-convention HTTP shape.
//
// GetRegistration — RFC 7592 §2.1 read via (ctx, req); maps 401 to
// ErrRegistrationUnauthorized for errors.Is branching.
//
// UpdateRegistration — RFC 7592 §2.2 full-replace update; auto-fills
// client_id and surfaces the rotated registration_access_token, which callers
// MUST persist before discarding the old one.
//
// DeleteRegistration — RFC 7592 §2.3 deletion (204 → success); afterward,
// tokens already issued under the client_id fail validation.
//
// ClientRegistrationRequest — RFC 7591 register / RFC 7592 update body;
// ClientID is unused on register but must match on update.
//
// ClientRegistrationResponse — parsed DCR response plus RFC 7592 §3
// management credentials, the inputs to subsequent management calls.
//
// ErrRegistrationUnauthorized — sentinel for any RFC 7592 401; per spec the
// AS uses 401 for wrong/missing token and unknown client_id alike, so callers
// cannot distinguish them.
//
// AuthTransport — http.RoundTripper that adds a static Bearer token, cloning
// the request before mutating it.
//
// ValidateHTTPS — asserts AS authorization/token endpoints use HTTPS, with a
// localhost exemption (RFC 6749 §3.1.2.1).
//
// ValidateCIMDURL — validates a Client ID Metadata Document URL (HTTPS plus a
// non-root path) per draft-parecki CIMD.
//
// IsLocalhost — shared loopback-host predicate used for the HTTPS exemption
// (RFC 8252 §8.3).
//
// # FLOWS
//
// See diagrams.md for: AS discovery with shared caching; client-credentials
// token acquisition with reactive + proactive refresh; and the browser/PKCE
// authorization-code login.
// <!-- design:end -->
package client
