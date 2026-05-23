// Package client is the client-side OAuth SDK for oneauth: AS discovery,
// browser/PKCE login, client-credentials and private_key_jwt token
// acquisition with caching and refresh, dynamic client registration, and
// an auth-injecting HTTP transport.
//
// This package is what an application embeds to talk to an OAuth
// authorization server: it discovers the AS's endpoints, drives the login
// flows that obtain tokens, caches and refreshes those tokens, and hands
// back an http.Client that injects them. It owns no server-side logic —
// every type here is a caller of remote endpoints. The central type is
// AuthClient, bound to a single server URL and a CredentialStore; around
// it sit a TokenSource abstraction for machine-to-machine auth, a
// discovery layer with an optional shared metadata cache, the RFC 7591
// and RFC 7592 dynamic-registration helpers, and small auth-method and
// validation utilities. A recurring constraint: initial token requests
// use the bare base transport rather than the auth-wrapping
// refreshTransport, to avoid a circular dependency where fetching a token
// would itself need a token.
//
// ENTITIES
//
// AuthClient — HTTP client bound to one server URL with automatic token
// storage, refresh, and login flows. Central type wiring CredentialStore,
// auth-injecting transport, and token-endpoint calls together.
//
// NewAuthClient — constructs an AuthClient, normalizing the server URL
// and wrapping the base transport with refreshTransport. A nil store
// becomes a no-op store so single-shot login flows work without
// persistence.
//
// ClientOption — functional option for AuthClient. Enables
// WithTokenEndpoint, WithHTTPClient, WithTransport, and WithASMetadata
// without expanding the constructor signature.
//
// WithTokenEndpoint — sets a custom token endpoint path on AuthClient.
// Lets callers point at non-default token URLs.
//
// WithHTTPClient — copies timeout, redirect, and jar from a user-supplied
// http.Client and adopts its transport. Preserves user TLS, timeout, and
// cookie configuration while still wrapping for auth.
//
// WithTransport — sets a custom base http.RoundTripper on AuthClient.
// Permits connection pooling, proxies, and test fakes without going
// through an http.Client.
//
// WithASMetadata — pre-populates cached AS discovery metadata on
// AuthClient. Lets ClientCredentialsToken negotiate the auth method
// without a separate discovery fetch.
//
// AuthClient.HTTPClient — returns the underlying http.Client with auth
// handling wired in. Application code uses this client for all
// authenticated requests.
//
// AuthClient.ServerURL — returns the normalized server URL this client
// is bound to. Lets callers key external state by the same canonical URL.
//
// AuthClient.GetToken — returns the current access token, refreshing
// proactively when within RefreshThreshold of expiry. Hot path called by
// refreshTransport before every authenticated request.
//
// AuthClient.GetCredential — returns the stored ServerCredential for
// this server. Exposes refresh tokens, scopes, and authorization_details
// to callers needing more than the access token.
//
// AuthClient.Login — performs the password grant via JSON to the
// oneauth-specific /auth/cli/token endpoint. Legacy first-party path used
// by oneauth's own CLI; persists the credential on success.
//
// AuthClient.ClientCredentialsToken — executes RFC 6749 §4.4
// machine-to-machine grant with negotiated auth method. Posts
// form-encoded credentials via the bare base transport to dodge the auth
// loop.
//
// AuthClient.ClientCredentialsTokenWithAssertion — variant of
// ClientCredentialsToken using private_key_jwt instead of a shared
// secret. Mints a fresh signed assertion per call with the token
// endpoint URL as audience.
//
// AuthClient.LoginWithBrowser — RFC 8252 authorization-code + PKCE flow
// with loopback redirect, CSRF state check, and code exchange. Standard
// interactive login for CLI and headless clients; enforces PKCE S256
// when discovery is used.
//
// AuthClient.Logout — removes the credential for this server and saves
// the store. Single deterministic cleanup for the bound server URL.
//
// AuthClient.IsLoggedIn — reports whether a non-expired credential
// exists in the store. Quick gate without forcing a refresh attempt.
//
// AuthClient.OnToken — optional callback fired after a successful
// refresh_token grant. Runs under the client mutex so the callback must
// not re-enter AuthClient methods or it deadlocks.
//
// OAuth2TokenRequest — JSON body for the legacy /auth/cli/token
// endpoint. Carries grant_type plus the per-grant fields (password,
// refresh_token, code, code_verifier).
//
// OAuth2TokenResponse — parsed token response shared between JSON and
// form-encoded paths. Holds access/refresh tokens, expires_in, scope,
// RFC 9396 authorization_details, and error fields.
//
// RefreshThreshold — how long before expiry GetToken triggers a
// proactive refresh. Five minutes balances staleness against
// unnecessary refresh chatter.
//
// BrowserLoginConfig — inputs to LoginWithBrowser: endpoints, client
// identity, scopes, callback port, timeout, headless overrides.
// ClientAssertion and ClientSecret are mutually exclusive; assertion
// wins and switches the exchange to private_key_jwt.
//
// FollowRedirects — OpenBrowser replacement that GETs the authorization
// URL for headless or CI flows. Works only with auto-approving AS
// endpoints, not form-login servers like Keycloak.
//
// ClientCredentialsSource — TokenSource that caches client_credentials
// access tokens and refreshes them on demand or in the background.
// OnToken fires outside the source mutex so callbacks may safely
// re-enter Token without deadlock.
//
// ClientCredentialsSource.Token — returns a cached access token or
// fetches one via client_credentials. Starts the background refresh
// goroutine lazily on first call when Refresher.Buffer is positive.
//
// ClientCredentialsSource.TokenForScopes — invalidates the cache,
// unions the requested scopes with existing ones, and fetches a fresh
// token. Implements scope step-up for callers needing additional scopes
// mid-session.
//
// ClientCredentialsSource.Close — stops the background refresh
// goroutine, idempotent. io.Closer compliance; safe to call even if
// Token was never invoked.
//
// ProactiveRefresher — bundles the pre-expiry refresh Buffer with the
// background goroutine lifecycle state. Goroutine starts lazily and is
// stopped via the source's Close; double-close is guarded.
//
// TokenSource — single Token method that returns a current access token
// or error. Structurally matches mcpkit/core.TokenSource so callers
// avoid a cross-module import.
//
// ScopeAwareTokenSource — TokenSource plus TokenForScopes for scope
// step-up. Callers needing additional scopes can detect support via
// type assertion.
//
// ServerCredential — stored auth material for one server: access and
// refresh tokens, expiry, scope, RFC 9396 authorization_details. Single
// shape persisted by CredentialStore and returned by every login path.
//
// ServerCredential.IsExpired — reports whether the access token's
// expires_at is already in the past. Cheap gate used by IsLoggedIn and
// GetToken.
//
// ServerCredential.IsExpiringSoon — reports whether the token expires
// within a caller-supplied window. Drives proactive refresh inside
// GetToken via RefreshThreshold.
//
// ServerCredential.HasRefreshToken — reports whether a refresh token is
// set. Determines whether the auto-refresh code path is viable.
//
// CredentialStore — pluggable persistence for ServerCredentials keyed
// by server URL. Save is separate from SetCredential so batching
// backends can defer writes.
//
// DiscoverAS — fetches AS metadata by trying RFC 8414 and OIDC
// well-known URLs in order. Handles path-based multi-tenant issuers by
// trying both well-known layouts; supports an optional shared cache.
//
// ASMetadata — parsed RFC 8414 / OIDC discovery document.
// token_endpoint_auth_methods_supported drives SelectAuthMethod;
// CodeChallengeMethodsSupported gates PKCE.
//
// DiscoveryOption — functional option for DiscoverAS.
// WithHTTPClientForDiscovery, WithASMetadataStore, and WithASCacheTTL
// keep the public signature stable.
//
// WithHTTPClientForDiscovery — injects a custom http.Client for the
// discovery request. Required for httptest fixtures and custom TLS
// roots.
//
// WithASMetadataStore — enables caching of discovered metadata via an
// ASMetadataStore. One shared store across N token sources collapses N
// discovery fetches into one per issuer.
//
// WithASCacheTTL — sets a custom TTL for cache writes during discovery.
// Lets callers tune freshness against fetch frequency per call site.
//
// ASMetadataStore — concurrency-safe Get/Put cache of AS metadata by
// issuer. Shared across token sources so N resource servers on one AS
// trigger one fetch instead of N.
//
// MemoryASMetadataStore — in-memory RWMutex-backed ASMetadataStore with
// lazy TTL eviction. Suitable for single-process deployments; no
// background eviction goroutine to manage.
//
// NewMemoryASMetadataStore — constructs a MemoryASMetadataStore with
// the given default TTL. Zero TTL collapses to DefaultASCacheTTL (1
// hour).
//
// DefaultASCacheTTL — one-hour default TTL for cached AS metadata
// entries. Metadata rotates rarely; one hour balances freshness against
// redundant fetches.
//
// SelectAuthMethod — picks the token-endpoint auth method from the
// client secret and AS-advertised methods. Prefers client_secret_basic
// (creds in header, less likely logged); defaults to it for empty or
// unknown sets.
//
// TokenEndpointAuthMethod — named string for RFC 6749 §2.3 auth methods.
// Drives applyAuthToForm where Basic intentionally omits creds from the
// form body.
//
// ClientAssertionConfig — signing material (key, alg, kid, lifetime)
// for private_key_jwt assertions. Lifetime must be at most 5 minutes for
// OneAuth's server-side cap; defaults to 60s.
//
// MintClientAssertion — produces a single-use signed JWT (RFC 7523 §3
// and OIDC Core §9 claims) for client_assertion. Fresh jti, iat, and
// exp per call enforce single-use; supports RS256 and ES256.
//
// AuthMethodPrivateKeyJWT — TokenEndpointAuthMethod value for
// private_key_jwt. Strongest standard method — no shared secret to leak.
//
// DefaultClientAssertionLifetime — 60-second default lifetime for
// minted client assertions. Matches OIDC Core §9 short-lived
// recommendation and FAPI guidance.
//
// RegisterClient — RFC 7591 Dynamic Client Registration POST returning
// the assigned client_id/secret plus RFC 7592 management credentials.
// Kept in the pre-convention HTTP shape until migration to (ctx,
// *Request).
//
// GetRegistration — RFC 7592 §2.1 read via (ctx, *Request). Maps 401 to
// ErrRegistrationUnauthorized so callers can branch on errors.Is.
//
// UpdateRegistration — RFC 7592 §2.2 full-replace update. Auto-fills
// client_id and surfaces the rotated registration_access_token; callers
// MUST persist the new token before discarding the old one.
//
// DeleteRegistration — RFC 7592 §2.3 deletion (204 means success).
// After success, tokens already issued under the client_id fail
// validation.
//
// ClientRegistrationRequest — RFC 7591 register / RFC 7592 update body.
// ClientID is unused on register but must match on update.
//
// ClientRegistrationResponse — parsed DCR response plus RFC 7592 §3
// management credentials. Carries the inputs to subsequent management
// calls (URI plus access token).
//
// GetRegistrationRequest — inputs to GetRegistration: URI, token,
// optional HTTPClient. HTTPClient lives on the request so the method
// keeps a strict (ctx, req) shape.
//
// GetRegistrationResponse — wraps the parsed registration metadata.
// Wrapped (not bare) for symmetry with the server-side manager and
// forward-compat headroom.
//
// UpdateRegistrationRequest — inputs to UpdateRegistration: URI, token,
// ClientID, Metadata, optional HTTPClient. SDK auto-fills
// Metadata.ClientID if the caller omits it.
//
// UpdateRegistrationResponse — wraps the post-update registration
// including the rotated access token. Caller MUST persist the new token
// before discarding the old one.
//
// DeleteRegistrationRequest — inputs to DeleteRegistration: URI, token,
// optional HTTPClient. Same transport-option shape as the other
// management calls.
//
// DeleteRegistrationResponse — empty response wrapper for
// DeleteRegistration. Preserves the (ctx, *Req) convention and leaves
// room for future fields.
//
// ErrRegistrationUnauthorized — sentinel error for any RFC 7592 401.
// Per spec the AS uses 401 for wrong or missing token and unknown
// client_id alike — callers cannot distinguish.
//
// AuthTransport — http.RoundTripper that adds a static Bearer token to
// outgoing requests. Clones the request before mutating headers so it
// never affects the caller's original.
//
// NewAuthTransport — constructs an AuthTransport wrapping
// http.DefaultTransport. Convenience for the common single-token case.
//
// NewAuthTransportWithBase — constructs an AuthTransport with a
// caller-supplied base transport. Lets the token-injecting layer
// compose with other RoundTrippers (logging, retries).
//
// ValidateHTTPS — asserts AS authorization and token endpoints use
// HTTPS. Localhost exemption per RFC 6749 §3.1.2.1 keeps local
// development viable.
//
// ValidateCIMDURL — validates a Client ID Metadata Document URL (HTTPS
// plus non-root path) per draft-parecki CIMD. Surfaces malformed CIMDs
// before they fail at the AS with a less actionable error.
//
// IsLocalhost — loopback-host predicate covering localhost, 127.0.0.1,
// and ::1. Shared exemption helper for HTTPS enforcement (RFC 8252
// §8.3).
//
// FLOWS
//
// See diagrams.md for sequence diagrams of: AS discovery with shared
// caching; client-credentials token acquisition with reactive plus
// proactive refresh; and the browser PKCE authorization-code login.
package client
