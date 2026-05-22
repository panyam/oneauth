---
package: client
purpose: Client-side OAuth 2.0 SDK for oneauth — credential storage, automatic token refresh, AS discovery, browser/headless login (auth-code+PKCE), client_credentials and private_key_jwt flows, and dynamic client registration.
last_rebuilt: ca8a742623b748f06d2564dce90465d1eeb10c6d
entities:
  - name: AuthClient
    kind: struct
    role: Per-server authenticated HTTP client that owns a CredentialStore and hands out an http.Client whose transport auto-injects bearer tokens and refreshes them.
    why: Holds a single mutex guarding all credential mutations; the OnToken callback fires under that lock, so callbacks must never re-enter AuthClient methods or they deadlock.
  - name: ClientOption
    kind: type (func)
    role: Functional-option configurator for NewAuthClient (token endpoint, HTTP client/transport, pre-cached AS metadata).
    why: WithHTTPClient deliberately copies only timeout/redirect/jar and steals the base transport — it does NOT keep the passed client, because the client's transport gets rewrapped by refreshTransport.
  - name: NewAuthClient
    kind: func
    role: Constructs an AuthClient, normalizing the server URL to scheme://host and substituting a no-op store when store is nil.
    why: A nil store is a supported single-request mode — login methods still return the credential to the caller; only persistence between calls is dropped.
  - name: refreshTransport
    kind: struct
    role: http.RoundTripper that fetches/refreshes the token before each request and retries once on a 401.
    why: Wraps the base transport, but token-acquisition paths (requestToken*) bypass it and use baseTransport directly to avoid an infinite auth loop when fetching the very first token.
  - name: OAuth2TokenRequest / OAuth2TokenResponse
    kind: struct
    role: JSON wire types for the legacy oneauth-specific /auth/cli/token endpoint (password & refresh_token grants).
    why: Distinct from the form-encoded RFC 6749 path; AuthorizationDetails arrives as []any raw JSON and is re-marshalled into typed core.AuthorizationDetail (RFC 9396).
  - name: ServerCredential
    kind: struct
    role: Persisted credential record (tokens, scope, user identity, expiry, RFC 9396 authorization_details) with expiry-check helpers.
    why: IsExpiringSoon drives proactive refresh; callbacks always receive a copy so they cannot mutate stored/cached state.
  - name: CredentialStore
    kind: interface
    role: Pluggable backend for get/set/remove/list credentials plus an explicit Save for batch-writing stores.
    why: GetCredential returns (nil, nil) — not an error — for "no credential", so callers branch on nil rather than error type.
  - name: noopCredentialStore
    kind: struct
    role: Silent CredentialStore used when NewAuthClient gets a nil store.
    why: Lets single-shot login flows work without forcing callers to wire up persistence.
  - name: TokenSource
    kind: interface
    role: Minimal Token() (string, error) producer.
    why: Structurally matches mcpkit/core.TokenSource so no cross-module import is needed to interoperate.
  - name: ScopeAwareTokenSource
    kind: interface
    role: TokenSource plus TokenForScopes for scope step-up.
    why: Step-up invalidates the cache and merges (not replaces) scopes, so privileges only ever widen.
  - name: ClientCredentialsSource
    kind: struct
    role: TokenSource implementation for M2M client_credentials auth with in-memory caching, reactive refresh, and optional proactive background refresh.
    why: Its OnToken fires OUTSIDE the source mutex (unlike AuthClient's), so callbacks may safely call back into Token(); lazily builds an internal AuthClient pointed at the token endpoint.
  - name: ProactiveRefresher
    kind: struct
    role: Bundles refresh policy (Buffer) with goroutine lifecycle state (once/stop/closed).
    why: Background goroutine starts lazily on first Token() and is guarded by sync.Once + a stop channel; Close is idempotent and safe even if Token() was never called.
  - name: ASMetadata
    kind: struct
    role: Parsed RFC 8414 / OIDC Discovery authorization-server metadata.
    why: Carries token_endpoint_auth_methods_supported and code_challenge_methods_supported that drive auth-method negotiation and the mandatory PKCE-S256 capability check.
  - name: DiscoverAS
    kind: func
    role: Fetches AS metadata, trying oauth-authorization-server then openid-configuration well-known URLs (path-aware), with optional caching.
    why: Path-based issuers use the RFC 8414 path-injection layout for the oauth variant but the suffix layout for the OIDC variant — the two well-known schemes disagree, so both forms are tried.
  - name: DiscoveryOption
    kind: type (func)
    role: Options for DiscoverAS (HTTP client, metadata store, cache TTL).
    why: Caching is opt-in via WithASMetadataStore so N token sources sharing one AS trigger one fetch, not N.
  - name: ASMetadataStore
    kind: interface
    role: Concurrency-safe cache of AS metadata keyed by issuer URL.
    why: Positioned as a hot-path optimization shared across token sources; a TTL of 0 on Put means "use store default".
  - name: MemoryASMetadataStore
    kind: struct
    role: In-memory RWMutex-backed ASMetadataStore.
    why: Eviction is lazy-on-Get only (no background goroutine) — acceptable because the keyspace is bounded by the number of distinct issuer URLs.
  - name: TokenEndpointAuthMethod
    kind: type (string)
    role: Enum of token-endpoint client-auth methods (none, client_secret_post, client_secret_basic, private_key_jwt).
    why: Models the RFC 6749 §2.3 / RFC 8414 negotiation vocabulary as typed constants.
  - name: SelectAuthMethod
    kind: func
    role: Picks the auth method from the client secret presence and the AS's advertised methods.
    why: Prefers client_secret_basic over _post (credentials in header are less likely to be logged than in body); falls back to basic for unknown advertised methods rather than failing.
  - name: applyAuthToForm
    kind: func
    role: Writes the right client-auth params into the form for a given method.
    why: For Basic it intentionally writes NOTHING to the form — the caller must additionally call req.SetBasicAuth — to avoid sending credentials in both header and body.
  - name: BrowserLoginConfig
    kind: struct
    role: Configures the auth-code + PKCE loopback flow (endpoints, client id/secret, scopes, resource indicator, browser opener, optional client assertion).
    why: ClientAssertion and ClientSecret are mutually exclusive (assertion wins); explicit endpoints skip discovery but then require TokenEndpointAuthMethods to be supplied or the client wrongly defaults to basic.
  - name: AuthClient.LoginWithBrowser
    kind: method
    role: Runs the full RFC 8252/7636 auth-code+PKCE flow: spin a loopback server, open browser, validate state, exchange code, store credential.
    why: Enforces code_challenge_methods_supported contains S256 ONLY when it discovered the endpoints itself; the callback HTML never echoes untrusted error params (G705/CWE-79) and the loopback server sets ReadHeaderTimeout (Slowloris/CWE-400).
  - name: FollowRedirects
    kind: func
    role: Returns an OpenBrowser substitute that GETs the auth URL via HTTP instead of launching a browser, for headless/CI use.
    why: Only works against auto-approving AS endpoints — it does no form login or cookie/session handling, so it is unsuitable for Keycloak-style interactive login.
  - name: exchangeCodeParams
    kind: struct
    role: Bundles the inputs to the code→token exchange.
    why: Grouped into a struct because the positional signature grew unreadable; new fields are added here rather than appended to the call site.
  - name: ClientAssertionConfig
    kind: struct
    role: Material (private key, signing alg, optional kid, lifetime) for minting private_key_jwt assertions.
    why: Reused across calls but each mint is fresh; Lifetime must be <= 5min to satisfy oneauth's server-side assertion cap (default 60s per OIDC Core §9).
  - name: MintClientAssertion
    kind: func
    role: Produces a signed single-use JWT for client_assertion (RFC 7523 §3 claims).
    why: Each call generates a fresh random jti/iat/exp so assertions are single-use; aud is the token-endpoint URL (or AS issuer), which oneauth's authenticator accepts either way.
  - name: applyAssertionToForm
    kind: func
    role: Attaches client_assertion + client_assertion_type + client_id to the form.
    why: Sets client_id even though it duplicates the assertion iss, because some IdPs require it.
  - name: ClientRegistrationRequest / ClientRegistrationResponse
    kind: struct
    role: RFC 7591 DCR request and response, the latter extended with RFC 7592 §3 management credentials (registration_access_token, registration_client_uri).
    why: One request type serves both register and update; on update client_id MUST match the existing identifier or the AS returns 400.
  - name: RegisterClient
    kind: func
    role: Performs RFC 7591 dynamic client registration via POST.
    why: Pre-convention positional signature kept as-is (conversion to the ctx/req shape tracked under issue 175) while the 7592 management calls already follow the new shape.
  - name: GetRegistration / UpdateRegistration / DeleteRegistration
    kind: func
    role: RFC 7592 §2.1/2.2/2.3 registration management calls following the (ctx, *Req) → (*Resp, error) gRPC-shape convention.
    why: HTTPClient lives on the request struct (analog of a gRPC CallOption) to keep the two-arg signature; UpdateRegistration rotates the access token and callers MUST persist the new one before discarding the old.
  - name: ErrRegistrationUnauthorized
    kind: var (error)
    role: Sentinel for any RFC 7592 401 (wrong/missing token or unknown client_id).
    why: The RFC collapses all auth failures to 401, so this sentinel deliberately cannot distinguish the underlying cause.
  - name: AuthTransport
    kind: struct
    role: Simple static-token http.RoundTripper that injects a fixed bearer header.
    why: The non-refreshing counterpart to refreshTransport, for callers who already hold a token; clones the request to avoid mutating the original.
  - name: ValidateHTTPS
    kind: func
    role: Asserts AS authorization/token endpoints use HTTPS, exempting loopback hosts.
    why: Localhost exemption (RFC 8252 §8.3) is what lets dev/test servers run over plain HTTP.
  - name: ValidateCIMDURL
    kind: func
    role: Validates a Client ID Metadata Document URL (HTTPS + non-root path).
    why: A root/empty path is rejected because a CIMD URL must identify a specific document, not an origin.
depends_on:
  - folder: core
    entities: [AuthorizationDetail, TokenSource, UnionScopes]
  - folder: utils
    entities: [SigningMethodForAlg]
---

The package is organized around `AuthClient` (one per server) which composes a pluggable `CredentialStore` and exposes an `*http.Client` whose `refreshTransport` transparently injects and refreshes bearer tokens. Token acquisition has two distinct code paths: a legacy JSON path (`requestToken`) hitting the oneauth-specific `/auth/cli/token` endpoint for password/refresh grants, and a standards-compliant form-encoded path (`requestTokenForm` / `executeTokenRequest`) for `client_credentials`, auth-code exchange, and `private_key_jwt`. All acquisition paths use the base transport directly to avoid recursing through the auth-injecting transport.

Two callback contracts deliberately differ and are the main footgun: `AuthClient.OnToken` fires while the internal mutex is held (callbacks must not re-enter), whereas `ClientCredentialsSource.OnToken` fires outside its mutex (re-entry safe). Both pass a copy of the credential.

Auth-method negotiation (`SelectAuthMethod` + `applyAuthToForm` + the `private_key_jwt` helpers in `private_key_jwt.go`) is shared between the browser/auth-code flow and the client_credentials flow, and is the reason `BrowserLoginConfig.TokenEndpointAuthMethods` exists — it lets callers who skip discovery still negotiate correctly.

`DiscoverAS` plus the `ASMetadataStore`/`MemoryASMetadataStore` caching layer exist to collapse redundant well-known fetches when many token sources share one AS. `validation.go` (HTTPS / CIMD checks) and `transport.go` (`AuthTransport`, the static-token sibling of the refresh transport) are standalone utilities with no dependency on `AuthClient`.
