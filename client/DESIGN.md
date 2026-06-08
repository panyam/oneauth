# client

Go SDK for talking to an OAuth 2.0 / OIDC authorization server. Owns server discovery (RFC 8414 + OIDC Discovery), the login shapes a real client needs (browser + PKCE, machine-to-machine `client_credentials`, RFC 8693 token exchange, RFC 7523 jwt-bearer, and the legacy username/password JSON path), token caching with refresh-on-expiry, transparent `Authorization: Bearer` injection into outbound HTTP, dynamic client registration management (RFC 7591/7592), and the helper types (`TokenSource`, `ClientCredentialsSource`) that mcpkit-style consumers plug into.

The package deliberately doesn't own credential persistence (that's `CredentialStore` implementations in `client/stores/`), AS-side issuance (that lives in `apiauth/`), or anything HS256 / introspection / revocation related — those are server concerns. It also doesn't try to be a full OIDC RP: there's no ID-token validation, userinfo, or session state. It's the client side of the token endpoint plus the minimum dance to get there. Issue #217 consolidated the public methods onto the `MethodName(ctx, *XRequest) → (..., error)` convention; `ClientCredentialsToken` / `ClientCredentialsTokenWithAssertion` survive as 3-line deprecated shims.

## Contents

- [Entities](#entities)
- [Flows](#flows)
  - [Browser login (auth code + PKCE)](#browser-login-auth-code--pkce)
  - [ClientCredentialsSource cached token with proactive refresh](#clientcredentialssource-cached-token-with-proactive-refresh)
  - [ClientCredentials with private_key_jwt](#clientcredentials-with-private_key_jwt)
  - [Dynamic client registration (DCR)](#dynamic-client-registration-dcr)
- [Gotchas](#gotchas)
- [Depends on](#depends-on)

## Entities

| Entity | Kind | Role | Why |
|---|---|---|---|
| `AuthClient` | struct | HTTP client bound to one server URL with automatic token storage, refresh, and login flows. | Central type that wires `CredentialStore`, the auth-injecting transport, and token-endpoint calls. |
| `NewAuthClient` | func | Constructs an `AuthClient`, normalizing the server URL and wrapping the base transport with `refreshTransport`. | A nil store becomes a no-op store so single-shot login flows work without persistence. |
| `ClientOption` | type | Functional option for `AuthClient`. | Enables `WithTokenEndpoint`, `WithHTTPClient`, `WithTransport`, `WithASMetadata` without expanding the constructor. |
| `WithTokenEndpoint` | func | Overrides the default `/auth/cli/token` path. | Lets callers point at non-default token URLs (e.g. `/oauth/token`). |
| `WithHTTPClient` | func | Adopts a user `*http.Client`'s transport plus timeout / redirect / jar. | Preserves TLS, timeout, and cookie configuration while still wrapping for auth. |
| `WithTransport` | func | Sets a custom base `http.RoundTripper`. | Lets callers plug in pools, proxies, or test transports without losing auth wrapping. |
| `WithASMetadata` | func | Pre-populates cached AS discovery metadata. | Skips a redundant discovery round-trip and feeds `SelectAuthMethod`. |
| `AuthClient.HTTPClient` | method | Returns the auth-injecting `*http.Client`. | Drop-in `*http.Client`; Bearer header and refresh are transparent. |
| `AuthClient.ServerURL` | method | Returns the normalized server URL. | Used as the `CredentialStore` key — exposed for diagnostics. |
| `AuthClient.GetToken` | method | Returns the current access token, refreshing if within `RefreshThreshold`. | Single read path used by `refreshTransport` before every request. |
| `AuthClient.GetCredential` | method | Returns the raw stored `ServerCredential`. | Lets callers inspect refresh token, scope, expiry, or RFC 9396 details. |
| `LoginRequest` | struct | Input to `AuthClient.Login` — username, password, scope, optional `ClientID` (defaults to `"cli"`). | gRPC-shape request struct so password grant inputs can gain fields without breaking the call signature. |
| `AuthClient.Login` | method | OAuth `password` grant against the legacy JSON `/auth/cli/token` endpoint; ctx-shaped (#217). | First-party username/password login for OneAuth's own server. |
| `ClientCredentialsRequest` | struct | Inputs to `ClientCredentials` — clientID, secret or assertion, scopes, RFC 8707 resources, RFC 9396 `authorization_details`. | One struct gathers every §4.4 parameter; legacy wrappers reduce to 3-line shims. |
| `AuthClient.ClientCredentials` | method | RFC 6749 §4.4 grant — negotiates `client_secret_basic` / `client_secret_post` / `private_key_jwt`, emits RFC 8707 `resource` and RFC 9396 `authorization_details`, persists the credential. | Single chokepoint for §4.4 so client-auth negotiation and standards extensions live in one place. |
| `AuthClient.ClientCredentialsToken` | method | Deprecated compat wrapper — 3-line shim that calls `ClientCredentials` with `context.Background()`. | Keeps pre-#217 callers compiling while #169 funnels new code through the request-struct method. |
| `AuthClient.ClientCredentialsTokenWithAssertion` | method | Deprecated compat wrapper — `private_key_jwt` shim that calls `ClientCredentials` with `context.Background()`. | Same rationale as `ClientCredentialsToken`. |
| `AuthClient.LoginWithBrowser` | method | RFC 8252 + RFC 7636 auth-code-with-PKCE flow with loopback callback; ctx-shaped (#217). | CLI/headless apps still need user-context tokens. |
| `BrowserLoginRequest` | struct | All inputs to `LoginWithBrowser`. | Renamed from `BrowserLoginConfig` in #217 to match the (ctx, *XRequest) convention. |
| `AuthClient.Logout` | method | Removes the credential for this server and persists. | Local logout — no server-side revocation implied. |
| `AuthClient.IsLoggedIn` | method | Reports whether a non-expired credential exists. | Cheap UI/CLI check that doesn't trigger a refresh. |
| `AuthClient.OnToken` | field | Callback fired after a successful `refresh_token` grant. | External persistence + metrics hook; only the auto-refresh path fires it. |
| `TokenExchangeGrantType` | const | RFC 8693 grant_type URN. | One place owns the spec literal so the form value can't drift. |
| `TokenExchangeRequest` | struct | Inputs to RFC 8693 token exchange — subject token + type (required), optional actor token, audience, resource, scope, plus client auth. | Captures every §2.1 parameter behind one ctx-shaped method. |
| `TokenExchangeResponse` | struct | Parsed RFC 8693 §2.2 response — `issued_token_type` plus scope as a slice. | Promotes the wire string into a Go-friendly slice. |
| `rawTokenExchangeResponse` | struct | Wire-shape mirror of `TokenExchangeResponse`. | Keeps space-delimited scope decoding internal. |
| `AuthClient.TokenExchange` | method | Performs an RFC 8693 token exchange; does not persist (it's a fan-out grant). | Delegation flows need exchange without polluting the cached refresh-token state. |
| `JwtBearerGrantType` | const | RFC 7523 §2.1 grant_type URN. | Distinct from the `private_key_jwt` CLIENT auth method — both coexist in one form. |
| `JwtBearerGrantRequest` | struct | Inputs to RFC 7523 §2.1 — bearer `Assertion`, optional scope/resources, plus client auth. | Trusted-IdP token bridge; ctx-shaped for cancellation. |
| `AuthClient.JwtBearerGrant` | method | RFC 7523 §2.1 jwt-bearer grant exchange returning a `ServerCredential`. | Lets a client present a third-party JWT as the authorization grant. |
| `AuthClient.buildTokenRequest` | method | Builds the form-encoded token-endpoint POST with negotiated client auth; shared by `TokenExchange` + `JwtBearerGrant`. | Same form/auth shape but shape-specific response decoding, so only the request side is dedup-able. |
| `refreshTransport` | struct | `RoundTripper` that fetches the token, sets Bearer, and retries once on 401 after refresh. | Makes auth invisible to callers. |
| `AuthClient.refreshTokenLocked` | method | Exchanges the stored refresh token for a new credential and persists it. | Single chokepoint for refresh — keeps lock contract and `OnToken` ordering consistent. |
| `RefreshTokenRequest` | struct | Caller-supplied inputs to `RefreshToken` — clientID, optional secret, refresh_token, optional scope subset. | Mirrors the `ClientCredentialsRequest` shape so the two grant entry points feel symmetric. |
| `AuthClient.RefreshToken` | method | RFC 6749 §6 refresh_token grant against the AS-discovered token endpoint (form-encoded). Distinct from `refreshTokenLocked`. | Standards-compliant entry point used by `cmd/oneauth token refresh`; works against any RFC 8414 / OIDC AS, not just oneauth's own. |
| `AuthClient.requestToken` | method | JSON-encoded token request against the legacy `/auth/cli/token` endpoint. | Used by `Login` + refresh; kept separate from the form path. |
| `AuthClient.requestTokenForm` | method | Form-encoded token request with `applyAuthToForm` + optional `SetBasicAuth`. | The RFC-correct path used by `ClientCredentials` + `exchangeCode`. |
| `AuthClient.requestTokenFormWithAssertion` | method | Form-encoded request that mints a `private_key_jwt` and posts it as `client_assertion`. | Splits the assertion path off so call sites stay readable. |
| `AuthClient.executeTokenRequest` | method | Dispatches a prepared token request and decodes into a `ServerCredential`. | Shared by the two form builders so decode + error mapping lives in one place. |
| `OAuth2TokenRequest` | struct | JSON body shape for the legacy `/auth/cli/token` endpoint. | JSON path stays separate from the form path so they can't drift. |
| `OAuth2TokenResponse` | struct | Parsed token endpoint response. | Single shape lets both JSON and form paths share decode + error mapping. |
| `parseAuthzDetailsFromRaw` | func | Re-marshals raw `authorization_details []any` into typed `core.AuthorizationDetail`. | Avoids leaking `core` types into the wire struct while round-tripping RFC 9396. |
| `RefreshThreshold` | const | 5-minute window before expiry that triggers proactive refresh. | Keeps refresh decisions in one place. |
| `ServerCredential` | struct | Token bundle (access + refresh + scope + RFC 9396 details + expiry) persisted per server URL. | One value handed to callers, the store, and `OnToken`. |
| `ServerCredential.IsExpired` | method | Reports whether `ExpiresAt` is in the past. | Hot-path check used everywhere. |
| `ServerCredential.IsExpiringSoon` | method | Reports whether the token will expire within a window. | Drives proactive refresh inside `RefreshThreshold`. |
| `ServerCredential.HasRefreshToken` | method | Reports whether a refresh token is available. | Skips refresh attempts for grants that don't issue one. |
| `CredentialStore` | interface | Persistence contract — get/set/remove a credential keyed by server URL, plus `Save` and `ListServers`. | Lets callers swap in file, keychain, or test stores. |
| `noopCredentialStore` | struct | `CredentialStore` that silently discards writes. | Default when `NewAuthClient` is called with nil. |
| `TokenSource` | interface | `Token() (string, error)`. | Decouples consumers from any particular OAuth grant; structurally compatible with mcpkit. |
| `ScopeAwareTokenSource` | interface | `TokenSource` + `TokenForScopes`. | Lets resource clients request elevated scopes on demand. |
| `ClientCredentialsSource` | struct | `TokenSource` impl that caches a `client_credentials` token and refreshes on expiry. | Standard M2M entry point — drop-in for any `TokenSource` consumer. |
| `ClientCredentialsSource.Token` | method | Returns cached token if still valid (30s skew buffer) or fetches a new one. | Hot-path read; also lazily starts the background refresher. |
| `ClientCredentialsSource.TokenForScopes` | method | Invalidates the cache, unions extra scopes, fetches a fresh token. | Scope step-up entry point. |
| `ClientCredentialsSource.Close` | method | Stops the background refresh goroutine; safe to call multiple times. | `io.Closer` compliance for long-lived processes. |
| `ClientCredentialsSource.fetchTokenLocked` | method | Lazily constructs the underlying `AuthClient` and calls `ClientCredentials`. | Atomic fetch + cache update; returns the cred so `OnToken` fires outside the lock. |
| `ClientCredentialsSource.fireOnToken` | method | Invokes `OnToken` with a defensive copy of the credential, outside the source's mutex. | Callbacks free to re-enter `Token()` without deadlock; cache state immutable from callbacks. |
| `ClientCredentialsSource.backgroundRefresh` | method | Goroutine sleeping until (expiry − `Refresher.Buffer`) then refreshing. | Tail-latency hiding for predictable token rotation. |
| `ClientCredentialsSource.doBackgroundRefresh` | method | Performs one proactive fetch under lock; logs and swallows failures. | Reactive path is the safety net — better a logged failure than a silent goroutine exit. |
| `ClientCredentialsSource.OnToken` | field | Callback fired after every successful fetch. | External persistence without implementing the full `CredentialStore`. |
| `ProactiveRefresher` | struct | Buffer policy + runtime state for the background refresh goroutine. | Bundles policy + lifecycle; makes lazy goroutine start explicit. |
| `tokenExpiryBuffer` | const | 30s subtracted from expiry in the freshness check. | Absorbs clock skew + network latency. |
| `ASMetadata` | struct | Parsed RFC 8414 / OIDC Discovery 1.0 AS metadata. | One typed shape used by discovery, the cache, and auth-method negotiation. |
| `DiscoverAS` | func | Fetches AS metadata, trying RFC 8414 then OIDC Discovery (path-aware). | Single entry point abstracting over the two conflicting well-known specs. |
| `DiscoveryOption` | type | Functional option for `DiscoverAS`. | Lets callers share a cache across token sources. |
| `WithHTTPClientForDiscovery` | func | Plugs a custom HTTP client into `DiscoverAS`. | Composable without exposing internal config. |
| `WithASMetadataStore` | func | Enables caching via an `ASMetadataStore`. | Opt-in dedup of discovery fetches across N sources sharing one AS. |
| `WithASCacheTTL` | func | Overrides the cache TTL for one `DiscoverAS` call. | Tighten freshness without touching the store's default. |
| `buildDiscoveryURLs` | func | Constructs the ordered list of well-known URLs to try. | Centralizes path-handling rules. |
| `splitOriginPath` | func | Splits an issuer URL into origin and path. | RFC 8414 vs OIDC Discovery differ on path placement — quirk lives here. |
| `fetchMetadata` | func | One GET + JSON decode + sanity check. | Lets `DiscoverAS` iterate over candidate URLs cleanly. |
| `ASMetadataStore` | interface | Concurrency-safe cache of `ASMetadata` keyed by issuer URL with TTL. | Decouples `DiscoverAS` from a concrete cache implementation. |
| `MemoryASMetadataStore` | struct | In-memory store backed by `sync.RWMutex` map with lazy TTL eviction. | Single-process default; no goroutines to manage. |
| `NewMemoryASMetadataStore` | func | Constructs a `MemoryASMetadataStore`. | One-line wiring for the common case. |
| `cachedAS` | struct | Internal entry pairing metadata with expiry. | Keeps the map's value type self-describing. |
| `DefaultASCacheTTL` | const | One-hour default TTL. | AS metadata changes rarely. |
| `TokenEndpointAuthMethod` | type | Enum of token endpoint auth methods. | RFC 6749 §2.3 / RFC 8414 vocabulary, typed to prevent drift. |
| `AuthMethodNone` | const | Public client — no secret. | Native/SPA + PKCE clients legitimately lack a secret. |
| `AuthMethodClientSecretPost` | const | Credentials in form body. | Required by some AS implementations. |
| `AuthMethodClientSecretBasic` | const | HTTP Basic auth in the Authorization header. | RFC 6749 §2.3.1 default; credentials stay out of the body. |
| `AuthMethodPrivateKeyJWT` | const | Client signs a JWT as `client_assertion`. | Strongest standard method. |
| `SelectAuthMethod` | func | Picks the best supported method given a secret + AS-advertised list. | One source of truth for negotiation. |
| `applyAuthToForm` | func | Writes client-auth parameters onto a `url.Values`. | Pairs with `req.SetBasicAuth` so creds never leak into both header and body. |
| `ClientAssertionConfig` | struct | Private key, alg, optional `kid`, lifetime, and override audience for `client_assertion`. | One value threaded through browser login, `client_credentials`, token exchange, and jwt-bearer. |
| `MintClientAssertion` | func | Signs a fresh JWT (`iss`/`sub`=clientID, `aud`=`cfg.Audience` or endpoint, random `jti`, short `exp`). | Centralizes claim shape so every call site is spec-compliant. |
| `applyAssertionToForm` | func | Writes `client_id`, `client_assertion_type`, `client_assertion`. | Mirrors `applyAuthToForm` so `private_key_jwt` looks the same at call sites. |
| `randomJTI` | func | 128-bit random `jti` (base64-RawURL). | Single-use assertions for AS replay protection. |
| `DefaultClientAssertionLifetime` | const | 60s assertion lifetime. | OIDC Core §9 short-lived recommendation. |
| `exchangeCodeParams` | struct | Internal bundle of inputs to `AuthClient.exchangeCode`. | Same rationale as `BrowserLoginRequest`. |
| `AuthClient.exchangeCode` | method | Exchanges an auth code for tokens using the negotiated client auth. | Single chokepoint for the code → token step. |
| `buildAuthorizationURL` | func | Composes `/authorize` URL with PKCE, state, scopes, optional resource. | Keeps query-param ordering consistent. |
| `startLoopbackListener` | func | Opens a TCP listener on `localhost:<port>`. | RFC 8252 native-app redirect target. |
| `generateState` | func | 128-bit random `state` for CSRF protection. | Required by RFC 6749 §10.12. |
| `generateCodeVerifier` | func | 256-bit random PKCE verifier (RFC 7636 §4.1). | 32 bytes → 43 base64url chars; hits the spec minimum without padding. |
| `computeCodeChallenge` | func | SHA-256 of the verifier, base64-RawURL. | PKCE S256 — only place the hash is computed. |
| `containsString` | func | Linear lookup helper. | One-off used to verify `S256` is advertised. |
| `FollowRedirects` | func | Returns an `OpenBrowser` function that GETs the auth URL via an HTTP client. | Headless CI / conformance / test — same loopback dance, no real browser. |
| `openBrowserDefault` | func | Platform-aware browser launcher (`open` / `xdg-open` / `rundll32`). | Default `OpenBrowser` so the common case needs no config. |
| `callbackResult` | struct | Result delivered onto the result channel by the loopback handler. | Either-or shape keeps the caller's `select` clean. |
| `AuthTransport` | struct | Standalone `RoundTripper` that injects a static Bearer token. | Lightweight escape hatch when refresh isn't needed. |
| `NewAuthTransport` | func | `AuthTransport` over `http.DefaultTransport`. | Common-case helper. |
| `NewAuthTransportWithBase` | func | `AuthTransport` with a caller-supplied base. | Keep your own pool/proxy settings. |
| `AuthTransport.RoundTrip` | method | Clones the request and sets the Bearer header. | Clone-before-mutate per `http.RoundTripper` contract. |
| `ClientRegistrationRequest` | struct | RFC 7591 DCR / RFC 7592 update body including OIDC `application_type`. | One struct for both register and update. |
| `ClientRegistrationResponse` | struct | Parsed DCR response including RFC 7592 management credentials. | Lets callers plug straight into `GetRegistration` / `UpdateRegistration` / `DeleteRegistration`. |
| `RegisterClient` | func | POST RFC 7591 registration to the DCR endpoint. | Pre-convention helper sufficient for one-shot registration. |
| `GetRegistration` | func | RFC 7592 §2.1 GET against the management endpoint. | gRPC-shape `(ctx, *Req) → (*Resp, err)`. |
| `GetRegistrationRequest` | struct | Inputs (URI, token, optional HTTPClient). | HTTPClient lives on the request (gRPC-CallOption analog). |
| `GetRegistrationResponse` | struct | Wraps the parsed registration. | Wrapper preserves headroom for future fields. |
| `UpdateRegistration` | func | RFC 7592 §2.2 full-replace PUT. | Surfaces the AS-rotated `registration_access_token`. |
| `UpdateRegistrationRequest` | struct | Inputs + full replacement metadata. | `ClientID` mandatory per RFC 7592 §2.2; auto-filled into metadata. |
| `UpdateRegistrationResponse` | struct | Wraps the post-update registration. | Same wrapping rationale. |
| `DeleteRegistration` | func | RFC 7592 §2.3 DELETE. | AS invalidates all tokens issued for the `client_id`. |
| `DeleteRegistrationRequest` | struct | Inputs to delete. | Stays in the `(ctx, *Req)` shape. |
| `DeleteRegistrationResponse` | struct | Intentionally empty (AS returns 204). | Preserves the convention. |
| `ErrRegistrationUnauthorized` | var | Sentinel returned on 401 from RFC 7592 management calls. | Lets callers `errors.Is` to detect token-rotation drift. |
| `ValidateHTTPS` | func | Checks AS endpoints use HTTPS (localhost exempt). | RFC 6749 §3.1.2.1. |
| `IsLocalhost` | func | True for `localhost` / `127.0.0.1` / `::1`. | One definition of "loopback". |
| `ValidateCIMDURL` | func | Checks Client ID Metadata Document URLs (HTTPS + non-root path). | Encodes the draft CIMD rules. |

## Flows

### Browser login (auth code + PKCE)

```mermaid
sequenceDiagram
    participant App as CLI App
    participant AC as AuthClient
    participant Disc as DiscoverAS
    participant LB as Loopback :randomPort
    participant Browser as User Browser
    participant AS as Auth Server

    App->>AC: LoginWithBrowser(ctx, *BrowserLoginRequest)
    AC->>AC: generateCodeVerifier + computeCodeChallenge (S256)
    AC->>AC: generateState (128-bit)
    AC->>LB: startLoopbackListener(0)
    LB-->>AC: assigned port P

    alt endpoints not provided
        AC->>Disc: DiscoverAS(serverURL)
        Disc->>AS: GET /.well-known/oauth-authorization-server
        AS-->>Disc: ASMetadata
        Disc-->>AC: meta (incl. CodeChallengeMethodsSupported)
        AC->>AC: verify S256 advertised (else error)
        AC->>AC: SelectAuthMethod(secret, meta.TokenEndpointAuthMethods)
    end

    AC->>AC: buildAuthorizationURL(endpoint, ..., resource)
    AC->>Browser: openBrowserDefault(authURL)
    Browser->>AS: GET /authorize?...&code_challenge=...&state=...
    AS-->>Browser: 302 to http://localhost:P/callback?code&state
    Browser->>LB: GET /callback?code=...&state=...
    LB-->>AC: callbackResult{Code, State}
    AC->>AC: validate state matches (else CSRF error)
    AC->>AC: exchangeCode(code, verifier, authMethod, ...)
    AC->>AS: POST /token (form, Basic / Post / private_key_jwt)
    AS-->>AC: 200 OAuth2TokenResponse
    AC->>AC: store.SetCredential + Save (under c.mu)
    AC-->>App: *ServerCredential
```

### ClientCredentialsSource cached token with proactive refresh

```mermaid
sequenceDiagram
    participant Consumer
    participant S as ClientCredentialsSource
    participant BG as backgroundRefresh goroutine
    participant AC as AuthClient
    participant CB as OnToken

    Consumer->>S: Token()
    alt Refresher.Buffer > 0
        S->>S: once.Do — create stop chan
        S->>BG: go backgroundRefresh()
    end
    S->>S: mu.Lock
    alt token cached && now+30s < expiry
        S-->>Consumer: cached token
    else miss / stale
        S->>AC: ClientCredentials(ctx, *Request)
        AC-->>S: *ServerCredential
        S->>S: token=cred.AccessToken; expiry=cred.ExpiresAt
        S->>S: mu.Unlock
        S->>CB: fireOnToken (copy, outside lock)
        S-->>Consumer: cred.AccessToken
    end

    loop until Close
        BG->>BG: sleep min(500ms, expiry - Buffer)
        alt now > expiry - Buffer
            BG->>AC: ClientCredentials(ctx, *Request)
            alt success
                BG->>S: update token + expiry
                BG->>CB: fireOnToken
            else failure
                BG->>BG: log; reactive Token() retries later
            end
        end
    end

    Consumer->>S: Close()
    S->>BG: close(stop) — Close is idempotent
```

### ClientCredentials with private_key_jwt

```mermaid
sequenceDiagram
    participant App
    participant AC as AuthClient
    participant Mint as MintClientAssertion
    participant AS

    App->>AC: ClientCredentials(ctx, *ClientCredentialsRequest{ClientAssertion: cfg})
    AC->>AC: choose endpoint (cachedASMeta.TokenEndpoint or serverURL+path)
    AC->>AC: assemble form (grant_type, scope, resource[], authorization_details)
    AC->>Mint: MintClientAssertion(clientID, audience=tokenEndpoint, cfg)
    Mint->>Mint: randomJTI; iss/sub=clientID; iat/exp=now+Lifetime
    Mint->>Mint: sign w/ cfg.PrivateKey + cfg.SigningAlg (RS256/ES256)
    Mint-->>AC: compact JWS
    AC->>AC: applyAssertionToForm(clientID, jws, data)
    AC->>AS: POST /token (form, client_assertion_type + client_assertion)
    AS-->>AC: 200 OAuth2TokenResponse
    AC->>AC: parseAuthzDetailsFromRaw (RFC 9396)
    AC->>AC: store.SetCredential + Save
    AC-->>App: *ServerCredential
```

### Dynamic client registration (DCR)

```mermaid
sequenceDiagram
    participant App
    participant Reg as RegisterClient
    participant Get as GetRegistration
    participant Upd as UpdateRegistration
    participant Del as DeleteRegistration
    participant AS

    App->>Reg: RegisterClient(endpoint, ClientRegistrationRequest, http)
    Reg->>AS: POST /register (RFC 7591 JSON)
    AS-->>Reg: 201 ClientRegistrationResponse (+ registration_access_token + registration_client_uri)
    Reg-->>App: response

    App->>App: persist client_id, client_secret, RAT, registration_client_uri

    App->>Get: GetRegistration(ctx, *Request)
    Get->>AS: GET registration_client_uri (Bearer RAT)
    alt 401
        AS-->>Get: 401
        Get-->>App: ErrRegistrationUnauthorized
    else 200
        AS-->>Get: ClientRegistrationResponse
        Get-->>App: response
    end

    App->>Upd: UpdateRegistration(ctx, *Request{Metadata})
    Upd->>Upd: auto-fill Metadata.ClientID if missing
    Upd->>AS: PUT registration_client_uri (full replace)
    AS-->>Upd: 200 (rotated registration_access_token)
    Upd-->>App: response (callers MUST persist new RAT)

    App->>Del: DeleteRegistration(ctx, *Request)
    Del->>AS: DELETE registration_client_uri
    AS-->>Del: 204 No Content
    Del-->>App: empty response (AS invalidates all tokens for client_id)
```

## Gotchas

- **`OnToken` runs while `AuthClient.mu` is held** — the refresh-grant callback fires from inside `refreshTokenLocked`, which is invoked under `c.mu`. If the callback re-enters any `AuthClient` method that takes that mutex (`GetToken`, `Login`, `Logout`, `IsLoggedIn` via the path that locks, etc.) the goroutine deadlocks. The doc on the field calls this out — keep callbacks lightweight and non-blocking. `ClientCredentialsSource.OnToken` has the opposite contract (fired outside the source's mutex), so don't carry the wrong assumption across the two callbacks.

- **`refreshTransport` retries 401 exactly once, with a tiny race window** — when a 401 comes back the transport locks `c.mu`, refreshes, unlocks, then calls `GetToken` again before retrying. Another goroutine can squeeze in between unlock and `GetToken` and refresh the credential again; the second refresh will succeed but it's a wasted network round-trip. Tolerable because 401s are rare on the hot path, but worth knowing if you're hammering the same client from many goroutines.

- **`Login` / `LoginWithBrowser` / `ClientCredentials` / `TokenExchange` / `JwtBearerGrant` don't fire `OnToken`** — only the automatic refresh path does. Initial grant methods return the credential to the caller, who is expected to persist it themselves (the store call inside the method already did, where applicable). If you've wired `OnToken` to side-effects like metrics or external persistence, remember to do an equivalent action on the credential the grant method returns.

- **`TokenExchange` and `JwtBearerGrant` intentionally don't persist** — they're fan-out grants where the access token is consumed by a downstream peer, not the AuthClient itself. Persisting would pollute the cached refresh-token state for the AuthClient's own user-context session. `JwtBearerGrant` returns a `*ServerCredential` for symmetry but the caller owns its lifecycle.

- **Two token-request code paths, one for JSON and one for forms** — `requestToken` posts JSON to `c.serverURL + c.tokenEndpoint` (the OneAuth-native `/auth/cli/token` shape used by `Login` + refresh). `requestTokenForm` / `requestTokenFormWithAssertion` / `buildTokenRequest` post `application/x-www-form-urlencoded` to the (possibly discovered) token endpoint, which is the RFC-correct path. The two share `OAuth2TokenResponse` parsing but not the request side — adding a new grant means picking the right one. New OAuth-spec work goes through the form path.

- **`private_key_jwt` audience varies by AS** — `MintClientAssertion` uses `cfg.Audience` when set, otherwise the positional `audience` argument (typically the token endpoint URL). OIDC Core §9 says the AS *should* accept the token endpoint; RFC 7523bis requires the issuer. Third-party ASes are inconsistent (Auth0 wants the issuer, Keycloak the endpoint). Set `ClientAssertionConfig.Audience` explicitly when targeting an RFC 7523bis-strict AS.

- **Discovery has two well-known shapes, tried in order** — for a plain origin we try `/.well-known/oauth-authorization-server` first, then `/.well-known/openid-configuration`. For an issuer with a path (`https://host/tenant1`) we try `/.well-known/oauth-authorization-server/tenant1` (RFC 8414) then `/tenant1/.well-known/openid-configuration` (OIDC Discovery). The first 200 with a non-empty issuer or token endpoint wins. If your AS only serves one shape make sure you know which — and Keycloak realms put the realm path inside the issuer URL.

- **`MemoryASMetadataStore` evicts lazily on `Get` only** — there's no background sweeper. Expired entries sit in the map until something asks for them. Fine for bounded workloads (one entry per unique issuer URL) but if you're synthesizing thousands of distinct issuer URLs in a test, the map will grow.

- **`ProactiveRefresher.Close` must be idempotent because `Token()` may never have been called** — the stop channel is created lazily inside `Token()`'s `once.Do`. `Close` guards on `closed` to avoid the double-close panic. The same flag also short-circuits subsequent `Close` calls. After `Close`, the source still serves reactive refreshes — closing only stops the proactive goroutine.

- **`ServerCredential.IsExpired` uses local wall-clock time** — no skew handling. The 30-second `tokenExpiryBuffer` in `ClientCredentialsSource` is the only place we account for clock drift; `AuthClient.GetToken` relies on `IsExpired` + `IsExpiringSoon(RefreshThreshold)` and trusts that 5 minutes of headroom is enough to outlast typical skew + network RTT. Heavily-skewed clients will see "valid" tokens rejected by the AS — fix the client clock.

- **`refreshTransport` uses the base transport for token requests, not the wrapped one** — `requestToken`, `executeTokenRequest`, and `TokenExchange` explicitly construct an `http.Client{Transport: c.baseTransport}` so the token endpoint isn't itself Bearer-authenticated by a stale token. If you wrap the AuthClient's HTTP client in another auth layer outside, that outer layer is bypassed too — by design, but surprising the first time you debug it.

- **RFC 7592 token rotation is mandatory** — `UpdateRegistration` *must* persist the new `registration_access_token` in the response before discarding the old one. Forget this and the next management call gets `ErrRegistrationUnauthorized`. The response type wraps the registration specifically to make the new token impossible to miss.

- **`ErrRegistrationUnauthorized` is fuzzy on purpose** — the AS returns 401 for wrong token, missing token, or unknown `client_id` — same status, no discriminator. Callers cannot distinguish those cases from this error alone; treat it as "your management credentials are no longer valid, re-register or re-fetch them" and move on.

- **`LoginWithBrowser` only enforces PKCE S256 when it ran discovery itself** — if you pass explicit `AuthorizationEndpoint` + `TokenEndpoint`, the check against `code_challenge_methods_supported` is skipped, because the caller has already decided what the AS supports. Combined with `TokenEndpointAuthMethods` (which carries the same caller-supplied negotiation hint for the token endpoint), this lets MCP-style PRM-then-AS flows skip a second discovery round-trip while still picking the right auth method.

- **`ClientCredentialsToken` and `ClientCredentialsTokenWithAssertion` are deprecated shims** — they call `ClientCredentials` with `context.Background()`, losing the caller's cancellation and tracing context. New code should call `ClientCredentials` directly with a real `ctx`. The shims are kept so pre-#217 callers compile, but plan to migrate before any deprecation cycle removes them.

- **The static `AuthTransport` is a footgun for long-lived processes** — it captures a single token at construction and never refreshes. Use it when you have a short-lived token and a short-lived job; for anything that runs longer than the token's lifetime, use `AuthClient.HTTPClient` or thread a `TokenSource.Token()` call into your request builder.

## Depends on

- [`../core/`](../core/DESIGN.md) — `core.AuthorizationDetail` is the typed shape on `ServerCredential.AuthorizationDetails`, `ClientCredentialsSource.AuthorizationDetails`, and the slice rebuilt by `parseAuthzDetailsFromRaw` for RFC 9396 round-tripping; `core.UnionScopes` powers `ClientCredentialsSource.TokenForScopes` so step-up calls merge with the source's existing scope set.
- [`../utils/`](../utils/DESIGN.md) — `utils.SigningMethodForAlg` resolves `ClientAssertionConfig.SigningAlg` to a `jwt.SigningMethod` inside `MintClientAssertion`, so `private_key_jwt` works for any supported alg without duplicating the alg → method mapping.
