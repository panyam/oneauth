# client/ — OAuth Client SDK

Go client library for OAuth 2.0 authentication: browser-based login (authorization code + PKCE), headless login, client_credentials, AS metadata discovery, credential storage, and automatic token refresh.

## Contents
- **client.go** — `AuthClient` (token management, `Login`, `ClientCredentials`, `GetToken`, auto-refresh transport), `WithASMetadata`, `WithTokenEndpoint`, `WithHTTPClient`. `ClientCredentialsToken` / `ClientCredentialsTokenWithAssertion` retained as `// Deprecated:` compat wrappers.
- **browser_login.go** — `LoginWithBrowser` (authorization code + PKCE flow, RFC 8252), `FollowRedirects` (headless HTTP redirect mode), `BrowserLoginRequest` (with `ClientSecret` for confidential clients, `TokenEndpointAuthMethods` for explicit endpoint auth method override, `ClientAssertion` for `private_key_jwt`)
- **auth_method.go** — `TokenEndpointAuthMethod` type, `SelectAuthMethod` (negotiates `client_secret_basic` vs `client_secret_post` vs `none` from AS metadata), `applyAuthToForm`
- **private_key_jwt.go** — `AuthMethodPrivateKeyJWT` constant, `ClientAssertionConfig`, `MintClientAssertion` (RFC 7523 §2.2 / OIDC Core §9 assertion minter — fresh `jti` + bounded lifetime per call)
- **discovery.go** — `ASMetadata`, `DiscoverAS` (RFC 8414 + OIDC Discovery fallback), `DiscoveryOption`
- **credentials.go** — `ServerCredential`, `CredentialStore` interface
- **transport.go** — `AuthTransport` (static Bearer token transport)
- **dcr.go** — `RegisterClient` (RFC 7591 client-side Dynamic Client Registration), `ClientRegistrationRequest`, `ClientRegistrationResponse`
- **validation.go** — `ValidateHTTPS` (HTTPS enforcement for AS endpoints, RFC 6749 §3.1.2.1), `IsLocalhost` (loopback detection), `ValidateCIMDURL` (Client ID Metadata Document URL validation)
- **client_credentials_source.go** — `ClientCredentialsSource` (RFC 6749 §4.4 client_credentials grant with token caching), `TokenSource` and `ScopeAwareTokenSource` interfaces
- **stores/fs/** — `FSCredentialStore` (filesystem-based credential persistence)

## Recent Changes
- **`ValidateIss` helper (#238)** — `client.ValidateIss(iss, expectedIssuer, asAdvertisedSupport, strict)` implements the RFC 9207 §2.4 truth table that every consumer of `BrowserLoginRequest.OnCallback` would otherwise re-derive. Returns `ErrIssMismatch` / `ErrIssMissing` sentinels (safe for `errors.Is`). Issuer comparison applies RFC 3986 §6.2 scheme + host lowercasing and trailing-slash stripping. Strict-mode argument lets FAPI 2.0 / Open Banking consumers enforce iss regardless of AS advertisement.
- **`authorization_response_iss_parameter_supported` on `ASMetadata` (#239)** — surfaces the RFC 9207 AS advertisement value at decode time. Pointer-typed `*bool` to preserve the absent / explicit-false / explicit-true tristate consumers need for §2.4 enforcement (mirrors the server-side field on `apiauth.ASServerMetadata`). No change to `DiscoverAS` logic; validation lives in consumers per #235's split.
- **`private_key_jwt` client auth (#158)** — new `AuthMethodPrivateKeyJWT` constant + `ClientAssertionConfig` + `MintClientAssertion`. `AuthClient.ClientCredentialsTokenWithAssertion` is the SDK entrypoint for the machine-to-machine path. `BrowserLoginConfig.ClientAssertion` opts the auth-code flow into private_key_jwt at the token-exchange step. `exchangeCode` parameters were grouped into `exchangeCodeParams` (struct) since the positional list grew past readability.
- **Headless OAuth flow (#71)** — `FollowRedirects(httpClient)` returns an `OpenBrowser`-compatible function that follows HTTP redirects instead of opening a browser. Enables CI, conformance testing, and headless CLI environments.
- **Token endpoint auth method negotiation (#72)** — `SelectAuthMethod` picks the appropriate auth method (`client_secret_basic`, `client_secret_post`, or `none`) based on AS discovery metadata. Threaded through `LoginWithBrowser` (via `ClientSecret` config field) and `ClientCredentialsToken` (via `WithASMetadata` option). `ClientCredentialsToken` now sends RFC 6749-compliant form-encoded requests instead of JSON.
- **Explicit endpoint auth method fix (#74)** — `BrowserLoginConfig.TokenEndpointAuthMethods` allows callers to pass auth methods when providing explicit endpoints (skipping discovery). Fixes the bug where explicit endpoints caused `SelectAuthMethod` to get an empty list and default to `client_secret_basic` regardless of AS support.
- **Nil CredentialStore safety (#76)** — `NewAuthClient(url, nil)` no longer panics. A no-op store (null object pattern) is substituted when nil is passed, so methods like `LoginWithBrowser` and `ClientCredentialsToken` work for single-request flows without persistence. Matches the `admin.NoAuth` precedent.
- **Legacy note** — `requestToken` (JSON-based) is retained for `Login` and `refreshTokenLocked` which use the oneauth-specific `/auth/cli/token` endpoint. New standards-compliant flows use `requestTokenForm`. The legacy `/api/token` JSON endpoint can be removed once all clients migrate to form-encoded `/oauth/token`.

## Recent Changes
- **Client-side DCR + validation utilities (mcpkit#158)** — `RegisterClient` (client-side RFC 7591 DCR caller), `ValidateHTTPS`/`IsLocalhost`/`ValidateCIMDURL` (OAuth endpoint validation), `ClientCredentialsSource` (RFC 6749 §4.4 grant wrapper with caching). Pushed down from mcpkit/ext/auth as pure-OAuth reusable code. See oneauth#78.
- **DCR `application_type` (mcpkit#440)** — added `ApplicationType` to `ClientRegistrationRequest` per OpenID Connect Dynamic Client Registration 1.0. `omitempty` so existing oneauth callers stay wire-compatible; consumers whose spec requires it (MCP per SEP-837) set it explicitly to `"native"` or `"web"`.
- **gRPC-shape convention (#217)** — `AuthClient` token-acquisition methods all follow `MethodName(ctx context.Context, req *XRequest) (..., error)`: `Login(ctx, *LoginRequest)`, `ClientCredentials(ctx, *ClientCredentialsRequest)`, `TokenExchange(ctx, *TokenExchangeRequest)`, `JwtBearerGrant(ctx, *JwtBearerGrantRequest)`, `LoginWithBrowser(ctx, *BrowserLoginRequest)`. Matches the convention adopted across `apiauth/`, `admin/`, and store-layer interfaces (#175 / #172 / #204).

## Tracing (SEP-414 / #254)

The client SDK only *propagates* trace context — it does not emit spans of its own (the caller's span is the trace anchor). Every outbound HTTP call now passes a `traceparent` header from the supplied `ctx`:

- `DiscoverASWithContext` injects on the well-known fetch (legacy `DiscoverAS` wraps it with `context.Background()`).
- `LoginWithBrowser` injects on the token-exchange request.
- `TokenExchange` and `JwtBearerGrant` inject via the shared `buildTokenRequest` path.

OTel-aware AS deployments (oneauth's own `JWKSHandler` / token / introspect / revoke handlers, or any other server speaking W3C Trace Context) will stitch their server-side work into the caller's trace automatically.

## Dependencies
`core/` is imported for `UnionScopes`, `tracing/` for SEP-414 propagation. Otherwise standalone with only stdlib + `stretchr/testify` (testing).
