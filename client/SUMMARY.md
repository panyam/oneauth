# client/ — OAuth Client SDK

Go client library for OAuth 2.0 authentication: browser-based login (authorization code + PKCE), headless login, client_credentials, AS metadata discovery, credential storage, and automatic token refresh.

## Contents
- **client.go** — `AuthClient` (token management, `Login`, `ClientCredentialsToken`, `GetToken`, auto-refresh transport), `WithASMetadata`, `WithTokenEndpoint`, `WithHTTPClient`
- **browser_login.go** — `LoginWithBrowser` (authorization code + PKCE flow, RFC 8252), `FollowRedirects` (headless HTTP redirect mode), `BrowserLoginConfig` (with `ClientSecret` for confidential clients, `TokenEndpointAuthMethods` for explicit endpoint auth method override)
- **auth_method.go** — `TokenEndpointAuthMethod` type, `SelectAuthMethod` (negotiates `client_secret_basic` vs `client_secret_post` vs `none` from AS metadata), `applyAuthToForm`
- **discovery.go** — `ASMetadata`, `DiscoverAS` (RFC 8414 + OIDC Discovery fallback), `DiscoveryOption`
- **credentials.go** — `ServerCredential`, `CredentialStore` interface
- **transport.go** — `AuthTransport` (static Bearer token transport)
- **dcr.go** — `RegisterClient` (RFC 7591 client-side Dynamic Client Registration), `ClientRegistrationRequest`, `ClientRegistrationResponse`
- **validation.go** — `ValidateHTTPS` (HTTPS enforcement for AS endpoints, RFC 6749 §3.1.2.1), `IsLocalhost` (loopback detection), `ValidateCIMDURL` (Client ID Metadata Document URL validation)
- **client_credentials_source.go** — `ClientCredentialsSource` (RFC 6749 §4.4 client_credentials grant with token caching), `TokenSource` and `ScopeAwareTokenSource` interfaces
- **stores/fs/** — `FSCredentialStore` (filesystem-based credential persistence)

## Recent Changes
- **Headless OAuth flow (#71)** — `FollowRedirects(httpClient)` returns an `OpenBrowser`-compatible function that follows HTTP redirects instead of opening a browser. Enables CI, conformance testing, and headless CLI environments.
- **Token endpoint auth method negotiation (#72)** — `SelectAuthMethod` picks the appropriate auth method (`client_secret_basic`, `client_secret_post`, or `none`) based on AS discovery metadata. Threaded through `LoginWithBrowser` (via `ClientSecret` config field) and `ClientCredentialsToken` (via `WithASMetadata` option). `ClientCredentialsToken` now sends RFC 6749-compliant form-encoded requests instead of JSON.
- **Explicit endpoint auth method fix (#74)** — `BrowserLoginConfig.TokenEndpointAuthMethods` allows callers to pass auth methods when providing explicit endpoints (skipping discovery). Fixes the bug where explicit endpoints caused `SelectAuthMethod` to get an empty list and default to `client_secret_basic` regardless of AS support.
- **Nil CredentialStore safety (#76)** — `NewAuthClient(url, nil)` no longer panics. A no-op store (null object pattern) is substituted when nil is passed, so methods like `LoginWithBrowser` and `ClientCredentialsToken` work for single-request flows without persistence. Matches the `admin.NoAuth` precedent.
- **Legacy note** — `requestToken` (JSON-based) is retained for `Login` and `refreshTokenLocked` which use the oneauth-specific `/auth/cli/token` endpoint. New standards-compliant flows use `requestTokenForm`. The legacy `/api/token` JSON endpoint can be removed once all clients migrate to form-encoded `/oauth/token`.

## Recent Changes
- **Client-side DCR + validation utilities (mcpkit#158)** — `RegisterClient` (client-side RFC 7591 DCR caller), `ValidateHTTPS`/`IsLocalhost`/`ValidateCIMDURL` (OAuth endpoint validation), `ClientCredentialsSource` (RFC 6749 §4.4 grant wrapper with caching). Pushed down from mcpkit/ext/auth as pure-OAuth reusable code. See oneauth#78.

## Dependencies
`core/` is imported for `UnionScopes`. Otherwise standalone with only stdlib + `stretchr/testify` (testing).
