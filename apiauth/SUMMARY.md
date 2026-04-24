# apiauth/ — API Token Authentication

JWT-based API authentication: token issuance (login/refresh/client_credentials), validation middleware, API key support, and multi-tenant JWT verification.

## Contents
- **auth.go** — `APIAuth` (login/logout/refresh/client_credentials handlers, `CreateAccessToken`, `ValidateAccessToken`), `APIMiddleware` (`ValidateToken`, `RequireScopes`, `Optional`), context helpers (`GetUserIDFromAPIContext`, etc.)
- **as_metadata.go** — `ASServerMetadata` struct + `NewASMetadataHandler` for RFC 8414 / OIDC Discovery
- **introspection.go** — `IntrospectionHandler` for RFC 7662 token introspection (server side)
- **introspection_client.go** — `IntrospectionValidator` for RFC 7662 token introspection (client side, with caching)
- **protected_resource.go** — `ProtectedResourceMetadata` struct + `NewProtectedResourceHandler` for RFC 9728 discovery

## Recent Changes
- **RFC 9396 Rich Authorization Requests** — Token endpoint accepts `authorization_details` parameter (JSON body or form-encoded JSON string). Granted details are embedded in JWT claims and returned in token/introspection responses. `CreateAccessToken` signature: `(userID, scopes, authzDetails)`. `standardClaims` guard blocks `CustomClaimsFunc` from overriding `authorization_details`.
- **client_credentials grant** — `APIAuth.ClientKeyStore` enables machine-to-machine auth via `grant_type=client_credentials` (RFC 6749 §4.4). Supports `client_secret_post` and `client_secret_basic`.
- **Protected Resource Metadata** — `NewProtectedResourceHandler` serves RFC 9728 metadata at `/.well-known/oauth-protected-resource`, enabling clients to auto-discover resource server capabilities
- **Audience validation** — `ValidateAccessToken` checks `aud` claim against expected audiences; handles both string and array formats (RFC 7519 §4.1.3, #52)
- **Token blacklist** — `APIAuth.Blacklist` and `APIMiddleware.Blacklist` fields enable jti-based token revocation via `core.TokenBlacklist`. All tokens now include a `jti` claim.
- **RateLimiter moved to core** — the `RateLimiter` interface was extracted from `apiauth` to `core/` so it can be shared across packages (e.g., `localauth`)

## Dependencies
`core/` for store interfaces, token types, scopes, rate limiting. `keys/` for `KeyLookup`. `utils/` for JWT helpers.
