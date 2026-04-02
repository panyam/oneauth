# apiauth/ — API Token Authentication

JWT-based API authentication: token issuance (login/refresh), validation middleware, API key support, and multi-tenant JWT verification.

## Contents
- **auth.go** — `APIAuth` (login/logout/refresh handlers, `CreateAccessToken`, `ValidateAccessToken`), `APIMiddleware` (`ValidateToken`, `RequireScopes`, `Optional`), context helpers (`GetUserIDFromAPIContext`, etc.)

## Recent Changes
- **Audience validation** — `ValidateAccessToken` now checks the `aud` claim against expected audiences, rejecting tokens not intended for this service
- **RateLimiter moved to core** — the `RateLimiter` interface was extracted from `apiauth` to `core/` so it can be shared across packages (e.g., `localauth`)

## Dependencies
`core/` for store interfaces, token types, scopes, rate limiting. `keys/` for `KeyLookup`. `utils/` for JWT helpers.
