# apiauth/ — API Token Authentication

JWT-based API authentication: token issuance (login/refresh), validation middleware, API key support, and multi-tenant JWT verification.

## Contents
- **auth.go** — `APIAuth` (login/logout/refresh handlers, `CreateAccessToken`, `ValidateAccessToken`), `APIMiddleware` (`ValidateToken`, `RequireScopes`, `Optional`), context helpers (`GetUserIDFromAPIContext`, etc.)

## Dependencies
`core/` for store interfaces, token types, scopes. `keys/` for `KeyLookup`. `utils/` for JWT helpers.
