# httpauth/ — HTTP Middleware, CSRF, Session Mux

HTTP-layer auth: session-based middleware, CSRF protection, and the OneAuth session mux for OAuth callback handling.

## Contents
- **middleware.go** — `Middleware` struct (`ExtractUser`, `EnsureUser`, `GetLoggedInUserId`)
- **csrf.go** — `CSRFMiddleware`, `CSRFToken()`, `CSRFTemplateField()`
- **mux.go** — `OneAuth` struct, `AuthUserStore` interface, OAuth callback handling, `LinkOAuthConfig`

## Dependencies
`core/` for user/store types. `scs/v2` for sessions. `golang-jwt/jwt/v5` for JWT verification.
