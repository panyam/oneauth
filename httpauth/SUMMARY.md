# httpauth/ — HTTP Middleware, CSRF, Session Mux

HTTP-layer auth: session-based middleware, CSRF protection, and the OneAuth session mux for OAuth callback handling.

## Contents
- **middleware.go** — `Middleware` struct (`ExtractUser`, `EnsureUser`, `GetLoggedInUserId`)
- **csrf.go** — `CSRFMiddleware`, `CSRFToken()`, `CSRFTemplateField()`
- **mux.go** — `OneAuth` struct, `AuthUserStore` interface, OAuth callback handling, `LinkOAuthConfig`

## Recent Additions
- **LimitBody** middleware — caps request body size to prevent oversized payload attacks
- **SecurityHeaders** middleware — sets standard security response headers (X-Content-Type-Options, X-Frame-Options, etc.)
- **DenyFraming** (`pagesafety.go`) — X-Frame-Options: DENY plus `frame-ancestors 'none'` when no CSP is set; the authorize, device and localauth pages call it so they can't be clickjacked without the deployment's middleware.
- **LocalRedirect** (`pagesafety.go`) — returns a redirect target only if it's a path on this site; used for logout `?to=` and the federated `callbackURL` (CWE-601).
- **Session cookies (issue 88)** — `SetLoggedInSubject` renews the scs token, sets Secure (opt-out `InsecureCookies`) + SameSite=Lax cookies on every cookie domain (HttpOnly for the JWT), and mints `type: session` JWTs. `/logout` is POST-only. No fixed fallback secret.

## Dependencies
`core/` for user/store types. `scs/v2` for sessions. `golang-jwt/jwt/v5` for JWT verification.
