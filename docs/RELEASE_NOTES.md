# OneAuth Release Notes

## Version 0.0.32

### APIMiddleware Enhancements

**Query-parameter token fallback**: Added configurable `TokenQueryParam` field to `APIMiddleware`. WebSocket clients often cannot set Authorization headers, so this enables `GET /ws?token=<jwt>` as a fallback. The Authorization header always takes precedence when both are present.

**Custom claims in request context**: Custom (non-standard) JWT claims are now stored in the request context during validation. Use the new `GetCustomClaimsFromContext(ctx)` helper to retrieve them downstream.

**Internal changes**: `validateRequest` and `validateJWT` now return custom claims alongside standard fields. All middleware methods (`ValidateToken`, `RequireScopes`, `Optional`) propagate custom claims into the request context.

---

## Version 0.0.31

### App Registration API & Reference Server

- **`AdminAuth` interface** with `APIKeyAuth` and `NoAuth` implementations for protecting admin endpoints
- **`AppRegistrar` HTTP handler** providing full App CRUD: register, list, get, delete, and rotate secret
- **`MintResourceToken` helper** for issuing resource-scoped JWTs with app/subject claims
- **Config-driven reference server** in `cmd/oneauth-server/` with YAML config and environment variable substitution
- Deployable to **GAE, Docker Compose, and Kubernetes**
- **Integration tests** (pytest) covering the full app registration lifecycle

---

## Version 0.0.30

### Redirect Mode for Password Reset Flows

`LocalAuth` now supports redirect-based password reset for server-rendered apps. New fields `ForgotPasswordURL` and `ResetPasswordURL` control the behavior: when set, GET requests redirect to the app's themed page, and POST requests redirect with query params (`?sent=true`, `?success=true`, `?error=...`). When empty (default), handlers behave as before (HTML form / JSON response).

### Bug Fix: Multipart Form Parsing

`HandleForgotPassword` and `HandleResetPassword` now correctly parse both `application/x-www-form-urlencoded` and `multipart/form-data` bodies. Previously, JavaScript `new FormData(form)` submissions returned 400 errors.

---

## Version 0.0.29

### Bug Fix: Password Reset for OAuth-Only Users

`NewUpdatePasswordFunc` now creates a local channel on-demand when one doesn't exist, enabling OAuth-only users to set a password via the standard reset flow. Previously these users received "local auth not configured" errors.

---

## Version 0.2.0

### API Authentication & Store Reorganization

Major release adding API authentication (JWT access tokens, refresh tokens with rotation and theft detection, API keys, scopes) and new store backends.

**New endpoints**: `/api/login`, `/api/logout`, `/api/logout-all`, `/api/keys` (CRUD).

**APIMiddleware**: `ValidateToken`, `RequireScopes`, and `Optional` handlers for protecting API routes. Supports both JWT and API key authentication.

**Store reorganization**: Stores moved to `stores/fs`, `stores/gorm`, and `stores/gae` subdirectories. GORM provides full SQL database support; GAE provides Google Cloud Datastore support.

**New store interfaces**: `RefreshTokenStore` and `APIKeyStore`.

**Breaking change**: Import paths changed from `github.com/panyam/oneauth/stores` to `github.com/panyam/oneauth/stores/{fs,gorm,gae}`.

**New dependencies**: `github.com/golang-jwt/jwt/v5`, `gorm.io/gorm` (optional), `cloud.google.com/go/datastore` (optional).

---

## Version 0.1.0 (Initial Release)

### Overview

Initial release of OneAuth, a Go authentication library providing unified local and OAuth-based authentication with multi-method account linking.

### Core Features

- **Three-layer model**: Users, Identities, and Channels with global identity verification
- **Local auth**: Email/phone + password with bcrypt hashing, configurable validation
- **OAuth integration**: Google, GitHub, etc. with automatic identity unification across providers
- **Email verification**: Token-based flow with configurable expiry and extensible sender interface
- **Password reset**: Secure token-based flow with anti-enumeration (always returns success)
- **Session management**: Callback-based (`HandleUser`) supporting cookies, JWTs, or custom schemes

### Storage

- **File-based stores** (FS): JSON file storage for Users, Identities, Channels, and Tokens. Suitable for development and small-scale use (<1000 users).
- **Database-agnostic interfaces**: `UserStore`, `IdentityStore`, `ChannelStore`, `TokenStore` for production implementations.

### HTTP Endpoints

`/auth/login`, `/auth/signup`, `/auth/verify-email`, `/auth/forgot-password`, `/auth/reset-password`. Accepts form-encoded and JSON bodies; returns JSON responses.

### Helper Functions

`NewCreateUserFunc`, `NewCredentialsValidator`, `NewVerifyEmailFunc`, `NewUpdatePasswordFunc`, `DetectUsernameType`, `DefaultSignupValidator`, `GenerateSecureToken`.

### Known Limitations

File-based stores not recommended at scale. No built-in rate limiting, CSRF protection, or session storage (application responsibility). Console email sender only.

### Dependencies

`golang.org/x/crypto/bcrypt`, `golang.org/x/oauth2` (optional).
