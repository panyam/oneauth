# OneAuth Release Notes

## Version 0.1.4 (PR 2b — Subject vocab consumer-side rename)

### Subject vocabulary — phase 2: consumers, helpers, transports

**Breaking.** Completes the rename started in v0.1.3 (PR 2a). All Go API surfaces that handle the *principal-of-a-token* concept now use **Subject** — context helpers, scope callbacks, response types, HTTP middleware methods, gRPC functions, gRPC metadata header, and the session cookie key. Account-model types (`accounts.User`, `accounts.Identity.UserID`, `accounts.Username.UserID`, etc.) stay as **UserID** — see v0.1.3 notes.

**Go API renames:**

| Before | After |
|---|---|
| `core.GetUserIDFromContext(ctx)` | `core.GetSubjectFromContext(ctx)` |
| `core.SetUserIDInContext(ctx, ...)` | `core.SetSubjectInContext(ctx, ...)` |
| `core.DefaultUserParamName = "loggedInUserId"` | `core.DefaultSubjectParamName = "loggedInSubject"` |
| `core.GetUserScopesFunc` / `DefaultGetUserScopes` | `core.GetSubjectScopesFunc` / `DefaultGetSubjectScopes` |
| `apiauth.APIAuth.GetUserScopes` | `apiauth.APIAuth.GetSubjectScopes` |
| `apiauth.OneAuthConfig.GetUserScopes` | `apiauth.OneAuthConfig.GetSubjectScopes` |
| `apiauth.JWTIssuerConfig.GetUserScopes` | `apiauth.JWTIssuerConfig.GetSubjectScopes` |
| `apiauth.PasswordGrantResponse.UserID` | `.Subject` |
| `apiauth.TokenInfo.UserID` | `.Subject` |
| `apiauth.GetUserIDFromAPIContext(ctx)` | `GetSubjectFromAPIContext(ctx)` |
| `httpauth.Middleware.UserParamName` | `SubjectParamName` |
| `httpauth.Middleware.GetLoggedInUserId(r)` | `GetLoggedInSubject(r)` |
| `httpauth.OneAuth.SetLoggedInUserID(...)` | `SetLoggedInSubject(...)` |
| `grpc.UserIDFromContext` / `UserIDFromContextWithConfig` | `SubjectFromContext` / `SubjectFromContextWithConfig` |
| `grpc.UserIDToOutgoingContext` / `WithKey` | `SubjectToOutgoingContext` / `WithKey` |
| `grpc.DefaultMetadataKeyUserID = "x-user-id"` | `DefaultMetadataKeySubject = "x-subject"` |
| `grpc.Config.MetadataKeyUserID` | `MetadataKeySubject` |

**Active sessions invalidated.** The session-cookie key flipped from `loggedInUserId` to `loggedInSubject`. Cookies issued by v0.1.3 and earlier are not recognised by v0.1.4 — affected users will be prompted to log in again. No code or data migration needed; the new cookies are issued on next login.

**gRPC clients/servers must upgrade in lock-step.** The metadata header changed from `x-user-id` to `x-subject`. A v0.1.4 server will not see subjects sent by a v0.1.3 client (and vice versa).

**`SwitchUser*` stays.** `grpc.SwitchUserToOutgoingContext`, `SwitchUserToOutgoingContextWithKey`, `MetadataKeySwitchUser`, and `DefaultMetadataKeySwitchUser = "x-switch-user"` are unchanged — impersonation is human-user-scoped by nature.

Combined with v0.1.3, this completes the Subject vocab rename across the library.

---

## Version 0.1.3 (PR 2a — token Subject foundation)

### Subject vocabulary — phase 1: token-bearing types

**Breaking.** The token-bearing types in `core/` and `localauth/` now use **Subject** (RFC 7519 `sub`) for the principal field, replacing **UserID**. Motivation: in `client_credentials` flows the principal is a service account, not a human user — `UserID` was misleading. `Subject` is what the JWT `sub` claim, RFC 7662 introspection, RFC 8693 token exchange, and Spring Security / JWT / X.509 idiom all call this concept. Account-model types (`accounts.User`, `accounts.Identity.UserID`, `accounts.Username.UserID`) stay as **UserID** — those are application user records, not OAuth subjects.

**Go API renames:**

| Before | After |
|---|---|
| `core.RefreshToken.UserID` (`json:"user_id"`) | `core.RefreshToken.Subject` (`json:"subject"`) |
| `core.APIKey.UserID` (`json:"user_id"`) | `core.APIKey.Subject` (`json:"subject"`) |
| `localauth.VerificationToken.UserID` (`json:"user_id"`) | `localauth.VerificationToken.Subject` (`json:"subject"`) |
| `RefreshTokenStore.CreateRefreshToken(userID, ...)` | `CreateRefreshToken(subject, ...)` |
| `RefreshTokenStore.RevokeUserTokens(userID)` | `RevokeSubjectTokens(subject)` |
| `RefreshTokenStore.GetUserTokens(userID)` | `GetSubjectTokens(subject)` |
| `APIKeyStore.CreateAPIKey(userID, ...)` | `CreateAPIKey(subject, ...)` |
| `APIKeyStore.ListUserAPIKeys(userID)` | `ListSubjectAPIKeys(subject)` |
| `VerificationTokenStore.CreateToken(userID, ...)` | `CreateToken(subject, ...)` |
| `VerificationTokenStore.DeleteUserTokens(userID, ...)` | `DeleteSubjectTokens(subject, ...)` |

All three backends (`stores/fs`, `stores/gorm`, `stores/gae`) updated. Models renamed in lock-step.

**Storage migration required.** GORM column renames: `refresh_tokens.user_id` → `subject`, `api_keys.user_id` → `subject`, `auth_tokens.user_id` → `subject`. FS JSON storage: `user_id` → `subject` on the three token kinds. GAE Datastore: same field renames. Existing data must be migrated or the affected stores reset — see `docs/MIGRATION.md`.

**Out of scope (deferred to PR 2b):**
- `core.GetUserIDFromContext` / `SetUserIDInContext` / `DefaultUserParamName="loggedInUserId"`
- `core.GetUserScopesFunc`
- `apiauth.PasswordGrantResponse.UserID` / `TokenInfo.UserID` / `GetUserIDFromAPIContext`
- `httpauth.Middleware.GetLoggedInUserId` / `OneAuth.SetLoggedInUserID` (public surface stays — internals flip in PR 2b)
- `grpc.UserIDFromContext` / `DefaultMetadataKeyUserID="x-user-id"`
- Session cookie key `loggedInUserId` (PR 2b invalidates active sessions)

See issue tracker for PR 2b.

---

## Version 0.1.2

### Client SDK — gRPC-shape `ClientCredentials` + RFC 8707 / RFC 9396 plumbing

**New `AuthClient.ClientCredentials(req *ClientCredentialsRequest)`.** Consolidated entry point for the client_credentials grant. Single request struct carries `ClientID`, `ClientSecret`, optional `ClientAssertion` (private_key_jwt), `Scopes`, `Resources []string` (RFC 8707 resource indicators — emitted as repeated `resource` form values per §2), and `AuthorizationDetails []core.AuthorizationDetail` (RFC 9396 — JSON-encoded into the `authorization_details` form value per §6.1). Extends the `(ctx, *XRequest) → (*XResponse, error)` convention adopted by `apiauth/` (#175) and `admin/` (#172) into the client SDK.

**`ClientCredentialsToken` and `ClientCredentialsTokenWithAssertion`** now wrap `ClientCredentials` — existing callers unaffected. New code should target the request struct directly to access `Resources` / `AuthorizationDetails`.

**`ClientCredentialsSource.Resources` and `.AuthorizationDetails`** restored as live fields, this time actually wired into the underlying token request. Resolves the dead-field gap that #211 flagged when removing the previous (non-functional) versions.

End-to-end coverage: `TestRAR_ClientCredentials_SDKForm` in the e2e suite exercises the full SDK → AS round-trip with both RFCs in play.

Follow-up to #211.

---

## Version 0.1.1

### Client SDK — `private_key_jwt` ergonomics

**`ClientAssertionConfig.Audience` (additive).** New field on `ClientAssertionConfig` overrides the `aud` claim of a minted assertion. When empty, behaviour is unchanged (positional argument — typically the token endpoint URL — per OIDC Core §9). Set the field when targeting an RFC 7523bis-strict AS that requires `aud` to be the issuer identifier. `MintClientAssertion` and `ClientCredentialsTokenWithAssertion` both honour the override.

**`ClientCredentialsSource.ClientAssertion` (additive).** New `*ClientAssertionConfig` field on `ClientCredentialsSource`. When non-nil, the source routes through `ClientCredentialsTokenWithAssertion` instead of `ClientCredentialsToken`, applying the same caching, OnToken, and `ProactiveRefresher` machinery as the secret-based path. `ClientSecret` is ignored when `ClientAssertion` is set.

**Cleanup — dead fields removed (breaking).** Removed `ClientCredentialsSource.Audience` (RFC 8707 resource indicator) and `ClientCredentialsSource.AuthorizationDetails` (RFC 9396). Both fields were declared on the struct but **never** wired into the underlying token request, making them silent no-ops. No internal caller and no downstream consumer (mcpkit, goapplib, projects/*) set these fields. Proper RFC 8707 / RFC 9396 plumbing for client_credentials is tracked as a follow-up — the right home is the token-request layer, not the cached source.

Unblocks SEP-1046 conformance work in mcpkit issue 447 (umbrella 439).

See: issue 211.

---

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
