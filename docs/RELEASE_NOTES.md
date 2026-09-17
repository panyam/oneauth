# OneAuth Release Notes

> Versions 0.1.7 through 0.1.36 shipped tag-only; this file picks up again at
> 0.1.37. Use `git log v0.1.<n-1>..v0.1.<n>` for anything in that range.

## Version 0.1.37

### DPoP — sender-constrained access and refresh tokens (RFC 9449)

A token can now be bound to a key the client holds, so a leaked token is
unusable by whoever leaks it. Both halves ship together: the authorization
server binds the token, and the resource server refuses to honor it unless the
presenter proves the key.

Everything here is off by default. An existing deployment that wires neither
side behaves exactly as it did in 0.1.36.

**Issuance (PR 370).** Set `OneAuthConfig.DPoP` to a `DPoPProofValidator` and
the token endpoint starts accepting a `DPoP` proof header on any grant. A
request that carries a valid proof gets `cnf.jkt` in the access token,
`token_type: DPoP` in the response, and a refresh token only that key can
rotate. A request with no proof gets exactly what it got before.

- Proof validation per §4.3: `typ`, an asymmetric `alg` allow-list (ES256,
  RS256, PS256 by default; symmetric algorithms can never be enabled), the
  embedded public `jwk` with private members rejected, the signature, `htm`,
  `htu`, an `iat` window, and `jti` replay through the existing `JTIStore`.
- Refresh-token binding persists in all three backends (FS, GORM, Datastore)
  and is carried forward on rotation. A bound refresh token presented without
  its key is `invalid_grant`.
- `dpop_signing_alg_values_supported` on authorization-server metadata.

**Enforcement (PR 372).** Set `APIMiddleware.DPoP` and the resource server
accepts `Authorization: DPoP <token>` with a per-request proof, checks the
proof's `ath` against the presented token, and matches the proof key against
the token's `cnf.jkt`.

- A bound token presented under the `Bearer` scheme is refused, per §7.2.
  Without that check a thief drops the `DPoP` header and the binding buys
  nothing.
- `WWW-Authenticate` advertises both schemes, with error information on the
  scheme the client actually used.
- `APIMiddleware.RequireDPoP` refuses bearer presentations outright, backing
  `dpop_bound_access_tokens_required` on protected-resource metadata
  (RFC 9728), which lands alongside `dpop_signing_alg_values_supported`.
- Introspection responses carry `cnf`, so a resource server that validates
  remotely enforces the same binding as one validating the JWT locally.

**Rollout order.** A resource server with `APIMiddleware.DPoP` unset accepts a
bound token as an ordinary bearer token, which RFC 9449 §7.2 both predicts and
permits. Wire enforcement at the resource servers first, then start issuing
bound tokens. The reverse order leaves a window where the binding protects
nothing.

**Deployment note (GORM).** The `refresh_tokens` table gains a
`confirmation_jkt` column. Run `AutoMigrate` before deploying. The column is
empty for existing rows, which reads back as an unbound token, so current
behavior is preserved. Datastore adds an equivalent optional property and
needs no migration.

**API additions.** `core.Confirmation` (the RFC 7800 `cnf` claim as a type),
`CreateAccessTokenRequest.Confirmation`, `CreateAccessTokenResponse.TokenType`,
`RefreshGrantRequest.Confirmation` and the same field on each grant request
type, `TokenInfo.Confirmation`, `IntrospectionResult.Cnf`, and
`IntrospectionValidator.ValidateInfo`. The confirmation is a struct rather
than a bare thumbprint string so that mTLS certificate binding (`x5t#S256`,
issue 335) adds a field instead of a second parameter on every issuance path.

**One behavior change without a flag.** `cnf` is now a standard claim, so it
no longer appears in `TokenInfo.CustomClaims`. Code reading `cnf` out of the
custom-claims bag should read `TokenInfo.Confirmation` instead. This also stops
a deployment's `CustomClaimsFunc` from writing a binding the server never
verified.

**Conformance.** Validated against the RFC's own published vectors: the
Figure 2 proof and the Figure 9 thumbprint it produces, plus the Figure 13
access token and the Figure 14 `ath` computed from it.

Closes issue 336. Remaining RFC 9449 surface: the nonce protocol (§8, §9) and
`dpop_jkt` on the authorization request (§10). Keycloak interop for the
resource-server half is issue 371.

### Documentation

Coverage tables that still listed DPoP as a gap are corrected (`RFC_9449.md`,
`RFC_9728.md`, the Authlete gap analysis, the FAPI readiness note), and
`ROADMAP.md` records the two PRs with the design decisions behind them
(PR 373). `CAPABILITIES.md` gains the `dpop-sender-constrained-tokens` entry.
`testutil`'s `WithConfidentialClient` is documented in its sidecar (PR 367).

### Dependencies

Grouped `go_modules` security bumps across the workspace (PRs 368, 369).

---

## Version 0.1.6

### Convention closure for issues 175 + 172

The `(ctx, *XRequest) → (*XResponse, error)` convention adopted across the library (CLAUDE.md "gRPC-shape convention everywhere") is now closed-loop for `apiauth/` and `admin/`:

- **`apiauth/`**: all five transport-agnostic interfaces (`TokenIssuer`, `TokenValidator`, `TokenIntrospector`, `TokenRevoker`, `ClientAuthenticator`) follow the convention. HTTP handlers are thin wrappers. Four legacy positional methods on `APIAuth` — `CreateAccessToken`, `ValidateAccessToken`, `ValidateAccessTokenFull`, `VerifyTokenFunc` — are now marked `// Deprecated:` and point at the canonical interface methods. They remain as the internal implementation backing the HTTP handlers; consolidation + outright removal is tracked under issue 218.
- **`admin/`**: `ClientRegistrar` interface (Register / RegisterLegacy / ListClients / GetClient / DeleteClient / RotateSecret) is in shape, implemented on `AppRegistrar`, and covered by pure-Go interface tests (`client_admin_test.go`) that bypass HTTP entirely. `ClientRegistrationManager` (RFC 7592 self-service) already adopted the convention via issues 168/169/170.

Documentation updated: `apiauth/SUMMARY.md` now carries the convention paragraph that `admin/SUMMARY.md` already had.

Closes 175, 172. Follow-up consolidation tracked under 218. Client SDK migration tracked under 217.

---

## Version 0.1.5

### Client SDK — RFC 8693 token exchange + RFC 7523 §2.1 JWT bearer grant

Two new general-purpose OAuth primitives on `AuthClient`. Both are additive — no existing behavior changes.

**`AuthClient.TokenExchange(*TokenExchangeRequest)` — RFC 8693.** Exchange a subject token (plus optional actor token / requested type / audience / resource / scope) for a freshly issued token. Returns `TokenExchangeResponse` including `IssuedTokenType` (required by RFC 8693 §2.2). Useful for bridging trust domains — e.g. exchanging an upstream-IdP ID token for an internal ID-JAG.

**`AuthClient.JwtBearerGrant(*JwtBearerGrantRequest)` — RFC 7523 §2.1.** Present a signed JWT (typically the output of a prior token exchange or trusted upstream issuance) as `assertion` at the token endpoint to obtain an access token. Distinct from the `private_key_jwt` client authentication method, which authenticates the client itself — both can coexist in the same request.

Both methods reuse the existing `AuthClient` client-authentication negotiation: `client_secret_basic`, `client_secret_post`, and `private_key_jwt` (via `ClientAssertionConfig`) all work transparently.

**Wire shape:** `application/x-www-form-urlencoded` with the appropriate `grant_type` value. `audience` and `resource` are emitted as repeated form values per RFC 8693 §2.1 / RFC 8707 §2. `scope` is space-delimited per RFC 6749 §3.3.

**Tests:** 5 unit tests covering wire shape + minimal request omission + all three client-auth methods, plus 2 e2e tests against the in-process `testutil.TestAuthServer` with `TrustedAssertionIssuers` configured.

Near-term consumer: mcpkit's SEP-990 enterprise-managed authorization (mcpkit issue 448), which chains these two primitives in an `EnterpriseManagedTokenSource` with two-stage caching.

See issue 213.

---

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
