# OneAuth Release Notes

> Versions 0.1.7 through 0.1.36 shipped tag-only; this file picks up again at
> 0.1.37. Use `git log v0.1.<n-1>..v0.1.<n>` for anything in that range.

## Version 0.1.41

### DPoP audit and requiring DPoP (issue 88, PR 396)

We walked RFC 9449 and the DPoP parts of FAPI 2.0 against the code, one
requirement at a time. The matrix is in `docs/SECURITY_AUDIT.md`, also on the
site under Conformance. The walk turned up a few bugs and one missing feature.

- **Requiring DPoP.** `OneAuthConfig.RequireDPoP` makes the token endpoint
  refuse any request without a proof (FAPI 2.0 §5.3.2.1). A client registered
  with `dpop_bound_access_tokens` (RFC 9449 §5.2) is held to it on its own.
  The field is on `core.AppRegistration` and DCR. Either way a missing proof
  gets 400 `invalid_dpop_proof`, never a bearer token.
- **PAR with a shared validator.** `/par` checks a proof's `htu` against its
  own URL, so `MountAuthorize` giving it the token endpoint's validator works.
  Before, every correct PAR proof failed behind a proxy, and a proof made for
  the token endpoint was accepted at `/par`. PAR also answers a nonce
  challenge with `use_dpop_nonce` and `DPoP-Nonce`.
- **`htu` comparison** follows RFC 3986 §6.2 normalization (case, default
  ports, percent-encoding, dot segments).
- RSA proof keys under 2048 bits are refused, `jti` is capped at 256 bytes, and
  `apiauth.FAPIDPoPAlgs()` returns ES256 and PS256.
- **SDK.** The automatic refresh now carries a proof, so a DPoP client can
  redeem its own bound refresh token. A `DPoP-Nonce` on any response is kept
  for the next request.
- **GORM and GAE app stores** now persist `dpop_bound_access_tokens`, and the
  `backchannel_logout_uri` / `backchannel_logout_session_required` settings
  they used to drop, which switched off back-channel logout after a restart.

### The refresh grant checks the client (issue 395, PR 397)

The refresh grant used to check only the token, so a leaked refresh token
redeemed under any `client_id`, or none, and a confidential client's token
redeemed without its secret (RFC 6749 §6).

- If the token's owner is registered confidential, the request has to
  authenticate as a client, or it gets 401 `invalid_client`.
- The token must belong to the presenting `client_id`, or the grant answers
  `invalid_grant` before rotating, so a refused attempt doesn't use up the
  owner's token. A token stored with no client still redeems.
- `RefreshGrantRequest.ClientID` carries the presenting client for library
  callers of `TokenIssuer.RefreshGrant`.
- The shared confidential-client check treats an AppStore error other than
  not-found as a 500, where it used to treat the client as public. This also
  reaches jwt-bearer, token-exchange and PAR.
- **SDK.** `ServerCredential.ClientID` records which client a credential was
  issued to, and the automatic refresh sends it instead of `"cli"`.

### Upgrading

- **GORM deployments need `AutoMigrate`** for the new app-registration columns
  (`dpop_bound_access_tokens` and the two back-channel logout fields).
- **Refresh callers must send their `client_id`**, and confidential clients
  their credentials. Callers that left `client_id` off, or sent another one,
  are now refused.
- **The SDK's automatic refresh sends no client secret**, so a confidential
  client logged in with `LoginWithBrowser` and a `ClientSecret` can't
  auto-refresh. Call `RefreshToken` with the secret (issue 395 item 4).

## Version 0.1.40

### Typed login and token errors (issues 392, 393, PR 394)

A caller can now tell why a login failed without matching on text. That's
what mcpkit needs to re-register a client the server has forgotten, without
showing the consent page again to someone who clicked Deny.

- **`LoginWithBrowser`** returns `*AuthorizeError` (the AS refused
  `/authorize`), `*CallbackError` (`?error=` on the redirect, e.g.
  `access_denied`), `*TokenError` (the code exchange failed),
  `*BrowserOpenError` (the opener failed, unwrapping to its cause) and
  `ErrLoginTimeout`. Use `errors.As` / `errors.Is`. The messages are the same
  as before.
- **`*TokenError` from every grant**: `Login`, `ClientCredentials`,
  `RefreshToken`, `JwtBearerGrant`, `TokenExchange`, `DeviceAuthorization`,
  and `PollDeviceToken` for codes other than its four RFC 8628 sentinels.
  A token endpoint that answers with a non-JSON error page now reports its
  status instead of a JSON decode error.
- **JSON `/authorize` errors.** oneauth's error page for an unknown client or
  unregistered `redirect_uri` answers with the RFC 6749 §5.2 JSON object
  when `Accept` lists `application/json`. `FollowRedirects` and
  `ApproveConsent` send `Accept: text/html, application/json;q=0.9`, so they
  get `AuthorizeError.Code` from oneauth and from Keycloak. For servers that
  only send HTML, `AuthorizeError.Body` is the page's visible text.

## Version 0.1.39

Documentation only; the code is the same as 0.1.38. The client SDK guide
covers the caller-owned listener, `RedirectURI`, `ApproveConsent` and the
fail-fast `FollowRedirects`, and its browser-login snippets use the current
`LoginWithBrowser(ctx, &BrowserLoginRequest{...})` signature.
`CAPABILITIES.md`, the roadmap and the Keycloak test README are brought up to
date, and these notes now cover 0.1.38.

## Version 0.1.38

### DPoP, the rest of RFC 9449

0.1.37 shipped DPoP-bound tokens on both sides. This release finishes the
spec and gives the client SDK the means to use it.

- **`dpop_jkt` on `/authorize` (PR 378).** The authorization code is bound to
  the client's DPoP key, so an intercepted code can't be redeemed with a
  different one (§10). A missing proof against a bound code is
  `invalid_grant`.
- **Client SDK proofs (PR 379).** `client.DPoPKey` (ES256) mints a proof per
  request, and `WithDPoPKey` attaches proofs to token requests, presents
  tokens under the `DPoP` scheme with `ath`, and sends `dpop_jkt` on browser
  login.
- **The nonce protocol (PR 384).** `DPoPConfig.NoncePolicy` with a stateless
  HMAC `NonceSource` lets the AS (§8) and the resource server (§9) demand a
  server-supplied nonce; the SDK retries `use_dpop_nonce` automatically. Off
  by default.
- **Keycloak interop (PR 385).** OneAuth's middleware accepts a
  Keycloak-issued bound token and refuses it presented as Bearer.

### Pushed authorization requests (RFC 9126, PR 381)

`POST /par` stores the authorization request and returns a `request_uri`, and
`/authorize` accepts a request carrying only `client_id` + `request_uri`.
Mounted by `MountAuthorize` when `AuthorizeMountConfig.PushedStore` is set,
with in-memory and GORM stores. A push may carry a DPoP key in its header or
as `dpop_jkt` (RFC 9449 §10.1).

### Loopback redirects for native clients (PR 388)

- **Caller-owned listener (issue 387).** `BrowserLoginRequest.Listener` takes
  a loopback listener the caller already bound, and
  `LoopbackRedirectURI(addr)` names the redirect the login will send. A
  client that registers via DCR first registers exactly that string, so an AS
  that matches `redirect_uri` byte-for-byte accepts it, and nothing can take
  the port between registration and login. `LoginWithBrowser` closes the
  listener when it returns.
- **`RedirectURI`** sends a registered redirect verbatim (an IP literal, a
  path other than `/callback`). It must be loopback `http` with an explicit
  port matching the listener, checked before the browser opens.
- **`FollowRedirects` fails fast.** A 400-or-worse from `/authorize` now
  returns the AS's `error` / `error_description`. Before, `LoginWithBrowser`
  sat out its timeout (five minutes by default) waiting for a callback that
  was never coming.
- **`ApproveConsent`** is a headless opener for demo servers that answer
  `/authorize` with a consent form. It posts the approve button and refuses a
  form without one.
- **Behavior change on the AS (issue 389).** `/authorize` now ignores the port
  when matching an `http` redirect on 127.0.0.1, [::1] or localhost, as
  RFC 8252 §7.3 requires; scheme, host, path and query still match exactly.
  Deployments relying on the old exact port match for loopback clients will
  now accept any port. `apiauth.RedirectURIMatches` is exported for custom
  `RedirectURIValidator`s.

### Tooling and CI

- The Go directive is 1.26.9 across all modules (GO-2026-6617, an HTTP/2
  HPACK race in `net/http`), with `golang.org/x/net` v0.60.0 where it's
  pulled in (PR 388). `go.opentelemetry.io/otel/sdk` 1.45.0 (PR 376).
- The Keycloak interop workflow runs `make testkcl` and triggers on relevant
  PRs (PR 390). It had never got past starting Keycloak before. The test
  realm defines Keycloak's `basic` scope so tokens carry `sub` on 25+, and
  `test-confidential` names itself in `aud` so 26.x lets it introspect.
- The docs site renders mermaid diagrams and publishes the spec library and
  guides (PR 383).

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
