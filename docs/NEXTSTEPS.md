# OneAuth Next Steps

## Priority & Urgency Legend

**Priority Levels:**
- `P0` — Critical path, blocks other work or releases
- `P1` — High value, should be done soon
- `P2` — Nice to have, do when time permits

**Urgency Tags:**
- `[BLOCKER]` — Blocks a release or other features
- `[SECURITY]` — Security vulnerability or compliance risk
- `[COMPLIANCE]` — Required for regulatory compliance (GDPR, SOC2, etc.)
- `[ADOPTION]` — Blocks user/customer adoption
- `[DX]` — Developer experience improvement
- `[SCALE]` — Required for production scale

**Dependency notation:** `Requires: X, Y` means those items must be completed first.

---

## Completed (Go E2E Tests — #44)

### In-Process E2E Test Suite
- [x] `tests/e2e/` — 28 Go e2e tests using httptest.NewServer (no subprocess, no Python)
- [x] Auth server + 2 resource servers start in-process (~2s total)
- [x] All 4 previously-skipped federated flow tests now work (no JWKS timing race)
- [x] Race detector works across all servers (same process)
- [x] Remote mode: `TEST_BASE_URL=https://...` for GAE verification
- [x] `make e2e` target, wired into `make test-hard`
- [x] Covers: health, auth enforcement, app lifecycle, token refresh, security, federated flow, blacklist

---

## Completed (Load Testing — #38)

### Performance Verification
- [x] Load tests in `tests/integration/test_10_load.py` using `hey` (#38)
- [x] Health endpoint: 1000 req @ 50 concurrent → zero errors
- [x] Login flood: 50 concurrent wrong-password attempts → no 500s
- [x] JWT validation throughput: 500 req @ 50 concurrent → all 200s
- [x] Admin endpoint concurrent reads → no 500s
- [x] `make test-load` for standalone load testing
- [x] `make test-hard` now includes: unit + integration + load + secret scan

---

## Completed (Secret Scanning + ZAP — #36, #37)

### CI Security Scanning
- [x] Gitleaks secret scanning in CI — detects accidentally committed secrets (#36)
- [x] `.gitleaks.toml` config with allowlisted test files and known test values
- [x] `make secrets` for local scanning
- [x] ZAP baseline scan against live server on push to main (#37)
- [x] `.zap-rules.tsv` for suppressing known false positives
- [x] All GitHub Actions pinned by SHA (CVE-2025-30066 mitigation)

---

## Completed (JWT Blacklist — #23)

### Token Revocation
- [x] `core.TokenBlacklist` interface + `InMemoryBlacklist` implementation (#23)
- [x] `jti` (JWT ID) claim in all access tokens (RFC 7519 §4.1.7)
- [x] `APIAuth.Blacklist` — checks blacklist in `ValidateAccessToken` and `ValidateAccessTokenFull`
- [x] `APIMiddleware.Blacklist` — checks blacklist in middleware validation
- [x] Auto-expiring entries (no unbounded growth)
- [x] Backward compatible: nil blacklist = stateless validation (no change)
- [x] 10 tests covering revocation, expiry, middleware, multi-tenant, and false-positive prevention

---

## Completed (Security Hardening Batch — #28, #24, #14, #15, #29, #31, #33, #34, #35)

### Crypto & Validation
- [x] Min RSA key size 2048 bits, NIST SP 800-57 (#29)
- [x] `EncodePrivateKeyPEM` returns error instead of panic (#29)
- [x] `SigningMethodForAlg` returns error on unknown algorithms (#29)
- [x] Audience validation in `ValidateAccessToken`/`ValidateAccessTokenFull` — RFC 7519 §4.1.3 (#33)
- [x] OAuth state cookie TTL 30d → 10m (#29)

### Rate Limiting & Lockout
- [x] `core.RateLimiter` interface + `InMemoryRateLimiter` (token bucket) (#31)
- [x] `core.AccountLockout` — locks after N failures, auto-expires (#31)
- [x] `LocalAuth.RateLimiter` + `LocalAuth.Lockout` fields (#31)
- [x] Timing oracle fix — dummy bcrypt on user-not-found (CWE-208) (#31)

### Middleware & Headers
- [x] `httpauth.SecurityHeaders` middleware — HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy (#28)
- [x] `httpauth.LimitBody` middleware — 413 on oversized requests (#34)
- [x] JWKS ETag + If-None-Match → 304 support (#24)

### Static Analysis & CI
- [x] `jwt/v5` upgraded v5.2.1 → v5.2.2, Go 1.24 → 1.26.1 (#14)
- [x] `govulncheck` passes clean — 0 vulnerabilities (#14)
- [x] `make vulncheck`, `make seccheck`, `make lint` targets (#14, #15)
- [x] GitHub Actions CI: test + security jobs on every push/PR (#35)

---

## Completed (FS Path Traversal Fix — #17)

### Storage Backend Security
- [x] `safeName()` sanitizer in `stores/fs/utils.go` — rejects `..`, null bytes, absolute paths; replaces `/`, `\`, `:`
- [x] Applied to 6 vulnerable stores (user, key, channel, token, apikey, username)
- [x] Directory permissions: `0755` → `0700`; file permissions: umask → `0600`
- [x] 50+ security tests in `stores/fs/security_test.go`
- [x] Already-safe stores documented (identity: `filepath.Base`, refresh token: SHA256 hash)

---

## Completed (Sub-Module Split — #43)

### Heavy Backends → Separate go.mod
- [x] Core module trimmed to 6 direct deps (jwt, scs, fernet, x/crypto, x/oauth2, testify)
- [x] `stores/gorm/go.mod` — evicts gorm.io/gorm + CGo sqlite
- [x] `stores/gae/go.mod` — evicts cloud.google.com/go/datastore + GCP SDK
- [x] `saml/go.mod` — evicts crewjam/saml
- [x] `grpc/go.mod` — evicts google.golang.org/grpc
- [x] `oauth2/go.mod` — evicts x/oauth2/google provider deps
- [x] `cmd/*/go.mod` — all binaries are sub-modules
- [x] `go.work` for local multi-module dev
- [x] Makefile: `ball`, `tall`, `tidy`, `deps`, `norep`, `rep`
- [x] Binaries output to `build/` (gitignored)
- [x] Migration guide: `docs/MIGRATION.md`

---

## Completed (Security Hardening + Reorganization)

### JWKS Security (#26) + JWT Security Tests (#16)
- [x] `key_ops: ["verify"]` on all JWK entries (RFC 7517 §4.3)
- [x] 5 safety-proof tests proving JWK struct cannot leak private key fields
- [x] 13 security tests in `apiauth/security_test.go`: algorithm confusion (CVE-2015-9235, alg:none), claim validation (expired, wrong type/issuer/sub), edge cases
- [x] `ExampleAPIMiddleware_algorithmConfusionPrevention` — runnable attack scenario documentation
- [x] `ExampleJWKSHandler_securityProperties` — runnable JWKS safety proof
- [x] Closed #4 (asymmetric signing), #7 (JWKS), #16 (JWT security tests), #21 (CSRF), #26 (JWKS security)
- [x] Deprioritized #22 (FS permissions) to P2 — FS stores are dev/test only

### Root .go Files → Subpackages
- [x] Created `core/` — foundation types, interfaces (User, Identity, Channel, stores, tokens, credentials, scopes, email, context)
- [x] Created `keys/` — key storage (KeyRecord, KeyLookup, KeyStorage, InMemoryKeyStore, EncryptedKeyStorage, KidStore, JWKSHandler, JWKSKeyStore)
- [x] Created `admin/` — admin auth (AdminAuth, AppRegistrar, MintResourceToken)
- [x] Created `apiauth/` — API auth (APIAuth, APIMiddleware, context helpers)
- [x] Created `localauth/` — local auth (LocalAuth, signup, helpers)
- [x] Created `httpauth/` — HTTP middleware (Middleware, CSRFMiddleware, OneAuth mux)
- [x] Updated all store backends (fs, gorm, gae) to import from core/ and keys/
- [x] Updated cmd/, examples/, keystoretest/ consumers
- [x] All tests passing, all packages build clean
- [x] SUMMARY.md in each subpackage for LLM discoverability
- [x] Used `git mv` to preserve file history where possible
- [x] BasicUser fields exported (ID, ProfileData) for cross-package access

---

## Completed (Federated Auth Demo)

### Reference Server Browser UI
- [x] Template-based HTML pages (landing, login, signup, dashboard, forgot/reset password)
- [x] `APIAuth` wiring for `POST /api/token` (password + refresh token grants)
- [x] User stores (FS and GORM) via config
- [x] JWT-based session cookies (`oa_token`)

### Demo Stack (`demo/` + `cmd/demo-hostapp/` + `cmd/demo-resource-server/`)
- [x] 6-service Docker Compose: PostgreSQL, oneauth-server, 2 apps, 2 resource servers
- [x] App auto-registration with oneauth-server on startup
- [x] Startup credential verification — auto re-registers if auth server DB was reset
- [x] Independent FS-backed user databases per app
- [x] Interactive resource token minting and validation UI with guided walkthrough
- [x] Cross-app and cross-resource-server JWT validation via shared KeyStore
- [x] CORS support on resource servers for browser-based validation
- [x] Devloop config for live-reload development (PG in Docker, services native)
- [x] Per-page template isolation (fixed template content block collision)

### Integration Tests (test_05 through test_08)
- [x] Browser auth flow (signup, login, logout, cookie management)
- [x] Federated flow (app registration, token minting, resource server validation)
- [x] Multi-app scenarios (cross-resource-server, signature mismatch rejection)
- [x] Token refresh lifecycle (password grant, refresh grant, token reuse detection, revocation)

---

## Completed (Client SDK — Phase 4)

### Client SDK (`client/` package)

- [x] `CredentialStore` interface (Get, Set, Remove, List credentials) ✅
- [x] `ServerCredential` struct (access token, refresh token, expiry, user info) ✅
- [x] `client/stores/fs/` — FS-based credential store (`~/.config/<app>/credentials.json`) ✅
- [x] `AuthTransport` — `http.RoundTripper` that injects Bearer headers ✅
- [x] `NewHTTPClient` convenience wrapper ✅
- [x] Automatic token refresh (on 401 and before expiry) ✅

---

## Completed (Federated Auth)

- [x] **P0** `CustomClaimsFunc` + multi-tenant `KeyStore` interface (#2) ✅
- [x] **P0** App registration API + service component (#3) ✅
  > `AdminAuth` interface, `AppRegistrar` HTTP handler, `MintResourceToken` helper, reference server
- [x] **P1** Persistent `KeyStore` implementations — FS, GORM, GAE (#5) ✅
  > `WritableKeyStore` interface, shared test suite (`keystoretest`), GORM/FS/GAE implementations
- [x] **P1** `APIMiddleware` enhancements — `TokenQueryParam` for query-param token extraction, `GetCustomClaimsFromContext()` for custom claims in context ✅
  > Needed for WebSocket auth where clients can't always set Authorization headers.

---

## Completed (v0.3.0)

### SignupPolicy - Configurable Signup Requirements
- [x] `SignupPolicy` type with configurable field requirements
- [x] Preset policies: `PolicyUsernameRequired`, `PolicyEmailOnly`, `PolicyFlexible`
- [x] Custom username patterns via regex
- [x] Configurable minimum password length

### Structured Error Handling
- [x] `AuthError` type with code, message, and field
- [x] Custom error handlers (`OnSignupError`, `OnLoginError`)
- [x] Field-level error codes for form validation
- [x] Backwards-compatible JSON error responses

### Username Uniqueness (UsernameStore)
- [x] `UsernameStore` interface for username → userID mapping
- [x] FS implementation with atomic file operations
- [x] GORM implementation with optimistic concurrency
- [x] GAE implementation with Datastore transactions
- [x] Case-insensitive lookup with case-preserving storage

### Channel Linking (Multiple Auth Methods)
- [x] `NewEnsureAuthUserFunc` - channel-aware user creation for OAuth
- [x] `LinkLocalCredentials` - add password to OAuth-only users
- [x] `HandleLinkCredentials` - HTTP handler for linking credentials
- [x] `HandleLinkOAuthCallback` - link OAuth to existing password users
- [x] `NewCredentialsValidatorWithUsername` - username-based login
- [x] Profile tracking of linked channels (`profile["channels"]`)

---

## Completed (v0.2.0)

### Core Authentication
- [x] LocalAuth - browser-based login, signup, email verification, password reset
- [x] APIAuth - JWT access tokens, refresh tokens with rotation
- [x] API Keys for long-lived programmatic access
- [x] OAuth2 providers (Google, GitHub) with extensible base
- [x] Basic SAML support

### Security
- [x] Scope-based access control with role mapping
- [x] APIMiddleware for endpoint protection
- [x] Token rotation with theft detection (token family tracking)
- [x] Secure password hashing (bcrypt)
- [x] Cryptographically secure token generation

### Storage Backends
- [x] File-based stores (`stores/fs/`) - all 6 interfaces + UsernameStore
- [x] GORM stores (`stores/gorm/`) - SQL databases with auto-migration + UsernameStore
- [x] GAE/Datastore stores (`stores/gae/`) - Google Cloud + UsernameStore

### Infrastructure
- [x] gRPC support - context utilities, auth interceptors
- [x] Session management - cookie and header-based
- [x] Comprehensive test coverage (~3,000+ lines)

---

## Short-term

### Federated Auth (Remaining)

- [x] **P1** Asymmetric signing support — RS256/ES256 (#4) ✅
  > `MintResourceTokenWithKey` with auto-detected algorithm, `APIAuth.JWTSigningKey`/`JWTVerifyKey`,
  > `APIMiddleware.validateJWT` decodes PEM via `utils.DecodeVerifyKey`, `AppRegistrar` accepts `public_key` PEM for asymmetric registration,
  > shared keystoretest for asymmetric round-trip, algorithm confusion attack prevention

- [x] **P1** JWKS endpoint for federated public key discovery (#7) ✅
  > `JWKSHandler` serves `/.well-known/jwks.json` with asymmetric public keys (RS256/ES256). HS256 secrets never exposed.
  > `JWKSKeyStore` fetches keys from remote JWKS URL with background refresh and caching.
  > `utils/jwk.go` — JWK/JWKSet types, `PublicKeyToJWK`/`JWKToPublicKey` conversion (no new dependencies).
  > Demo resource server supports `JWKS_URL` env var as alternative to shared database.

### kid in JWTs + Key Rotation
- [x] **P1** kid (Key ID) in JWT headers + key rotation with grace period (#25) ✅
  > All minted JWTs include `kid` header (RFC 7638 thumbprint). `KidStore` retains old keys during rotation grace period.
  > `APIMiddleware` tries kid-based lookup first, falls back to `client_id` claim. Cross-app forgery prevented.
  > JWKS endpoint uses thumbprint-based kids. `CompositeKeyLookup` chains KeyStorage + KidStore.

### KeyStore Interface Refactor
- [x] **P0** Decompose KeyStore god interface (#40) ✅
  > Replaced `KeyStore`/`WritableKeyStore`/`KidResolver` with `KeyLookup` (read) + `KeyStorage` (read+write) + `KeyRecord` struct.
  > `EncryptedKeyStorage` correctly computes kid from plaintext. `JWKSKeyStore` implements only `KeyLookup`.
  > Adding new fields to `KeyRecord` doesn't change the interface.

### Encryption at Rest
- [x] **P1** `[SECURITY]` HS256 secret encryption at rest (#19) ✅
  > `EncryptedKeyStore` decorator wraps any `WritableKeyStore` with AES-256-GCM encryption.
  > HKDF-SHA256 key derivation from master key with versioned info string.
  > Asymmetric keys pass through unencrypted. Plaintext fallback for migration.
  > Configured via `ONEAUTH_MASTER_KEY` env var. Demo stack updated.

### Bug Fixes

- [x] **P0** Fix JWT `aud` claim validation for JSON arrays — RFC 7519 §4.1.3 (#52) ✅
  > `matchesAudience()` helper handles both string and `[]interface{}` aud formats. 8 new tests (array accepted/rejected across ValidateAccessToken, ValidateAccessTokenFull, and APIMiddleware). Unblocks Keycloak interop (#49).

### Phase 3: OAuth Integration for API

- [x] **P1** `[ADOPTION]` Headless OAuth authorization code + PKCE for CLI clients (#54) ✅
  > `LoginWithBrowser()` on `AuthClient` with loopback redirect (RFC 8252), PKCE, state validation, auto-discovery. 6 unit tests + Keycloak interop test (full auth code flow against real IdP).

- [ ] ~~**P0** `[BLOCKER]` Add API mode to OAuth callbacks~~ → Superseded by #54
  > ~~**Scenario**: A React SPA calls `/auth/google/callback?mode=api`...~~

- [ ] ~~**P0** `[BLOCKER]` Support token response for mobile OAuth flows~~ → Superseded by #54
  > ~~**Requires**: API mode OAuth callbacks~~

- [x] **P1** `[ADOPTION]` `client_credentials` grant support — RFC 6749 §4.4 (#53) ✅
  > Server: `handleClientCredentialsGrant` in `APIAuth` with `ClientKeyStore` field. Client: `ClientCredentialsToken()` on `AuthClient`. Supports `client_secret_post` and `client_secret_basic`. 8 unit + 2 e2e tests.

- [x] **P1** `[ADOPTION]` OAuth AS Metadata Discovery client — RFC 8414 (#51) ✅
  > `DiscoverAS()` in `client/discovery.go`. Fallback chain: RFC 8414 → OIDC Discovery. Path-based issuer support. 8 unit tests + Keycloak interop test.

- [x] **P1** `[SECURITY]` PKCE support for public clients (#27) ✅
  > PKCE (RFC 7636) enabled by default for all OAuth2 flows. `DisablePKCE` opt-out with warning.
  > Code verifier stored in HttpOnly cookie, code challenge sent as S256.
  > 8 tests covering full flow.

### Phase 4: Client SDK (Remaining)

- [ ] **P1** `[ADOPTION]` Migrate lilbattle CLI to use oneauth/client package
  > **Scenario**: Validate the client SDK works end-to-end by replacing lilbattle's hand-rolled auth with `oneauth/client`.
  >
  > **Urgency**: Proves the SDK works in real usage. Finds edge cases before wider adoption.
  >
  > **Requires**: Full client SDK (CredentialStore, AuthTransport, token refresh) — all done

### Phase 5: Model Generation with protoc-gen-dal

Reference: `lilbattle/protos/lilbattle/v1/gorm/models.proto` and `gae/` subfolder

Currently each store implementation redeclares model types (FSUser, GORMUser, GAEUser, etc.). Use protoc-gen-dal to generate database-specific models from a single proto definition.

- [ ] **P2** `[DX]` Proto-based model generation
  - [ ] Create `protos/oneauth/v1/models.proto` with core types (User, Identity, Channel, Token, etc.)
  - [ ] Create `protos/oneauth/v1/gorm/models.proto` with GORM annotations
  - [ ] Create `protos/oneauth/v1/gae/models.proto` with Datastore annotations
  - [ ] Generate models with `buf generate`
  - [ ] Refactor `stores/fs/` to use generated types
  - [ ] Refactor `stores/gorm/` to use generated GORM models
  - [ ] Refactor `stores/gae/` to use generated GAE models
  - [ ] Remove hand-written model types from store implementations
  > **Scenario**: Add a `last_login_at` field — update one proto file, run `buf generate`, all stores (FS, GORM, GAE) get the field automatically. Currently requires editing 3+ model files manually.
  >
  > **Urgency**: Developer experience. Current approach works but is tedious. Can defer until more schema changes needed.

### Improvements

- [ ] **P1** `[SECURITY]` Token blacklist for immediate JWT revocation
  > **Scenario**: User clicks "Sign out all devices". Without blacklist, existing JWTs remain valid until expiry (15 min). With blacklist, all tokens invalidated immediately.
  >
  > **Urgency**: Security gap. Compromised tokens cannot be revoked quickly. Required for enterprise customers.
  >
  > **Requires**: Redis store (for distributed deployments) OR in-memory (single instance)

- [ ] **P2** `[COMPLIANCE]` Audit logging with default implementations
  > **Scenario**: Security team needs to investigate suspicious activity. `AuditLog.Query(userID, "login_failed", last24h)` returns all failed login attempts with IP, timestamp, and user agent.
  >
  > **Urgency**: Required for SOC2, HIPAA compliance. Can defer if not targeting regulated industries yet.

### Standards & Interop (new — see [ROADMAP.md](ROADMAP.md) for full details)

- [x] **P1** `[ADOPTION]` Protected Resource Metadata — RFC 9728 (#46) ✅
  > `ProtectedResourceMetadata` struct + `NewProtectedResourceHandler` in `apiauth/`. 7 unit tests + 3 e2e tests. Wired into demo resource server and e2e test environment.

- [x] **P1** `[ADOPTION]` Token Introspection — RFC 7662 (#47) ✅
  > `IntrospectionHandler` in `apiauth/`. Resource servers POST tokens to auth server for validation. Checks blacklist, returns RFC 7662 response. Authenticated via client_credentials (#53). 9 unit + 3 e2e tests.

- [x] **P1** `[ADOPTION]` `[DX]` Keycloak interop test suite (#49) ✅
  > 10 interop tests proving `APIMiddleware` + `JWKSKeyStore` validate Keycloak-issued tokens. Pre-baked realm JSON, `make upkcl/testkcl/downkcl`, manual-trigger CI. Separate Go module.

- [x] **P2** `[ADOPTION]` DCR conformance wrapper — RFC 7591 (#48) ✅
  > `DCRHandler` in `admin/dcr.go`, served at `POST /apps/dcr` via `AppRegistrar.Handler()`. Maps JWK→PEM, client_uri→client_domain. 6 unit + 2 e2e tests.

- [x] **P2** `[ADOPTION]` Token Introspection client for resource servers — RFC 7662 (#55) ✅
  > `IntrospectionValidator` in `apiauth/introspection_client.go`. Integrates into `APIMiddleware` as fallback validation. Response caching. 7 unit + 1 e2e + 2 Keycloak interop tests.

- [x] **P2** `[ADOPTION]` OIDC Discovery metadata — RFC 8414 (#50) ✅
  > `ASServerMetadata` + `NewASMetadataHandler` in `apiauth/`. Serves `/.well-known/openid-configuration`. Metadata-only. 6 unit + 3 e2e tests (incl. `DiscoverAS` round-trip). Wired into reference server.

---

## Medium-term

### Security Enhancements

- [ ] **P1** `[SECURITY]` `[COMPLIANCE]` Multi-factor authentication (TOTP, WebAuthn)
  > **Scenario**: Bank app requires 2FA. User logs in with password, then enters 6-digit code from Google Authenticator. `auth.VerifyTOTP(userID, "123456")` completes login.
  >
  > **Urgency**: Required for fintech, healthcare, enterprise. Increasingly expected by all users.
  >
  > **Requires**: Token blacklist (for MFA bypass revocation)

- [ ] **P1** `[SECURITY]` Account lockout after failed attempts
  > **Scenario**: Attacker tries password spray attack. After 5 failed attempts, account locked for 15 min. Legitimate user sees "Account temporarily locked, try again in 14:32".
  >
  > **Urgency**: Basic security hygiene. Without this, brute force attacks are trivial.

- [ ] **P2** `[SECURITY]` Suspicious activity detection
  > **Scenario**: User logs in from NYC, then 5 min later from Tokyo. System flags impossible travel, triggers step-up auth or blocks login pending verification.
  >
  > **Urgency**: Advanced security. Nice for enterprise but not blocking.
  >
  > **Requires**: Audit logging, MFA (for step-up auth)

- [ ] **P1** `[SECURITY]` IP-based rate limiting (beyond current interface)
  > **Scenario**: Single IP makes 1000 login attempts/min across different accounts. Rate limiter blocks IP entirely: "Too many requests, try again later."
  >
  > **Urgency**: Prevents credential stuffing attacks. Current interface-only approach puts burden on implementer.
  >
  > **Requires**: Redis store (for distributed rate limiting)

### Features

- [ ] **P2** `[DX]` Remember me tokens (extended session cookies)
  > **Scenario**: User checks "Remember me" on personal laptop. Session lasts 30 days instead of closing with browser. `SetSessionOptions(RememberMe: true, Duration: 30*24*time.Hour)`.
  >
  > **Urgency**: UX improvement. Users expect this but can work around.

- [ ] **P1** `[COMPLIANCE]` Account deletion and data export (GDPR)
  > **Scenario**: EU user requests data deletion. `auth.DeleteAccount(userID)` removes all PII, tokens, sessions. `auth.ExportData(userID)` generates JSON with all stored user data.
  >
  > **Urgency**: Legal requirement for EU users. Required before EU market launch.

- [ ] **P2** `[DX]` Social provider profile synchronization
  > **Scenario**: User updates GitHub profile picture. On next OAuth login, oneauth updates local profile: `user.AvatarURL` reflects new GitHub avatar automatically.
  >
  > **Urgency**: Nice to have. Most apps don't need real-time sync.

- [ ] **P2** `[SECURITY]` Password strength validation
  > **Scenario**: User tries "password123". Registration fails: "Password must include uppercase, number, and special character. Strength: weak." Uses zxcvbn-style entropy check.
  >
  > **Urgency**: Security best practice but can be done client-side initially.

- [x] **P1** `[ADOPTION]` Token introspection endpoint — RFC 7662 (#47) ✅
  > Completed. See Standards & Interop section above.

### Infrastructure

- [ ] **P1** `[SCALE]` `[BLOCKER]` Redis store implementation
  > **Scenario**: App runs on 10 Kubernetes pods. Session created on pod-1 must be readable from pod-5. Redis store enables shared session state across instances.
  >
  > **Urgency**: Blocks production deployments with >1 instance. File-based stores don't work in clusters.

- [ ] **P2** `[ADOPTION]` MongoDB store implementation
  > **Scenario**: Team already uses MongoDB. `stores.NewMongoUserStore(mongoClient)` integrates oneauth without adding PostgreSQL dependency.
  >
  > **Urgency**: Expands addressable market. Not blocking if users can use GORM with other DBs.

- [ ] **P2** `[DX]` Metrics and observability hooks
  > **Scenario**: Ops team monitors auth health. `auth.OnLogin(func(ctx, user) { prometheus.LoginCounter.Inc() })` — custom hooks for login, logout, token refresh events.
  >
  > **Urgency**: Production readiness. Can defer for MVP but needed for serious deployments.

- [ ] **P2** `[DX]` OpenTelemetry integration
  > **Scenario**: Debug slow login: trace shows `VerifyPassword: 200ms, CreateSession: 50ms, SendEmail: 2000ms`. Pinpoints email sender as bottleneck.
  >
  > **Urgency**: Nice for debugging. Not blocking.
  >
  > **Requires**: Metrics hooks

---

## Long-term

### Advanced Features

- [ ] **P2** `[ADOPTION]` Organization/team support
  > **Scenario**: SaaS app where users belong to companies. `user.Organizations = ["acme-corp"]`, permissions scoped: "Can edit documents in acme-corp only."
  >
  > **Urgency**: Required for B2B SaaS multi-tenancy. Can defer for B2C apps.

- [ ] **P2** `[ADOPTION]` Role-based access control (RBAC)
  > **Scenario**: Admin assigns roles: `user.Roles = ["editor", "billing-viewer"]`. Middleware checks: `RequireRole("editor")` on document endpoints.
  >
  > **Urgency**: Enterprise feature. Current scope-based system covers basic cases.
  >
  > **Requires**: Organization support (for org-scoped roles)

- [x] **P2** `[DX]` Custom claims in JWT ✅ **COMPLETED (oneauth#2)**
  > `CustomClaimsFunc` on `APIAuth` + `ValidateAccessTokenFull` for extraction.
  > Multi-tenant `KeyStore` interface with `InMemoryKeyStore` implementation.
  > `APIMiddleware` supports per-client key lookup via `KeyStore`.

- [ ] **P2** `[DX]` Device management UI components
  > **Scenario**: User views "Active Sessions" page: "Chrome on MacBook (current), Safari on iPhone, Firefox on Windows". Can click "Sign out" on any device.
  >
  > **Urgency**: UX feature. Requires session tracking infrastructure first.
  >
  > **Requires**: Token blacklist, Redis store

### Ecosystem

- [ ] **P1** `[ADOPTION]` Example applications
  > **Scenario**: New developer evaluates oneauth. Clones `examples/react-spa/`, runs `docker-compose up`, has working auth demo in 2 minutes.
  >
  > **Urgency**: Critical for adoption. Hard to evaluate library without working examples.

- [ ] **P2** `[DX]` Admin dashboard package
  > **Scenario**: Support team needs to unlock user account. `oneauth-admin` UI shows user list, session history, "Reset Password" and "Unlock Account" buttons.
  >
  > **Urgency**: Ops convenience. Can use direct DB access initially.
  >
  > **Requires**: Account lockout, audit logging

- [ ] **P2** `[ADOPTION]` React/Vue component library for auth UI
  > **Scenario**: `import { LoginForm, SignupForm } from '@oneauth/react'` — drop-in components with built-in validation, loading states, error handling.
  >
  > **Urgency**: Reduces integration time but not blocking. Developers can build their own forms.

- [ ] **P2** `[DX]` CLI tool for token management
  > **Scenario**: Developer debugging API: `oneauth token decode eyJ...` shows claims. `oneauth token refresh --profile=dev` gets new access token.
  >
  > **Urgency**: Developer convenience. Can use jwt.io or similar tools.
  >
  > **Requires**: Client SDK — now complete

---

## Dependency Graph (Critical Path)

```
Bug Fixes (do first)
    #52 Fix aud array validation (P0) ◄── blocks Keycloak interop

Phase 3: OAuth for Non-Browser Clients
    #54 Headless OAuth + PKCE (CLI) ◄── supersedes old Phase 3 items
    #53 client_credentials grant
    #51 AS Metadata Discovery ◄── #54 benefits from this

Phase 4: Client SDK ✅ COMPLETE
    CredentialStore ──► AuthTransport ──► NewHTTPClient
                              │
                              ▼
                       Token Refresh ──► lilbattle migration (remaining)

Standards & Interop (parallel track — see ROADMAP.md)
    #46 PRM (RFC 9728) ◄── smallest, do first
    #47 Token Introspection server (RFC 7662)
              │
    ┌─────────┼──────────┐
    ▼                     ▼
    #48 DCR (7591)    #49 Keycloak Tests ◄── validates all of the above
         │                │
         │          ┌─────┘
         ▼          ▼
    #55 Introspection client (requires #47 + #53)
    #50 OIDC Discovery (optional)

Infrastructure (parallel track)
    Redis Store ──► Token Blacklist ──► MFA
                │
                └── Rate Limiting
                └── Distributed Sessions

Compliance (can be parallel)
    Audit Logging ──► Suspicious Activity Detection
    GDPR (Account Deletion)
```

## Recommended Execution Order

1. **#52 Fix aud array** (P0 bug) — ~10 lines, blocks Keycloak interop
2. **#46 PRM** (P1) — Smallest standards item, immediate interop value
3. **#49 Keycloak tests** (P1) — Proves interop story, can start in parallel with PRM
4. **#53 client_credentials** (P1) — Foundational grant type, enables #55
5. **#54 Headless OAuth + PKCE** (P1) — CLI/agent auth, supersedes old Phase 3
6. **#47 Token Introspection server** (P1) — Keycloak tests validate it
7. **#51 AS Discovery client** (P1) — Enhances #54, enables auto-config
8. **lilbattle migration** (P1) — Validates Client SDK end-to-end
9. **Redis Store** (P1) — Unblocks production deployments
10. **#48 DCR wrapper** (P2) — Standards-compliant registration
11. **#55 Introspection client** (P2) — Requires #47 + #53
12. **GDPR + Audit Logging** (P1 compliance) — If targeting EU/enterprise
13. **MFA** (P1 security) — Enterprise requirement
14. **#50 OIDC Discovery** (P2) — Only if reference server sees standalone adoption
15. **Everything else** (P2) — As needed

---

## Known Limitations

1. **File-based stores**: Not suitable for >1000 users or clustered deployments
2. ~~**Rate limiting interface only**~~ **Resolved** — `InMemoryRateLimiter` + `AccountLockout` built in; per-process (use Redis-backed impl for distributed)
3. ~~**No CSRF protection**~~ **Resolved** — `CSRFMiddleware` provides double-submit cookie pattern
4. **Console email sender only**: Production requires custom EmailSender implementation
5. **No MFA yet**: TOTP/WebAuthn planned for medium-term
6. **AppRegistrar state is in-memory** (#20, **P1**): App registrations (incl. DCR) lost on server restart. `AppRegistrationStore` interface with FS/GORM backends needed. See issue #20 for full design.
7. **Token blacklist is per-process** (#23): `InMemoryBlacklist` doesn't share state across nodes. Use Redis-backed `TokenBlacklist` for distributed deployments.

## Contributing

See CONTRIBUTING.md for guidelines. Priority areas:
- Documentation improvements
- Additional store implementations
- Security review and hardening
- Example applications
