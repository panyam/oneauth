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

### Phase 3: OAuth Integration for API

- [ ] **P0** `[BLOCKER]` Add API mode to OAuth callbacks (return tokens instead of session)
  > **Scenario**: A React SPA calls `/auth/google/callback?mode=api` and receives `{access_token, refresh_token}` JSON instead of a cookie redirect, enabling client-side token storage.
  >
  > **Urgency**: Blocks all SPA and mobile OAuth implementations. Without this, non-browser clients cannot use OAuth.

- [ ] **P0** `[BLOCKER]` Support token response for mobile OAuth flows
  > **Scenario**: iOS app opens Google OAuth in Safari, receives deep link `myapp://auth?code=xyz`, exchanges code for tokens via API without needing cookies.
  >
  > **Urgency**: Blocks mobile app releases. Native apps cannot use cookie-based auth.
  >
  > **Requires**: API mode OAuth callbacks

- [ ] **P1** `[SECURITY]` PKCE support for public clients
  > **Scenario**: Mobile app generates `code_verifier`, sends `code_challenge` with OAuth request. Server validates on token exchange, preventing authorization code interception attacks.
  >
  > **Urgency**: Security requirement for public OAuth clients (mobile, SPA). Required by OAuth 2.1 spec.
  >
  > **Requires**: API mode OAuth callbacks

### Phase 4: Client SDK

Reference implementation: `lilbattle/cmd/cli/cmd/{credentials.go,login.go}` and `connectclient/worlds_client.go`

- [ ] **P0** `[BLOCKER]` Create `client/` package with stores pattern:
  - [ ] `CredentialStore` interface (Get, Set, Remove, List credentials)
  - [ ] `ServerCredential` struct (access token, refresh token, expiry, user info)
  - [ ] `client/stores/fs/` - FS-based credential store (`~/.config/<app>/credentials.json`)
  - [ ] Future: `client/stores/gorm/`, `client/stores/gae/`
  > **Scenario**: CLI tool stores credentials locally: `store.Set("prod", cred)` saves to `~/.config/mycli/credentials.json`, enabling `mycli --profile=prod list-items` without re-login.
  >
  > **Urgency**: Foundation for all client-side auth. Blocks AuthTransport, token refresh, and CLI tools.

- [ ] **P0** `[BLOCKER]` `AuthTransport` - `http.RoundTripper` that injects Bearer headers
  > **Scenario**: `client := &http.Client{Transport: oneauth.NewAuthTransport(store)}` — all requests automatically include `Authorization: Bearer <token>` header.
  >
  > **Urgency**: Core building block. Every authenticated HTTP client needs this.
  >
  > **Requires**: CredentialStore interface

- [ ] **P1** `[DX]` `NewHTTPClient(serverURL, store)` - creates authenticated HTTP client
  > **Scenario**: `client := oneauth.NewHTTPClient("https://api.example.com", store)` — one-liner to get a fully configured authenticated client.
  >
  > **Urgency**: Convenience wrapper. Reduces boilerplate for consumers.
  >
  > **Requires**: AuthTransport

- [ ] **P0** `[BLOCKER]` Automatic token refresh:
  - [ ] Store refresh tokens alongside access tokens
  - [ ] Transparent refresh on 401 or before expiry
  - [ ] `grant_type=refresh_token` support
  > **Scenario**: Long-running daemon makes API call, token expired. Transport auto-refreshes using stored refresh token, retries request — no manual token management needed.
  >
  > **Urgency**: Without this, tokens expire and break long-running processes. Users must manually re-authenticate.
  >
  > **Requires**: AuthTransport, CredentialStore

- [ ] **P1** `[ADOPTION]` Migrate lilbattle CLI to use oneauth/client package
  > **Scenario**: Validate the client SDK works end-to-end by replacing lilbattle's hand-rolled auth with `oneauth/client`.
  >
  > **Urgency**: Proves the SDK works in real usage. Finds edge cases before wider adoption.
  >
  > **Requires**: Full client SDK (CredentialStore, AuthTransport, token refresh)

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

- [x] **P2** `[ADOPTION]` Username-based login (previously email/phone only) ✅ **COMPLETED v0.3.0**
  > **Scenario**: Gaming platform where users prefer handles like "DragonSlayer99" over email. `auth.Login("DragonSlayer99", password)` should work alongside email login.
  >
  > **Implementation**: Added `UsernameStore` interface with FS, GORM, and GAE implementations. Use `NewCredentialsValidatorWithUsername()` for username-based login support.

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

- [ ] **P1** `[ADOPTION]` Token introspection endpoint (RFC 7662)
  > **Scenario**: Resource server receives token, needs to validate: `POST /oauth/introspect {token: "..."}` returns `{active: true, scope: "read write", exp: 1699999999}`.
  >
  > **Urgency**: Required for microservice architectures where services can't share JWT secrets. Blocks distributed deployments.

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

- [ ] **P2** `[DX]` Custom claims in JWT
  > **Scenario**: App needs tenant_id in every token. Configure: `JWTClaims: func(user) { return map{"tenant_id": user.TenantID} }`. All tokens include custom claim.
  >
  > **Urgency**: Flexibility feature. Workaround: fetch from user store on each request.

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
  > **Requires**: Client SDK

---

## Dependency Graph (Critical Path)

```
Phase 3: OAuth API Mode
    └── Mobile OAuth flows
    └── PKCE support

Phase 4: Client SDK
    CredentialStore ──► AuthTransport ──► NewHTTPClient
                              │
                              ▼
                       Token Refresh ──► lilbattle migration

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

1. **Phase 3 + Phase 4** (P0 blockers) — Unblocks mobile/SPA/CLI clients
2. **Redis Store** (P1) — Unblocks production deployments
3. **Token Blacklist + Account Lockout** (P1 security) — Basic security hardening
4. **GDPR + Audit Logging** (P1 compliance) — If targeting EU/enterprise
5. **MFA** (P1 security) — Enterprise requirement
6. **Examples** (P1 adoption) — Accelerates adoption
7. **Everything else** (P2) — As needed

---

## Known Limitations

1. **File-based stores**: Not suitable for >1000 users or clustered deployments
2. **Rate limiting interface only**: Provides interface, application implements logic
3. **No CSRF protection**: Application must implement
4. **Console email sender only**: Production requires custom EmailSender implementation
5. **No MFA yet**: TOTP/WebAuthn planned for medium-term

## Contributing

See CONTRIBUTING.md for guidelines. Priority areas:
- Documentation improvements
- Additional store implementations
- Security review and hardening
- Example applications
