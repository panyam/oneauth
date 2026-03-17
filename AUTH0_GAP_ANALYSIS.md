# Auth0 vs OneAuth — Gap Analysis

**Date:** 2026-03-17
**Purpose:** Comprehensive comparison of Auth0's feature set against OneAuth to identify gaps, strengths, and roadmap priorities.

---

## Executive Summary

Auth0 is a mature, enterprise-grade identity platform with 100+ features spanning authentication, authorization, user management, security, extensibility, and compliance. OneAuth is a focused Go authentication library with solid fundamentals — local/OAuth auth, multi-tenant JWT, federated resource server auth, and three storage backends — but lacks many features that Auth0 provides as a managed service.

**Key takeaway:** OneAuth covers ~30% of Auth0's surface area. The gaps are largest in **security hardening** (MFA, anomaly detection), **standards compliance** (OIDC, PKCE), **UX components** (Universal Login, SDKs), **user management** (search, roles, organizations), and **extensibility** (Actions, webhooks, log streaming).

---

## Comparison Matrix

### Legend
- **Full** = Feature parity or equivalent
- **Partial** = Some capability exists but incomplete
- **None** = Not implemented
- **N/A** = Not applicable (managed service feature)

---

## 1. Authentication API

| Feature | Auth0 | OneAuth | Gap |
|---------|-------|---------|-----|
| **Username/Password Login** | POST /oauth/token (ROPC) | POST /auth/login, POST /api/token | Full |
| **Signup** | POST /dbconnections/signup | POST /auth/signup | Full |
| **Email Verification** | POST /jobs/verification-email | GET /auth/verify-email?token= | Full |
| **Password Reset (forgot)** | POST /dbconnections/change_password | POST /auth/forgot-password | Full |
| **Password Reset (execute)** | Hosted page + token | POST /auth/reset-password | Full |
| **Credential Linking** | POST /api/v2/users/{id}/identities | POST /auth/link-credentials | Full |
| **Authorization Code Flow** | GET /authorize + POST /oauth/token | None | **None** |
| **Authorization Code + PKCE** | GET /authorize + code_verifier | None | **None** |
| **Implicit Flow** | GET /authorize?response_type=token | None | **None** |
| **Client Credentials Flow** | POST /oauth/token (client_credentials) | None | **None** |
| **Device Authorization Flow** | POST /oauth/device/code | None | **None** |
| **Passwordless (Email)** | POST /passwordless/start (email) | None | **None** |
| **Passwordless (SMS)** | POST /passwordless/start (sms) | None | **None** |
| **Passkeys / WebAuthn** | Native passkey management | None | **None** |
| **Social Login (Google)** | Via connections (50+ providers) | oauth2/google.go | Full |
| **Social Login (GitHub)** | Via connections | oauth2/github.go | Full |
| **Social Login (Apple)** | Via connections | None | **None** |
| **Social Login (Microsoft)** | Via connections | None | **None** |
| **Social Login (Facebook)** | Via connections | None | **None** |
| **Social Login (LinkedIn)** | Via connections | None | **None** |
| **Social Login (Twitter/X)** | Via connections | None | **None** |
| **Enterprise SSO (SAML)** | Via connections | saml/saml.go | Full |
| **Enterprise SSO (OIDC)** | Via connections (generic OIDC) | None | **None** |
| **Enterprise SSO (LDAP/AD)** | Via AD Connector | None | **None** |
| **Enterprise SSO (WS-Federation)** | Via connections | None | **None** |
| **SCIM Provisioning** | Built-in SCIM support | None | **None** |
| **Refresh Token Grant** | POST /oauth/token (refresh_token) | POST /api/token (refresh_token) | Full |
| **Refresh Token Rotation** | Automatic rotation + theft detection | Family-based rotation + theft detection | Full |
| **Token Revocation** | POST /oauth/revoke | POST /api/logout | Full |
| **Logout (local)** | GET /v2/logout | POST /api/logout | Full |
| **Logout (federated)** | GET /v2/logout?federated | None | **None** |
| **Single Logout (SAML)** | SLO support | saml/saml.go (basic) | Partial |
| **DPoP (Proof of Possession)** | Supported (2025) | None | **None** |

### OneAuth Authentication Strengths
- Clean, composable Go interfaces (LocalAuth, APIAuth, APIMiddleware)
- Flexible HandleUser/HandleSignup callbacks
- Configurable signup policies (email-only, username-required, flexible)
- Custom claims injection without overriding standard claims
- Algorithm confusion prevention (GetExpectedAlg)

---

## 2. Token & JWT Management

| Feature | Auth0 | OneAuth | Gap |
|---------|-------|---------|-----|
| **Access Tokens (JWT)** | RS256 by default, configurable | HS256, RS256, ES256 | Full |
| **ID Tokens (OIDC)** | Standard OIDC id_token | None (no OIDC) | **None** |
| **Refresh Tokens** | Configurable rotation + lifetime | Family-based rotation, 7-day default | Full |
| **API Keys** | Via Management API | oa_ prefix, bcrypt hash, scopes | Full |
| **Custom Claims** | Actions/Rules pipeline | CustomClaimsFunc callback | Full |
| **Token Lifetime Configuration** | Per-API, per-client | Configurable AccessTokenExpiry | Full |
| **Token Introspection (RFC 7662)** | Not standard (use /userinfo) | None | **None** |
| **Token Exchange (RFC 8693)** | Supported | None | **None** |
| **Scopes System** | OAuth2 standard scopes | Custom scope system (5 built-in) | Partial |
| **Resource Indicators (RFC 8707)** | Supported | Via federated MintResourceToken | Partial |
| **Multi-tenant Key Management** | Per-tenant keys | WritableKeyStore (per-client keys) | Full |
| **Key Rotation** | Automatic + manual | POST /apps/{id}/rotate (manual) | Partial |
| **JWKS Endpoint** | /.well-known/jwks.json | `GET /.well-known/jwks.json` via JWKSHandler — serves RS256/ES256 public keys, filters HS256 secrets, Cache-Control headers | Full |
| **JWKS Client (key fetching)** | SDKs fetch from JWKS | JWKSKeyStore — fetches from remote JWKS, caches locally, background refresh, cache-miss retry | Full |
| **OpenID Discovery** | /.well-known/openid-configuration | None | **None** |

### OneAuth Token Strengths
- MintResourceToken / MintResourceTokenWithKey for federated resource servers
- Three signing algorithms (HS256, RS256, ES256) with per-client selection
- InMemoryKeyStore for testing, FSKeyStore, GORMKeyStore, GAEKeyStore
- Shared KeyStore test suite (keystoretest.RunAll)
- **JWKSHandler** serves RFC 7517 compliant JWKS endpoint with proper security (HS256 secrets excluded)
- **JWKSKeyStore** enables resource servers to auto-discover public keys via HTTP instead of shared DB access
- Full JWK conversion utilities for RSA and ECDSA keys (utils/jwk.go)

---

## 3. User Management

| Feature | Auth0 | OneAuth | Gap |
|---------|-------|---------|-----|
| **Create User** | POST /api/v2/users | NewCreateUserFunc (via signup) | Full |
| **Get User by ID** | GET /api/v2/users/{id} | UserStore.GetUserById | Full |
| **Update User** | PATCH /api/v2/users/{id} | UserStore.SaveUser | Partial |
| **Delete User** | DELETE /api/v2/users/{id} | None | **None** |
| **List Users** | GET /api/v2/users (paginated) | None | **None** |
| **Search Users** | Lucene query syntax, full-text search | None | **None** |
| **User Metadata** | user_metadata + app_metadata | Profile map[string]any (flat) | Partial |
| **User Blocking** | PATCH blocked: true | None (isActive flag only) | **None** |
| **User Roles** | GET/POST /api/v2/users/{id}/roles | None | **None** |
| **User Permissions** | GET /api/v2/users/{id}/permissions | Scopes only (no user-level perms) | **None** |
| **Account Linking** | POST /api/v2/users/{id}/identities | Identity-based (email match) | Partial |
| **User Import/Export** | POST /api/v2/jobs/users-imports | None | **None** |
| **Bulk User Management** | Jobs API (async) | None | **None** |
| **User Migration** | Automatic migration connections | None | **None** |
| **Email Change** | PATCH /api/v2/users/{id} | None (identity-based) | **None** |
| **Password Change (admin)** | PATCH /api/v2/users/{id} | None (user self-service only) | **None** |
| **Username Management** | Built into user model | UsernameStore (reserve/change/release) | Full |
| **User Identities** | Multiple linked identities | IdentityStore (email/phone) | Full |
| **Channels / Providers** | Connections per identity | ChannelStore (local/oauth/saml) | Full |
| **Profile Picture** | Via social or custom | Stored in profile map | Full |

### OneAuth User Strengths
- Clean separation: User / Identity / Channel model
- Username reservation with uniqueness enforcement
- Three storage backends (FS, GORM, GAE)
- Identity verification tracking (email/phone)

---

## 4. Authorization & RBAC

| Feature | Auth0 | OneAuth | Gap |
|---------|-------|---------|-----|
| **Roles** | Full RBAC (create, assign, nest) | None | **None** |
| **Permissions** | Fine-grained per-API permissions | Scopes only | **None** |
| **Role-Permission Assignment** | POST /api/v2/roles/{id}/permissions | None | **None** |
| **Organizations** | Multi-org support, per-org roles | None | **None** |
| **Organization Invitations** | Email-based member invitations | None | **None** |
| **Organization Connections** | Per-org identity providers | None | **None** |
| **Fine-Grained Authorization (FGA)** | OpenFGA-based (Zanzibar model) | None | **None** |
| **Scopes** | OAuth2 standard scopes | Custom scope system (parse/join/intersect/validate) | Partial |
| **Scope Enforcement (middleware)** | Via API settings | RequireScopes middleware | Full |
| **Resource Server Registration** | POST /api/v2/resource-servers | POST /apps/register | Full |
| **API Audience** | Per-API audience setting | Configurable Audience field | Full |

### OneAuth Authorization Strengths
- App Registration + federated resource token model is unique
- Per-app quotas (max_rooms, max_msg_rate) in JWT claims
- Multi-tenant KeyStore for resource server validation

---

## 5. Security Features

| Feature | Auth0 | OneAuth | Gap |
|---------|-------|---------|-----|
| **MFA - TOTP** | Built-in (Guardian, Google Authenticator) | None | **None** |
| **MFA - SMS** | Built-in | None | **None** |
| **MFA - Push Notifications** | Auth0 Guardian app | None | **None** |
| **MFA - Email OTP** | Built-in | None | **None** |
| **MFA - WebAuthn/FIDO2** | Built-in | None | **None** |
| **MFA - Recovery Codes** | Auto-generated on enrollment | None | **None** |
| **Adaptive MFA** | Risk-based triggering | None | **None** |
| **Brute Force Protection** | Auto-block after 10 failed attempts | None | **None** |
| **Suspicious IP Throttling** | IP-based rate limiting | None | **None** |
| **Bot Detection** | CAPTCHA challenge on suspicious logins | None | **None** |
| **Breached Password Detection** | 2.5M compromised accounts/day DB | None | **None** |
| **Credential Stuffing Protection** | Multi-signal detection | None | **None** |
| **Password Complexity Rules** | Configurable policies (length, chars, history) | MinPasswordLength only | **None** |
| **Password History** | Prevent N recent passwords | None | **None** |
| **Password Bcrypt Hashing** | bcrypt (configurable rounds) | bcrypt (default cost) | Full |
| **Constant-time Comparison** | Standard practice | crypto/subtle for API keys | Full |
| **CSRF Protection** | Built-in state parameter | OAuth state validation | Partial |
| **Rate Limiting** | Built-in, per-endpoint | Optional interface, no built-in impl | **None** |
| **Anomaly Detection Alerts** | Email alerts to admins | None | **None** |
| **IP Allowlisting** | Per-feature allowlists | None | **None** |
| **Session Management** | Configurable timeouts, force logout | List sessions, logout-all | Partial |
| **Refresh Token Theft Detection** | Automatic family revocation | Family-based rotation + revocation | Full |
| **Algorithm Confusion Prevention** | N/A (managed) | GetExpectedAlg per client | Full |

### OneAuth Security Strengths
- Solid token rotation with theft detection
- Per-client algorithm enforcement prevents confusion attacks
- Constant-time admin key comparison
- Secret Manager integration (GAE)

---

## 6. UX Components & SDKs

| Feature | Auth0 | OneAuth | Gap |
|---------|-------|---------|-----|
| **Universal Login (hosted page)** | Full-featured, customizable | Basic HTML templates | **None** |
| **New Universal Login Experience** | No-code customization | None | **None** |
| **Classic Universal Login** | Full HTML/CSS/JS control | Basic templates (login, signup, etc.) | Partial |
| **Lock Widget** | Embeddable login widget | None | **None** |
| **Custom Domains** | Custom domain for login pages | None (app controls domain) | N/A |
| **Branding (logo, colors, fonts)** | Full theme customization | None | **None** |
| **Email Templates** | Customizable HTML templates | ConsoleEmailSender (logging only) | **None** |
| **SMS Templates** | Customizable | None | **None** |
| **React SDK** | @auth0/auth0-react | None | **None** |
| **Angular SDK** | @auth0/auth0-angular | None | **None** |
| **Vue SDK** | @auth0/auth0-vue | None | **None** |
| **Next.js SDK** | @auth0/nextjs-auth0 | None | **None** |
| **iOS SDK** | Auth0.swift | None | **None** |
| **Android SDK** | auth0-android | None | **None** |
| **Flutter SDK** | auth0-flutter | None | **None** |
| **Go SDK (server)** | go-auth0 (Management API client) | Full library (this is the SDK) | Full |
| **Python SDK** | auth0-python | None | **None** |
| **Node.js SDK** | node-auth0 | None | **None** |
| **Client SDK (Go)** | N/A | client/AuthClient with auto-refresh | Full |
| **gRPC Interceptors** | N/A | Unary + Stream interceptors | Full |
| **HTTP Middleware** | N/A | ExtractUser/EnsureUser middleware | Full |

### OneAuth UX Strengths
- Go-native library (import, not SaaS)
- AuthClient with transparent token refresh
- gRPC interceptors (not available in Auth0)
- HTTP middleware with cookie fallback

---

## 7. Extensibility & Integrations

| Feature | Auth0 | OneAuth | Gap |
|---------|-------|---------|-----|
| **Actions (post-login, etc.)** | 18+ trigger points, Node.js runtime | None | **None** |
| **Rules (deprecated)** | JavaScript pipeline | None | **None** |
| **Hooks (deprecated)** | Pre/post registration, etc. | None (Go callbacks instead) | Partial |
| **Webhooks** | Via Actions + Log Streaming | None | **None** |
| **Log Streaming** | Datadog, Splunk, AWS, etc. | None | **None** |
| **Event Streams** | Real-time user/org change events | None | **None** |
| **Custom Social Connections** | OAuth2 generic connection | BaseOAuth2 (extensible) | Full |
| **Custom DB Connections** | SQL/REST user migration scripts | Three-backend store pattern | Full |
| **Marketplace / Integrations** | 50+ pre-built integrations | None | **None** |
| **Custom Claims Pipeline** | Via Actions | CustomClaimsFunc callback | Full |
| **Email Providers** | SendGrid, Mailgun, SES, custom SMTP | Pluggable EmailSender interface (console only) | Partial |
| **Go Callback Pattern** | N/A | HandleUser, HandleSignup callbacks | Full |
| **Config-driven Server** | Dashboard (no config files) | YAML + ${ENV_VAR} substitution | Full |

### OneAuth Extensibility Strengths
- Go callback pattern is more type-safe than Auth0's JS Actions
- Three-backend store pattern with shared test suites
- Config-driven reference server with env var substitution
- BaseOAuth2 makes adding providers straightforward

---

## 8. Management & Operations

| Feature | Auth0 | OneAuth | Gap |
|---------|-------|---------|-----|
| **Admin Dashboard** | Full web UI | None | **None** |
| **Management API** | 100+ endpoints | ~20 HTTP endpoints | Partial |
| **Tenant Management** | Multi-tenant SaaS | Per-client KeyStore | Partial |
| **Connections Management** | CRUD for all connection types | Config-driven (YAML) | Partial |
| **Client/Application Management** | Full CRUD + settings | POST /apps/register + CRUD | Partial |
| **Audit Logs** | Searchable event log | None | **None** |
| **Log Retention** | 2-30 days (by plan) | None | **None** |
| **Metrics / Analytics** | Built-in usage analytics | None | **None** |
| **Real-time Metric Streaming** | Datadog, New Relic, etc. | None | **None** |
| **Custom Domains** | Per-tenant custom domain | N/A (self-hosted) | N/A |
| **Deployment Regions** | US, EU, AU, JP | Self-hosted (any region) | Full |
| **Private Cloud** | Auth0 Private Cloud | Self-hosted by design | Full |
| **Health Endpoint** | Managed (SLA) | /_ah/health | Full |
| **CLI Tool** | auth0 CLI | None | **None** |

---

## 9. Standards Compliance

| Standard | Auth0 | OneAuth | Gap |
|----------|-------|---------|-----|
| **OAuth 2.0 (RFC 6749)** | Full compliance | Partial (password + refresh grants only) | Partial |
| **OpenID Connect (OIDC)** | Full compliance | None | **None** |
| **SAML 2.0** | Full (IdP + SP) | SP only (via crewjam/saml) | Partial |
| **WS-Federation** | Supported | None | **None** |
| **SCIM 2.0** | Supported | None | **None** |
| **LDAP** | Via AD Connector | None | **None** |
| **JWKS (RFC 7517)** | /.well-known/jwks.json | `GET /.well-known/jwks.json` (JWKSHandler + JWKSKeyStore) | Full |
| **OAuth 2.0 Token Revocation (RFC 7009)** | Supported | Custom endpoint | Partial |
| **DPoP (RFC 9449)** | Supported (2025) | None | **None** |
| **FIDO2/WebAuthn** | Supported | None | **None** |
| **JWT (RFC 7519)** | Full | Full (HS256, RS256, ES256) | Full |
| **PKCE (RFC 7636)** | Supported | None | **None** |

---

## 10. Compliance & Enterprise

| Feature | Auth0 | OneAuth | Gap |
|---------|-------|---------|-----|
| **SOC 2 Type II** | Certified | N/A (self-hosted) | N/A |
| **HIPAA** | BAA available | N/A (self-hosted) | N/A |
| **GDPR** | Data processing agreements | N/A (self-hosted) | N/A |
| **Data Residency** | Regional deployment | Self-hosted (full control) | Full |
| **Uptime SLA** | 99.99% (Enterprise) | Self-managed | N/A |
| **Support** | 24/7 Enterprise support | Community / self-support | N/A |

---

## Gap Priority Matrix

### P0 — Critical Gaps (high impact, foundational)

| # | Gap | Why Critical | Effort |
|---|-----|-------------|--------|
| 1 | **OIDC Compliance** | Industry standard; required for enterprise SSO, federation | Large |
| 2 | **Authorization Code Flow + PKCE** | Required for SPAs, mobile apps; ROPC is deprecated | Medium |
| 3 | ~~**JWKS Endpoint**~~ | ~~Required for standard token validation by third parties~~ | **Done** |
| 4 | **OpenID Discovery** | Required for OIDC compliance; enables auto-configuration | Small |
| 5 | **MFA (TOTP at minimum)** | Table stakes for any production auth system | Medium |

### P1 — Important Gaps (significant value, frequently expected)

| # | Gap | Why Important | Effort |
|---|-----|--------------|--------|
| 6 | **Brute Force Protection** | Basic security hygiene; Auth0 enables by default | Small |
| 7 | **Rate Limiting (built-in)** | Interface exists but no implementation | Small |
| 8 | **Password Complexity Policies** | Only length enforced; need char classes, history | Small |
| 9 | **User Search/List API** | No way to find users except by ID | Medium |
| 10 | **Delete User** | Basic CRUD gap | Small |
| 11 | **Roles & Permissions (RBAC)** | Only scopes exist; no role hierarchy | Medium |
| 12 | **Client Credentials Flow** | Needed for M2M (machine-to-machine) auth | Small |
| 13 | **More Social Providers** | Apple, Microsoft, Facebook at minimum | Small each |
| 14 | **Email Delivery** | Only ConsoleEmailSender exists | Small |
| 15 | **Audit Logging** | No event trail for security/compliance | Medium |

### P2 — Nice to Have (enterprise/advanced features)

| # | Gap | Value | Effort |
|---|-----|-------|--------|
| 16 | **Organizations / Multi-org** | B2B SaaS requirement | Large |
| 17 | **Passwordless (magic link, OTP)** | Modern UX trend | Medium |
| 18 | **Passkeys/WebAuthn** | Growing adoption | Large |
| 19 | **Bot Detection / CAPTCHA** | Advanced security | Medium |
| 20 | **Breached Password Detection** | Requires external DB | Medium |
| 21 | **Actions/Webhooks System** | Extensibility for custom logic | Large |
| 22 | **Admin Dashboard** | Visual management | Large |
| 23 | **Frontend SDKs** | React, Next.js, etc. | Large |
| 24 | **User Import/Export** | Migration support | Medium |
| 25 | **Log Streaming** | Observability integration | Medium |
| 26 | **Device Authorization Flow** | CLI/IoT auth | Small |
| 27 | **SCIM Provisioning** | Enterprise directory sync | Large |
| 28 | **FGA (Fine-Grained Authorization)** | Complex authorization models | Large |

---

## OneAuth Competitive Advantages (vs Auth0)

These are areas where OneAuth's architecture is arguably **better** than Auth0:

1. **Self-hosted / No vendor lock-in** — Full control over data, deployment, and customization. No per-user pricing.

2. **Go-native library** — Import as a package, not a SaaS dependency. Type-safe callbacks vs Auth0's JS Actions runtime.

3. **Federated Resource Token model** — MintResourceToken / MintResourceTokenWithKey is a unique pattern for multi-service architectures that Auth0 doesn't natively support.

4. **Three storage backends** — FS (dev), GORM (production SQL), GAE (serverless) with shared test suites. Auth0 is opaque about storage.

5. **gRPC support** — First-class gRPC interceptors. Auth0 has no native gRPC support.

6. **Algorithm confusion prevention** — Explicit per-client algorithm enforcement. Auth0 handles this internally but doesn't expose it.

7. **JWKS-based key discovery** — Both server-side (JWKSHandler) and client-side (JWKSKeyStore with caching + background refresh). Resource servers can auto-discover keys via HTTP instead of sharing a database.

8. **Config-driven deployment** — YAML + env var substitution. Auth0 requires dashboard/API configuration.

9. **No per-user pricing** — Auth0's pricing scales with MAU ($35/mo for 500 MAU on B2C). OneAuth is free.

10. **Per-app resource quotas** — JWT claims include max_rooms, max_msg_rate for resource server enforcement. Auth0 has no built-in quota system.

11. **Transparent token rotation** — Client SDK handles refresh automatically. Auth0 SDKs do too, but OneAuth's is simpler to understand/debug.

---

## Recommended Roadmap

### Phase 1: Standards Foundation (P0)
- ~~Add `/.well-known/jwks.json` endpoint~~ **Done** — JWKSHandler + JWKSKeyStore + JWK utils (issue #7)
- Add `/.well-known/openid-configuration` discovery
- Implement Authorization Code flow + PKCE
- Add ID token generation (OIDC compliance)
- Implement TOTP-based MFA

### Phase 2: Security Hardening (P1)
- Built-in brute force protection (login attempt tracking)
- Built-in rate limiting implementation
- Password complexity policies (char classes, dictionary check)
- Email delivery integration (SMTP, SendGrid, SES)
- Audit event logging

### Phase 3: User Management (P1)
- User search/list API with pagination
- Delete user endpoint
- RBAC (roles + permissions model)
- User blocking/suspension
- Client credentials grant (M2M)

### Phase 4: Enterprise Features (P2)
- Organizations / multi-org support
- Passwordless authentication (magic link + email OTP)
- Additional social providers (Apple, Microsoft, Facebook)
- Webhooks / event system
- Admin dashboard (optional web UI)

---

## Summary Statistics

| Category | Auth0 Features | OneAuth Features | Coverage |
|----------|---------------|-----------------|----------|
| Authentication Methods | ~15 | 4 (local, Google, GitHub, SAML) | ~27% |
| OAuth2 Grant Types | 6 | 2 (password, refresh_token) | 33% |
| User Management | ~15 | 6 (create, get, save, identities, channels, usernames) | 40% |
| Security Features | ~12 | 3 (bcrypt, token rotation, algorithm enforcement) | 25% |
| UX Components | ~12 SDKs + Universal Login | 1 (Go client SDK) + basic templates | ~8% |
| Token Types | 4 (access, ID, refresh, API key) | 3 (access, refresh, API key) | 75% |
| Standards | 10+ | 4 (JWT, JWKS, OAuth2 partial, SAML partial) | ~33% |
| Extensibility | Actions, Rules, Hooks, Webhooks, Marketplace | Go callbacks, config-driven | ~15% |
| Storage Backends | Managed (opaque) | 3 (FS, GORM, GAE) | N/A |
| **Overall Estimated Coverage** | | | **~30%** |

---

*Sources: [Auth0 API Documentation](https://auth0.com/docs/api), [Auth0 Authentication API](https://auth0.com/docs/api/authentication), [Auth0 Management API v2](https://auth0.com/docs/api/management/v2), [Auth0 Attack Protection](https://auth0.com/learn/anomaly-detection), [Auth0 Bot Detection](https://auth0.com/docs/secure/attack-protection/playbooks/bot-detection-playbook), [Auth0 Changelog](https://auth0.com/changelog)*
