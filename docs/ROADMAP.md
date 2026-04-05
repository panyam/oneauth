# OneAuth Roadmap

## Vision

OneAuth is an **embeddable Go authentication library** — not an identity server. It handles local auth, API auth (JWT/refresh/API keys), and federated resource auth (app registration, scoped token minting, multi-tenant validation via KeyStore/JWKS).

**What we are not building:** A full OIDC Identity Provider (that's Keycloak's job). Instead, we **interoperate** with real IdPs and focus on making resource servers and apps easy to secure in Go.

---

## Standards & Interop Track

This track moves OneAuth from custom-protocol federated auth toward **standards-compliant interoperability** with the broader OAuth2/OIDC ecosystem. The guiding principle: **prove interop with real-world tools (Keycloak) instead of reimplementing them.**

### Phase 1: Resource Server Standards (Short-term)

These are low-effort, high-value additions that make OneAuth resource servers self-describing and interoperable.

#### Protected Resource Metadata — RFC 9728 (#46) ✅ COMPLETE

`ProtectedResourceMetadata` struct + `NewProtectedResourceHandler()` in `apiauth/`. Serves JSON at `GET /.well-known/oauth-protected-resource` with `Cache-Control` headers. 7 unit tests + 3 e2e tests. Wired into demo resource server and e2e test environment.

#### Token Introspection — RFC 7662 (#47) ✅ COMPLETE

`IntrospectionHandler` in `apiauth/introspection.go`. Resource servers POST tokens to `POST /oauth/introspect` (authenticated via client_credentials). Returns RFC 7662 response with `active`, `sub`, `scope`, `exp`, `iss`, `jti`. Checks `TokenBlacklist`. Cache-Control: no-store. 9 unit + 3 e2e tests. Wired into reference server and e2e auth server.

### Phase 2: Client Registration Standards (Medium-term)

#### DCR Conformance Wrapper — RFC 7591 / RFC 7592 (#48)

**Priority: P2 | Urgency: [ADOPTION]**

Add a standards-compliant Dynamic Client Registration endpoint **alongside** the existing `AppRegistrar`, not replacing it.

**Approach: Conformance wrapper, not rewrite.**

| Phase | What | Effort |
|-------|------|--------|
| 2a | `POST /register` accepts DCR request format, maps to internal AppRegistrar | Small |
| 2b | DCR response format (RFC 7591 §3.2.1) with `registration_access_token` | Medium |
| 2c | RFC 7592 client management (`PUT /register/{id}`, `DELETE /register/{id}`) | Medium |
| 2d | Deprecate custom `/apps/*` endpoints | Small |

**Why not rip-and-replace AppRegistrar?**
- `AppQuota` (MaxRooms, MaxMsgRate) is domain-specific — DCR supports custom fields but existing consumers depend on current format
- `KidStore` + grace period rotation is genuinely useful and not standardized
- AppRegistrar is ~370 lines, not a maintenance burden
- Existing consumers (excaliframe, demo apps) would break

**What changes:**
- DCR uses `jwks` (JWK format) instead of raw PEM `public_key` — we already have `utils/jwk.go` for conversion
- DCR uses `client_uri` instead of `client_domain`
- `initial_access_token` replaces `X-Admin-Key` (or support both)
- AppQuota fields become DCR custom metadata

**What stays:**
- `KeyStore`, `KidStore`, grace period rotation — all internal, unaffected
- `AdminAuth` interface — still needed for admin-only operations (list all, bulk ops)
- `MintResourceToken` / `MintResourceTokenWithKey` — app-side, unrelated to registration wire format

### Phase 3: Keycloak Interop Test Suite (#49) ✅ COMPLETE

10 interop tests in `tests/keycloak/` proving `APIMiddleware` + `JWKSKeyStore` validate Keycloak-issued tokens. Pre-baked realm JSON, `make upkcl/testkcl/downkcl`, manual-trigger CI workflow. Separate Go module (`tests/keycloak/go.mod`).

**Architecture:**
```
tests/keycloak/
├── realm.json          # Pre-baked Keycloak realm config (imported on startup)
├── keycloak_test.go    # Go tests using testcontainers or Docker
└── README.md
```

**Realm config (checked in as JSON):**
- Realm with RS256 signing
- Confidential client (for client_credentials flow)
- Public client (for PKCE testing)
- Test user with known credentials

**Test categories:**

1. **Interop tests** (OneAuth as resource server validating Keycloak tokens):
   - `JWKSKeyStore` fetches Keycloak's JWKS via `/.well-known/openid-configuration`
   - `APIMiddleware` validates Keycloak-issued JWT
   - Scopes, audience, expiry, kid lookup all work
   - Algorithm confusion: Keycloak RS256 token rejected when validated as HS256

2. **Standards conformance tests:**
   - Keycloak JWKS response parses through `JWKToPublicKey`
   - Keycloak `kid` values resolve via `GetKeyByKid`
   - Token introspection (when built) matches Keycloak's response format

3. **What we skip:**
   - Keycloak's login flows through LocalAuth (different layers)
   - Keycloak admin API testing (their problem)

**Infrastructure:**
- `make testkcl` — starts Keycloak container, runs interop tests
- Keycloak image: `quay.io/keycloak/keycloak` with `start-dev` + realm import (~10-15s startup)
- Separate from `make e2e` (which stays fast at ~2s)
- Optional in CI (like `testpg` / `testds`)

**Adoption story:** "OneAuth middleware validates Keycloak-issued tokens correctly" — one-line pitch.

### Phase 4: OIDC Discovery Metadata (Long-term, Optional)

#### OIDC Discovery — RFC 8414 (#50)

**Priority: P2 | Urgency: [ADOPTION]**

Add `GET /.well-known/openid-configuration` to the reference server so standard OIDC clients can discover endpoints.

**Scope decision:** This is metadata-only — we advertise what we support, we do NOT implement a full OIDC authorization server. The reference server already has token, JWKS, and (planned) introspection endpoints.

```json
{
  "issuer": "https://auth.example.com",
  "token_endpoint": "https://auth.example.com/api/token",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
  "introspection_endpoint": "https://auth.example.com/oauth/introspect",
  "registration_endpoint": "https://auth.example.com/register",
  "scopes_supported": ["read", "write", "admin"],
  "response_types_supported": ["token"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "private_key_jwt"],
  "grant_types_supported": ["password", "refresh_token", "client_credentials"]
}
```

**Why optional:** This pushes toward being an auth server, which is explicitly not our goal. Only do this if the reference server sees real adoption as a standalone deployment.

---

## OAuth Client Capabilities (#51–#55)

These issues complete the OAuth client story — making OneAuth useful not just for building auth servers, but for building OAuth-aware clients and resource servers that interoperate with any AS.

### Prerequisites

#### Fix `aud` array validation — #52 (P0, Bug) ✅ COMPLETE

`matchesAudience()` helper handles both string and `[]interface{}` aud formats at all 3 validation sites. 8 new tests covering array accepted/rejected for ValidateAccessToken, ValidateAccessTokenFull, and APIMiddleware.

### Client-Side OAuth

#### `client_credentials` grant — #53 (P1) ✅ COMPLETE

Server: `handleClientCredentialsGrant` in `APIAuth` with `ClientKeyStore` field. Client: `ClientCredentialsToken()` on `AuthClient`. Supports `client_secret_post` and `client_secret_basic`. 8 unit + 2 e2e tests.

#### Headless OAuth + PKCE for CLI — #54 (P1)

Loopback redirect (RFC 8252) flow for CLI/agents. Supersedes the old "Phase 3: OAuth API Mode" items in NEXTSTEPS. Uses existing PKCE primitives from `oauth2/pkce.go`.

#### AS Metadata Discovery client — #51 (P1) ✅ COMPLETE

`DiscoverAS()` in `client/discovery.go`. Fallback chain: RFC 8414 → OIDC Discovery. Path-based issuer support. 8 unit tests + Keycloak interop test.

#### Token Introspection client — #55 (P2)

Client-side counterpart to #47. `IntrospectionValidator` as alternative validation strategy in `APIMiddleware`. Requires #47 + #53.

---

## Execution Order

```
Bug Fixes
    #52 Fix aud array (P0) ◄── blocks everything

                    ┌─────────────────────────┐
                    │ Phase 1: Resource Server │
                    │ Standards                │
                    ├─────────────────────────┤
                    │ #46 PRM (RFC 9728)      │◄── Smallest, do first
                    │ #47 Introspection (7662)│◄── Already on roadmap
                    └───────────┬─────────────┘
                                │
              ┌─────────────────┼─────────────────┐
              ▼                                   ▼
┌─────────────────────────┐         ┌─────────────────────────┐
│ Phase 2: DCR Wrapper    │         │ Phase 3: Keycloak Tests │
│ #48 (RFC 7591/7592)     │         │ #49                     │◄── Can start in parallel
└─────────────────────────┘         └─────────────┬───────────┘
                                                  │
              ┌───────────────────────────────────┘
              ▼
OAuth Client Capabilities (parallel track)
    #53 client_credentials ◄── foundational grant
    #54 Headless OAuth + PKCE ◄── supersedes old Phase 3
    #51 AS Discovery client ◄── enhances #54
    #55 Introspection client ◄── requires #47 + #53
    #50 OIDC Discovery server (optional)
```

**Recommended order:**
1. ~~**#52 Fix aud array** (P0 bug)~~ ✅ DONE
2. ~~**#46 PRM**~~ ✅ DONE
3. ~~**#49 Keycloak tests**~~ ✅ DONE
4. ~~**#53 client_credentials**~~ ✅ DONE
5. **#54 Headless OAuth + PKCE** — CLI/agent auth, supersedes old Phase 3
6. ~~**#47 Token Introspection server**~~ ✅ DONE
7. ~~**#51 AS Discovery client**~~ ✅ DONE
8. **#48 DCR wrapper** — standards-compliant registration
9. **#55 Introspection client** — requires #47 + #53
10. **#50 OIDC Discovery server** — only if reference server sees standalone adoption

---

## Relationship to Existing Work

### What this track does NOT change
- Core library architecture (embeddable, not a service)
- `KeyStore` / `KeyLookup` / `KeyStorage` interfaces
- `MintResourceToken` / `MintResourceTokenWithKey`
- `AdminAuth` interface
- Three-backend store pattern (FS, GORM, GAE)
- E2e test suite (`make e2e`)

### What this track complements
- **NEXTSTEPS Phase 3** (OAuth for non-browser clients) — #54 supersedes vague Phase 3 items, #53 adds machine-to-machine
- **NEXTSTEPS Redis Store** — introspection endpoint needs fast token lookup
- **NEXTSTEPS Token Blacklist** — introspection must check blacklist
- **Issue #20** (persist AppRegistrar state) — DCR wrapper benefits from persistent registrations

### Positioning vs Keycloak
OneAuth and Keycloak are **complementary, not competing:**
- Keycloak **is** the authorization server / IdP
- OneAuth **helps you build** Go services that validate tokens from Keycloak (or any OIDC provider)
- The Keycloak test suite (#49) makes this relationship explicit and tested
