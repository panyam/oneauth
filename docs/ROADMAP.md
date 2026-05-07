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

#### DCR Conformance Wrapper — RFC 7591 (#48) ✅ COMPLETE

`DCRHandler` in `admin/dcr.go`, served at `POST /apps/dcr` via `AppRegistrar.Handler()`. Maps JWK→PEM, `client_uri`→`client_domain`, `token_endpoint_auth_method`→`signing_alg`. Returns RFC 7591 response format. Supports both `X-Admin-Key` and Bearer auth. 6 unit + 2 e2e tests. Custom `/apps/*` endpoints continue working unchanged.

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

#### OIDC Discovery — RFC 8414 (#50) ✅ COMPLETE

`ASServerMetadata` + `NewASMetadataHandler` in `apiauth/as_metadata.go`. Serves `GET /.well-known/openid-configuration` with token, JWKS, introspection, registration endpoints. Metadata-only — does NOT make us a full OIDC server. 6 unit + 3 e2e tests (incl. `DiscoverAS` round-trip) + Keycloak field compatibility test. Wired into reference server and e2e auth server.

---

## OAuth Client Capabilities (#51–#55)

These issues complete the OAuth client story — making OneAuth useful not just for building auth servers, but for building OAuth-aware clients and resource servers that interoperate with any AS.

### Prerequisites

#### Fix `aud` array validation — #52 (P0, Bug) ✅ COMPLETE

`matchesAudience()` helper handles both string and `[]interface{}` aud formats at all 3 validation sites. 8 new tests covering array accepted/rejected for ValidateAccessToken, ValidateAccessTokenFull, and APIMiddleware.

### Client-Side OAuth

#### `client_credentials` grant — #53 (P1) ✅ COMPLETE

Server: `handleClientCredentialsGrant` in `APIAuth` with `ClientKeyStore` field. Client: `ClientCredentialsToken()` on `AuthClient`. Supports `client_secret_post` and `client_secret_basic`. 8 unit + 2 e2e tests.

#### Headless OAuth + PKCE for CLI — #54 (P1) ✅ COMPLETE

`LoginWithBrowser()` on `AuthClient`. Loopback redirect server, PKCE, state validation, auto-discovery via DiscoverAS (#51). 6 unit tests + Keycloak interop test. Supersedes old Phase 3.

#### AS Metadata Discovery client — #51 (P1) ✅ COMPLETE

`DiscoverAS()` in `client/discovery.go`. Fallback chain: RFC 8414 → OIDC Discovery. Path-based issuer support. 8 unit tests + Keycloak interop test.

#### Token Introspection client — #55 (P2) ✅ COMPLETE

`IntrospectionValidator` in `apiauth/introspection_client.go`. Integrates into `APIMiddleware.Introspection` as fallback when local JWT validation fails. Response caching with configurable TTL. 7 unit + 1 e2e + 2 Keycloak interop tests.

### Bug Fixes

#### Fix auth method negotiation with explicit endpoints — #74 (P1, Bug) ✅ COMPLETE

`BrowserLoginConfig.TokenEndpointAuthMethods` field. When explicit endpoints are provided (discovery skipped), callers can pass `token_endpoint_auth_methods_supported` from their own discovery so `SelectAuthMethod` negotiates correctly instead of defaulting to `client_secret_basic`. Found by MCPKit conformance test. 3 unit + 2 e2e tests.

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
5. ~~**#54 Headless OAuth + PKCE**~~ ✅ DONE
6. ~~**#47 Token Introspection server**~~ ✅ DONE
7. ~~**#51 AS Discovery client**~~ ✅ DONE
8. ~~**#48 DCR wrapper**~~ ✅ DONE
9. ~~**#55 Introspection client**~~ ✅ DONE
10. ~~**#50 OIDC Discovery server**~~ ✅ DONE

---

## MCPKit Pushdown — Generic OAuth Code (#78)

Pure-OAuth code pushed down from mcpkit/ext/auth (mcpkit#158) into oneauth for broader reusability.

### Client-Side DCR + Validation Utilities (#78) ✅ COMPLETE

- `client/dcr.go` — `RegisterClient` (RFC 7591 client-side DCR caller), `ClientRegistrationRequest`, `ClientRegistrationResponse`. Note: server-side DCR was already in `admin/dcr.go`; this is the client-side counterpart.
- `client/validation.go` — `ValidateHTTPS` (RFC 6749 §3.1.2.1 HTTPS enforcement with localhost exemption), `IsLocalhost` (loopback detection), `ValidateCIMDURL` (draft-ietf-oauth-client-id-metadata-document validation)
- `client/client_credentials_source.go` — `ClientCredentialsSource` (RFC 6749 §4.4 grant wrapper with token caching and scope step-up), `TokenSource` and `ScopeAwareTokenSource` interfaces
- `core/scopes.go` — `UnionScopes` (sorted, deduplicated scope union, complement to `IntersectScopes`)
- 20+ tests across `client/dcr_test.go`, `client/validation_test.go`, `client/client_credentials_source_test.go`, `core/scopes_test.go`

---

## App Registrar Persistence

Splits issue 20 (Persist AppRegistrar state) into shippable backend chunks. The schema additions for issue 157 (RFC 7592 management) are baked in upfront so subsequent tickets do not churn the table layout.

| # | Scope | Status |
|---|-------|--------|
| 165 | `AppRegistrationStore` interface + `InMemoryAppStore` + AppRegistrar refactor (cache + write-through) + `appstoretest` contract suite + e2e simulated-restart test | In progress |
| 166 | `FSAppStore` (filesystem backend) | Pending |
| 167 | `GORMAppStore` + reference-server config wiring | Pending |

After 167 lands, parent issue 20 can close. The chain unblocks the entire RFC 7592 track (issues 168 / 169 / 170 / 171) tracked under issue 157.

## RFC 7592 — DCR Management

Splits issue 157 (parent) into vertical verb-by-verb slices. Each ticket ships a server handler, a client SDK helper, tests, and a walkthrough step in `examples/06-dynamic-client-registration/`. The `ClientRegistrationManager` interface introduced in 168 is also the blueprint for issue 172 (transport-agnostic refactor of legacy admin/ surface).

| # | Slice | Status |
|---|-------|--------|
| 168 | Foundation + GET — registration_access_token + registration_client_uri issuance, `ClientRegistrationManager` interface, `DCRManagementHandler`, `client.GetRegistration`, walkthrough step | Merged |
| 169 | PUT — full-replace update + token re-issuance + `client.UpdateRegistration` + walkthrough steps; **manager interface and client SDK adopt the `(ctx, *Req) → (*Resp, error)` convention** (blueprint for 172 / 175) | Merged |
| 170 | DELETE — registration removal + KeyStore credential invalidation + `client.DeleteRegistration` + walkthrough step. Closes the verb trio. | In progress |
| 171 | Keycloak interop — full lifecycle test against Keycloak's RFC 7592 endpoints | Pending |

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
- **OAuth for non-browser clients** — #54 (headless OAuth + PKCE) and #53 (client_credentials) cover CLI/agent and machine-to-machine flows
- **Redis-backed distributed stores** (#115) — introspection endpoint benefits from fast token lookup
- **Token blacklist** — introspection checks the blacklist
- **Persist AppRegistrar state** (#20) — DCR wrapper benefits from persistent registrations
- **Authlete-superset tracker** (#163) — meta-issue aggregating gap-closure work, see [docs/gaps/AUTHLETE_GAP_ANALYSIS.md](gaps/AUTHLETE_GAP_ANALYSIS.md)

### Positioning vs Keycloak
OneAuth and Keycloak are **complementary, not competing:**
- Keycloak **is** the authorization server / IdP
- OneAuth **helps you build** Go services that validate tokens from Keycloak (or any OIDC provider)
- The Keycloak test suite (#49) makes this relationship explicit and tested
