# Keycloak interop

Hand-authored audit of what [`tests/keycloak/`](https://github.com/panyam/oneauth/tree/main/tests/keycloak) proves about OneAuth's interoperability with [Keycloak](https://www.keycloak.org/) — a battle-tested OAuth/OIDC server widely deployed as a corporate IdP.

The pitch: OneAuth has to behave correctly when *both* sides of the conversation are real implementations. That includes accepting Keycloak-minted tokens at our middleware, talking to Keycloak's discovery / JWKS / introspection / DCR endpoints from our client SDK, and surviving the wire-level quirks (audience as string-or-array, kid lookup, rotated registration access tokens). This page is the audit trail of *what we actually check* — distinct from the Go-native conformance ratchet at [`docs/conformance/native.md`](native.md), which exercises OneAuth as an AS without a third party in the loop.

## How it runs

| | |
|---|---|
| Command | `make testkcl` (auto-starts the container if needed) |
| Container | `keycloak/keycloak` started by `make upkcl` |
| Realm | `tests/keycloak/realm.json` (imported on startup) |
| Default ports | KC=`8180`, RAR sidecar=`8181` (`KC_PORT` / `RAR_PORT` override) |
| Source | `tests/keycloak/{interop,private_key_jwt,dcr_management,rar_interop}_test.go` |

The container takes ~15 seconds to come up and import the realm. Tests are fully in-process: they fetch Keycloak's discovery doc, mint tokens, and assert OneAuth's middleware / client behavior against them.

## Coverage map

OneAuth surface × Keycloak behavior. ✅ = test exists and passes; ⛌ = deliberately deferred (linked to issue).

### Discovery + metadata

| OneAuth | Test | Notes |
|---|---|---|
| `client.DiscoverAS` parses Keycloak's `/.well-known/openid-configuration` | `TestKeycloak_OIDCDiscovery`, `TestKeycloak_DiscoverAS_Integration` | Both raw HTTP parse and SDK helper. |
| Metadata field compatibility (issuer, endpoints, alg lists) | `TestKeycloak_ASMetadataFieldCompatibility` | Sanity check on the field surface OneAuth depends on. |
| RFC 8414 metadata proxying | `TestKeycloak_RFC8414Proxy` | Confirms our handler can stand in front of an upstream Keycloak. |

### Key handling

| OneAuth | Test |
|---|---|
| `JWKSKeyStore` fetches + parses Keycloak JWKS | `TestKeycloak_JWKS_FetchAndParse`, `TestKeycloak_JWKSKeyStore_Integration` |
| `utils.JWKToPublicKey` handles Keycloak's RSA JWKs | `TestKeycloak_JWKS_ParseViaJWKToPublicKey` |
| `kid`-header → key lookup via `GetKeyByKid` | `TestKeycloak_ValidateToken_KidLookup` |

### Token validation (APIMiddleware accepts Keycloak tokens)

| Grant / scenario | Test |
|---|---|
| client_credentials | `TestKeycloak_ValidateToken_ClientCredentials` |
| password grant | `TestKeycloak_ValidateToken_PasswordGrant` |
| `aud` as string or array | `TestKeycloak_ValidateToken_AudienceArray` (issue 52) |
| Tampered token rejected | `TestKeycloak_InvalidToken_Rejected` |
| Wrong client_secret rejected | `TestKeycloak_WrongSecret_Rejected` |
| Authorization code + PKCE end-to-end | `TestKeycloak_AuthorizationCodePKCE_FullFlow` |

### Client authentication negotiation

| Method | Test |
|---|---|
| `client_secret_basic` | `TestKeycloak_AuthMethodNegotiation_Basic`, `TestKeycloak_ClientCredentials_WithAuthMethod` |
| `client_secret_post` | `TestKeycloak_AuthMethodNegotiation_Post` |
| `private_key_jwt` | `tests/keycloak/private_key_jwt_test.go` (full set) |

### Introspection

| OneAuth | Test |
|---|---|
| `client.Introspect` against Keycloak's `/protocol/openid-connect/token/introspect` | `TestKeycloak_IntrospectionClient` |
| Negative path: invalid token returns `active:false` | `TestKeycloak_IntrospectionClient_InvalidToken` |

### Dynamic Client Registration

| Feature | Test |
|---|---|
| RFC 7592 lifecycle (Get / Update / Delete) | `TestKeycloak_DCRManagement_Lifecycle` (issue 171) |
| `registration_access_token` rotation on PUT | covered by the same test |
| Rotated-out token rejected | covered by the same test |

### Rich Authorization Requests (RFC 9396)

RAR conformance is tested against a sidecar issuer (`cmd/oneauth-server/deploy-examples/rar-test.yaml`) rather than Keycloak directly — Keycloak's RAR support is partial. See [`tests/keycloak/rar_interop_test.go`](https://github.com/panyam/oneauth/tree/main/tests/keycloak/rar_interop_test.go); the RAR-specific scorecard is the Go-native ratchet plus the OIDF Phase 2 plan.

## What this suite deliberately does *not* prove

- **Issuance from OneAuth that Keycloak accepts.** The arrow is one-way: tokens flow `Keycloak → OneAuth.APIMiddleware`. The reverse path (Keycloak accepting OneAuth-minted tokens) isn't a meaningful interop story because Keycloak isn't a resource server for our tokens in any real deployment.
- **End-user UI flows.** Discovery / token / introspection are wire tests; the browser-driven login flows live in `examples/` walkthroughs, not here.
- **High-availability / clustering quirks.** Single container, single realm, single key.

## How this page is published

This file is the source of truth. The docs site at `docs/site/content/conformance/keycloak.html` renders it verbatim via `renderMarkdownFile`. Update this `.md` and the published `/conformance/keycloak/` page picks the change up on the next build.

## Follow-ups

- **Auto-regenerate from `go test -json`.** Today this page is hand-curated; future work parses the test stream so the table stays in lockstep with the suite. Tracked alongside the same idea for the Authlete suite — file an issue when the duplication gets painful enough.
