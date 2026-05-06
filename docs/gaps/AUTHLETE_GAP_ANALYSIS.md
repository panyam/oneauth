# Authlete vs OneAuth — Gap Analysis

**Date:** 2026-04-28
**Purpose:** Compare Authlete's OAuth/OIDC backend service against OneAuth to identify gaps, surface architectural differences, and decide which (if any) to close.

---

## Executive Summary

Authlete and OneAuth answer different questions. Auth0 (covered in [AUTH0_GAP_ANALYSIS.md](AUTH0_GAP_ANALYSIS.md)) is a full IdP-as-a-service. **Authlete is a semi-hosted OAuth/OIDC *protocol engine*** — its customer builds an authorization-server frontend (login UI, consent screens, user store, sessions) and delegates all the protocol-correct token issuance, validation, and lifecycle work to Authlete via REST APIs. Authlete does not see end users.

OneAuth is a **Go library** that bundles user/identity/channel management *and* a transport-independent token engine into one importable package. It overlaps with Authlete in the token-engine layer; it overlaps with Auth0 in the user-mgmt layer.

**Headline gap:** Authlete is the leading **spec-completeness** play — FAPI 1 & 2, JAR, JARM, PAR, RAR, CIBA, DPoP, mTLS, OpenID Federation 1.0, OID4VCI, Token Exchange, Device Flow, multiple regional Open Banking profiles. OneAuth covers a much narrower surface: bearer JWT issuance via password/client_credentials/refresh, RAR on the token endpoint, RFC-compliant introspection/revocation/discovery/DCR/JWKS metadata, and Keycloak interop. **No /authorize endpoint, no id_token, no DPoP/mTLS/PAR/JAR/JARM/CIBA/Federation/OID4VC.**

The honest framing: **OneAuth doesn't compete with Authlete and shouldn't try to.** Authlete is engineered to pass conformance suites for regulated industries (UK/AU/BR/KSA Open Banking, EUDI Wallet, GAIN, FAPI). OneAuth is engineered to make Go services easy to authenticate against an existing IdP (Keycloak, Authlete, Auth0, etc.). The right strategic posture is: pick a small set of Authlete-grade specs that have value *for the resource-server / federated-app niche* and adopt those; ignore the rest.

---

## 1. Architectural Model Comparison

| Dimension | Authlete | OneAuth |
|---|---|---|
| **Form factor** | Hosted (or self-hosted enterprise) backend; integrate via REST APIs | Go library, embedded in your binary |
| **What customer builds** | The AS frontend: `/authorize`, login UI, consent UI, user store, sessions | Your application — OneAuth provides `/api/token`, login handlers, middleware, optional reference server (`cmd/oneauth-server`) |
| **Where token data lives** | Authlete's database (DB-less for the customer) | Your database, via `TokenStore`, `RefreshTokenStore`, `KeyStorage` (FS / GORM / GAE) |
| **Where user data lives** | Customer's database (Authlete never sees users) | OneAuth's stores (`UserStore`, `IdentityStore`, `ChannelStore`) — **you can replace these** |
| **Protocol scope** | Comprehensive — designed to pass FAPI / Open Banking / EUDI conformance | Pragmatic — JWT bearer flows, federated resource tokens, Keycloak interop |
| **Pricing model** | Per-API-call SaaS (or licensed self-host) | OSS / no per-user cost |
| **Language** | Java reference + customer-written frontends in any language | Go (only) |
| **Audit & compliance** | SOC2 / ISO certified service | You self-host; your problem |

**The single most important consequence:** Authlete *intentionally* does not own the user. OneAuth does (User → Identity → Channel). If you want to combine them you'd use OneAuth's user model on the AS frontend and Authlete on the protocol backend — they're not redundant in that configuration.

---

## 2. Use-Case Comparison

### Authlete's sweet spot
1. **Regulated AS operators** that must pass FAPI / Open Banking / FAPI-CIBA conformance and don't want to maintain spec-compliant code themselves.
2. **VC issuers** (governments, banks, universities) standing up OID4VCI / SD-JWT VC / mDL endpoints.
3. **National digital-identity programs** (EUDI, Trusted Web, GAIN POC) where every spec change must be tracked.
4. **Banks doing Open Banking** in UK / AU / BR / KSA — Authlete ships profile-specific certified configurations.
5. **CIBA / decoupled-auth flows** for high-assurance financial APIs.
6. **mTLS / DPoP sender-constrained tokens** for clients that legally can't accept bearer-only.

### OneAuth's sweet spot
1. **Go services** that need user signup / login / OAuth social link without a SaaS dependency.
2. **Federated multi-service systems** (the `MintResourceToken` / per-app KeyStore pattern from massrelay/excaliframe) where one host app vouches for tokens consumed by other resource servers.
3. **Resource servers validating tokens from external IdPs** (Keycloak, Auth0, Authlete) via JWKS / introspection / RFC 9728 protected-resource-metadata.
4. **CLI tools** — `AuthClient` with auto-refresh, browser-launched Authorization Code + PKCE against any RFC 8414 / OIDC-Discovery AS.
5. **Internal / dev / SMB SaaS** where Auth0 pricing is unjustified and FAPI is overkill.
6. **gRPC services** — first-class interceptors, no Authlete equivalent.

### What neither targets
- Authlete: turnkey IdP for an SMB app (no UI / user mgmt / MFA / SDKs).
- OneAuth: regulated finance / sovereign-identity programs (insufficient spec breadth).

---

## 3. Standards Coverage Matrix

Legend: **Full** = implemented and conformance-tested · **Partial** = implemented at one layer only · **None** = not implemented · **N/A** = doesn't apply to OneAuth's posture

| Spec | RFC / link | Authlete | OneAuth | Gap |
|---|---|---|---|---|
| **OAuth 2.0 framework** | RFC 6749 | Full (all grants) | Partial (`password`, `refresh_token`, `client_credentials` — **no `authorization_code`**, no implicit) | Partial |
| **Bearer Token Usage** | RFC 6750 | Full | Full | Full |
| **PKCE** | RFC 7636 | Full (server + enforces) | Partial — **client-side only** (`AuthClient` uses PKCE against external AS); OneAuth as AS doesn't issue authorization codes | Partial |
| **Token Introspection** | RFC 7662 | Full | Full (`/oauth/introspect`, `IntrospectionHandler` + caching client) | Full |
| **Token Revocation** | RFC 7009 | Full | Full (`/oauth/revoke`, `RevocationHandler`) | Full |
| **Token Exchange** | RFC 8693 | Full | None | **None** |
| **Device Authorization Grant** | RFC 8628 | Full | None (CLI uses browser-loopback PKCE instead) | **None** |
| **AS Metadata** | RFC 8414 | Full | Full (`/.well-known/oauth-authorization-server`, `NewASMetadataHandler`) | Full |
| **OIDC Discovery** | OIDC-Discovery 1.0 | Full | Partial — serves the doc, but no OIDC primitives behind it (no id_token / userinfo) | Partial |
| **JWKS** | RFC 7517 | Full | Full (`JWKSHandler` + `JWKSKeyStore` client) | Full |
| **JWT** | RFC 7519 | Full | Full (HS256 / RS256 / ES256, algorithm-confusion prevention) | Full |
| **DCR** | RFC 7591 | Full | Full (`DCRHandler` at `/apps/dcr`) | Full |
| **DCR Management** | RFC 7592 | Full | None (no PUT/DELETE on registered clients via DCR) | **None** |
| **Protected Resource Metadata** | RFC 9728 | Full | Full (`NewProtectedResourceHandler`) | Full |
| **Rich Authorization Requests (RAR)** | RFC 9396 | Full | Full on `/api/token`, introspection, middleware enforcement | Full |
| **Resource Indicators** | RFC 8707 | Full | Partial (via `MintResourceToken` audience) | Partial |
| **PAR (Pushed Authorization Requests)** | RFC 9126 | Full | None | **None** |
| **JAR (JWT-Secured Authz Request)** | RFC 9101 | Full | None | **None** |
| **JARM (JWT-Secured Authz Response Mode)** | OpenID FAPI JARM | Full | None | **None** |
| **DPoP** | RFC 9449 | Full | None | **None** |
| **mTLS Client Auth + Cert-Bound Tokens** | RFC 8705 | Full | None | **None** |
| **HTTP Message Signatures** | RFC 9421 (FAPI 2.0 MS) | Full | None | **None** |
| **CIBA Core** | OpenID CIBA 1.0 | Full (since 2019) | None | **None** |
| **OpenID Connect Core** | OIDC Core 1.0 | Full | None — **no id_token, no userinfo, no `/authorize`** | **None** |
| **OIDC Session Management / Front-Channel / Back-Channel Logout** | OIDC suite | Full | None | **None** |
| **OIDC Federation 1.0** | OpenID Federation 1.0 | Full | None | **None** |
| **OID4VCI (VC Issuance)** | OID4VCI | Full (SD-JWT VC, mdoc / mDL) | None | **None** |
| **OID4VP (VC Presentation)** | OID4VP | Full | None | **None** |
| **FAPI 1.0 baseline + advanced** | FAPI 1.0 | Full (certified) | None | **None** |
| **FAPI 2.0 Security Profile** | FAPI 2.0 | Full (certified) | None | **None** |
| **FAPI 2.0 Message Signing** | FAPI 2.0 MS | Full | None | **None** |
| **FAPI-CIBA** | OpenID FAPI-CIBA | Full (certified) | None | **None** |
| **UK / AU / BR / KSA Open Banking profiles** | regional | Full | None | **None** |
| **WebAuthn / FIDO2** | W3C / FIDO2 | N/A (Authlete delegates auth to frontend) | None | N/A |
| **MFA (TOTP, push, SMS)** | — | N/A (frontend concern) | None | N/A |
| **SAML 2.0** | OASIS | Out of scope | Partial (SP only via `crewjam/saml`) | n/a vs Authlete |

---

## 4. Client Authentication Method Coverage

| Method | Authlete | OneAuth |
|---|---|---|
| `none` (public client) | Full | Full |
| `client_secret_basic` | Full | Full |
| `client_secret_post` | Full | Full |
| `client_secret_jwt` | Full | None |
| `private_key_jwt` | Full | None |
| `tls_client_auth` | Full | None |
| `self_signed_tls_client_auth` | Full | None |
| `attest_jwt_client_auth` (FAPI 2.0 attest) | Full | None |

OneAuth client SDK (`client/auth_method.go`) **negotiates** auth methods from AS metadata and falls back when the AS only advertises ones it doesn't support — so it's aware of `private_key_jwt` and `tls_client_auth`, but doesn't implement them.

---

## 5. Where OneAuth Has Things Authlete Does Not

These are not gaps in OneAuth — they are scope choices Authlete made deliberately.

1. **Embedded Go library, no service to operate.** Authlete is always a network call (or a self-hosted Java service).
2. **Three-layer User → Identity → Channel model.** Authlete has no opinion on user data — that's the customer's problem.
3. **Federated resource-token pattern (`MintResourceToken`).** Per-app KeyStore + JWKS-based discovery for multi-service architectures. Authlete supports the underlying RFCs but doesn't ship this opinionated pattern.
4. **Per-app quotas in JWT claims** (`max_rooms`, `max_msg_rate`).
5. **gRPC interceptors.** No Authlete equivalent.
6. **Algorithm-confusion prevention exposed per-client** (`GetExpectedAlg`). Authlete does this internally, doesn't expose it.
7. **Three storage backends with shared test suite** (FS / GORM / GAE).
8. **Config-driven reference server** (`cmd/oneauth-server`) with YAML + `${ENV_VAR}` substitution.
9. **No per-call cost.** Authlete's pricing scales with token-endpoint traffic.
10. **Local/social login + OAuth providers built in.** Authlete is downstream of all of this.

---

## 6. Strategic Read

Authlete and OneAuth are *layer-different*. A production deployment could legitimately be **OneAuth (user + AS frontend) → Authlete (protocol engine)** if the customer needs FAPI/CIBA/OID4VCI compliance but wants OneAuth's user model and Go ergonomics. We don't need to "catch up" to Authlete to be useful.

That said, a few Authlete capabilities have value for OneAuth's actual niche (resource servers, federated multi-service apps) and are worth considering:

### Worth picking up (would benefit OneAuth's users)

| # | Capability | Why it fits OneAuth's niche | Effort |
|---|---|---|---|
| 1 | **DPoP (RFC 9449)** for access tokens | Sender-constrained tokens — useful for federated multi-service architectures where a token leak shouldn't let an attacker replay. Validation is cheap; issuance is moderate. | Medium |
| 2 | **`private_key_jwt` client auth** | Removes shared-secret distribution for the federated `MintResourceToken` flow; aligns with what Keycloak / Authlete / Auth0 already accept. | Small |
| 3 | **Token Exchange (RFC 8693)** | Useful for service-to-service downscoping in federated systems; `MintResourceToken` is already philosophically close. | Medium |
| 4 | **`authorization_code` grant + `/authorize` endpoint + id_token** | Would make OneAuth a real (minimal) OIDC provider, not just a metadata advertiser. Big lift but is the door to "use OneAuth instead of Keycloak for small deployments." Carefully decide if this is in scope vs. the stated "we are not a full OIDC IdP" position in [ROADMAP.md](../ROADMAP.md). | Large |
| 5 | **PAR (RFC 9126)** | Only valuable if (4) lands. | Small once (4) exists |

### Probably not worth it (out of niche)

- **FAPI 1/2 conformance, FAPI-CIBA, JARM, mTLS cert-bound tokens, OpenID Federation, OID4VCI, regional Open Banking profiles** — these are Authlete's moat. Pursuing them means re-targeting OneAuth at regulated industries, which conflicts with the "embeddable Go library" identity in [ROADMAP.md](../ROADMAP.md).
- **CIBA** — only relevant if you're issuing tokens for high-assurance decoupled flows.
- **Token Introspection of Authlete-issued tokens** — already supported via `IntrospectionValidator`, no work needed.

### Clear non-goals (already settled in the roadmap)

- Hosted multi-tenant SaaS form factor
- Conformance certification programs
- VC issuance / digital wallet support

---

## 7. Recommended Position Statement

> "OneAuth is a Go library for building authenticated services and federated resource servers. For protocol-engine work that requires regulatory-grade conformance — FAPI, Open Banking, EUDI Wallet, OID4VCI, CIBA — pair OneAuth's user model and middleware with a dedicated AS backend like Authlete or Keycloak. OneAuth's Keycloak interop suite ([`tests/keycloak/`](../../tests/keycloak/)) demonstrates this pattern; an Authlete equivalent could be added if a real consumer needs it."

If we eventually want to make this concrete, an `tests/authlete/` interop suite (mirroring `tests/keycloak/`) would prove the pairing the same way and give us the same one-liner credibility for regulated-industry conversations.

---

## Sources

- [Authlete Overview](https://www.authlete.com/developers/overview/)
- [Authlete Spec Sheet](https://www.authlete.com/legal/spec_sheet/)
- [Authlete FAPI Compliance](https://www.authlete.com/developers/fapi/)
- [Authlete CIBA](https://www.authlete.com/developers/ciba/)
- [Authlete OID4VCI announcement (Authlete 3.0)](https://www.prnewswire.com/news-releases/authlete-introduces-support-for-openid-for-verifiable-credential-issuance-with-authlete-3-0--302296725.html)
- [Authlete API Protection Overview](https://www.authlete.com/developers/api_protection/)
- [Authlete DPoP guide](https://www.authlete.com/kb/oauth-and-openid-connect/proof-of-possession-pop-tokens/dpop/)
- [Authlete JARM guide](https://kb.authlete.com/en/s/oauth-and-openid-connect/a/enabling-jarm)
- OneAuth: [README.md](../../README.md) · [CAPABILITIES.md](../../CAPABILITIES.md) · [ROADMAP.md](../ROADMAP.md) · [ARCHITECTURE.md](../ARCHITECTURE.md) · [AUTH0_GAP_ANALYSIS.md](AUTH0_GAP_ANALYSIS.md)
