# Authlete interop

Hand-authored audit of what [`tests/authlete/`](https://github.com/panyam/oneauth/tree/main/tests/authlete) proves about OneAuth's interoperability with [Authlete](https://www.authlete.com/) — the semi-hosted OAuth/OIDC token engine that powers several commercial deployments and the FAPI conformance suite.

The pitch is the same as for [Keycloak](keycloak.md): OneAuth has to validate, introspect, and round-trip tokens minted by a real implementation. Authlete is more interesting than Keycloak for one specific reason — it ships RFC 9396 (Rich Authorization Requests) end-to-end, which means we can verify our middleware against authoritative RAR tokens, not just against ourselves. See also: the [Authlete gap analysis](../gaps/AUTHLETE_GAP_ANALYSIS.md).

## Architecture

Authlete is *not* a self-contained AS. The local Docker container we run (`authlete/java-oauth-server`) is the AS **frontend** only — it serves wire endpoints (`/api/token`, `/.well-known/openid-configuration`, etc.) and back-channels every token operation over HTTPS to Authlete's cloud REST API:

```
test → java-oauth-server (local container) → HTTPS → Authlete cloud
       (frontend wire layer)                          (engine, signing keys, client store)
```

You need both a (free dev tier) Authlete cloud account *and* the local container; neither runs alone. The [`tests/authlete/provisioner/`](https://github.com/panyam/oneauth/tree/main/tests/authlete/provisioner) helper drives the cloud-side setup (registering clients, switching signing algorithms) via Authlete's management API so test runs are reproducible.

## How it runs

| | |
|---|---|
| Command | `make testauthlete` (requires the env vars below) |
| Container | `authlete/java-oauth-server` (frontend) |
| Cloud | `us.authlete.com` / `api.authlete.com` (free dev tier) |
| Source | `tests/authlete/{interop,testutil}_test.go` |
| Required env | `AUTHLETE_SERVICEID`, `AUTHLETE_ACCESS_TOKEN`, `AUTHLETE_CLIENTID`, `AUTHLETE_CLIENTSECRET` |

`make testauthlete` skips the suite cleanly when the env isn't set, so the default repo build is unaffected.

## Coverage map

OneAuth surface × Authlete behavior. ✅ = test exists and passes; ⛌ = deliberately deferred (linked to issue).

### Discovery + metadata

| OneAuth | Test |
|---|---|
| `client.DiscoverAS` parses Authlete's `/.well-known/openid-configuration` | `TestAuthlete_OIDCDiscovery`, `TestAuthlete_DiscoverAS_Integration` |

### JWKS + token validation

| OneAuth | Test | Notes |
|---|---|---|
| `JWKSKeyStore` parses Authlete's published JWKS | `TestAuthlete_JWKS_ParseableByOneAuth` | The kind of validation that catches "Authlete uses an alg/curve we mis-decode." |
| `APIMiddleware` accepts Authlete-issued tokens | `TestAuthlete_JWKSFetchAndTokenValidation` | Full mint-token-then-validate round trip. |
| `IntrospectionValidator` against Authlete | `TestAuthlete_IntrospectionResponseParses` | We accept the response shape Authlete returns. |
| Algorithm confusion (RS-signed token rejected against HS keystore) | `TestAuthlete_AlgorithmConfusion_RejectedAgainstHSKeyStore` | Defense-in-depth: same posture we enforce in the Go-native ratchet. |

### Rich Authorization Requests (RFC 9396)

| Flow | Test |
|---|---|
| End-to-end RAR round trip: client requests `authorization_details`, Authlete mints, OneAuth validates | `TestAuthlete_RARRoundTrip` |

The RAR round trip is the suite's load-bearing claim. The Go-native ratchet exercises `core/authorization_details.go` in isolation; this test runs it against Authlete's real RAR machinery so we catch shape drift that an in-process test wouldn't see.

## What this suite deliberately does *not* prove

- **FAPI 2.0 / mTLS / DPoP.** Authlete supports them; we don't yet. The matrix-mode runner that attempted to flip signing algs was abandoned in [PR 249](https://github.com/panyam/oneauth/pull/249) because Authlete's cloud takes minutes to settle after `SetSignAlg` PUTs — not worth the runtime tax until we have surface to test.
- **Issuance from OneAuth that Authlete consumes.** Same one-way arrow as the Keycloak suite: tokens flow Authlete → OneAuth, not the reverse.
- **Authlete-specific extensions** beyond what the Authlete gap analysis lists as "in scope." See [`docs/gaps/AUTHLETE_GAP_ANALYSIS.md`](../gaps/AUTHLETE_GAP_ANALYSIS.md) for the full inventory of "stays blocked on missing OneAuth surface."

## How this page is published

Source of truth lives here. The docs site at `docs/site/content/conformance/authlete.html` renders it verbatim via `renderMarkdownFile`. The published `/conformance/authlete/` page picks up changes on the next build.

## Follow-ups

- **Auto-regenerate from `go test -json`.** Same future work flagged in [keycloak.md](keycloak.md) — when the curation cost gets painful, parse the test stream and emit this table mechanically.
- **Re-attempt matrix-mode signing-alg sweep** once Authlete's settle-time becomes a smaller fraction of total runtime, or once `SetSignAlg` can be batched.
