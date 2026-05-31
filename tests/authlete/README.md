# Authlete Interop Tests

Tests that prove OneAuth's `APIMiddleware`, `JWKSKeyStore`, and `IntrospectionValidator` correctly accept tokens issued by [Authlete](https://www.authlete.com/) — the semi-hosted OAuth/OIDC protocol engine. Same "OneAuth validates X's tokens correctly" credibility pitch we have for Keycloak (see [tests/keycloak/README.md](../keycloak/README.md)).

## Architecture

Authlete is **not** a self-contained AS. The Docker container we run locally (`authlete/java-oauth-server`) is only the AS **frontend** — it serves the wire endpoints (`/api/token`, `/.well-known/openid-configuration`, etc.) and back-channels every actual token operation to Authlete's cloud REST API:

```
test → java-oauth-server container → HTTPS → Authlete cloud (us.authlete.com / api.authlete.com)
       (frontend wire layer)                 (token engine, signing keys, client store, spec compliance)
```

You need both an Authlete cloud account (free dev tier works) AND the local container. The container alone has nothing to talk to.

## Prerequisites

1. **Authlete dev account** — sign up at https://console.authlete.com/. Free tier is sufficient.
2. **An OAuth client registered in your service** — under Service → Clients → "Register Client." Set `tokenAuthMethod` to `client_secret_basic`. If you set a `clientIdAlias`, that's what tests pass over the wire (not the numeric ID).
3. **Service-level access token** — Service → API Authentication. Required for the local container's back-channel.
4. **Docker** — for the local frontend container.

## Quick start

```bash
export AUTHLETE_SERVICEID=<numeric service ID>
export AUTHLETE_ACCESS_TOKEN=<service access token>
export AUTHLETE_CLIENTID=<client alias if set, else numeric client ID>
export AUTHLETE_CLIENTSECRET=<client secret>

# Optional — defaults to https://api.authlete.com. Override for regional tenants:
export AUTH_API_SERVER=https://us.authlete.com

make upauthlete         # clones + builds + runs the frontend container (~5–10 min first time)
make authlete-provision # configures service for full PASS (issue 244, idempotent)
make testauthlete       # runs the interop suite
make downauthlete       # stops when done

# Reverse the service changes when finished:
make authlete-deprovision
```

First `upauthlete` clones `authlete/java-oauth-server` into `tests/authlete/.frontend/` (gitignored), Maven-builds the WAR, and runs Jetty on port 8280. Subsequent runs use Docker's layer cache and finish in ~30 s.

## What `make authlete-provision` does (issue 244)

A vanilla Authlete service ships with no JWKS, no RAR types, and no per-client RAR declarations. Without those, half the interop tests skip with actionable messages — useful for diagnosing, but bad DX for "just run the suite."

`make authlete-provision` is a one-shot, idempotent Make target that uses the Authlete management API (via the service access token you already have) to apply the missing config:

| Mutation | Effect on the suite |
|---|---|
| Generate an RSA-2048 JWK Set + set the service's `jwks` field | Authlete signs JWTs instead of opaque tokens — unlocks JWKS-based validation + algorithm-confusion tests |
| Add `payment_initiation` to `supportedAuthorizationDetailsTypes` (service) | Authlete admits RFC 9396 token requests for that type |
| Add `payment_initiation` to the TestClient's `authorizationDetailsTypes` (client) | Authlete enforces declared types on the *client* in addition to the service — both needed for the RAR test |

A snapshot of the pre-provision state is written to `tests/authlete/.frontend/.preprovision.json` (gitignored). `make authlete-deprovision` reads it and reverses every mutation, restoring the service to its prior state.

**Safety belt:** export `AUTHLETE_TEST_SERVICEID=<different-service-id>` to operate on a separate test service instead of `AUTHLETE_SERVICEID` — avoids mutating a primary tenant.

**Introspection note:** the suite uses java-oauth-server's built-in resource-server credentials (`rs0`/`rs0-secret`, baked into the container's `/resource_servers.json`) for RFC 7662 introspection. No Authlete-side provisioning needed for that. Override with `AUTHLETE_INTROSPECTOR_CLIENTID` / `AUTHLETE_INTROSPECTOR_CLIENTSECRET` if your frontend uses different RS creds.

## What's tested

| Test | What it proves | After `make authlete-provision` |
|------|---------------|---|
| `OIDCDiscovery` | Authlete's `/.well-known/openid-configuration` is parseable JSON | PASS |
| `DiscoverAS_Integration` | The discovery doc decodes into OneAuth's `client.ASMetadata` struct without errors | PASS |
| `JWKSFetchAndTokenValidation` | A `client_credentials` grant succeeds; if the token has a `sub`, `APIMiddleware` validates it via `JWKSKeyStore` | SKIP — Authlete's client_credentials grant emits `sub:null`, which `APIMiddleware` correctly rejects. Switch to a `password` / `auth_code` grant in this test to flip to PASS. |
| `JWKS_ParseableByOneAuth` | OneAuth's JWKS parser handles every key Authlete publishes | PASS |
| `RARRoundTrip` | RFC 9396 `authorization_details` round-trip end-to-end | PASS |
| `IntrospectionResponseParses` | RFC 7662 introspection response shape matches OneAuth's expectations | PASS |
| `AlgorithmConfusion_RejectedAgainstHSKeyStore` | An Authlete asymmetric token can't be smuggled through an HS256 keystore (CVE-2015-9235) | PASS |

Result after `make authlete-provision`: **6 PASS + 1 SKIP** (the JWT-sub interop wrinkle is the only remaining skip).

## Env vars reference

| Env var | Purpose | Used by |
|---|---|---|
| `AUTHLETE_SERVICEID` | Numeric service identifier (your tenant) | Container back-channel |
| `AUTHLETE_ACCESS_TOKEN` | Service Access Token (Bearer auth to Authlete cloud) | Container back-channel |
| `AUTHLETE_CLIENTID` | OAuth client identifier — **alias if one is set, else numeric** | Tests (token endpoint) |
| `AUTHLETE_CLIENTSECRET` | OAuth client secret | Tests (token + introspection) |
| `AUTH_API_SERVER` | Authlete cloud base URL — defaults `https://api.authlete.com`; override for regions (`us.authlete.com`, `eu.authlete.com`, etc.) | Container back-channel |
| `AUTHLETE_AS_URL` | Frontend base URL — defaults `http://localhost:8280`; set by `make testauthlete` | Tests |

### Why "alias if set, else numeric" for `AUTHLETE_CLIENTID`

Authlete identifies clients two ways: an internal numeric `clientId` (e.g., `1506059443`) and an optional human-readable `clientIdAlias` (e.g., `TestClientId`). When an alias is set, Authlete's wire layer **requires** the alias on the token endpoint and **rejects** the numeric ID with `A493304 No client has the specified identifier`. The numeric ID stays useful for management-API calls (listing/getting clients) but cannot be sent as `client_id` over the OAuth wire.

## Keeping java-oauth-server current

Upstream doesn't tag releases (only master commits). The Makefile pins a specific commit SHA via `AUTH_FRONTEND_REF`. To bump:

```bash
make upauthlete-refresh AUTH_FRONTEND_REF=<new-commit-sha>
```

That clears the local clone and the cached Docker image so the next `upauthlete` rebuilds against the new ref. Track upstream at https://github.com/authlete/java-oauth-server.

## What this suite does NOT cover

- `/authorize` endpoint flow — OneAuth doesn't have one (#116 tracks it); the AS frontend has it, but our tests live one layer up.
- DPoP / mTLS / PAR / JAR / JARM interop — out of OneAuth's spec scope today (see [docs/gaps/AUTHLETE_GAP_ANALYSIS.md](../../docs/gaps/AUTHLETE_GAP_ANALYSIS.md)).
- FAPI 1 / FAPI 2 conformance — separate effort under #163.
- Authlete's REST API directly (no `client.AuthleteClient` SDK). The frontend container is the only way OneAuth talks to Authlete.
