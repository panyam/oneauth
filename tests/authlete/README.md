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

make upauthlete       # clones + builds + runs the frontend container (~5–10 min first time)
make testauthlete     # runs the interop suite
make downauthlete     # stops when done
```

First `upauthlete` clones `authlete/java-oauth-server` into `tests/authlete/.frontend/` (gitignored), Maven-builds the WAR, and runs Jetty on port 8280. Subsequent runs use Docker's layer cache and finish in ~30 s.

## What's tested

| Test | What it proves | Expected on a fresh service |
|------|---------------|---|
| `OIDCDiscovery` | Authlete's `/.well-known/openid-configuration` is parseable JSON | PASS |
| `DiscoverAS_Integration` | The discovery doc decodes into OneAuth's `client.ASMetadata` struct without errors | PASS |
| `JWKSFetchAndTokenValidation` | A `client_credentials` grant succeeds; if the token is a JWT, `APIMiddleware` validates it via `JWKSKeyStore` | PASS (validation skipped when opaque) |
| `JWKS_ParseableByOneAuth` | OneAuth's JWKS parser handles every key Authlete publishes | SKIP unless the service has RS256/ES256 keys configured |
| `RARRoundTrip` | RFC 9396 `authorization_details` round-trip end-to-end | SKIP unless `payment_initiation` is in the service's supported AD types |
| `IntrospectionResponseParses` | RFC 7662 introspection response shape matches OneAuth's expectations | SKIP unless a `clientType=RESOURCE_SERVER` client is registered |
| `AlgorithmConfusion_RejectedAgainstHSKeyStore` | An Authlete asymmetric token can't be smuggled through an HS256 keystore (CVE-2015-9235) | SKIP when token is opaque or HMAC |

**Every SKIP carries a one-line remediation in its message.** Add the missing service-config piece in the Authlete console and the SKIP transitions to PASS.

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
