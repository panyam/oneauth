# OIDF conformance baseline — 2026-06-09

Re-run after issue 250 closed Cluster B (TLS-fronted harness variant).
Discovery plan now runs against `https://host.docker.internal:8888`
with `cmd/oneauth-server`'s built-in TLS mode presenting a self-signed
cert from `tests/oidf-conformance/certs/server.crt`; the harness JVM
trusts the matching CA via `truststore.jks` mounted into the container.

**Setup:** harness via `make upoidf`, AS via `make upoidf-as` (memory
mode, RS256 ephemeral signing, TLS enabled, `iss=https://host.docker.internal:8888`).
Image tags as of run: `mongo:6.0.13` + harness `latest` from
`registry.gitlab.com/openid/conformance-suite`.

## Scoreboard

| Plan | Modules | Verdict | Remaining blocker |
|---|---|---|---|
| `oidcc-config-certification-test-plan` | 1 (`oidcc-discovery-endpoint-verification`) | **PASSED with 1 expected-fail** (down from 8 failures + 3 warnings) | `userinfo_endpoint` missing → issue 116 |
| `oidcc-basic-certification-test-plan` (1st test — `oidcc-server`) | 35 modules total | **FAILED — interrupted at step 1**, unchanged | `authorization_endpoint` missing → issue 116 |
| `oidcc-dynamic-certification-test-plan` | 22+ modules | Same blocker as Basic — unchanged | issue 116 |

## What changed between 2026-05-09 and 2026-06-09

| Check | 2026-05-09 | 2026-06-09 | How |
|---|---|---|---|
| `OIDCCCheckDiscEndpointClaimsSupported` | warning | **pass** | `cmd/oneauth-server` now populates `claims_supported` by default (`sub`, `iss`, `aud`, `exp`, `iat`, `jti`, `scope`, `client_id`) |
| `CheckDiscEndpointScopesSupportedContainsOpenId` | warning | **pass** | `cmd/oneauth-server` now populates `scopes_supported` by default (`openid`, `profile`, `email`, `read`, `write`, `offline`) |
| `CheckDiscEndpointDiscoveryUrl` | failure (https expected) | **pass** | TLS mode advertised on discovery |
| `CheckDiscEndpointTokenEndpoint` | failure (https expected) | **pass** | same |
| `CheckDiscEndpointRegistrationEndpoint` | failure (https expected) | **pass** | same |
| `CheckJwksUri` | failure (https expected) | **pass** | same |
| `CheckDiscEndpointAllEndpointsAreHttps` | failure (aggregate) | **pass** | same |

## Discovery-test remaining failure

Test: `oidcc-discovery-endpoint-verification` against `https://host.docker.internal:8888/.well-known/openid-configuration`.

| Failure | Source check | Type | Why still open |
|---|---|---|---|
| `userinfo_endpoint`: not present (warning) | `CheckDiscEndpointUserinfoEndpoint` | endpoint missing | issue 116 (the userinfo endpoint is part of the OIDC IdP surface) |

Plus the 4 substantive gaps still gated on issue 116:

- `OIDCCCheckDiscEndpointResponseTypesSupported`
- `OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported`
- `CheckDiscEndpointAuthorizationEndpoint`
- `CheckDiscEndpointUserinfoEndpoint`

## Auth-flow plans (Basic / Dynamic / Form-Post / Logout)

Unchanged from 2026-05-09 — every one of these requires `/authorize` at
step 1 and remains blocked on issue 116. They'll wire into the ratchet
in a follow-up once 116 ships.

## Provenance

- Harness Docker image: `registry.gitlab.com/openid/conformance-suite:latest` (pulled 2026-06-09)
- Mongo image: `mongo:6.0.13`
- oneauth: branch `chore/250-oidf-tls` (this PR), `cmd/oneauth-server` running with `tests/oidf-conformance/oneauth-server.yaml`
