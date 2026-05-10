# OIDF conformance baseline — 2026-05-09

First run of the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite) against `cmd/oneauth-server`. Phase 1 of issue 197 — measure the gap, don't fix anything yet.

**Setup:** prebuilt harness via `make upoidf`, AS via `make upoidf-as` (memory-mode config, RS256 ephemeral signing, `iss=http://host.docker.internal:8888`). Image tags as of run: `mongo:6.0.13` + harness `latest` from `registry.gitlab.com/openid/conformance-suite`.

## Scoreboard

| Plan | Modules | Verdict | Blocker |
|---|---|---|---|
| `oidcc-config-certification-test-plan` | 1 (`oidcc-discovery-endpoint-verification`) | **FAILED** with 8 failures + 3 warnings on the single discovery test | mostly metadata-shape gaps, fixable independently of `/authorize` |
| `oidcc-basic-certification-test-plan` (1st test only — `oidcc-server`) | 35 modules total; only ran the first | **FAILED — interrupted at step 1** | `authorization_endpoint` missing → blocks the entire Basic / Hybrid / Implicit / Form-Post / Logout family. Tracked under issue 116 (full OIDC provider). |
| `oidcc-dynamic-certification-test-plan` | 22+ modules | Same blocker as Basic — needs `authorization_endpoint`. Not run beyond plan creation. | issue 116 |

## Discovery-test failure breakdown

Test: `oidcc-discovery-endpoint-verification` against `http://host.docker.internal:8888/.well-known/openid-configuration`.

### Substantive gaps (not deployment-mode noise)

| Failure | Source check | Type | Fixable today? |
|---|---|---|---|
| `response_types_supported` lacks any OIDC type | `OIDCCCheckDiscEndpointResponseTypesSupported` | `/authorize`-flow related | **No** — tied to issue 116 (`code`, `id_token`, `code id_token`, etc. are response types of the auth endpoint we don't have) |
| `id_token_signing_alg_values_supported`: not found | `OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported` | metadata advertisement | **Partial** — we *could* advertise `["RS256","ES256"]` to mirror access-token signing, but the field is semantically about id_token signing, which is gated on issue 116 issuing id_tokens at all |
| `authorization_endpoint`: URL not found | `CheckDiscEndpointAuthorizationEndpoint` | endpoint missing | **No** — issue 116 |
| `claims_supported`: not found (warning) | `OIDCCCheckDiscEndpointClaimsSupported` | metadata advertisement | **Partial** — we can advertise the bearer-token claims we already issue (`sub`, `iss`, `aud`, `exp`, `iat`, `jti`); fuller list (`email`, `name`, `preferred_username`) is gated on a userinfo source |
| `scopes_supported`: not advertised (warning skips dependent check) | `CheckDiscEndpointScopesSupportedContainsOpenId` | metadata advertisement | **Yes** — `apiauth.ASServerMetadata.ScopesSupported` is already a struct field; reference deployments just don't populate it. Single-line fix in `cmd/oneauth-server/main.go` and `testutil/server.go`. |
| `userinfo_endpoint`: not present (warning) | `CheckDiscEndpointUserinfoEndpoint` | endpoint missing | **No** — issue 116 |

### Deployment-mode failures (not spec-compliance signal)

These all reduce to "the harness expects HTTPS in production mode". Running OneAuth on `http://` produces them; they say nothing about whether the AS is OIDC-compliant.

- `Expected https protocol for server.discoveryUrl`
- `Expected https protocol for token_endpoint`
- `Expected https protocol for jwks_uri`
- `Expected https protocol for registration_endpoint`
- `Expected https protocol for token_endpoint` (twice — once via per-endpoint check, once via aggregate `CheckDiscEndpointAllEndpointsAreHttps`)

Phase 2 will run the harness against a TLS-fronted AS to clear these and isolate the substantive gaps.

## Basic OP failure breakdown

Plan: `oidcc-basic-certification-test-plan`. Ran the canonical first test (`oidcc-server`) with variant `{response_type: "code", client_auth_type: "client_secret_basic"}`. Status: **INTERRUPTED**.

Single failure, recorded by `CheckServerConfiguration`:

```
required: authorization_endpoint
msg: Couldn't find required component
```

The check fails before any HTTP request is made — discovery doesn't expose `authorization_endpoint`, the test module aborts. This is the gating fact: **34 of the 35 Basic OP tests can't even start until issue 116 ships `/authorize`.** Once it lands, this plan becomes the right place to drive the next round of conformance work (id_token signing details, scope handling, prompt/display/max_age semantics, codereuse, etc.).

## Headline finding

**Resource-server interop is solid** (RFC 8414 / 9728 / 7517 / 7662 — discovery, JWKS, introspection, protected-resource metadata — all the validation-side endpoints work). **AS-side OIDC flows are blocked on a single missing piece** — `/authorize` (issue 116). Once that's in, most of the discovery-metadata gaps cascade fixable.

For the "0-effort migration from a 3p IdP" pitch: today, that pitch holds for **resource servers** (you can swap your token validator for OneAuth's middleware/JWKSKeyStore against any RFC-8414-compliant AS) and **machine-to-machine clients**. It does **not** hold for **full IdP replacement** until issue 116.

## Concrete follow-up issues to file

1. **Quick win**: advertise `scopes_supported` in AS metadata defaults (cmd/oneauth-server, testutil). Closes one OIDF check standalone, no other dependencies.
2. **Quick win**: advertise `claims_supported` for the claims OneAuth already emits in access tokens. Closes a warning standalone.
3. **TLS deployment doc**: add a tested example of running `cmd/oneauth-server` behind TLS so the Phase 2 harness run can be apples-to-apples on protocols.
4. **Phase 2 of issue 197**: ratchet wiring — `tests/conformance/cmd/runner` consumes the `suite + plan + test` external schema and turns the OIDF results into ratchet entries.
5. **Issue 116** (already filed) gates the next big gap-closure wave.

## Reproducing this run

```bash
make upoidf       # in one shell
make upoidf-as    # in another
# Then follow the API recipe in tests/oidf-conformance/README.md.
```

The captured logs in this directory:

- `config-cert-discovery.json` — full harness log for the discovery test
- `config-cert-discovery.failures.txt` — failure-only summary
- `basic-op-oidcc-server.json` — full log for the Basic OP entry test
