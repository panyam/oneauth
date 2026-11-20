# OneAuth Conformance, Load & Adversarial Testing

> **Status:** Strategy, partly implemented. The ratchet runner and its first fixtures live in `tests/conformance/` (`make testconformance`), and the OIDF discovery plan in `tests/oidf-conformance/` (`make testoidf`). Load testing, fuzzing, semgrep and nuclei are not built yet; per-suite work lives behind tracking issues.

This document covers three forms of external testing OneAuth will run continuously:

1. **Conformance** — does OneAuth implement the specs it claims, the way the specs say?
2. **Load** — does it stay correct and fast under realistic concurrency?
3. **Adversarial** — does it resist the published threat model?

The unifying principle is the **ratcheting model** described below. Every test we know about runs in CI on every change — including tests we currently fail. Failures are tracked in a manifest, not skipped. When a feature lands and a test starts passing, CI fails noisily until we update the manifest. This keeps "what we don't yet support" visible at all times.

---

## 1. The ratcheting model

Three invariants govern every suite under this strategy:

1. **Every known test runs every time.** No `t.Skip()` for "not implemented yet". A test we deliberately don't pass is still executed; its expected result is "fail", recorded in a manifest.
2. **CI fails on diff, not absolute count.** The runner asserts `actual_failures == expected_failures` for conformance and adversarial suites, and `actual_metrics ≤ baseline * margin` for load. Movement in either direction breaks the build.
3. **Suppression has metadata.** Every entry in a `known-gaps` / `baseline` / `suppressions` file carries a tracking issue, an owner, a reason, and an `expires:` date. The ratchet itself is the strongest staleness signal — a gap silently shipped will already break CI as a "ratchet up" failure. For human review of long-lived gaps, `make testconformance` writes a Markdown summary to `docs/conformance/native.md` sorted by `expires:` so old entries surface on demand. The published docs site renders that file under `/conformance/native/`. The `expires:` field is advisory: the gating runner does not fail on past dates.

The result: when a feature PR lands and a previously-failing conformance test starts passing, CI breaks immediately ("you forgot to remove `oidc-discovery-required-fields` from `known-gaps.yaml`"). The author flips the entry, the test moves from "known gap" to "regression-protected", and the gap count drops by one. There is no scenario where a passing test silently gets credit it didn't earn, and no scenario where a regression on something we already supported gets dismissed.

This is the same pattern Web Platform Tests, V8, and Google Tricorder use. It is the only sustainable way to run a comprehensive suite while accepting that we will not be 100% green.

### Manifest schemas

`known-gaps.yaml` accepts two entry shapes, discriminated by which fields are populated. Go-native suites use `suite + id`; external suites (OIDF, MCP) use `suite + plan + test`. The runner validates the shape at startup.

```yaml
# tests/conformance/known-gaps.yaml

# Go-native suite (RFC fixtures we own)
- suite: as_metadata                                  # package basename
  id: TestDualPathParity/rfc8414_path_parity          # full Go test name incl. subtest
  status: expected-fail                               # only legal value today
  issue: 187
  owner: panyam
  reason: |
    OneAuth AS only registers /.well-known/openid-configuration.
    RFC 8414 §3 requires /.well-known/oauth-authorization-server too.
  expires: 2026-08-07                                 # ISO date; advisory

# External suite (when we adopt OIDF / MCP)
- suite: oidf
  plan: dynamic-op-basic
  test: dcr-rejects-non-https-redirect-uri
  status: expected-fail
  issue: 999
  owner: panyam
  reason: |
    DCR validator currently allows http:// redirect_uris in dev mode.
    Plan: tighten in 999 once dev-mode opt-in flag is wired through.
  expires: 2026-08-01
```

```json
// tests/load/baseline.json — one entry per scenario+endpoint
{
  "scenario": "mixed-baseline",
  "endpoint": "token",
  "metrics": {
    "p95_ms": 12, "p99_ms": 38,
    "rps_floor": 4500, "error_rate_max": 0.001
  },
  "margin": { "p95": 1.15, "p99": 1.30 },
  "captured_at": "2026-05-07",
  "captured_on": "self-hosted-runner-load-1"
}
```

```yaml
# tests/security/suppressions.yaml — per scanner
- tool: gosec
  rule: G401
  file: stores/legacy/hmac.go
  line: 42
  severity: medium
  reason: |
    Backwards-compat HS256 path for v0.0.x clients.
    Removal tracked in #888; remove this entry when that lands.
  issue: 888
  expires: 2026-09-01
```

---

## 2. Conformance testing

### 2.1 What we run today

`make conformance` runs every external and cross-spec suite registered in `conformance/suites.yaml` and prints one line per suite (mission 489). `SUITE=<name>` runs one, and each log goes to `test-reports/conformance/<name>.log`. A gating suite's failure fails the run; an info suite is only reported. `make test` checks that the registry and `conformance/Makefile` agree.

| Suite | Location | Specs covered |
|---|---|---|
| Keycloak interop | `tests/keycloak/` | RFC 6749/7517/7662/7009/8414, OIDC Discovery, RFC 9396 (RAR), as a resource server validating Keycloak tokens. Also DPoP-bound tokens, accepted under `DPoP` and refused as Bearer (0.1.38); refresh requests sent to both servers and compared, and `LoginWithBrowser` against Keycloak (0.1.42); Keycloak ID tokens refused as access tokens (0.1.46); revocation parity for cross-client and missing-token requests (0.1.54). Runs in CI through `keycloak-interop.yml` on PRs touching `apiauth/`, `client/`, `keys/`, `core/`, `cmd/oneauth-server/` or `tests/keycloak/`, and on pushes to main (PR 390). |
| RAR conformance | `tests/keycloak/rar_interop_test.go` | RFC 9396 round-trip — currently the most thorough public RAR interop test we know of |
| In-process e2e | `tests/e2e/` | All endpoints end-to-end against `cmd/oneauth-server` |
| Conformance ratchet | `tests/conformance/` | RFC 8414 dual-path (`as_metadata/`), RFC 7662 (`introspection/`), `private_key_jwt` (`client_auth/`); expected failures in `known-gaps.yaml`, run by `make testconformance` |
| OIDF discovery plan | `tests/oidf-conformance/` | `oidcc-config-certification-test-plan` through `make testoidf`. CI runs every OIDF plan nightly and on demand (`oidf-conformance.yml`, issue 498), against the harness release pinned in the compose file. |
| OIDF FAPI 2.0 plan | `tests/oidf-conformance/fapi2/` | `fapi2-security-profile-final-test-plan` through `make testoidf` (and `make exercise-fapi2`); whole-module `expected-review` / `expected-skip` entries in `known-gaps.yaml`. Local only, like the discovery plan. |
| OIDF OIDC Basic OP plan | `tests/oidf-conformance/oidcc/` | `oidcc-basic-certification-test-plan` through `make testoidf` (and `make exercise-oidcc`), mission 477; whole-module entries in `known-gaps.yaml` like FAPI 2.0. Local only. |
| OIDF Dynamic OP plan and `oidcc-test-plan` | `tests/oidf-conformance/oidcdyn/` | `oidcc-dynamic-certification-test-plan` (`make exercise-oidcdyn`, issue 493) and `oidcc-test-plan` once per client auth method (`make exercise-oidcctp AUTH=<method>`, issue 494), both through `make testoidf`. The harness registers its own clients through DCR. One `known-gaps.yaml` entry can name several plans with `plans:`. Local only. |
| MCP server auth | `tests/mcpauth/` | The MCP server-auth scenarios (RFC 9728 discovery, RFC 8414 AS metadata, RFC 6750 Bearer enforcement, RFC 7519 `exp` / `aud` / `iss`, scope step-up) with oneauth-server as the AS, through two MCP SDKs: the official Go SDK with oneauth's `APIMiddleware` (`mcp-auth-gosdk`), and mcpkit with its `ext/auth` (`mcp-auth-mcpkit`). `make exercise-mcpauth SDK=gosdk\|mcpkit`, issue 495. A check failing only in the mcpkit run points at mcpkit. Needs node. |

### 2.2 OIDF plans: which apply

The OpenID Foundation suite offers 81 plans (the harness's `/api/plan/available`, November 2026). Each one runs in `make conformance`, is owed by mission 489, needs a feature oneauth doesn't have, belongs to a separate mission, or doesn't apply. Plans that test a relying party (`*-client-*`) would test the client SDK, not the server.

| Plan | Modules | Status | Why, or where it's tracked |
|---|---|---|---|
| `fapi2-security-profile-final-test-plan` | 68 | Runs | `SUITE=oidf-fapi2` (`make testoidf`), mission 98 |
| `oidcc-basic-certification-test-plan` | 38 | Runs | `SUITE=oidf-basic-op` (`make testoidf`), mission 477 |
| `oidcc-config-certification-test-plan` | 1 | Runs | `make conformance SUITE=oidf-config` (`make testoidf`) |
| `oidcc-dynamic-certification-test-plan` | 23 | Runs | `SUITE=oidf-dynamic-op` (`make testoidf`), issue 493. The harness registers its own clients through DCR. Also run with `response_type` `id_token` and `id_token token` (`SUITE=oidf-dynamic-id-token`, `-id-token-token`), the opt-in implicit flow (issue 507) |
| `oidcc-test-plan` | 55 | Runs | `SUITE=oidf-tp-<method>` (`make testoidf`), issue 494: once each for `client_secret_post`, `client_secret_jwt` and `private_key_jwt`, which the Basic and Dynamic plans don't vary. `none` and `mtls` are left out (§2.3) |
| `fapi-ciba-id1-test-plan` | 71 | Needs a feature | CIBA: #341 |
| `fapi1-advanced-final-brazil-dcr-test-plan` | 18 | Needs a feature | Open Finance Brasil profile: #161 |
| `fapi1-advanced-final-test-plan` | 69 | Needs a feature | FAPI 1 Advanced: PS256 (#330), JARM (#409), mTLS-bound tokens (#335) |
| `fapi2-message-signing-final-test-plan` | 86 | Needs a feature | JAR (#338), JARM (#409) and HTTP Message Signatures (#152) |
| `fapi2-message-signing-id1-test-plan` | 80 | Needs a feature | JAR (#338), JARM (#409) and HTTP Message Signatures (#152) |
| `fapi2-security-profile-final-brazil-dcr-test-plan` | 17 | Needs a feature | Open Finance Brasil profile: #161 |
| `fapi2-security-profile-id2-brazil-dcr-test-plan` | 17 | Needs a feature | Open Finance Brasil profile: #161 |
| `oidcc-3rdparty-init-login-certification-test-plan` | 2 | Needs a feature | Third-party-initiated login (`initiate_login_uri`, OIDC Core §4): not filed |
| `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | 2 | Needs a feature | RP-initiated logout, session management, front-channel logout: #340 (back-channel logout tokens exist; the plans start from `end_session_endpoint`) |
| `oidcc-formpost-basic-certification-test-plan` | 38 | Needs a feature | `response_mode=form_post`, #500 |
| `oidcc-frontchannel-rp-initiated-logout-certification-test-plan` | 2 | Needs a feature | RP-initiated logout, session management, front-channel logout: #340 (back-channel logout tokens exist; the plans start from `end_session_endpoint`) |
| `oidcc-rp-initiated-logout-certification-test-plan` | 11 | Needs a feature | RP-initiated logout, session management, front-channel logout: #340 (back-channel logout tokens exist; the plans start from `end_session_endpoint`) |
| `oidcc-session-management-certification-test-plan` | 2 | Needs a feature | RP-initiated logout, session management, front-channel logout: #340 (back-channel logout tokens exist; the plans start from `end_session_endpoint`) |
| `fapi-ciba-id1-client-test-plan` | 34 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `fapi1-advanced-final-client-test-plan` | 28 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `fapi2-message-signing-final-client-test-plan` | 35 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `fapi2-message-signing-id1-client-test-plan` | 32 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `fapi2-security-profile-final-brazil-client-test-plan` | 33 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `fapi2-security-profile-final-client-test-plan` | 27 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `fapi2-security-profile-id2-brazil-client-test-plan` | 32 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `fapi2-security-profile-id2-client-test-plan` | 24 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-back-channel-logout-rp-basic` | 8 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-back-channel-logout-rp-hybrid` | 8 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-back-channel-logout-rp-implicit` | 8 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-basic-certification-test-plan` | 14 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-config-certification-test-plan` | 6 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-dynamic-certification-test-plan` | 12 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-formpost-basic-certification-test-plan` | 14 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-formpost-hybrid-certification-test-plan` | 18 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-formpost-implicit-certification-test-plan` | 15 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-front-channel-logout-rp-basic` | 1 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-front-channel-logout-rp-hybrid` | 1 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-front-channel-logout-rp-implicit` | 1 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-hybrid-certification-test-plan` | 18 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-implicit-certification-test-plan` | 15 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-logout-test-plan` | 14 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-refreshtoken-test-plan` | 3 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-rp-initiated-logout-rp-basic` | 3 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-rp-initiated-logout-rp-hybrid` | 3 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-rp-initiated-logout-rp-implicit` | 3 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-rp-session-management-rp-basic` | 1 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-rp-session-management-rp-hybrid` | 1 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-rp-session-management-rp-implicit` | 1 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-test-3rd-party-init-login-test-plan` | 1 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `oidcc-client-test-plan` | 39 | Separate mission | Tests a relying party: the client SDK against the OIDF RP plans, a future mission (not filed) |
| `authzen-pdp-action-search-test-plan` | 22 | Not applicable | AuthZEN policy decision point: oneauth is not a PDP |
| `authzen-pdp-evaluation-test-plan` | 33 | Not applicable | AuthZEN policy decision point: oneauth is not a PDP |
| `authzen-pdp-evaluations-comprehensive-test-plan` | 26 | Not applicable | AuthZEN policy decision point: oneauth is not a PDP |
| `authzen-pdp-evaluations-test-plan` | 23 | Not applicable | AuthZEN policy decision point: oneauth is not a PDP |
| `authzen-pdp-resource-search-test-plan` | 20 | Not applicable | AuthZEN policy decision point: oneauth is not a PDP |
| `authzen-pdp-subject-search-test-plan` | 25 | Not applicable | AuthZEN policy decision point: oneauth is not a PDP |
| `ekyc-test-plan-oidccore` | 12 | Not applicable | eKYC and Identity Assurance (verified claims): not in scope |
| `fapi2-security-profile-id2-test-plan` | 67 | Not applicable | Implementer's Draft 2, superseded by the final profile oneauth runs |
| `oid4vci-1_0-issuer-haip-test-plan` | 61 | Not applicable | OpenID for Verifiable Credentials (issuer, wallet, verifier): not in scope |
| `oid4vci-1_0-issuer-test-plan` | 21 | Not applicable | OpenID for Verifiable Credentials (issuer, wallet, verifier): not in scope |
| `oid4vci-1_0-wallet-haip-test-plan` | 15 | Not applicable | OpenID for Verifiable Credentials (issuer, wallet, verifier): not in scope |
| `oid4vci-1_0-wallet-test-plan` | 5 | Not applicable | OpenID for Verifiable Credentials (issuer, wallet, verifier): not in scope |
| `oid4vp-1final-verifier-haip-test-plan` | 15 | Not applicable | OpenID for Verifiable Credentials (issuer, wallet, verifier): not in scope |
| `oid4vp-1final-verifier-test-plan` | 15 | Not applicable | OpenID for Verifiable Credentials (issuer, wallet, verifier): not in scope |
| `oid4vp-1final-wallet-haip-test-plan` | 20 | Not applicable | OpenID for Verifiable Credentials (issuer, wallet, verifier): not in scope |
| `oid4vp-1final-wallet-test-plan` | 21 | Not applicable | OpenID for Verifiable Credentials (issuer, wallet, verifier): not in scope |
| `oid4vp-id2-verifier-test-plan` | 1 | Not applicable | OpenID for Verifiable Credentials (issuer, wallet, verifier): not in scope |
| `oid4vp-id2-wallet-test-plan` | 4 | Not applicable | OpenID for Verifiable Credentials (issuer, wallet, verifier): not in scope |
| `oid4vp-id3-verifier-test-plan` | 1 | Not applicable | OpenID for Verifiable Credentials (issuer, wallet, verifier): not in scope |
| `oid4vp-id3-wallet-test-plan` | 4 | Not applicable | OpenID for Verifiable Credentials (issuer, wallet, verifier): not in scope |
| `oidcc-formpost-hybrid-certification-test-plan` | 37 | Not applicable | Hybrid and implicit response types: OAuth 2.1 drops them, and oneauth issues only `response_type=code` |
| `oidcc-formpost-implicit-certification-test-plan` | 31 | Not applicable | Hybrid and implicit response types: OAuth 2.1 drops them, and oneauth issues only `response_type=code` |
| `oidcc-hybrid-certification-test-plan` | 37 | Not applicable | Hybrid and implicit response types: OAuth 2.1 drops them, and oneauth issues only `response_type=code` |
| `oidcc-implicit-certification-test-plan` | 31 | Not applicable | Hybrid and implicit response types: OAuth 2.1 drops them, and oneauth issues only `response_type=code` |
| `openid-federation-deployed-entity-test-plan` | 5 | Not applicable | OpenID Federation: not in scope |
| `openid-federation-entity-joined-to-test-federation-op-test-plan` | 20 | Not applicable | OpenID Federation: not in scope |
| `openid-federation-entity-joined-to-test-federation-rp-test-plan` | 10 | Not applicable | OpenID Federation: not in scope |
| `openid-ssf-receiver-caep-test-plan` | 12 | Not applicable | Shared Signals (SSF / CAEP): not in scope |
| `openid-ssf-receiver-test-plan` | 15 | Not applicable | Shared Signals (SSF / CAEP): not in scope |
| `openid-ssf-transmitter-caep-test-plan` | 28 | Not applicable | Shared Signals (SSF / CAEP): not in scope |
| `openid-ssf-transmitter-test-plan` | 36 | Not applicable | Shared Signals (SSF / CAEP): not in scope |

### 2.3 What doesn't pass, and whether it should

Every OIDF module that doesn't pass has a `known-gaps.yaml` entry. This table groups those entries by cause and gives each cause a verdict. **Roadmap** means oneauth should do it, and an issue tracks it. **Won't do** means the spec or the security advice argues against it. **Review** means the module passes once a person checks a screenshot. **Harness** means the module needs a person partway through.

| Cause | Modules | Verdict |
|---|---|---|
| Hybrid response types (`code id_token`, ...) | Not run: the Dynamic plan runs with `code`, `id_token` and `id_token token`. | Won't do. FAPI 1 used hybrid, FAPI 2.0 is code-only, and nothing has asked for it. The implicit types themselves are opt-in since issue 507 (`code_flow.implicit`, plus the client's registration), which lets oneauth meet the Dynamic OP's §15.2 list. |
| Public clients without PKCE | `oidcc-test-plan`'s `none` variant sends public clients without PKCE, so every flow stops at `code_challenge is required`. The variant isn't run. | Won't do. RFC 9700 §2.1.1 and OAuth 2.1 require PKCE from public clients. |
| Unsigned ID tokens (`alg: none`) | `idtoken-unsigned` is skipped | Won't do. |
| The `typ: ID` claim in the ID token | `server` warns in every OIDC plan | Won't do, per issue 339. Relying-party libraries refuse a JOSE `typ` header other than `JWT`. |
| Request objects and `request_uri` (JAR) | `request-uri-unsigned` and `request-uri-signed-rs256` fail. `unsigned-request-object-...` is skipped. `ensure-request-object-with-redirect-uri` ends in REVIEW on oneauth's refusal. | Roadmap, issue 338. FAPI 2.0 Message Signing and FAPI 1 need it too. |
| Client logo, policy and terms on the consent page | `registration-logo-uri`, `-policy-uri` and `-tos-uri` end in REVIEW | Review. The consent page shows them (issue 507), and each entry's evidence checks the captured page. |
| Error pages and re-login pages | `ensure-registered-redirect-uri`, `ensure-redirect-uri-in-authorization-request`, `redirect-uri-query-mismatch`, `redirect-uri-query-added`, `prompt-login` and `max-age-1` end in REVIEW | Review. oneauth shows the right page, and each entry's evidence checks the captured page says so. |

### 2.4 Suites to adopt (Tier 1)

#### OpenID Foundation Conformance Suite

- **Repo:** [gitlab.com/openid/conformance-suite](https://gitlab.com/openid/conformance-suite) (Apache 2.0; GitHub mirror at `openid-certification/conformance-suite` is read-only)
- **Runs as:** Docker Compose stack (Java + Spring Boot + MongoDB + httpd). Uses `localhost.emobix.co.uk:8443` (resolves to 127.0.0.1, ships a real cert chain) so callbacks can be HTTPS.
- **Drives in CI** via the suite's published Python wrapper (headless). The harness, server config and baselines are checked into our repo at `tests/oidf-conformance/`.
- **Plans:** see §2.2. Config, Basic OP, Dynamic OP, `oidcc-test-plan` and FAPI 2.0 run today. §2.3 says why each module that doesn't pass doesn't.

OIDF cert (the paid logo) is **not** a goal. We run the tests; we do not submit results.

#### MCP Conformance Suite

- **Repo:** [github.com/modelcontextprotocol/conformance](https://github.com/modelcontextprotocol/conformance)
- **Runs as:** `npx @modelcontextprotocol/conformance` (Node toolchain in CI).
- **Plans:** the server auth scenarios (RFC 9728 protected-resource metadata, RFC 8414 AS metadata, RFC 6750 Bearer enforcement, RFC 7519 claims, scope step-up) run against oneauth-server in `make conformance` as `mcp-auth-gosdk` and `mcp-auth-mcpkit` (issue 495, `tests/mcpauth/`). Upstream has no server auth suite yet, so they come from panyam/mcpconformance's `pending` branch, pinned in `scripts/exercise-mcpauth.sh`. Both SDKs give 19 SUCCESS and 4 SKIPPED, and #521 tracks the skips. The authorization-server suite is proposed upstream (`modelcontextprotocol/conformance` issue 208) and not implemented yet (#496). The client scenarios (`auth/basic-dcr`, `auth/basic-metadata-var1`) test a client, so they go with the SDK.

This is also the suite that surfaced bug 74 (`TokenEndpointAuthMethods` negotiation with explicit endpoints), per the "Fix auth method negotiation with explicit endpoints" entry in `docs/ROADMAP.md`. Worth running on every PR.

#### OAuch

- **Repo:** [github.com/DistriNet/OAuch](https://github.com/DistriNet/OAuch), an analyzer for OAuth 2.0 authorization servers that checks best practices and known threats rather than certifying conformance.
- **Runs:** by hand, since OAuch has only a web UI, as the `manual` suite `oauch` in `conformance/suites.yaml`. [`docs/conformance/oauch.md`](conformance/oauch.md) has the last run, each finding's verdict (a ticket, test setup, or an accepted reason) and the steps to run it again (issue 497).

### 2.5 Self-written suites (filling public gaps)

These RFCs have no public conformance tooling. We write them as transport-agnostic Go test fixtures so they can be pointed at OneAuth, Keycloak, or any third-party server.

| RFC | Suite | Notes |
|---|---|---|
| RFC 7662 (Introspection) | `tests/conformance/introspection/` | client_secret_basic vs. _post auth, `active` semantics, `token_type_hint`, scope echoing, RAR `authorization_details` echo. |
| RFC 7009 (Revocation) | `tests/conformance/revocation/` | Idempotent revocation, `token_type_hint`, refresh-token cascading revocation, unauthorized-client returns 200 (per spec). |
| RFC 9728 (PRM) — deep | `tests/conformance/prm/` | §3 required-field coverage, signed-metadata JWT variant, `bearer_methods_supported` enumeration. Complements MCP suite happy-path. |
| RFC 9396 (RAR) | extracted from `tests/keycloak/rar_interop_test.go` | Currently part of Keycloak suite; pull into a stand-alone fixture. Candidate to publish as `oneauth-rar-conformance` for the wider ecosystem — there is a real public gap here. |
| RFC 8414 dual-path | `tests/conformance/as_metadata/` | Asserts `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration` return identical content where they overlap. OIDF only checks the OIDC path. |

### 2.6 Explicitly out of scope

FAPI 1.0, FAPI-CIBA, OpenID Federation, OID4VCI, EUDI Wallet, regional Open Banking profiles. The OIDF suite has plans for all of these; we will not run them.

FAPI 2.0 is no longer on this list. oneauth implements the FAPI 2.0 Security Profile (`OneAuthConfig.FAPI2`, 0.1.52 and 0.1.54), and its OIDF plan runs in `make testoidf` (mission #98) (see [`docs/SECURITY_AUDIT.md`](SECURITY_AUDIT.md) for the caveats). JARM is mission #409 and mTLS certificate-bound tokens are #335. See [`docs/gaps/AUTHLETE_GAP_ANALYSIS.md`](gaps/AUTHLETE_GAP_ANALYSIS.md) for the rationale.

---

## 3. Load testing

### 3.1 Primary tool: k6

Picked over Vegeta, oha, wrk, Gatling, Locust because:

- **Go binary** — no JVM/Python/Node toolchain in CI
- **First-class threshold gating** — `thresholds:` block exits non-zero on breach
- **Multi-step OAuth flows** are natural in JS scenario scripts (setup mints token, per-VU iteration hammers, teardown revokes)
- **xk6 extensions in Go** — if we need a custom JWKS-rotating sampler we write it in Go

Vegeta stays as a cross-check for static-endpoint hammering (JWKS, OIDC discovery). All other tools surveyed are either single-endpoint hammerers (oha, hey, bombardier — no scripting), unmaintained (wrk2, hey), or wrong-toolchain (Gatling/JVM, Locust/Python).

There is **no actively-maintained OAuth-specific load harness** in OSS. The right substitute is "k6 + a small JS module of OAuth helpers." That helper module would itself be a useful artifact for OneAuth to publish under `examples/loadtest/`.

### 3.2 Scenario library

Six scenarios, all driven from `tests/load/k6/`. Budgets are order-of-magnitude on a 4 vCPU / 8 GB self-hosted runner with the GORM/SQLite backend; tune at first capture.

| # | Scenario | What it catches | First-pass budget |
|---|---|---|---|
| 1 | Sustained `client_credentials` | JWT signing throughput, client-auth hot path | Ed25519 ~5–15k tok/s; RS256-2048 ~1–3k tok/s; p99 < 50 ms at 70% saturation |
| 2 | Refresh-token storm (10k VUs in 1 s) | DB write contention on rotation, JWKS-read contention with token issuance | Drains in < 5 s; p99 < 500 ms (SQLite); 2–3x better on Postgres |
| 3 | Introspection cache hit/miss burst | Cache-key collisions, hot-path locking, allocations | Hit p99 < 1 ms / > 50k rps; miss p99 < 20 ms / > 5k rps |
| 4 | JWKS rotation under load | Race between issuer "use new kid" and validator JWKS cache TTL; thundering herd | Zero verify failures (hard); excursion confined to < 2 s window |
| 5 | DCR registration storm | Unique-client_id index contention, N+1 queries, secret-generator hotspot | SQLite ~200–500 reg/s; Postgres ~1–3k; FS ~100 (dev-only) |
| 6 | Mixed-workload baseline | Cross-endpoint resource competition; canonical regression gate | Establish once; ratchet from there |

### 3.3 CI lanes & ratchet mechanics

- **PR lane (gating):** scenario 6 only, 2 min wall, hard thresholds, **best-of-3** to kill outlier flakes. Must pass to merge.
- **Nightly lane (reporting):** all six scenarios, 5–15 min each. Failures open an issue, do not block.
- **Dedicated runner.** Load tests do not share runners with unit tests. Self-hosted GH Actions runner pinned by label.
- **Margin, not equality.** `baseline * 1.15` for p95, `baseline * 1.30` for p99, hard floor on error rate (`< 0.001`). Tail metrics are noisy; gate hardest on p95 and error rate.
- **Constant-arrival-rate executor only.** Ramps skew the histogram in the first 10s of every run.
- **Warmup with discarded metrics.** 5–10 s warmup; tagged so thresholds exclude.
- **Resource gates alongside latency.** Capture `process_resident_memory_bytes` and `go_goroutines`; assert no unbounded growth. Leaks show here before they show in latency.
- **Baseline file in repo.** `tests/load/baseline.json`. PR titled `loadtest: ratchet baseline` to update — never auto-update from CI.

---

## 4. Adversarial testing

### Tier 1 — automated scanning (every PR)

| Tool | Purpose | Run as |
|---|---|---|
| **gosec** | Go SAST: weak crypto (G401/G501), TLS InsecureSkipVerify (G402), `math/rand` for security (G404) — critical for state/nonce/PKCE generators | `gosec ./...`; suppressions in `tests/security/suppressions.yaml` |
| **semgrep** | OAuth/JWT-aware ruleset (`p/golang`, `p/jwt`, `p/owasp-top-ten`, `p/secrets`); flags `jwt.Parse` without explicit `Method` check | `semgrep --baseline-ref=origin/main` |
| **nuclei** | Black-box pattern scan; `http/misconfiguration/ssrf-via-oauth-misconfig.yaml`, JWT-leak templates, OIDC/OAuth detection | `nuclei -t http/misconfiguration/ -t http/miscellaneous/oauth* -u $TARGET` |
| **CodeQL** | `Security/CWE/CWE-347` (improper signature verification) catches `jwt.Parse` callbacks accepting any algorithm | GitHub Default Setup; reports as a check on every PR and on push to main |
| **`make audit`** | gitleaks (secrets), govulncheck (known vulnerabilities) and gosec (high severity, informational), at pinned versions via `go run`, plus the e2e suite under the race detector (0.1.47) | `make audit` locally. CI runs govulncheck and gitleaks as their own jobs in `ci.yml`. |

Of this table, CodeQL, govulncheck and gitleaks run in CI today, and gosec runs only through `make audit`. semgrep and nuclei are not wired yet, and `tests/security/suppressions.yaml` does not exist.

### Tier 1b — black-box dynamic scan (on push to main)

| Tool | Purpose | Run as |
|---|---|---|
| **OWASP ZAP** | Baseline (passive) scan of a running `cmd/oneauth-server`, with the AJAX spider. It is unauthenticated and does not fail the build; findings go to the run's `zap_scan` artifact (0.1.42). | `zaproxy/action-baseline` in the `zap` job of `ci.yml`, on every push to main, with rules in `.zap-rules.tsv` |

An authenticated active scan (ZAP's AuthHelper add-on driving OIDC discovery and the code flow, from a `tests/security/zap-plan.yaml`) is still the plan, not built.

### Tier 2 — fuzzing (PR + nightly)

Native Go fuzzing (`go test -fuzz=`) on parser surfaces. Targets:

| Target | Surface | Lives at |
|---|---|---|
| `FuzzJWTParse` | Algorithm confusion, malformed JWS, oversized headers, embedded JWK | `apiauth/` |
| `FuzzJWKSParse` | Untrusted JWKS (we fetch from clients in DCR + RP middleware); giant `n`/`e`, missing `kty`, unknown `kid` | `keys/` |
| `FuzzAuthorizationDetailParse` | RFC 9396; nested/recursive JSON | `core/authorization_details.go` |
| `FuzzTokenRequestForm` | `POST /api/token` body — grant_type confusion, repeated params, unicode normalization | `apiauth/` |
| `FuzzDCRRequest` | RFC 7591 metadata; `redirect_uris`, `client_uri`, `jwks_uri` are SSRF/injection bait | `admin/dcr.go` |
| `FuzzIntrospectRequest` / `FuzzRevokeRequest` | Form parsers + blacklist lookup | `apiauth/` |

CI mechanics:

- **PR gate:** `-fuzztime=60s` per target, parallel matrix, < 2 min wall
- **Nightly:** `-fuzztime=30m` per target on `main`
- **Corpus persistence:** `actions/cache` keyed on SHA so each run resumes
- **Crashes auto-promote** to deterministic regression tests in `testdata/fuzz/<TestName>/`
- **OSS-Fuzz** (Google's continuous fuzzer) skipped for now — worth integrating once OneAuth has external users

### Tier 3 — on-demand red-team (pre-release)

- **jwt_tool** (`ticarpi/jwt_tool`) — alg confusion, alg=none, key confusion, JWKS-URL trust probing, HMAC cracking. Run against a release-candidate build; output should show every attack rejected.
- **OWASP ZAP interactive** — manual exploration of auth flows (state/nonce/PKCE downgrade probing where a human-in-the-loop helps).
- **mitmproxy + mitmproxy-jwt** — manual JWT mutation in flight (free Burp alternative).
- **OWASP ASVS v4.0.3** chapters V3 / V6 / V8 / V14 as a release checklist.

### 4.1 Attack-category coverage matrix

15 attack categories × tool coverage. Items marked "custom" require a Go test in `apiauth/` or `tests/e2e/security/` — there is no scanner that probes them reliably. ~10 of 15 are custom; scanners are the floor, not the ceiling.

| # | Attack | Tool | Custom? |
|---|---|---|---|
| 1 | alg=none / RS256↔HS256 confusion | jwt_tool, semgrep | partial |
| 2 | JWT key confusion | jwt_tool + custom (foreign JWKS) | yes |
| 3 | PKCE downgrade / removal | custom — drive flow, omit `code_verifier` | **yes** |
| 4 | State / nonce reuse or omission | custom — replay captured state | **yes** |
| 5 | `redirect_uri` open-redirect / path traversal | nuclei + custom (exact-match enforcement) | partial |
| 6 | `aud` claim bypass | custom — string vs array, missing, wrong, multi | **yes** |
| 7 | Token replay across clients | custom — mint for A, present to B | **yes** |
| 8 | Refresh token rotation bypass | custom — second use of same refresh; assert family revoked | **yes** |
| 9 | JWKS SSRF | nuclei + custom (HTTPS-only, RFC1918 reject, size/timeout) | partial |
| 10 | DCR client-flooding / `client_uri` SSRF | custom — rate-limit + URL-validation | **yes** |
| 11 | Bearer token in URL / referrer leakage | gosec partial; ZAP review | partial |
| 12 | Mix-up attack (multiple AS) | custom — client SDK validates `iss` (RFC 9207) | **yes** |
| 13 | CSRF on revocation/introspection | ZAP + custom | partial |
| 14 | Timing attack on `client_secret` compare | semgrep custom rule + bench | partial |
| 15 | `scope` injection | custom — submit URL-encoded scopes, assert filtering | **yes** |

### 4.2 Threat-model references

Every security test continues the existing `// See:` convention, citing at least one of:

- **RFC 9700** — OAuth 2.0 Security Best Current Practice (BCP, 2024)
- **RFC 6819** — OAuth 2.0 Threat Model (canonical taxonomy)
- **RFC 9207** — `iss` parameter response, mix-up attack fix
- **draft-ietf-oauth-security-topics** — living BCP draft
- **OAuth 2.1 draft** — consolidates 6749 + 6750 + BCP
- **OWASP API Security Top 10 (2023)** — API2 Broken Auth, API8 Misconfig
- **OWASP ASVS v4.0.3** — chapters V3 / V6 / V8 / V14

A relevant CVE/CWE alongside the RFC remains the convention.

---

## 5. Adoption sequence

Order of work, lowest-friction first:

1. **Stand up `tests/conformance/` directory** with `known-gaps.yaml` schema, runner contract, and one trivial test to prove the ratchet mechanics. RFC 8414 dual-path is a fitting seed precisely because the AS does not currently register `/.well-known/oauth-authorization-server` (cmd/oneauth-server/main.go and testutil/server.go only register the OIDC path) — so the test ships failing on day one and exercises the expected-fail arm of the ratchet for real. Single PR. Runner lives in a separate Go submodule (`tests/conformance/`) mirroring `tests/keycloak/` to keep YAML parser + Go test orchestration deps out of the core module's graph.
2. **OIDF Config OP + Dynamic OP** as `make testoidf`. Highest ROI conformance — validates RFC 8414 / 7517 / 7591 with one suite.
3. **MCP conformance** as `make testmcp`. RFC 9728 (only public test) + second take on RFC 7591.
4. **gosec + semgrep + nuclei** as `make testsec`. Tier 1 scanners with `tests/security/suppressions.yaml`.
5. **Native Go fuzzing** on the six parser targets, `make testfuzz`. PR gate at 60s/target.
6. **k6 mixed-workload baseline** as `make testload`. PR gate. Other five scenarios nightly.
7. **OIDF Basic OP + Connect_RP** — these will surface a long known-gaps list (no `authorization_code` flow yet); accept that and ratchet.
8. **Self-written RFC 7662 / 7009 / 9728-deep / 9396 fixtures** as transport-agnostic Go modules (importable by Keycloak suite + OneAuth e2e).
9. **OWASP ZAP authenticated scan on main.** The baseline scan already runs on every push to main.

Each item is a tracking issue; sub-issues per test plan. Issues opened only after this doc is reviewed.

---

## 6. Open decisions

These need a call before issues are opened:

- ~~**Where does the runner contract live?**~~ **Resolved.** Small Go binary in a new `tests/conformance/` submodule (mirrors `tests/keycloak/`). Make targets wrap it (`testconformance` for gating, `testconformance-report` for the human review).
- **Do we publish self-written conformance fixtures as a separate Go module?** Defer until the fixtures stabilize against ≥1 non-OneAuth target. Keep them inside `tests/conformance/` for now.
- **Self-hosted runner for load tests — cloud or workstation?** Tail-latency gating needs a stable machine. Cheapest path: a single dedicated cloud VM that GH Actions reserves via runner labels. Doesn't gate item 1.
- ~~**Frequency of quarterly suppression review**~~ **Resolved.** No cron. `make testconformance` writes the report on every run; the result is checked into `docs/conformance/native.md` and published via the docs site. The ratchet itself catches the most important staleness case (gap silently shipped) without any review.

---

## 7. Files & references

Existing:
- `tests/keycloak/` — interop pattern this strategy mirrors
- `tests/keycloak/rar_interop_test.go` — RFC 9396 fixture to extract
- `tests/e2e/` — in-process e2e
- `cmd/oneauth-server/` — reference server, target for ZAP/nuclei
- [`docs/TESTING.md`](TESTING.md) — unit + integration testing patterns
- [`docs/gaps/AUTHLETE_GAP_ANALYSIS.md`](gaps/AUTHLETE_GAP_ANALYSIS.md) — rationale for the out-of-scope profiles
- `tests/conformance/` holds the ratchet runner (`cmd/runner`), `known-gaps.yaml`, and the `as_metadata`, `introspection` and `client_auth` fixtures
- `tests/oidf-conformance/` holds the OIDF suite docker harness, server config and baselines

To be created (per adoption sequence above):
- `tests/conformance/{revocation,prm}/`
- `tests/mcp/` — MCP conformance harness
- `tests/load/k6/` — six k6 scenarios + `baseline.json`
- `tests/security/suppressions.yaml`
- `tests/security/zap-plan.yaml`
