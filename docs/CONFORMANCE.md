# OneAuth Conformance, Load & Adversarial Testing

> **Status:** Draft strategy, not yet implemented. Tracks the plan; per-suite implementation lives behind tracking issues.

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
3. **Suppression has metadata.** Every entry in a `known-gaps` / `baseline` / `suppressions` file carries a tracking issue, an owner, a reason, and an `expires:` date. Quarterly review opens an issue listing entries older than 90 days.

The result: when a feature PR lands and a previously-failing conformance test starts passing, CI breaks immediately ("you forgot to remove `oidc-discovery-required-fields` from `known-gaps.yaml`"). The author flips the entry, the test moves from "known gap" to "regression-protected", and the gap count drops by one. There is no scenario where a passing test silently gets credit it didn't earn, and no scenario where a regression on something we already supported gets dismissed.

This is the same pattern Web Platform Tests, V8, and Google Tricorder use. It is the only sustainable way to run a comprehensive suite while accepting that we will not be 100% green.

### Manifest schemas

```yaml
# tests/conformance/known-gaps.yaml
- suite: oidf
  plan: dynamic-op-basic
  test: dcr-rejects-non-https-redirect-uri
  status: expected-fail
  issue: 999
  owner: panyam
  reason: |
    DCR validator currently allows http:// redirect_uris in dev mode.
    Plan: tighten in #999 once dev-mode opt-in flag is wired through.
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

| Suite | Location | Specs covered |
|---|---|---|
| Keycloak interop | `tests/keycloak/` | RFC 6749/7517/7662/7009/8414, OIDC Discovery, RFC 9396 (RAR) — as a resource server validating Keycloak tokens |
| RAR conformance | `tests/keycloak/rar_interop_test.go` | RFC 9396 round-trip — currently the most thorough public RAR interop test we know of |
| In-process e2e | `tests/e2e/` | All endpoints end-to-end against `cmd/oneauth-server` |

### 2.2 Suites to adopt (Tier 1)

#### OpenID Foundation Conformance Suite

- **Repo:** [gitlab.com/openid/conformance-suite](https://gitlab.com/openid/conformance-suite) (Apache 2.0; GitHub mirror at `openid-certification/conformance-suite` is read-only)
- **Runs as:** Docker Compose stack (Java + Spring Boot + MongoDB + httpd). Uses `localhost.emobix.co.uk:8443` (resolves to 127.0.0.1, ships a real cert chain) so callbacks can be HTTPS.
- **Drives in CI** via the suite's published Python wrapper (headless). Test plan IDs and configs are checked into our repo at `tests/oidf/plans/`.
- **Plans we run:**
  - **Config OP** — validates `/.well-known/openid-configuration` required fields (RFC 8414 + OIDC Discovery)
  - **Dynamic OP** — exercises `POST /apps/dcr` (RFC 7591), required response fields, error envelopes
  - **Basic OP** — RFC 6749 token endpoint (partial fit; many assertions assume `authorization_code` + ID token, which OneAuth does not currently issue — those will be expected-fail in `known-gaps.yaml` until issue 115 lands)
  - **Connect_RP** plans (Basic/Hybrid/Form Post) — exercise the `client/AuthClient` SDK against a fake OP. Real fit.

OIDF cert (the paid logo) is **not** a goal. We run the tests; we do not submit results.

#### MCP Conformance Suite

- **Repo:** [github.com/modelcontextprotocol/conformance](https://github.com/modelcontextprotocol/conformance)
- **Runs as:** `npx @modelcontextprotocol/conformance` (Node toolchain in CI).
- **Plans we run:**
  - `auth/basic-dcr` — RFC 7591 from a fresh client's perspective
  - `auth/basic-metadata-var1` — RFC 9728 PRM discovery (currently the only public conformance test for RFC 9728)

This is also the suite that surfaced bug #74 (`TokenEndpointAuthMethods` negotiation with explicit endpoints), per `docs/ROADMAP.md:116`. Worth running on every PR.

### 2.3 Self-written suites (filling public gaps)

These RFCs have no public conformance tooling. We write them as transport-agnostic Go test fixtures so they can be pointed at OneAuth, Keycloak, or any third-party server.

| RFC | Suite | Notes |
|---|---|---|
| RFC 7662 (Introspection) | `tests/conformance/introspection/` | client_secret_basic vs. _post auth, `active` semantics, `token_type_hint`, scope echoing, RAR `authorization_details` echo. |
| RFC 7009 (Revocation) | `tests/conformance/revocation/` | Idempotent revocation, `token_type_hint`, refresh-token cascading revocation, unauthorized-client returns 200 (per spec). |
| RFC 9728 (PRM) — deep | `tests/conformance/prm/` | §3 required-field coverage, signed-metadata JWT variant, `bearer_methods_supported` enumeration. Complements MCP suite happy-path. |
| RFC 9396 (RAR) | extracted from `tests/keycloak/rar_interop_test.go` | Currently part of Keycloak suite; pull into a stand-alone fixture. Candidate to publish as `oneauth-rar-conformance` for the wider ecosystem — there is a real public gap here. |
| RFC 8414 dual-path | `tests/conformance/as_metadata/` | Asserts `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration` return identical content where they overlap. OIDF only checks the OIDC path. |

### 2.4 Explicitly out of scope

FAPI 1/2, FAPI-CIBA, JARM, mTLS cert-bound tokens, OpenID Federation, OID4VCI, EUDI Wallet, regional Open Banking profiles. The OIDF suite has plans for all of these; we will not run them. See [`docs/gaps/AUTHLETE_GAP_ANALYSIS.md`](gaps/AUTHLETE_GAP_ANALYSIS.md) for the rationale.

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
| **CodeQL** | `Security/CWE/CWE-347` (improper signature verification) catches `jwt.Parse` callbacks accepting any algorithm | GitHub Default Setup; weekly + on push to main |

### Tier 1b — black-box dynamic scan (weekly on main)

| Tool | Purpose | Run as |
|---|---|---|
| **OWASP ZAP** | Authenticated active scan of running `cmd/oneauth-server`. AuthHelper add-on understands OIDC discovery + auth-code flow | `zap.sh -cmd -autorun tests/security/zap-plan.yaml` |

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

1. **Stand up `tests/conformance/` directory** with `known-gaps.yaml` schema, runner contract, and one trivial test (e.g., RFC 8414 dual-path) to prove the ratchet mechanics. Single PR.
2. **OIDF Config OP + Dynamic OP** as `make testoidf`. Highest ROI conformance — validates RFC 8414 / 7517 / 7591 with one suite.
3. **MCP conformance** as `make testmcp`. RFC 9728 (only public test) + second take on RFC 7591.
4. **gosec + semgrep + nuclei** as `make testsec`. Tier 1 scanners with `tests/security/suppressions.yaml`.
5. **Native Go fuzzing** on the six parser targets, `make testfuzz`. PR gate at 60s/target.
6. **k6 mixed-workload baseline** as `make testload`. PR gate. Other five scenarios nightly.
7. **OIDF Basic OP + Connect_RP** — these will surface a long known-gaps list (no `authorization_code` flow yet); accept that and ratchet.
8. **Self-written RFC 7662 / 7009 / 9728-deep / 9396 fixtures** as transport-agnostic Go modules (importable by Keycloak suite + OneAuth e2e).
9. **OWASP ZAP weekly main scan.**

Each item is a tracking issue; sub-issues per test plan. Issues opened only after this doc is reviewed.

---

## 6. Open decisions

These need a call before issues are opened:

- **Where does the runner contract live?** Options: a small Go binary in `cmd/conformance-runner/`, or a Make target wrapping `go test` + a manifest-diff script. Leaning toward the former — easier to reuse from other repos.
- **Do we publish self-written conformance fixtures as a separate Go module?** RFC 7662/7009/9396 fixtures could live at `github.com/panyam/oneauth-conformance` and be importable. Real public gap; modest extra maintenance cost.
- **Self-hosted runner for load tests — cloud or workstation?** Tail-latency gating needs a stable machine. Cheapest path: a single dedicated cloud VM that GH Actions reserves via runner labels.
- **Frequency of quarterly suppression review** — every 90 days as stated, or tied to release cadence?

---

## 7. Files & references

Existing:
- `tests/keycloak/` — interop pattern this strategy mirrors
- `tests/keycloak/rar_interop_test.go` — RFC 9396 fixture to extract
- `tests/e2e/` — in-process e2e
- `cmd/oneauth-server/` — reference server, target for ZAP/nuclei
- [`docs/TESTING.md`](TESTING.md) — unit + integration testing patterns
- [`docs/gaps/AUTHLETE_GAP_ANALYSIS.md`](gaps/AUTHLETE_GAP_ANALYSIS.md) — rationale for FAPI/CIBA out-of-scope

To be created (per adoption sequence above):
- `tests/conformance/known-gaps.yaml`
- `tests/conformance/{introspection,revocation,prm,as_metadata}/`
- `tests/oidf/` — OIDF suite docker harness + plan configs
- `tests/mcp/` — MCP conformance harness
- `tests/load/k6/` — six k6 scenarios + `baseline.json`
- `tests/security/suppressions.yaml`
- `tests/security/zap-plan.yaml`
- `cmd/conformance-runner/` — manifest-diff runner (pending decision in §6)
