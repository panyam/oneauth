# OneAuth — OAuth 2.1 Alignment Baseline

Baseline audit of OneAuth's current state against the [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/), filed under issue 140. This document captures *where we stand today* and *what's left to do* — it is the load-bearing reference for OAuth 2.1 alignment decisions.

**Headline:** OneAuth is **5/8 compliant** with the requirements OAuth 2.1 lays out, with 3 real gaps (ROPC, DCR redirect URI HTTPS validation, query-param bearer fallback). Half of the 5 compliant items are compliant **by absence** — i.e., the feature OAuth 2.1 removes doesn't exist in OneAuth at all because the AS-side flows that would carry it (`/authorize`, implicit grant) aren't built. Those items will need affirmative enforcement once `/authorize` ships (#116).

The strategic story is good: OneAuth's "embeddable library, not full IdP" positioning naturally aligns with OAuth 2.1 because the things 2.1 removes (implicit, `/authorize` ambiguity around exact-redirect-matching, query-param tokens in browsers) are largely things OneAuth never built.

---

## Audit table

| # | OAuth 2.1 requirement | OneAuth state | Verdict | Action |
|---|---|---|---|---|
| 1 | PKCE required for all authorization code flows | Client SDK enforces S256 client-side; no server `/authorize` exists yet (gated on #116). | Compliant by absence; full enforcement waits on #116. | Document expectation; enforce on `/authorize` when it ships. |
| 2 | Implicit grant removed | No `/authorize` endpoint at all — OneAuth has never had OAuth 2.0 implicit. `ResponseTypesSupported=["token"]` in AS metadata refers to the resource-token shape, not OAuth 2.0 implicit. | Compliant by absence. | None. |
| 3 | ROPC removed (no `grant_type=password`) | `password` grant handler still present and active. | **Non-compliant.** | Filed as a follow-up — removal needs migration-path analysis (`localauth/` HTTP login + cookie session is the documented alternative). |
| 4 | Exact redirect URI matching (no wildcards, no substring) | No `/authorize` to enforce on, but DCR (`/apps/dcr`) doesn't validate registered redirect URI format either. | Compliant by absence on the auth flow; DCR has a separate gap. | DCR-side validation shipped under this PR. Full enforcement on `/authorize` waits on #116. |
| 5 | PKCE method MUST be S256 (reject `plain`) | Client uses S256 only; no server-side enforcement needed yet. | Compliant by absence. | Enforce on `/authorize` when it ships; AS metadata already advertises `S256` only. |
| 6 | HTTPS for redirect URIs (loopback exception) | DCR previously accepted any URI; client SDK has `client.ValidateHTTPS` but for AS endpoints, not registered redirects. | **Non-compliant (DCR)** — fixed under this PR. | DCR now rejects `http://` registered redirect URIs except for loopback (`127.0.0.1`, `::1`, `localhost`). |
| 7 | Bearer tokens NOT in query string | `APIMiddleware.LegacyQueryParamBearer` opt-in fallback accepts `?token=…`. Default-off; deprecation warning fires once at first use. | **Compliant by default (when `LegacyQueryParamBearer` is nil).** | Field renamed under #295. Path retained for OAuth 2.0 deployments that genuinely need it (e.g., WebSocket upgrade where token can't ride Authorization header); see `docs/DEMOS.md` for three header-clean alternatives. Per capability-gating umbrella #344. |
| 8 | Refresh token rotation | Implemented with reuse detection and family-revoke-on-reuse. | **Compliant.** | None. |

## Per-row analysis

### 1. PKCE — compliant by absence

The OAuth 2.1 escalation is that **all** clients (public AND confidential) must use PKCE on the authorization code flow. OneAuth ships PKCE today only on the client side:

- `client/browser_login.go:255-260` rejects any AS whose discovery metadata doesn't advertise `S256` in `code_challenge_methods_supported`.
- `client/browser_login.go:468` hardcodes `code_challenge_method=S256` on outgoing authorization requests.

The server side has no `/authorize` endpoint to enforce against — issue 116 (full OIDC Provider) covers that. When 116 ships, the new authorization endpoint MUST:

1. Reject any request lacking `code_challenge`.
2. Reject `code_challenge_method=plain`.
3. Validate the verifier→challenge match at the token endpoint.

### 2. Implicit grant — compliant by absence

OneAuth has no `/authorize` endpoint and therefore no implicit grant. The `ResponseTypesSupported=["token"]` field in `cmd/oneauth-server`'s AS metadata refers to the OneAuth resource-token shape (the JWT minted by `MintResourceToken`), not OAuth 2.0's implicit `response_type=token`. When 116 ships, the new `/authorize` endpoint MUST NOT accept `response_type=token`.

### 3. ROPC — non-compliant, follow-up filed

`apiauth/auth.go:251` has the `case "password":` branch in the token endpoint, dispatched to `handlePasswordGrant`. OAuth 2.1 §7.6 removes this grant entirely.

**Why it's not removed in this PR:** the demo ecosystem (`cmd/demo-hostapp`, e2e tests, examples) needs auditing for password-grant callers. The documented alternative is `localauth/` HTTP login + cookie session (which is what every browser-based OneAuth deployment already uses), but identifying the migration scope cleanly deserves its own focused PR. Tracked under a new follow-up issue.

### 4. Exact redirect URI matching — DCR gap fixed; enforcement waits on /authorize

OAuth 2.1 §3.1.2.2 mandates exact string matching of redirect URIs at the authorization endpoint — no wildcard, no substring, no port-only swap. OneAuth's `/authorize` doesn't exist yet, so there's nothing to match against today. But DCR (`/apps/dcr`) does accept registered redirect URIs without format validation — and that's where wildcard/garbage URIs would land first.

Under this PR, `admin/registrar.go` (`Register` and `UpdateRegistration`) now validates each registered redirect URI is a parseable absolute URL with `https://` scheme, with a single carve-out for loopback (`127.0.0.1`, `::1`, `localhost`) which RFC 8252 §7.3 permits on `http://` for native apps. Future `/authorize` enforcement (under #116) gets a smaller surface to defend.

### 5. PKCE S256-only — compliant by absence

The current `cmd/oneauth-server` AS metadata advertises `CodeChallengeMethodsSupported=["S256"]` — no `plain`. The client SDK enforces this on the AS side. When `/authorize` ships, the endpoint MUST reject `code_challenge_method=plain` even if a client sends it.

### 6. HTTPS redirect URIs — non-compliant (fixed in this PR)

OAuth 2.1 §3.1.2.1 requires all redirect URIs to use `https://`. The only exemption is RFC 8252 §7.3 loopback (`127.0.0.1`, `::1`, `localhost`) for native-app clients.

Before this PR: `admin/registrar.go` accepted any string in the `redirect_uris` array. After: each URI is parsed; non-loopback URIs must use `https://`; non-parseable URIs are rejected; loopback exemption is explicit. Returns `ErrInvalidClientMetadata` per RFC 7591 §3.2.2.

### 7. Bearer in query string — compliant by default; OAuth 2.0 opt-in path retained

OAuth 2.1 §5.4 retired bearer tokens in query strings (RFC 6750 §2.3 had deprecated this in 2012). The query-string carry attacks:

- Tokens land in browser history and server access logs.
- `Referer` headers leak them across origins.
- Caches and CDNs persist them.

`apiauth/middleware.go` consults `APIMiddleware.LegacyQueryParamBearer`. The field is unset by default (compliant); when an operator sets it, a sync.Once log warns at first use that this is the legacy OAuth 2.0 path and points at `docs/DEMOS.md` for three header-clean alternatives.

The original audit (#140) filed this as "non-compliant (opt-in)" planning full removal. The capability-gating umbrella #344 rescoped that: OAuth 2.0 is still ~95% of real-world deployments; removal would break the WebSocket upgrade use case (where the initial GET can't carry an Authorization header) without a one-size-fits-all replacement. The path is retained as a deliberate OAuth 2.0 escape hatch.

#295 ships the rename + sharpened deprecation log + docs/DEMOS.md alternatives. Future deployments that don't set the field get OAuth 2.1 §5.4 compliance for free.

### 8. Refresh token rotation — compliant

OAuth 2.1 §6.1 requires refresh token rotation: each refresh-token exchange produces a new refresh token, and reuse of an old token triggers revocation of the entire token family.

OneAuth ships this via `RotateRefreshToken` (in every backend: in-memory, FS, GORM, GAE) and `apiauth/auth.go:383-389` detects reuse via the `core.ErrTokenReused` sentinel, then revokes the family via `RevokeTokenFamily`. The reuse-detection path is exercised by the existing `apiauth/auth_test.go` reuse subtest.

No work needed; this row is the cleanest in the table.

---

## Filed follow-ups

The original audit framed #294 and #295 as removals. The capability-gating umbrella **#344** rescoped them into per-deployment opt-in mechanisms (nil-handler for grants; flags for policies). See #344 for the framing.

| Issue | Scope | Status |
|---|---|---|
| #344 (umbrella) | OAuth 2.0/2.1 capability gating — nil-handler for grants, flags for policies | Open |
| #294 | Extract `PasswordGranter` peer interface; default-disable ROPC via nil-handler | Open |
| #295 | Rename `TokenQueryParam` → `LegacyQueryParamBearer`; sharpen deprecation; WebSocket alternatives in docs/DEMOS.md | Open |
| #345 | `AllowPlainPKCE` flag — opt-in OAuth 2.0 plain PKCE on `/authorize` | Open |
| #346 | Enforce per-client DCR `grant_types` at token endpoint dispatch | Open |

## What this audit does NOT cover

- **OAuth 2.1 §4** (Refresh Token Constraints): rotation is covered (row 8); sender-constrained refresh tokens (DPoP / mTLS) is a separate spec surface tracked under FAPI 2.0 work (issue 152).
- **OAuth 2.1 §5.3** (Access Token Privilege Restriction): not part of the alignment baseline; resource indicators (RFC 8707) is a separate enhancement.
- **DPoP / sender-constrained tokens**: tracked under issue 163 (Authlete-superset meta).
- **`/authorize`-specific requirements** (state parameter handling, error redirects per RFC 6749 §4.1.2.1): all gated on issue 116 and tracked there.

## Related work

- Issue 116 — Full OIDC Provider (`/authorize` + ID tokens + userinfo). Unblocks rows 1, 2, 4, 5.
- Issue 163 — Authlete-superset spec coverage meta.
- Issue 197 / 202 (closed) — OIDF conformance harness wiring.
- Issue 140 — this audit's home.
