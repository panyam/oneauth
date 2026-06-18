# _PENDING_GAPS.md — gaps surfaced during per-RFC doc writing

> **Working doc, not a deliverable.** This file collects implementation
> gaps that turned up while writing `docs/oauth/RFC_*.md` summaries. It
> exists so we can file GitHub issues in one batch at the end of the docs
> pass rather than interrupting the flow per-doc. **Delete this file once
> the corresponding issues are filed** (or it's empty).

Each entry below should become one GitHub issue, labeled appropriately
(probably `enhancement`, plus per-feature L-tier label from the
`docs:oauth:Ln-...` family if it ties to a topic we've already mapped).

For each gap, capture:
- **What** — the missing surface, in concrete terms
- **Where** — the file:line where the doc points (so the issue links the audit trail)
- **Why** — what it unlocks / which RFC compliance it tightens
- **Effort** — rough sense (S / M / L)

---

## L0 — Spine

### 1. `WWW-Authenticate` structured error fields not emitted (RFC 6750 §3)

- **What:** OneAuth currently returns bare `WWW-Authenticate: Bearer realm="api"` on 401. RFC 6750 §3 defines `error=`, `error_description=`, `error_uri=`, and `scope=` parameters that let clients distinguish *missing*, *expired*, and *insufficient-scope* token responses programmatically.
- **Where:** `apiauth/auth.go:1466` — only `Bearer realm="api"` emitted today.
- **Why:** Without `error=invalid_token` vs `error=insufficient_scope` on the challenge, clients can't refresh-vs-step-up intelligently. Forces fallback to "prompt the user again" UX.
- **Effort:** S. The hooks already exist (`a.errorResponse` etc.); plumbing the verifier-side error code into the challenge string is a small change.
- **Mentioned in:** [RFC_6750.md](RFC_6750.md) OneAuth status table.

---

## L1 — Token format / JOSE

### 2. `typ:at+jwt` header not emitted on access-token issuance (RFC 9068)

- **What:** OneAuth's signed access tokens carry `typ:JWT` (golang-jwt default). RFC 9068 §2.1 specifies the distinguishing media type `application/at+jwt` (`typ:at+jwt` in the header).
- **Where:** No occurrences of `at+jwt` anywhere in the codebase as of this commit.
- **Why:** With `typ:at+jwt`, RSes can reject id_tokens masquerading as access tokens with a single header check. Closes a known token-confusion class.
- **Effort:** S. Pass a custom header to the JWT encoder during access-token mint.
- **Mentioned in:** [RFC_9068.md](RFC_9068.md) OneAuth status table.

### 3. RS-side `typ` validation not enforced on access tokens

- **What:** Companion to gap #2. Even after we emit `typ:at+jwt`, the verifier side has to reject tokens whose `typ` doesn't match. Currently any signed JWT shape is accepted.
- **Where:** Search verifier paths in `apiauth/auth.go` and middleware — they don't consult `typ`.
- **Why:** Defense in depth. An attacker who tricks the issuer into minting an id_token where an access token should land would be caught by `typ` validation.
- **Effort:** S. Add a header check to the JWT validation path.
- **Mentioned in:** [RFC_9068.md](RFC_9068.md) OneAuth status table.

### 4. PS256 algorithm support (RFC 7518 / FAPI 1.0 Advanced)

- **What:** OneAuth supports HS256 / RS256 / ES256. PS256 (RSASSA-PSS + SHA-256) is required for FAPI 1.0 Advanced profile.
- **Where:** `apiauth/asymmetric_jwt_test.go` exercises only RS256 / ES256.
- **Why:** Unblocks FAPI 1.0 Advanced conformance. Not needed for FAPI 2.0 (which prefers PS256 but doesn't require it).
- **Effort:** S. Library supports it; wire the alg into the AS config + JWKS.
- **Mentioned in:** [RFC_7518.md](RFC_7518.md), [RFC_9068.md](RFC_9068.md).

### 5. EdDSA (Ed25519) algorithm support (RFC 8037 + 7518)

- **What:** Modern recommended signing alg. Smaller signatures, simpler verifier, no curve-parameter footguns.
- **Where:** Partial coverage via `sshkeys/` for SSH-only contexts; not wired into `apiauth/` signing paths.
- **Why:** Future-proofing; aligns with modern crypto guidance.
- **Effort:** M. Library has support; needs key-management plumbing (key gen, JWKS encoding via OKP `kty`).
- **Mentioned in:** [RFC_7518.md](RFC_7518.md).

### 6. JWE issuance / decryption (RFC 7516)

- **What:** No JWE support — encrypted JWTs cannot be issued or verified.
- **Where:** No JWE imports anywhere; gap by design until a use case appears.
- **Why:** Required for FAPI 1.0 Advanced encrypted id_token scenarios; needed for some regulator-mandated profiles (UK Open Banking, certain EU health).
- **Effort:** L. Needs JWE library wiring, recipient-key management (separate from signing keys), nested-JWT handling.
- **Mentioned in:** [RFC_7516.md](RFC_7516.md).

---

## (Append future gaps below as L2/L3/... docs land)

---

## Filing checklist (when ready)

For each numbered gap above:

1. Open a GitHub issue with a title like:
   `feat(apiauth): emit typ:at+jwt header on access-token mint (RFC 9068)`
2. Body should restate the *What / Where / Why / Effort* with the
   grep-verified citations.
3. Label with `enhancement` + the relevant `docs:oauth:Ln-...` topical tier
   if applicable.
4. Cross-link to the per-RFC doc that originally surfaced the gap.
5. Tick the entry off here. When this file is empty, delete it.
