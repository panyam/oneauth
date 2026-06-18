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

---

## L4 — Grant types

### 7. Token Exchange Phase 2 — actor_token, may_act, richer audience/resource enforcement (RFC 8693)

- **What:** Current OneAuth implementation is Phase 1 — JWT subject_token only, no actor_token delegation chain, audience/resource read but not richly enforced. Phase 2 deepens these.
- **Where:** `apiauth/auth.go:239–240` parses `actor_token` / `actor_token_type` into the request shape but no handler logic uses them. No `act` / `may_act` claim shape in `core/`.
- **Why:** Enables full delegation/impersonation chains as 8693 specifies — needed for federated multi-hop identity. Audit-trail use cases (who acted on behalf of whom) currently can't be expressed.
- **Effort:** M-L. Needs `act` claim shape in `core/`, actor-token validation, policy hooks for "is this actor allowed to act for this subject?", audience/resource enforcement against registered policy.
- **Mentioned in:** [RFC_8693.md](RFC_8693.md) OneAuth status table.

### 8. Token Exchange — additional subject_token_types (RFC 8693)

- **What:** Phase 1 supports `urn:ietf:params:oauth:token-type:jwt` subject tokens only. The spec also defines `access_token`, `refresh_token`, `id_token`, `saml1`, `saml2`.
- **Where:** `apiauth/token_exchange_grant_test.go:37` only exercises `TokenTypeJWT`.
- **Why:** Broader interop with federation patterns that ship non-JWT subject tokens.
- **Effort:** M. Each token type needs its own validation path; SAML is most work.
- **Mentioned in:** [RFC_8693.md](RFC_8693.md).

---

## L5 — Client auth strength / sender constraint

### 9. RFC 8705 (mTLS) — full implementation

- **What:** mTLS client authentication at `/token` (both `tls_client_auth` and `self_signed_tls_client_auth` flavors) AND certificate-bound access tokens (`cnf.x5t#S256` emission + validation).
- **Where:** No mTLS handlers in `apiauth/`; single unrelated reference in `admin/DESIGN.md:19` mentions mTLS as a *future* admin authenticator (different layer).
- **Why:** Unlocks FAPI 1.0 Advanced / FAPI 2.0 conformance for deployments with PKI infrastructure (banking, healthcare, government). Without it, OneAuth cannot serve any FAPI-mandated profile.
- **Sub-surfaces:**
  - `tls_client_auth` client auth method (CA-issued certs, registered subject DN / SANs)
  - `self_signed_tls_client_auth` (cert thumbprint in client JWKS)
  - `cnf.x5t#S256` claim emission on issued tokens
  - RS-side `cnf.x5t#S256` validation middleware
  - `tls_client_certificate_bound_access_tokens` AS metadata field
  - `mtls_endpoint_aliases` AS metadata field (for segregated endpoints)
  - DCR client metadata fields (`tls_client_auth_subject_dn`, `tls_client_auth_san_*`)
  - `ClientAuthenticator` strategy + `TokenBindingValidator` interface (shared seam with DPoP)
- **Effort:** L. Significant surface; expect PKI plumbing time to dominate. Cert termination behind a proxy is the typical pattern (read `X-Client-Cert` header).
- **Mentioned in:** [RFC_8705.md](RFC_8705.md) — full implementation sketch and migration path.

### 10. RFC 9449 (DPoP) — full implementation

- **What:** Public-client sender constraint via app-layer signed proof JWTs. `cnf.jkt` token binding + per-request DPoP proof validation.
- **Where:** No DPoP handlers anywhere in `apiauth/`. JWK thumbprint primitive (the building block for `cnf.jkt`) IS already implemented in `utils/jwk_thumbprint.go:19–82` — partial scaffolding exists.
- **Why:** Unlocks FAPI 2.0 for non-PKI deployments. The natural path for public-client sender constraint (mobile apps, SPAs, CLIs) where mTLS is impractical.
- **Sub-surfaces:**
  - DPoP proof JWT validation at `/token` (`htm`, `htu`, `iat`, `jti`, embedded `jwk`, signature)
  - `cnf.jkt` claim emission on issued tokens (uses existing thumbprint primitive)
  - `token_type: "DPoP"` in `/token` response
  - `Authorization: DPoP <token>` parser (replacing or alongside current Bearer-only at `apiauth/auth.go:1219`)
  - RS-side proof validation middleware (`htm`/`htu`/`ath`/`jti`/`cnf.jkt` match)
  - Nonce protocol (`DPoP-Nonce` header) — Phase 2
  - `dpop_signing_alg_values_supported` AS metadata field
  - `dpop_bound_access_tokens_required` PR metadata field (in `apiauth/protected_resource.go`)
  - `DPoPProofValidator` interface; reuse `JTIStore` from `apiauth/client_authenticator.go`
- **Effort:** M-L. Less than mTLS (no PKI), but still substantial wire-protocol work.
- **Mentioned in:** [RFC_9449.md](RFC_9449.md) — full implementation sketch.

---

## L6 — Request integrity

### 11. RFC 9126 (PAR) — full implementation

- **What:** `POST /par` back-channel endpoint that accepts an authorization request, stores it server-side, returns an opaque `request_uri` for the browser-borne `/authorize` redirect.
- **Where:** No PAR handlers in `apiauth/`. `apiauth/authorize.go:138` parses `request` and `request_object` candidates but `request_uri` isn't recognized.
- **Why:** Cleans up browser URLs (no parameter leakage to history / logs / Referer); enables RAR (RFC 9396) to carry rich JSON without URL-encoding huge bodies; mandated for FAPI 2.0 conformance.
- **Sub-surfaces:**
  - `POST /par` endpoint (reuse `ClientAuthenticator` for caller auth)
  - PAR store with TTL'd `request_uri` records (analogous to `AuthorizationCodeStore`, model on `apiauth/device_auth_grant.go`)
  - `request_uri` dereferencing at `/authorize`
  - `pushed_authorization_request_endpoint` AS metadata field
  - `require_pushed_authorization_requests` per-client metadata + deployment flag
- **Effort:** M. Shape closely mirrors RFC 8628 Device Authorization (same pre-flow-endpoint + opaque-reference pattern).
- **Mentioned in:** [RFC_9126.md](RFC_9126.md) — full implementation sketch.

### 12. RFC 9101 (JAR) — full implementation

- **What:** Validate signed `request=<JWT>` and `request_uri=<URL>` at `/authorize`; use JWT claims as canonical authorization request per §6.1.
- **Where:** `apiauth/authorize.go:138` parses `request` / `request_object` candidates but doesn't validate. Existing JWS-validation primitives in `apiauth/client_authenticator.go` are directly reusable.
- **Why:** Integrity protection on authorization requests; FAPI 1.0 Advanced + FAPI 2.0 mandate this. Tracked under repo issue 150.
- **Sub-surfaces:**
  - Request JWT signature validation (reuse `client_authenticator.go` JWS path — same key lookup by `kid` against client's registered JWKS)
  - Claim extraction (override URL params per §6.1)
  - `request_uri` HTTP fetch (for non-PAR delivery)
  - AS metadata: `request_parameter_supported`, `request_uri_parameter_supported`, `request_object_signing_alg_values_supported`
  - DCR metadata: `require_signed_request_object` per-client
  - Encrypted request objects (JWE) — gated on RFC 7516 gap, rarely needed
- **Effort:** M. Most JWS plumbing already exists; the work is parameterizing existing primitives for a different "what the JWT means" semantic.
- **Mentioned in:** [RFC_9101.md](RFC_9101.md) — full implementation sketch.

## (Append future gaps below as L7/... docs land)

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
