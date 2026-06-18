# FAPI 1.0 / 2.0 — Financial-grade API Security Profiles

> **Status:** OpenID Foundation Specifications (final)
> **Published:** FAPI 1.0 (2021), FAPI 2.0 Security Profile (2024)
> **L-tier / T-tier:** L8 · T0 (profile of all)
> **OneAuth coverage:** Not conformant — unlocks once L5 (DPoP/mTLS) + L6 (PAR/JAR) land
> **See also:** [`RFC_9126.md`](RFC_9126.md) · [`RFC_9101.md`](RFC_9101.md) · [`RFC_9449.md`](RFC_9449.md) · [`RFC_8705.md`](RFC_8705.md) · [`LANDSCAPE.md`](LANDSCAPE.md)

## In one sentence

FAPI is a *profile* of OAuth 2.0 + OIDC + the security extensions — it
doesn't invent new protocol surface; it *mandates* the right composition
(PAR + JAR + RAR + DPoP/mTLS + signed responses) for regulated, high-
stakes APIs.

## What problem does it solve?

| Without FAPI | With FAPI |
|---|---|
| Regulators of banking / open finance / healthcare can't tell you "use OAuth" because OAuth is too permissive — too many ways to get it insecure | One spec lists the mandatory extensions and forbids the insecure choices |
| Per-jurisdiction OAuth profiles diverge (UK Open Banking, EU PSD2, Brazil Open Finance, etc.) | FAPI is the common base; regional profiles layer minimal additions on top |
| Implementers don't know which extensions to combine for "secure enough" deployments | FAPI is the answer to "what extensions do I turn on for banking-grade security?" |
| Conformance testing is per-vendor | Open Identity Foundation runs a public FAPI conformance test suite |

FAPI is the *composition* of the L5 and L6 RFCs into a normative
deployment profile. It's the spec where "we want sender-constrained tokens
AND request integrity AND structured authorization" stops being a wish
list and starts being a checklist.

## Relatable example

You're integrating with a UK Open Banking account information service. The
regulator (Open Banking Implementation Entity) doesn't write its own
protocol; it points at FAPI:

- *"All AISPs/PISPs MUST be FAPI 1.0 Advanced conformant by Q3 2025."*

To pass conformance you must ship:
- PAR (request transport)
- JAR (signed requests)
- mTLS *or* private_key_jwt for client auth
- mTLS-bound *or* DPoP-bound access tokens
- JARM-signed authorization responses
- PS256 (FAPI 1.0) or ES256 (FAPI 2.0) signing

Each item is a separate RFC; FAPI is the document that says "all of them,
together, with these settings."

The same pattern shows up in Brazil Open Finance, Australia CDR, the EU's
PSD2 ecosystem, and increasingly in healthcare APIs requiring patient-
consent-driven access.

## Three FAPI profiles (which one matters?)

| Profile | Year | Scope | Notable mandates |
|---|---|---|---|
| **FAPI 1.0 Baseline** | 2021 | Read-only APIs (e.g., account info) | PKCE, JAR optional, mTLS-bound or DPoP-bound tokens, PS256 |
| **FAPI 1.0 Advanced** | 2021 | Read-write APIs (e.g., payment initiation) | PAR + JAR + RAR all mandatory, PS256, signed responses (JARM), mTLS or private_key_jwt |
| **FAPI 2.0 Security Profile** | 2024 | Successor to both | Simpler, modernized; PAR + DPoP/mTLS mandatory; deprecates JARM in favor of JAR-everywhere |

Most new builds in 2025+ target FAPI 2.0. The 1.0 profiles persist because
regulators move slowly — they wrote 1.0 conformance into rules and have
not yet rolled forward.

## Key concepts

1. **FAPI doesn't invent endpoints or grants.** It mandates which of the
   *existing* OAuth/OIDC extensions are required and forbids the loose
   alternatives (no implicit, no ROPC, no `plain` PKCE, no `none` alg).
2. **Sender-constrained tokens are mandatory.** Either mTLS-bound
   (`cnf.x5t#S256`, RFC 8705) or DPoP-bound (`cnf.jkt`, RFC 9449). The
   choice depends on PKI availability, not security level.
3. **Request integrity is mandatory.** JAR for the signature; PAR for the
   transport. Even at FAPI 2.0 with everything modernized, JAR/PAR
   remain the request-side baseline.
4. **Strict alg choices.** PS256 / ES256 only — `RS256` and `HS256` are
   forbidden. The "alg=none" footgun is closed by the spec, not just by
   the implementer.
5. **Public + open client model has gone.** All clients are confidential
   in FAPI; SPAs and mobile-only deployments either run an authorized
   backend (BFF pattern) or accept that they're not FAPI.
6. **JARM (JWT-secured Authorization Response Mode)** is the FAPI 1.0
   signed-response sibling of JAR (signed *request*). FAPI 2.0 reuses
   JAR's framework instead of carrying JARM separately.

## Wire pattern (the full FAPI 2.0 baseline)

```
Setup time (T0):
  ✓ AS publishes OIDC Discovery with strict capability advertisement
  ✓ JWKS published; only PS256 / ES256 signing keys
  ✓ DPoP / mTLS endpoint segregation if needed

Each request (T1):
  ✓ Client POSTs request to /par with JAR-signed JWT body
  ✓ AS returns short request_uri
  ✓ Client redirects: GET /authorize?client_id=X&request_uri=urn:ietf:...

User auth (T3):
  ✓ Strong authentication (MFA / FIDO2 typical)
  ✓ acr / amr / auth_time claims populated

Redirect back (T4):
  ✓ iss param on redirect (RFC 9207)

Token endpoint (T5):
  ✓ Client auth via mTLS or private_key_jwt
  ✓ Issued tokens carry cnf.x5t#S256 (mTLS) or cnf.jkt (DPoP)
  ✓ authorization_details (RAR) echoed back

Resource access (T6, T7):
  ✓ Bearer token + DPoP proof OR mTLS connection
  ✓ RS verifies cnf claim matches actual sender binding
  ✓ RS validates authorization_details matches the operation requested

Lifecycle (T8):
  ✓ Refresh rotation with reuse detection
  ✓ Revocation on user-initiated logout
```

Every checkmark corresponds to a specific RFC (mostly the L4–L6 + RFC 9700
ones). FAPI is the layer that says: "all of them, no exceptions."

## Where it lands on the OAuth abstraction

- **L8 profiles.** Not a peer to other RFCs — a *consumer* of them.
- **T0 (sets the deployment policy that gates all later T-steps).**
- **Composes L1 (JWT/JWS), L2 (discovery), L3 (DCR for cert-bound
  clients), L4 (the grants), L5 (mTLS or DPoP), L6 (PAR + JAR + RAR),
  L7 (OIDC), and L0 (PKCE + BCP).**

## OAuth 2.0 vs OAuth 2.1 status

FAPI 1.0 is layered on OAuth 2.0 explicitly. FAPI 2.0 references OAuth 2.1
as its baseline (along with OAuth 2.0 — many of FAPI 2.0's mandates *are*
2.1's mandates, just made explicit in a regulated context).

If your trajectory is FAPI 2.0:
- You're already on the 2.1-strict path (PKCE everywhere, no implicit, no
  ROPC, exact redirect, refresh rotation).
- You add the L5 and L6 layers explicitly (mTLS or DPoP, PAR, JAR).
- You restrict algorithms and disable the loose extensions.

## Migration path (regular OAuth → FAPI)

FAPI is gated on extension coverage; you can't "kind of" be FAPI. The
ordered path is:

1. **Close the L0 + L1 gaps first.** OAuth 2.1 alignment + JOSE +
   RFC 9068. (For OneAuth, this is done — see
   [`docs/OAUTH21_ALIGNMENT.md`](../OAUTH21_ALIGNMENT.md).)
2. **Ship the L5 sender constraint.** mTLS for confidential-with-PKI
   deployments; DPoP for everyone else. Most teams ship DPoP first
   because PKI is harder.
3. **Ship the L6 request integrity.** PAR + JAR. PAR is the easier
   precursor; JAR builds on existing JWS plumbing.
4. **Restrict alg choices.** Lock down to PS256 / ES256 in AS metadata
   and JWKS; reject HS256 and RS256.
5. **Run the OpenID FAPI conformance suite** against your AS in
   `dryrun` mode. It surfaces gaps mercilessly.
6. **Submit for self-certification** if a regulator requires it.

For OneAuth, that order is: L5 first (DPoP > mTLS), then L6 (PAR > JAR),
then alg lockdown. With those landed, FAPI 2.0 conformance is in reach.

## When NOT to use it

- **Consumer-grade OAuth without regulatory pressure.** FAPI is heavy.
  The operational complexity (cert management for mTLS, per-flow PAR
  state, signed-request construction) is wasted if you don't need it.
- **Internal services on controlled networks.** Same argument — the
  threat model FAPI defends against (browser-side leakage, regulator-
  required attribution, cross-org token replay) often doesn't apply.
- **Strict latency budgets.** PAR adds one round-trip; DPoP adds proof
  signing per request. Cheap, but not free. High-frequency internal
  services may not want the overhead.

## OneAuth status

**Not FAPI-conformant.** The blocking gaps are explicit:

| FAPI requirement | OneAuth status | Doc |
|---|---|---|
| PAR | Gap | [`RFC_9126.md`](RFC_9126.md) |
| JAR | Gap (repo issue 150) | [`RFC_9101.md`](RFC_9101.md) |
| RAR | **Implemented** | [`RFC_9396.md`](RFC_9396.md) |
| DPoP (sender constraint, public clients) | Gap | [`RFC_9449.md`](RFC_9449.md) |
| mTLS (sender constraint, PKI clients) | Gap | [`RFC_8705.md`](RFC_8705.md) |
| PS256 algorithm | Gap (logged) | [`RFC_7518.md`](RFC_7518.md) + `_PENDING_GAPS.md` entry 4 |
| OIDC Core (id_token issuance) | Gap (largest open item) | [`OIDC_Core.md`](OIDC_Core.md) |
| JARM (signed authz responses, FAPI 1.0 only) | Gap (tracked under repo issue 151) | — |
| 2.1 spine alignment (PKCE everywhere, no implicit, etc.) | Mostly compliant | [`docs/OAUTH21_ALIGNMENT.md`](../OAUTH21_ALIGNMENT.md) |
| Refresh rotation + reuse detect | Implemented | [`RFC_9700.md`](RFC_9700.md) |
| `iss` on redirect | Implemented | [`RFC_9207.md`](RFC_9207.md) |
| Strict redirect URI matching + HTTPS | Implemented (DCR + `/authorize`) | [`RFC_9700.md`](RFC_9700.md) |

The "what's needed" reduces to: **L5 (DPoP + mTLS) + L6 (PAR + JAR) +
OIDC Core id_token + PS256.** That's a substantial body of work but the
shape of each piece is well-defined.

**The strategic question** for OneAuth isn't *whether* FAPI is reachable
(it is), but *whether the user base needs it.* If demand exists for
banking-grade APIs the work pays off. If consumer SSO is the primary
target, FAPI may always be aspirational.

## Related specs

- [RFC 9126 PAR](RFC_9126.md) — mandatory
- [RFC 9101 JAR](RFC_9101.md) — mandatory
- [RFC 9396 RAR](RFC_9396.md) — strongly recommended for transaction APIs
- [RFC 9449 DPoP](RFC_9449.md) — sender constraint (public)
- [RFC 8705 mTLS](RFC_8705.md) — sender constraint (PKI)
- [OIDC Core](OIDC_Core.md) — id_token + auth_time + acr
- [RFC 9700 BCP](RFC_9700.md) — the security baseline
- Repo issues: 151 (JARM), 152 (RFC 9421 HTTP Message Signatures for FAPI 2.0 message signing), 160 (`attest_jwt_client_auth`), 161 (regional Open Banking profiles)

## Spec links

- [FAPI 1.0 Baseline](https://openid.net/specs/openid-financial-api-part-1-1_0.html)
- [FAPI 1.0 Advanced](https://openid.net/specs/openid-financial-api-part-2-1_0.html)
- [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-2_0-security-profile.html)
- [FAPI 2.0 Message Signing](https://openid.net/specs/fapi-2_0-message-signing.html)
- [OpenID Conformance Suite](https://gitlab.com/openid/conformance-suite) — the public test runner
- [FAPI WG home](https://openid.net/wg/fapi/)
