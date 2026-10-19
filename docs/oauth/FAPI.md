# FAPI 1.0 / 2.0 — Financial-grade API Security Profiles

> **Status:** OpenID Foundation Specifications (final)
> **Published:** FAPI 1.0 (2021), FAPI 2.0 Security Profile (final, 2025)
> **L-tier / T-tier:** L8 · T0 (profile of all)
> **OneAuth coverage:** FAPI 2.0 Security Profile §5.3.2 / §5.3.4 met through `OneAuthConfig.FAPI2` (0.1.52; reference server 0.1.54), with three caveats: DPoP is the only sender constraint (mTLS is #335), only ES256 client keys can be registered (#330, #331), and the OIDF conformance suite has never been run (mission #98, #433). FAPI 2.0 Message Signing (JAR #338, JARM mission #409) and FAPI 1.0 (ID tokens for `s_hash`, #339) are not supported
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
| **FAPI 2.0 Security Profile** | 2025 (final) | Successor to both | Simpler, modernized; PAR + PKCE + DPoP/mTLS + `private_key_jwt`/mTLS client auth mandatory. Signed requests (JAR) and signed responses (JARM) move to the separate FAPI 2.0 Message Signing profile |

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
3. **Request integrity is mandatory.** The FAPI 2.0 Security Profile gets
   it from PAR: the request travels over an authenticated back channel.
   FAPI 1.0 Advanced and FAPI 2.0 Message Signing also sign it with JAR,
   which adds non-repudiation.
4. **Strict alg choices.** PS256, ES256 or EdDSA (FAPI 2.0 §5.4.1), with
   RSA keys of at least 2048 bits. `RS256` and `HS256` are forbidden. The "alg=none" footgun is closed by the spec, not just by
   the implementer.
5. **Public + open client model has gone.** All clients are confidential
   in FAPI; SPAs and mobile-only deployments either run an authorized
   backend (BFF pattern) or accept that they're not FAPI.
6. **JARM (JWT-secured Authorization Response Mode)** is the
   signed-response sibling of JAR (signed *request*). FAPI 1.0 Advanced
   uses it, and FAPI 2.0 carries it in the Message Signing profile rather
   than the Security Profile.

## Wire pattern (the full FAPI 2.0 baseline)

```
Setup time (T0):
  ✓ AS publishes OIDC Discovery with strict capability advertisement
  ✓ JWKS published; only PS256 / ES256 / EdDSA signing keys
  ✓ DPoP / mTLS endpoint segregation if needed

Each request (T1):
  ✓ Client POSTs the request to /par (JAR-signed only under Message Signing)
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
  ✓ DPoP-bound token + DPoP proof, OR mTLS-bound token over the same TLS connection
  ✓ RS verifies cnf claim matches actual sender binding
  ✓ RS validates authorization_details matches the operation requested

Lifecycle (T8):
  ✓ No refresh-token rotation (FAPI 2.0 §5.3.2.1 forbids it outside
    extraordinary circumstances; the sender constraint protects the token)
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
- You add the L5 and L6 layers explicitly (mTLS or DPoP, PAR; JAR only for
  Message Signing).
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
3. **Ship the L6 request integrity.** PAR is what the FAPI 2.0 Security
   Profile needs. JAR comes next if you target Message Signing or FAPI
   1.0, and builds on existing JWS plumbing.
4. **Restrict alg choices.** Lock down to PS256 / ES256 / EdDSA in AS
   metadata and JWKS; reject HS256 and RS256.
5. **Run the OpenID FAPI conformance suite** against your AS in
   `dryrun` mode. It surfaces gaps mercilessly.
6. **Submit for self-certification** if a regulator requires it.

For OneAuth, steps 1 to 4 have landed for the FAPI 2.0 Security Profile:
DPoP (mTLS is still #335), PAR, and the algorithm lockdown, all switched on
together by `OneAuthConfig.FAPI2`. Step 5 has not happened. The OIDF suite
has never been run against oneauth (mission #98, #433).

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

**The FAPI 2.0 Security Profile is met but not certified.** oneauth meets
the profile's authorization-server and resource-server requirements (§5.3.2,
§5.3.4) through `OneAuthConfig.FAPI2`, and the reference server runs the
profile with `deploy-examples/fapi-dpop.yaml`. There are three caveats. DPoP
is the only sender constraint (mTLS is #335). Only ES256 client keys can be
registered, so FAPI clients use ES256 (PS256 is #330, EdDSA client keys
#331). The OIDF conformance suite has never been run (mission #98, #433), so
everything here is checked by oneauth's own tests and, where Keycloak supports
the feature, side by side with Keycloak 26. The requirement-by-requirement
matrix is in [`SECURITY_AUDIT.md`](../SECURITY_AUDIT.md).

| FAPI requirement | OneAuth status | Doc |
|---|---|---|
| FAPI 2.0 profile switch | **Implemented** (0.1.52). `OneAuthConfig.FAPI2` requires DPoP (sets `RequireDPoP`), turns off refresh-token rotation, accepts only `private_key_jwt` client authentication with the issuer as a string `aud`, refuses the password grant and public or unregistered clients, and makes `MountAuthorize` PAR-only with the code lifetime capped at 60 seconds and the `request_uri` lifetime under 600 seconds. `MountAuthorize` panics under `FAPI2` without a `PushedStore`. `OneAuthConfig.DPoP` must be set too, or every token request is refused | [`SECURITY_AUDIT.md`](../SECURITY_AUDIT.md) |
| Reference server | **Implemented** (0.1.54). `fapi2: true` sets `OneAuthConfig.FAPI2`. The server refuses to start without `dpop.enabled`, with a `jwt.signing_alg` other than ES256 (HS256 is the default, and FAPI 2.0 §5.4.1 allows PS256, ES256 and EdDSA), or with `code_flow` on but no `code_flow.par.enabled`. `code_flow.par.enabled` mounts `POST /par`, and `code_flow.par.required` refuses direct `/authorize`. Under `fapi2` the metadata lists `private_key_jwt` / ES256 only, the PAR endpoint, `require_pushed_authorization_requests`, and no password grant. `deploy-examples/fapi-dpop.yaml` runs the whole profile, signing with ES256 from `JWT_PRIVATE_KEY_PATH` or a key made at startup | [`RFC_9126.md`](RFC_9126.md) |
| PAR | **Implemented** (repo issue 337). Required under `FAPI2` | [`RFC_9126.md`](RFC_9126.md) |
| JAR | Gap (#338). Not part of the FAPI 2.0 Security Profile; FAPI 2.0 Message Signing and FAPI 1.0 Advanced use it | [`RFC_9101.md`](RFC_9101.md) |
| RAR | **Implemented** | [`RFC_9396.md`](RFC_9396.md) |
| DPoP (sender constraint) | **Implemented**. `OneAuthConfig.RequireDPoP` makes the AS issue only bound tokens (§5.3.2.1), and `FAPI2` sets it. `APIMiddleware.RequireDPoP` makes the RS accept only bound tokens (§5.3.4), and `apiauth.FAPIDPoPAlgs()` limits proofs to ES256 / EdDSA / PS256. The reference server turns all of it on with `deploy-examples/fapi-dpop.yaml` | [`RFC_9449.md`](RFC_9449.md), [`SECURITY_AUDIT.md`](../SECURITY_AUDIT.md) |
| mTLS (sender constraint, PKI clients) | Gap (#335). FAPI allows DPoP instead, so this is not blocking | [`RFC_8705.md`](RFC_8705.md) |
| Client authentication (§5.3.2.1 #6, #8) | **Implemented** under `FAPI2`: `private_key_jwt` only, with the issuer as the sole string `aud`. Since 0.1.52 the expected audience comes from `r.TLS` and `r.Host` (and the issuer), never from forwarded headers; behind a TLS proxy set `OneAuthConfig.AcceptedAudiences` | [`RFC_7523.md`](RFC_7523.md) |
| Algorithms (§5.4.1) | **Partial.** Under `FAPI2` only PS256 / ES256 / EdDSA client assertions pass (`AuthenticateClientRequest.AllowedAssertionAlgs`), but only ES256 client keys can be registered (PS256 #330, EdDSA #331). DPoP proofs accept ES256, EdDSA (0.1.43) and PS256. The AS signs tokens with ES256 but not PS256 (#330). RSA keys under 2048 bits are refused at load | [`RFC_7518.md`](RFC_7518.md) |
| OIDC Core (id_token issuance) | Gap (#339). Not needed for the FAPI 2.0 Security Profile; FAPI 1.0's `s_hash` rides on ID tokens | [`OIDC_Core.md`](OIDC_Core.md) |
| JARM (signed authz responses; FAPI 1.0 and FAPI 2.0 Message Signing) | Gap (mission #409) | — |
| 2.1 spine alignment (PKCE everywhere, no implicit, etc.) | Mostly compliant | [`docs/OAUTH21_ALIGNMENT.md`](../OAUTH21_ALIGNMENT.md) |
| Refresh tokens | **Implemented as an option.** OneAuth rotates on every use with reuse detection by default (RFC 9700). `OneAuthConfig.DisableRefreshTokenRotation` (server: `jwt.disable_refresh_token_rotation`) turns it off, as FAPI 2.0 §5.3.2.1 asks, and `FAPI2` sets it | [`RFC_9700.md`](RFC_9700.md) |
| `iss` on redirect | Implemented | [`RFC_9207.md`](RFC_9207.md) |
| Strict redirect URI matching + HTTPS | Implemented (DCR + `/authorize`) | [`RFC_9700.md`](RFC_9700.md) |
| OIDF conformance run | Not done. The OIDF workflow exists but has never run (mission #98, #433) | [`SECURITY_AUDIT.md`](../SECURITY_AUDIT.md) |

What remains for the FAPI 2.0 Security Profile is a first OIDF conformance
run, PS256 and EdDSA client keys, and mTLS as a second sender constraint.
FAPI 2.0 Message Signing adds JAR and JARM, and FAPI 1.0 adds OIDC ID tokens.

**The strategic question** for OneAuth isn't *whether* FAPI is reachable
(the Security Profile is met), but *whether the user base needs* the rest. If demand exists for
banking-grade APIs the work pays off. If consumer SSO is the primary
target, FAPI may always be aspirational.

## Related specs

- [RFC 9126 PAR](RFC_9126.md) — mandatory in the FAPI 2.0 Security Profile
- [RFC 9101 JAR](RFC_9101.md) — FAPI 1.0 Advanced and FAPI 2.0 Message Signing
- [RFC 9396 RAR](RFC_9396.md) — strongly recommended for transaction APIs
- [RFC 9449 DPoP](RFC_9449.md) — sender constraint (public)
- [RFC 8705 mTLS](RFC_8705.md) — sender constraint (PKI)
- [OIDC Core](OIDC_Core.md) — id_token + auth_time + acr
- [RFC 9700 BCP](RFC_9700.md) — the security baseline
- Repo issues: mission #409 (JARM; issue 151 is closed), 152 (RFC 9421 HTTP Message Signatures for FAPI 2.0 message signing), 160 (`attest_jwt_client_auth`), 161 (regional Open Banking profiles)

## Spec links

- [FAPI 1.0 Baseline](https://openid.net/specs/openid-financial-api-part-1-1_0.html)
- [FAPI 1.0 Advanced](https://openid.net/specs/openid-financial-api-part-2-1_0.html)
- [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-2_0-security-profile.html)
- [FAPI 2.0 Message Signing](https://openid.net/specs/fapi-2_0-message-signing.html)
- [OpenID Conformance Suite](https://gitlab.com/openid/conformance-suite) — the public test runner
- [FAPI WG home](https://openid.net/wg/fapi/)
