# GNAP — Grant Negotiation and Authorization Protocol (RFC 9635)

> **Status:** Standards Track
> **Published:** 2024-10
> **L-tier / T-tier:** L8 · (replacement, not extension)
> **OneAuth coverage:** Watch-only — no implementation planned
> **See also:** [`LANDSCAPE.md`](LANDSCAPE.md)

## In one sentence

GNAP is the IETF's *speculative replacement* for OAuth 2.0 — a from-scratch
redesign that consolidates "the spec is OAuth + N extensions" into one
larger document with cleaner primitives. Published 2024 as an IETF
Proposed Standard; production adoption is essentially zero.

## Why it exists

Through the 2010s the OAuth WG accumulated extensions: PKCE, JAR, PAR,
RAR, DPoP, mTLS, token exchange. Each one fit a real problem. *Together*
they form a complex deployment surface — every IdP picks a subset, every
client SDK supports a different combination, conformance becomes a per-
vendor matrix.

GNAP is the *clean-slate* answer to that complexity. Instead of
"OAuth 2.0 + 12 extensions," GNAP is one specification that incorporates
the lessons learned:

- Built-in support for multiple resource access patterns (not just
  bearer)
- Built-in support for cryptographic key binding (not bolted on via
  DPoP/mTLS)
- Cleaner extension model
- HTTP semantics that more naturally fit modern API patterns

## Current adoption state

**Essentially none in production.** As of mid-2026:

- A handful of academic and reference implementations exist
- No major IdP (Auth0, Okta, Azure AD, Keycloak, Google) has shipped
  production GNAP support
- No regulator (FAPI, Open Banking, healthcare) has adopted GNAP profiles
- OAuth 2.0 / 2.1 + the extension stack remains the deployed reality

The IETF community's posture is roughly: *OAuth 2.x will be the deployed
standard for the next decade; GNAP is a long-horizon successor*. Whether
it ever achieves widespread deployment depends on:

- Tooling support (client SDKs in every major language)
- Implementer demand
- Whether the marginal cleanliness wins over the network effects of
  the existing OAuth ecosystem

History suggests *successor* protocols rarely displace incumbents (SAML
didn't kill OAuth; OAuth 1.0a didn't survive OAuth 2.0; XACML never
achieved escape velocity). But GNAP could break that pattern if the
existing OAuth surface continues compounding.

## What it looks like (briefly)

GNAP uses one negotiation endpoint and structured JSON requests instead
of the form-encoded body of OAuth's token endpoint. A simplified GNAP
"start" request:

```http
POST /tx HTTP/1.1
Host: as.example.com
Content-Type: application/json

{
  "access_token": {
    "access": [
      { "type": "payment_initiation",
        "actions": ["initiate"],
        "amount": "500.00",
        "currency": "GBP" }
    ]
  },
  "client": {
    "key": { "proof": "httpsig",
             "jwk": { "kty":"EC", "crv":"P-256", "x":"...", "y":"..." } }
  },
  "interact": {
    "start": ["redirect"],
    "finish": { "method":"redirect",
                "uri":"https://client.example/cb",
                "nonce":"abc..." }
  }
}
```

The response is a structured continuation URI plus, when ready, a
structured access token grant.

The shape is *cleaner* than OAuth's accumulated wire — but the OAuth
ecosystem's switching cost is enormous.

## Where it lands on the OAuth abstraction

- **L8 (future / watch-only).** Not a peer of any L0–L7 RFC — a potential
  *replacement* for the whole stack.
- GNAP's relationship to OAuth is *succession* rather than composition.
  A GNAP-only AS doesn't speak OAuth on the wire (though it can be
  bridged).

## OAuth 2.0 / 2.1 status

GNAP doesn't extend or constrain OAuth 2.0/2.1 — it's a parallel,
incompatible protocol. The IETF GNAP WG explicitly positions it as a
*successor*, not an upgrade path.

This means:

- Production OAuth 2.0 deployments are unaffected.
- A new build today should *not* choose GNAP — interop with the
  ecosystem doesn't yet exist.
- A library project (like OneAuth) should monitor the spec's deployment
  trajectory without committing engineering effort.

## When to revisit

Three signals would justify GNAP work:

1. **A major IdP ships production GNAP** with public conformance.
   (None have as of mid-2026.)
2. **A regulator adopts GNAP** as the required protocol for some
   profile (e.g., a future FAPI 3.0 successor).
3. **A material consumer use case** asks for GNAP specifically — most
   likely an academic or research deployment.

Until one of those signals fires, GNAP stays in the *interesting future
work* column.

## OneAuth status

| GNAP surface | Status | Notes |
|---|---|---|
| Any GNAP support | **Not planned** | Watch-only |
| OAuth-to-GNAP bridging | **Not planned** | Premature; no producer or consumer demand |

This is a deliberate non-investment. The opportunity cost of GNAP work
today would be deferring real OAuth 2.x feature gaps that have
deployment demand.

## When NOT to think about it

In every working session of OneAuth development for the next several
years. Note its existence; check the spec's deployment trajectory
annually; otherwise direct effort at the L5/L6/L7 OAuth surfaces that
*do* have demand.

## Related specs

- [OAuth 2.0 / 2.1](RFC_6749.md) — what GNAP would notionally replace
- [GNAP design rationale](https://datatracker.ietf.org/doc/draft-ietf-gnap-resource-servers/)
- IETF GNAP WG home

## Spec links

- [RFC 9635: GNAP](https://datatracker.ietf.org/doc/rfc9635/)
- [RFC editor copy](https://www.rfc-editor.org/rfc/rfc9635.html)
- [IETF GNAP working group](https://datatracker.ietf.org/wg/gnap/)
- [GNAP resource servers spec](https://datatracker.ietf.org/doc/draft-ietf-gnap-resource-servers/) (companion)
