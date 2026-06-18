# OAuth 2.1 (draft-ietf-oauth-v2-1)

> **Status:** Internet-Draft (active)
> **Latest:** [draft-ietf-oauth-v2-1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)
> **L-tier / T-tier:** L0 · T0–T8 (foundational)
> **OneAuth coverage:** Baseline alignment landed in PR 296 (issue 140). Audit table: [`docs/OAUTH21_ALIGNMENT.md`](../OAUTH21_ALIGNMENT.md)
> **See also:** [`RFC_6749.md`](RFC_6749.md) · [`RFC_9700.md`](RFC_9700.md) · [`LANDSCAPE.md`](LANDSCAPE.md)

## In one sentence

OAuth 2.1 is RFC 6749 with the Security BCP (RFC 9700), PKCE (RFC 7636), and
Bearer Token Usage (RFC 6750) consolidated into a single document — and with
the grants that two decades of attacks killed (implicit, ROPC) removed.

## What problem does it solve?

| Without 2.1 | With 2.1 |
|---|---|
| To deploy an OAuth AS securely in 2025 you must read RFC 6749 + RFC 6750 + RFC 7636 + RFC 9700 + ~10 errata threads and synthesize them yourself | One document; the synthesis is the spec |
| Insecure flows (implicit, ROPC) are still legal per 6749 — deployments quietly leave them on | Removed at the spec level — implementations have a normative reason to delete the code |
| "PKCE is for public clients" is a popular misreading of 7636 | 2.1 mandates PKCE for *all* clients, confidential included |
| `iss` on redirect is "you should consider this" in 9700 | 2.1 makes it required for new deployments |

**Important framing:** 2.1 does not invent new protocol surface. It's
*subtractive* and *prescriptive*. If you already follow 9700 + 7636 against
6749, you're 90% of the way to 2.1. The remaining 10% is closing the legacy
trapdoors.

## Relatable example

You inherit an OAuth deployment from 2015. The audit asks: "are we OAuth 2.1
compliant?" You don't want to read four RFCs. You want a checklist. 2.1 is
that checklist:

- Implicit grant on? **Turn it off.** (§2.1.2)
- ROPC password grant on? **Turn it off.** (§7.6)
- PKCE optional? **Make it mandatory for everyone.** (§4.1.1)
- Redirect URI matching wildcard / substring? **Exact match only.** (§3.1.2.2)
- Refresh tokens long-lived without rotation? **Rotate + detect reuse.** (§6.1)
- Bearer tokens in `?access_token=...` query params? **Remove that path.** (§5.4)

Each item maps to a code change. The audit becomes a project plan.

## Key changes vs 2.0

| Area | OAuth 2.0 (6749) | OAuth 2.1 |
|---|---|---|
| Implicit grant | Allowed (§4.2) | **Removed** |
| Password grant (ROPC) | Allowed (§4.3) | **Removed** |
| PKCE | SHOULD for public clients (per 7636/BCP) | **MUST for all clients on auth-code** |
| PKCE methods | `plain` and `S256` | **`S256` only** (`plain` rejected) |
| Redirect URI matching | Various (vendor) | **Exact string match** |
| Redirect URI scheme | Any | **HTTPS** required (loopback exempt per RFC 8252) |
| Bearer in query string | Discouraged (6750 §2.3) | **Forbidden** (§5.4) |
| Refresh token | No rotation mandate | **Rotation + family-revoke on reuse** required |
| Mix-up defense | Nothing | `iss` on redirect per RFC 9207 required |

## Relation to other RFCs

OAuth 2.1 is the *spec-level digest* of the L0 spine:

```
        6749 (the framework)
            |
            +— 6750 (how to USE a bearer token) ─────────┐
            |                                              \
            +— 7636 (PKCE — proves the client requesting    > OAuth 2.1
            |        the code is the same client            /
            |        exchanging it)                        /
            |                                             /
            +— 9700 (the Security BCP — accumulated      /
                     wisdom from a decade of attacks) ─/
```

Reading 2.1 *after* you've read 9700 makes every restriction click. Reading
2.1 *first* leaves you wondering "but why?" — the answers are in 9700.

## Wire example

There is no "2.1 wire format" — the wire is still 6749's wire. What 2.1
changes is what's *required* vs *allowed*. The example from
[`RFC_6749.md`](RFC_6749.md) is already 2.1-compliant because it carries
PKCE (S256), an `iss` on the redirect, and exact redirect URI matching at
both registration and authorization. Under pre-2.1, the same `/authorize`
request without `code_challenge` would have been accepted. Under 2.1, it's
rejected:

```http
HTTP/1.1 302 Found
Location: https://client.example.com/cb?error=invalid_request
                                       &error_description=code_challenge+is+required+%28PKCE%29
                                       &state=xyzABC
                                       &iss=https://as.example.com
```

That redirect — error + `iss` — is exactly what OneAuth's `/authorize` does
today (`apiauth/authorize.go:173`).

## Where it lands on the OAuth abstraction

- **L0 spine.** 2.1 *is* the spine; it's the document that legitimizes the
  constraints downstream L-tiers assume.
- **T-tier: T0–T8.** Every T-step has at least one 2.1 paragraph against
  it — by design, since 2.1 is "all of 6749 + the defenses."

## When NOT to use it

If you maintain a legacy IdP for clients that don't yet support PKCE or fresh
redirect-URI rules, you may need to leave 6749-only flows enabled for a
deprecation window. 2.1 is a destination state, not a deployment day; plan
the path. OneAuth's own ROPC and query-param-bearer carve-outs (see
[`docs/OAUTH21_ALIGNMENT.md`](../OAUTH21_ALIGNMENT.md) rows 3 and 7) are
exactly this kind of deprecation window.

## OneAuth status

The single source of truth is [`docs/OAUTH21_ALIGNMENT.md`](../OAUTH21_ALIGNMENT.md).
The row-by-row table there is kept in lock-step with the codebase as each
non-compliance is closed. As of this writing (post PR 297):

| 2.1 requirement | OneAuth verdict | Tracking |
|---|---|---|
| 1. PKCE required for all auth-code | **Compliant** (server enforces on `/authorize`) | landed PR 297 |
| 2. Implicit grant removed | **Compliant by absence** | — |
| 3. ROPC removed | **Non-compliant** | issue 294 |
| 4. Exact redirect URI matching | **Compliant** (DCR + `/authorize`) | landed PR 296 / 297 |
| 5. PKCE S256-only | **Compliant** | landed PR 297 |
| 6. HTTPS redirect URIs | **Compliant** (DCR) | landed PR 296 |
| 7. Bearer NOT in query string | **Non-compliant** (opt-in deprecation warning) | issue 295 |
| 8. Refresh token rotation | **Compliant** | — |

If a row above moves, update `docs/OAUTH21_ALIGNMENT.md` *and* this doc *and*
[`LANDSCAPE.md`](LANDSCAPE.md) §6 in the same change.

## Related RFCs

- [RFC 6749](RFC_6749.md) — the framework 2.1 builds on
- [RFC 6750](RFC_6750.md) — Bearer; 2.1 §5 mostly re-exports 6750 with the query-string carve-out removed
- [RFC 7636](RFC_7636.md) — PKCE; 2.1 makes it universal
- [RFC 9700](RFC_9700.md) — the BCP whose *normative* recommendations 2.1 promotes to MUST
- [RFC 9207](RFC_9207.md) — `iss` on redirect; 2.1 mandates
- [RFC 8252](https://datatracker.ietf.org/doc/rfc8252/) — Native Apps; loopback redirect exemption

## Spec links

- [draft-ietf-oauth-v2-1 (latest)](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)
- [WG OAuth status page](https://datatracker.ietf.org/wg/oauth/about/) for the current revision

> **Maintenance note.** When 2.1 graduates to RFC status, update this file's
> title, status, and the spec-link section, and add `RFC_xxxx.md` redirection
> if the filename moves.
