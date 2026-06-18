# OpenID Connect Back-Channel Logout 1.0

> **Status:** OpenID Foundation Specification
> **Published:** 2019 (final)
> **L-tier / T-tier:** L7 · T8 (lifecycle / logout)
> **OneAuth coverage:** Implemented (`apiauth/BCLDispatcher` + `LogoutTokenIssuer`)
> **See also:** [`OIDC_Core.md`](OIDC_Core.md) · [`RFC_7009.md`](RFC_7009.md) · [`LANDSCAPE.md`](LANDSCAPE.md)

## In one sentence

OIDC Back-Channel Logout is the "log out everywhere" mechanism — when a
user logs out at the IdP, the AS *pushes* a signed `logout_token` to every
relying party (RP) that registered a logout receiver, so they can drop
their local session.

## What problem does it solve?

| Without BCL | With BCL |
|---|---|
| User logs out at the IdP, but their session at every relying party stays alive until each one's session cookie expires | AS broadcasts logout to every connected RP; RPs drop their session immediately |
| Cross-device logout ("log out from all devices") requires per-RP plumbing | Single source of truth at the AS; standardized notification protocol |
| Auditing "who logged out where, when" needs custom telemetry | The signed `logout_token` is the audit record |
| Front-channel logout (browser iframe magic) is fragile — third-party cookie blocking breaks it | Back-channel is server-to-server; immune to browser quirks |

OIDC defined three logout mechanisms — Front-Channel, Back-Channel, and
RP-Initiated. Back-Channel is the most operationally robust because it's
HTTP server-to-server, not browser-orchestrated. It's the mechanism modern
SSO deployments standardize on.

## Relatable example

You're using Google Workspace at a company. You're logged into Gmail,
Google Drive, the corporate intranet (which SSOs through Google), Slack
(which also SSOs through Google), and a few SaaS tools. You hit "Sign out
of all" at Google.

Under BCL, what happens next:

1. Google's AS marks your session ended.
2. Google's AS sends a `POST` to *each* RP's registered
   `backchannel_logout_uri`, with a signed `logout_token` JWT in the body.
3. Slack receives the POST, validates the token, kills your Slack session.
4. The corporate intranet receives, validates, kills.
5. Every other SSO-connected app does the same.

Within seconds, you're logged out everywhere. Your next visit to any of
those apps redirects you back to Google's login.

## Key concepts

1. **`logout_token` is a JWT, signed by the AS.** Required claims (§2.4):
   - `iss` — same as the OIDC issuer
   - `sub` and/or `sid` — `sub` for "log out *this user* everywhere";
     `sid` for "log out *this session*" (need at least one)
   - `aud` — the RP's client_id
   - `iat` — issued at
   - `jti` — unique per logout token (for replay defense)
   - `events` — exactly `{"http://schemas.openid.net/event/backchannel-logout": {}}`
     (yes, a JSON object with an HTTP URL as the key — that's the
     normative shape)
2. **`nonce` MUST NOT appear.** Per §2.4 ¶6, a stray `nonce` is grounds
   for the receiver to reject. The logout_token is *not* an id_token —
   different replay model.
3. **RP registers `backchannel_logout_uri` at DCR.** Plus optionally
   `backchannel_logout_session_required: true` — meaning "I want `sid`
   in the logout_token, not just `sub`."
4. **AS POSTs to the registered URI** with
   `Content-Type: application/x-www-form-urlencoded` and
   `logout_token=<JWT>`. Per §2.7 the receiver returns `200 OK` on
   success; non-200 responses are logged but don't block dispatch to
   other RPs.
5. **`logout_token` is single-purpose.** Don't reuse for anything else.
   Receivers identify it by `events` claim.

## Wire example

**RP registers logout receiver via DCR:**

```http
POST /apps/dcr HTTP/1.1
Host: as.example.com
Content-Type: application/json

{
  "client_name": "Acme SSO Client",
  "redirect_uris": ["https://acme.example/oauth/cb"],
  "backchannel_logout_uri": "https://acme.example/oauth/logout",
  "backchannel_logout_session_required": true
}
```

**AS dispatches logout (when user signs out):**

```http
POST /oauth/logout HTTP/1.1
Host: acme.example
Content-Type: application/x-www-form-urlencoded

logout_token=eyJhbGciOiJSUzI1NiIsImtpZCI6Imtfa2V5XzEifQ.eyJpc3MiOiJodHRwczovL2FzLmV4YW1wbGUuY29tIiwic3ViIjoidXNlci00MiIsImF1ZCI6ImFjbWUtY2xpZW50Iiwic2lkIjoic2Vzc2lvbi1mYW0tYWJjIiwiaWF0IjoxNzE3MDAwMDAwLCJqdGkiOiJsdC03N2RmIiwiZXZlbnRzIjp7Imh0dHA6Ly9zY2hlbWFzLm9wZW5pZC5uZXQvZXZlbnQvYmFja2NoYW5uZWwtbG9nb3V0Ijp7fX19.signature
```

Decoded `logout_token`:
```json
{
  "iss": "https://as.example.com",
  "sub": "user-42",
  "aud": "acme-client",
  "sid": "session-fam-abc",                  ← session ID
  "iat": 1717000000,
  "jti": "lt-77df",
  "events": {
    "http://schemas.openid.net/event/backchannel-logout": {}
  }
}
```

**RP responds 200 OK; RP kills the session(s) matching `sub` or `sid`.**

## Where it lands on the OAuth abstraction

- **L7 OIDC.** Identity-layer concern.
- **T8 (lifecycle).** Logout is an event after the active session phase.
- Pairs with **[RFC 7009 Revocation](RFC_7009.md)** — AS revokes the
  user's tokens *and* notifies RPs. Both happen at logout.

## OAuth 2.0 / 2.1 status

Not an OAuth spec at all; it's OIDC. Adopted by every major IdP that
supports OIDC SSO. The session-management story (front-channel logout,
session iframe, etc.) is messier and less universally adopted; back-
channel is the cleanest of the three OIDC logout specs and the one new
deployments standardize on.

## OneAuth status

| BCL surface | Status | Where (grep-verified) | Notes |
|---|---|---|---|
| `BCLDispatcher` — fans out logout to all subscribed RPs | **Implemented** | `apiauth/bcl_dispatcher.go:46` (struct) + `Dispatch` method at line 126 | Per-RP failure doesn't block other RPs |
| `LogoutTokenIssuer` — mints the signed `logout_token` JWT | **Implemented** | `apiauth/logout_token.go` | All required claims plus `events`; `nonce` deliberately omitted per §2.4 ¶6 (line 115) |
| `backchannel_logout_uri` DCR field | **Implemented** | `admin/dcr.go:112` echoed back per OIDC BCL §3.1 | RP registers via 7591 metadata |
| `backchannel_logout_session_required` DCR field | **Implemented** | `admin/dcr.go:113` | Controls whether `sid` MUST appear in the dispatched token |
| Per-RP `aud` enforcement | **Implemented** | `bcl_dispatcher.go:77` comment: "(mis-configured or malicious) `backchannel_logout_uri` cannot be" — RP receives only its own audience |
| `OnSubjectRevoked` / `OnTokenRevoked` hooks for orchestration | **Implemented** | `bcl_integration_test.go:72,126` exercises both | Composes with refresh-token family revoke (RFC 7009 + RFC 9700 §4.14) |
| AS metadata: `backchannel_logout_supported`, `backchannel_logout_session_supported` | **Implemented** | `apiauth/as_metadata.go:86,93` | Discovery advertised |
| `logout_token` JWT signature validation (RP side) | **Implemented** (in OneAuth's own client SDK) | Helps clients consuming OneAuth-issued logout_tokens | — |
| Test coverage | **Implemented** | `apiauth/bcl_dispatcher_test.go`, `bcl_integration_test.go`, `bcl_integration_test.go:122–145` end-to-end with `OnTokenRevoked` | — |

OneAuth's BCL implementation is one of the cleanest L7 surfaces in the
codebase. The dispatcher / issuer split, the explicit `sid` semantics, and
the hook-based revoke orchestration are reference-quality.

## Related specs

- [OIDC Core](OIDC_Core.md) — defines the session that's being terminated
- [OIDC Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html) — sibling; browser-driven (more fragile)
- [OIDC Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html) — sibling; iframe-based session-state polling
- [RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) — RP-side trigger that may chain into BCL
- [RFC 7009](RFC_7009.md) — Token Revocation; BCL often triggers revocation as a side effect
- [RFC 9700](RFC_9700.md) — §4.14 refresh rotation; the family revoke that BCL events also trigger
- Repo issue 156 covers the broader OIDC logout suite (front-channel, session management) for OneAuth

## Spec links

- [OIDC Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [OIDC Specifications](https://openid.net/specs/)
