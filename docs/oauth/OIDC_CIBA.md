# OpenID Connect Client-Initiated Backchannel Authentication (CIBA) 1.0

> **Status:** OpenID Foundation Specification
> **Published:** 2021 (final)
> **L-tier / T-tier:** L4 (grant) + L7 (identity) · T5
> **OneAuth coverage:** Gap
> **See also:** [`RFC_8628.md`](RFC_8628.md) · [`OIDC_Core.md`](OIDC_Core.md) · [`LANDSCAPE.md`](LANDSCAPE.md)

## In one sentence

CIBA lets a client *initiate authentication for a specific user* via a
back-channel call to the AS — the AS then pushes a confirmation prompt to
that user's device (push notification, in-app prompt) and the client polls
or gets notified when the user approves.

## What problem does it solve?

| Without CIBA | With CIBA |
|---|---|
| Pre-authenticated workflows ("Call center confirms a transfer with the customer") need ad-hoc out-of-band protocols | Standardized — CIBA is exactly this use case |
| Device flow (RFC 8628) requires the user to *read* a short code somewhere — doesn't fit voice assistants, IVRs, or push-only UX | CIBA pushes a prompt to the user's authenticator device directly |
| AI agents / orchestrators needing real-time user consent have no clean OIDC path | CIBA is the cleanest fit (Auth0's "Auth for AI Agents" track names this explicitly) |
| Bank fraud teams confirming high-value transfers need to verify "user actually approved" via the same trust chain as login | CIBA reuses the OIDC trust + audit chain |

CIBA is the *decoupled-authentication* path. Where OIDC Core assumes the
user has a browser at the client and the client redirects them, CIBA
assumes the user has an *authenticator device* (phone, security key) that
the AS can prompt independently.

## Relatable example

You're talking to a call-center agent who's helping you with your bank.
The agent wants to make a high-value change. Instead of asking you to log
in to a web portal:

1. Agent (client) calls the bank's CIBA endpoint with
   `login_hint="customer@example.com"` and a description of the change
   they're about to make.
2. The bank's AS receives the request, pushes a confirmation prompt to
   your phone: "Bank: Approve account-balance disclosure to call-center
   agent? [Approve] [Deny]"
3. You approve on your phone via biometric.
4. Agent's CIBA endpoint completes — the agent's client receives a token
   with `id_token` confirming "yes, customer@example.com did approve."
5. Agent proceeds, with an auditable record that the customer themselves
   approved.

This is also the pattern for "Confirm with Touch ID" UX in some banks, and
the emerging pattern for AI agent workflows where the agent needs to ask
the user for permission for a specific action without redirecting their
browser.

## Key concepts

1. **Decoupled in two dimensions**:
   - The *device* the user authenticates on (phone) is different from the
     *device* the client is on (call-center workstation, AI agent, IoT
     device, voice assistant).
   - The *channel* the client uses to talk to the AS (back-channel HTTP)
     is different from the channel the AS uses to talk to the user
     (push notification).
2. **One endpoint: `POST /bc-authorize`** (typically
   `/bc-authorize` or `/ciba`). Returns `auth_req_id` plus `expires_in`
   and `interval`. The client uses `auth_req_id` to track this specific
   authentication request.
3. **Three notification modes** (§7.1):
   - **`poll`** — client polls a CIBA-specific token endpoint until done
   - **`ping`** — AS pings the client's pre-registered URL when the user
     has approved; client then exchanges
   - **`push`** — AS pushes the tokens directly to the client (least
     common; security model is harder)
4. **`login_hint` or `id_token_hint` or `login_hint_token`** identifies
   which user the authentication is for. CIBA-aware ASes accept any of
   these per their deployment policy.
5. **`binding_message`** is the user-readable string shown on the
   authenticator device. Important for context: "Approve £500 transfer to
   ACME?" beats "Approve auth_req_id=abc123?".
6. **Polling discipline** mirrors RFC 8628 device flow: `interval`,
   `slow_down`, `authorization_pending`, `access_denied`,
   `expired_token`.

## Wire example

**Client initiates CIBA:**

```http
POST /bc-authorize HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <client-creds>

scope=openid+profile
&login_hint=customer%40example.com
&binding_message=Approve+%C2%A3500+transfer+to+ACME%3F
&acr_values=urn%3Amace%3Aincommon%3Aiap%3Asilver
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "auth_req_id":  "1c266114-a1be-4252-8ad1-04986c5b9ac1",
  "expires_in":   120,
  "interval":     5
}
```

**Push to user (mechanism is implementation-defined)** — typically a push
notification with `binding_message` shown on the user's authenticator
device. User approves with biometric or PIN.

**Client polls (poll mode):**

```http
POST /api/token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <client-creds>

grant_type=urn:openid:params:grant-type:ciba
&auth_req_id=1c266114-a1be-4252-8ad1-04986c5b9ac1
```

While pending: `{"error":"authorization_pending"}`. When approved:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "access_token":  "2YotnFZFEjr1zCsicMWpAA",
  "token_type":    "Bearer",
  "expires_in":    3600,
  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
  "id_token":      "eyJhbGciOi..."     ← carries proof user approved with binding_message
}
```

The `id_token` claims may include `urn:openid:params:jwt:claim:rt_hash`
and an `urn:openid:params:jwt:claim:auth_req_id` so the client can verify
this id_token corresponds to that specific authentication request.

## Where it lands on the OAuth abstraction

- **L4 grant + L7 identity.** CIBA is *both* a new grant type AND an
  OIDC-specific identity flow.
- **T5 (token endpoint).** No redirect, no browser at the client.
- **Sibling solution: [RFC 8628 device flow](RFC_8628.md)** — device
  flow assumes the user can read a code; CIBA assumes the user gets a
  push. Pick by the user-side UX you actually have.

## OAuth 2.0 / 2.1 status

Not an OAuth-WG spec; OpenID Foundation. Coexists with OAuth 2.0 / 2.1
unchanged. Treated as an OIDC-layer grant.

## Migration path

CIBA is largely additive — it's a new endpoint + new grant_type. Most of
the complexity is *not* in the OAuth/OIDC plumbing; it's in:

1. **The authenticator-device side** — building or integrating push-based
   authenticator support (custom app, FIDO2 token, vendor MFA solution).
2. **Identifying users from `login_hint`** — your IdP needs a way to map
   the hint to a known user + their authenticator device.
3. **The user consent UX** — the device-side prompt design is what
   determines if the spec actually works in practice.

The OAuth plumbing on top is short: add a back-channel auth endpoint,
add a new grant_type, plumb auth_req_id through the same token-mint path.

## When NOT to use it

- **The user has a browser at the client** — use OIDC Core auth-code +
  PKCE. CIBA is for "browser at the client is not available."
- **The user *only* has a browser** — device flow (RFC 8628) is the fit
  ("display this code on the laptop, go enter it on your phone").
- **No authenticator-device infrastructure** — CIBA assumes you can reach
  the user's device via push. Without that, you can't ship it.

## OneAuth status

| CIBA surface | Status | Notes |
|---|---|---|
| `POST /bc-authorize` endpoint | **Gap** | — |
| `urn:openid:params:grant-type:ciba` grant dispatch | **Gap** | Would slot alongside other grant types in the `apiauth/token_endpoint.go:69` switch |
| Poll / ping / push notification mode handling | **Gap** | Poll mode is the simplest first target |
| `login_hint` / `id_token_hint` resolution to user | **Gap** | Per-deployment user lookup integration |
| Push notification to authenticator device | **Gap** | Out-of-scope for an OAuth library — needs platform integration |
| `binding_message` propagation through to user-side prompt | **Gap** | Display-side concern |
| `auth_req_id` store with TTL | **Gap** | Analogous to `DeviceAuthorizationStore` |
| AS metadata: `backchannel_authentication_endpoint`, `backchannel_token_delivery_modes_supported`, etc. | **Gap** | Discovery advertisement |
| `id_token` issuance | **Gap** | Foundational — see [`OIDC_Core.md`](OIDC_Core.md) |

CIBA gates on two prerequisites in OneAuth: (1) OIDC Core id_token
issuance (currently a gap), and (2) authenticator-device integration
(out-of-scope for a library; depends on the deploying application's
stack).

OneAuth's Auth0-for-AI-Agents track (repo issue 125) is the natural home
for CIBA — AI agents calling APIs that need just-in-time user consent map
directly onto CIBA's design intent.

## Related specs

- [OIDC Core](OIDC_Core.md) — id_token issuance is a prerequisite
- [OIDC Discovery](OIDC_Discovery.md) — CIBA metadata advertised here
- [RFC 8628 Device Authorization](RFC_8628.md) — sibling decoupled-auth pattern
- [RFC 9396 RAR](RFC_9396.md) — `binding_message` plus RAR's structured `authorization_details` gives the user precise context on what they're approving
- Repo issue 125 — AI-agent auth track that naturally hosts CIBA work

## Spec links

- [OpenID Connect CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
- [FAPI-CIBA Profile](https://openid.net/specs/openid-financial-api-ciba-ID1.html) — FAPI's CIBA flavor
- [OIDC Specifications](https://openid.net/specs/)
