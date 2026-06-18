# OpenID Connect Core 1.0

> **Status:** OpenID Foundation Specification (not an IETF RFC)
> **Published:** 2014 (latest errata 2024)
> **L-tier / T-tier:** L7 · T3 (user auth) + T5 (id_token issue)
> **OneAuth coverage:** Partial — `/authorize` shipped in PR 297 (OAuth-layer), but id_token issuance, nonce, and `/userinfo` are gaps
> **See also:** [`OIDC_Discovery.md`](OIDC_Discovery.md) · [`OIDC_BCL.md`](OIDC_BCL.md) · [`OIDC_CIBA.md`](OIDC_CIBA.md) · [`LANDSCAPE.md`](LANDSCAPE.md)

## In one sentence

OpenID Connect Core is the identity layer on top of OAuth 2.0 — it adds the
`id_token` (a JWT carrying user identity claims), a standardized `/userinfo`
endpoint, and the protocol details for "Sign in with Google / GitHub /
Microsoft" that the world's consumer SSO depends on.

## What problem does it solve?

| Without OIDC | With OIDC |
|---|---|
| OAuth gives you an access token to *do things*, but no way to know *who the user is* | `id_token` is a JWT identity assertion; verify it, you know the user |
| Every IdP invents its own "who is this user?" endpoint with vendor-specific claim shapes | Standardized `/userinfo` returning standard claims (`sub`, `name`, `email`, `email_verified`, ...) |
| Cross-org SSO requires bespoke federation protocols (SAML, custom JWT) | OIDC works against any OAuth AS that's added the identity layer |
| Session management ("are they still logged in?") is per-vendor | OIDC adds standardized session, logout, and front-/back-channel notification |

OIDC's importance is *cultural*, not just technical: it's the spec that
made "Sign in with X" universal. Every modern consumer app that defers
auth to a third-party identity provider is using OIDC under the hood.

## Relatable example

When you click *"Sign in with Google"* on a new app:

1. The browser flows through OAuth (auth-code + PKCE) — covered by the L0
   spine.
2. The token endpoint returns `{access_token, id_token, refresh_token}` —
   the `id_token` is OIDC's contribution. Without OIDC, you'd only get the
   access token.
3. The app decodes the `id_token` and reads:
   ```json
   {
     "iss":            "https://accounts.google.com",
     "sub":            "100123456789012345678",
     "aud":            "32555350559.apps.googleusercontent.com",
     "exp":            1717003600,
     "iat":            1717000000,
     "auth_time":      1717000000,
     "nonce":          "abcd1234...",     ← matches the value the app sent
     "email":          "sri@example.com",
     "email_verified": true,
     "name":           "Sri Panyam",
     "picture":        "https://lh3.googleusercontent.com/...",
     "at_hash":        "x7vplJ-rh-OnePf-XKkLOA"
   }
   ```
4. The app now knows *who* the user is, without calling any further API.
   The access token is for *doing things* (calling Gmail, calendar, etc.);
   the id_token is for *knowing who*.

Every "Continue with X" button on the public internet ships this flow.

## Key concepts

1. **`id_token` is a JWT.** Always JWS-signed; sometimes JWE-encrypted on
   top. The header has `typ:JWT`; the payload carries identity claims.
2. **Required `id_token` claims**: `iss`, `sub`, `aud`, `exp`, `iat`. For
   public clients, `nonce` is also required.
3. **`nonce` is the id_token's replay defense.** Client generates a fresh
   random `nonce`, sends it on `/authorize`, AS echoes it in the
   `id_token`. Client verifies match.
4. **Three response_type modes** for getting the id_token:
   - `code` — auth-code flow, id_token at the *token endpoint* (the modern
     recommendation; safest)
   - `id_token` (or `id_token token`) — implicit flow, id_token in the
     redirect fragment. **OAuth 2.1 removes implicit; OIDC implicit is
     correspondingly deprecated.**
   - `code id_token` (or `code id_token token`) — hybrid flow, id_token
     in fragment + access token via code. Niche; mostly historical.
5. **The `openid` scope is required.** That's the magic that tells the AS
   "issue an id_token, not just an access token." Without `scope=openid`,
   you're doing pure OAuth, not OIDC.
6. **`/userinfo` endpoint** returns identity claims for callers holding an
   access token. The same claims that go in the id_token *can* be served
   here instead — useful when you want fresh data later in a session.
7. **Standard scopes for identity claims**: `openid` (required), `profile`,
   `email`, `address`, `phone`. Each scope unlocks a defined claim subset
   on `/userinfo` and (optionally) in the id_token.
8. **`acr` and `amr` claims** report *how* the user was authenticated
   (acr = Authentication Context Class Reference; amr = Authentication
   Methods References, e.g. `["pwd", "mfa"]`). Required for step-up auth.

## Wire example

**Authorization request** (note the `scope=openid` and `nonce`):

```http
GET /authorize?response_type=code
              &client_id=oidc-rp-1
              &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb
              &scope=openid+profile+email
              &state=xyz
              &nonce=abcd1234
              &code_challenge=E9Mel...
              &code_challenge_method=S256 HTTP/1.1
Host: as.example.com
```

**Token response includes `id_token`:**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "access_token":  "2YotnFZFEjr1zCsicMWpAA",
  "token_type":    "Bearer",
  "expires_in":    3600,
  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
  "scope":         "openid profile email",
  "id_token":      "eyJhbGciOi..."     ← the OIDC contribution
}
```

Decoded `id_token`:
```json
{
  "iss":            "https://as.example.com",
  "sub":            "user-42",
  "aud":            "oidc-rp-1",
  "exp":            1717003600,
  "iat":            1717000000,
  "auth_time":      1717000000,
  "nonce":          "abcd1234",
  "email":          "sri@example.com",
  "email_verified": true,
  "name":           "Sri Panyam",
  "at_hash":        "x7vplJ-rh-OnePf-XKkLOA"
}
```

**Userinfo call:**

```http
GET /userinfo HTTP/1.1
Host: as.example.com
Authorization: Bearer 2YotnFZFEjr1zCsicMWpAA
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "sub":            "user-42",
  "email":          "sri@example.com",
  "email_verified": true,
  "name":           "Sri Panyam"
}
```

## Where it lands on the OAuth abstraction

- **L7 identity.** OIDC is the identity layer; everything below it
  (L0–L6) is pure delegation.
- **T3 (user auth at AS)** is where OIDC's `acr`/`amr`/`auth_time`
  semantics matter; **T5 (token endpoint)** is where the `id_token`
  ships.
- OIDC composes with all the OAuth extensions — PKCE, PAR, JAR, RAR,
  DPoP. Most modern enterprise IdP deployments are OIDC + selected
  OAuth extensions.

## OAuth 2.0 status

OIDC is a layer *on top of* OAuth 2.0. It doesn't change OAuth's spec
status. Universal in consumer SSO. Standard in enterprise SSO (Azure AD /
Entra ID, Okta, Auth0, Keycloak all ship OIDC by default).

## OAuth 2.1 status

OIDC 1.0 wasn't updated alongside OAuth 2.1 (the OIDC working group is at
OpenID Foundation, not IETF). The two specs co-exist:

- OIDC implicit flow (response_type=id_token without code) is a peer of
  OAuth 2.0's implicit grant. 2.1 removes the OAuth implicit; OIDC
  implicit is correspondingly stale (still spec-legal but rarely shipped
  in new builds).
- OIDC hybrid flows are 2.1-compatible only with the `code id_token`
  shape (no `token` in response_type), with PKCE mandatory.

For new builds: ship OIDC with `response_type=code`, PKCE, and treat
implicit/hybrid as legacy.

## Migration path (pure OAuth → OIDC)

Adding OIDC to a working OAuth AS is largely additive:

1. **Implement id_token issuance** at `/token` when `scope=openid` is
   requested. Sign with the same JWKS used for access tokens (or a
   separate identity-signing key — same JWKS publication mechanism).
2. **Wire nonce parameter handling** at `/authorize` — store in the
   authorization code record, echo in the issued id_token.
3. **Stand up `/userinfo`** — bearer-token-authed; return identity claims
   per the granted scopes (`openid`, `profile`, `email`, ...).
4. **Update discovery** with OIDC-specific fields (see [`OIDC_Discovery.md`](OIDC_Discovery.md)).
5. **Add scope-to-claims mapping** for `profile`, `email`, `address`,
   `phone`.
6. **Add `auth_time`, `acr`, `amr` emission** based on how the user was
   authenticated. The hard work isn't OIDC; it's defining your
   authentication taxonomy.

## When NOT to use it

- **Pure machine-to-machine APIs.** No user → no identity → no OIDC. Use
  `client_credentials` only.
- **Federated authorization without identity.** If you're using OAuth for
  delegation but the resource server doesn't care *who* the user is
  beyond an opaque `sub`, you can skip id_token issuance and keep the
  surface smaller.

## OneAuth status

| OIDC Core surface | Status | Where (grep-verified) | Notes |
|---|---|---|---|
| `/authorize` endpoint | **Implemented** (OAuth layer) | `apiauth/authorize.go` `AuthorizationHandler` (PR 297) | Issues `code` only; no id_token issuance yet |
| `id_token` issuance | **Gap** | Only `apiauth/token_exchange_grant.go:27` `TokenTypeIDToken` constant exists (for 8693); no actual id_token mint anywhere | The foundational OIDC piece — without it the rest is mostly moot |
| `nonce` parameter handling | **Gap** | No `nonce` references in `apiauth/authorize*.go` or `core/authorization_code.go` | Required for OIDC replay defense |
| `/userinfo` endpoint | **Gap** | `apiauth/as_metadata.go:33` `UserinfoEndpoint` field is wired (advertises a URL) but no handler implements it | Discovery-advertised; needs implementation |
| `openid`/`profile`/`email`/etc. scope-to-claims mapping | **Gap** | No scope-aware claim selector | Needed for both id_token and userinfo |
| `auth_time`, `acr`, `amr` claims | **Gap** | — | Needed for OIDC step-up auth |
| `at_hash` claim (id_token integrity binding to access_token) | **Gap** | — | Required when issuing id_token + access_token together |
| OIDC Discovery (`/.well-known/openid-configuration`) | **Implemented** | `apiauth.MountASMetadata` co-serves both paths | See [`OIDC_Discovery.md`](OIDC_Discovery.md) |

**Implementation sketch.** OIDC Core is the single largest *implementable*
gap in OneAuth. The foundation (`/authorize`, JWKS, AS metadata, DCR) is
all in place; what's missing is the identity-layer plumbing:

1. **`IDTokenIssuer` interface** alongside `TokenIssuer`. Signs id_tokens
   with the same JWKS-published keys; emits required claims (`iss`,
   `sub`, `aud`, `exp`, `iat`, `nonce`, `at_hash`).
2. **Scope-driven claim selector** that maps `openid profile email` → set
   of claims. Configurable per-deployment via a `ClaimMapping` hook.
3. **`/userinfo` handler** that bearer-auths and returns the same claim
   set the id_token would have carried.
4. **`nonce` storage + echo** in the authorization code record.
5. **`UserSession` tracking** for `auth_time` and (eventually) for OIDC
   front-channel logout and session management.

This unblocks downstream work (CIBA, full FAPI 2.0 conformance, broader
OIDC ecosystem interop).

## Related specs

- [OIDC Discovery 1.0](OIDC_Discovery.md) — the discovery doc with OIDC-specific fields
- [OIDC BCL](OIDC_BCL.md) — back-channel logout
- [OIDC CIBA](OIDC_CIBA.md) — client-initiated backchannel auth
- [RFC 6749](RFC_6749.md) — the OAuth framework OIDC layers on
- [RFC 7519](RFC_7519.md) — JWT (the id_token format)
- [RFC 7515](RFC_7515.md) — JWS (signs the id_token)
- [RFC 7636](RFC_7636.md) — PKCE; mandatory companion in modern OIDC
- [RFC 9068](RFC_9068.md) — JWT AT profile (sibling of OIDC's id_token shape)

## Spec links

- [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OIDC Specifications](https://openid.net/specs/)
- [OpenID Foundation](https://openid.net/) — the standards body
- [Errata](https://openid.net/specs/openid-connect-core-1_0-errata-2.html) (most recent)
