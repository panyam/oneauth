# OpenID Connect Discovery 1.0

> **Status:** OpenID Foundation Specification
> **Published:** 2014 (latest errata 2024)
> **L-tier / T-tier:** L7 · T0 (setup)
> **OneAuth coverage:** Implemented (`apiauth.MountASMetadata` co-serves both well-known paths)
> **See also:** [`OIDC_Core.md`](OIDC_Core.md) · [`RFC_8414.md`](RFC_8414.md) · [`LANDSCAPE.md`](LANDSCAPE.md)

## In one sentence

OIDC Discovery is the identity-layer equivalent of [RFC 8414](RFC_8414.md) —
a discovery document at `/.well-known/openid-configuration` that adds
OIDC-specific metadata fields (id_token signing algs, supported claims,
acr values) on top of OAuth AS metadata.

## What problem does it solve?

OIDC Discovery solves the same problem as RFC 8414 (one URL → all
endpoints) but for OIDC-specific surface that 8414 doesn't cover. The
two specs converged: OIDC Discovery shipped first (2014), 8414 came later
(2018) and generalized the pattern for non-OIDC OAuth. Today most ASes
serve both URLs with effectively-identical content — the OIDC fields are
just additional, ignored by pure-OAuth clients.

| Without OIDC Discovery | With OIDC Discovery |
|---|---|
| OIDC RP libraries hardcode IdP endpoints and supported algs | One URL → full configuration |
| Per-IdP setup checklists for ACR values, claim shapes, signing algs | Standardized in the discovery doc |
| Adding a new claim requires every RP to know about it out-of-band | `claims_supported` field declares it |

## Relatable example

Every "Sign in with X" SDK starts with one URL:

```python
oidc = OIDCClient(issuer="https://accounts.google.com")
# SDK fetches: https://accounts.google.com/.well-known/openid-configuration
# Now it knows:
#   - authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri
#   - which scopes Google supports (openid, profile, email, ...)
#   - which signing algs are used for id_tokens (RS256)
#   - which claims will appear in id_tokens / userinfo
#   - which response_types are allowed (code only — Google killed implicit)
```

This is OIDC Discovery doing its job. The single string is the entire
configuration; the SDK auto-wires everything else.

## Key concepts

1. **Two well-known paths, one document**:
   `/.well-known/openid-configuration` (OIDC Discovery) and
   `/.well-known/oauth-authorization-server` (RFC 8414). Most ASes
   serve the same JSON at both URLs — OIDC clients hit the first, OAuth-
   only clients hit the second, content is union of both specs' fields.
2. **OIDC-specific additions** beyond 8414:
   - `userinfo_endpoint` — where `/userinfo` lives
   - `id_token_signing_alg_values_supported` — which algs for id_tokens
     (separate from access tokens; FAPI requires PS256 / ES256)
   - `id_token_encryption_alg_values_supported`,
     `id_token_encryption_enc_values_supported` — for encrypted
     id_tokens (rare)
   - `userinfo_signing_alg_values_supported` — `/userinfo` can return
     a signed JWT instead of plain JSON
   - `subject_types_supported` — `public` vs `pairwise` (pseudonymous
     subject identifiers per RP)
   - `claims_supported` — which user claims this IdP can emit
   - `acr_values_supported` — Authentication Context Class References
   - `display_values_supported` (`page`, `popup`, `touch`, `wap`)
   - `claims_parameter_supported`, `request_parameter_supported`,
     `request_uri_parameter_supported` — fine-grained capability flags
3. **`issuer` is normative.** The `issuer` field in the discovery doc
   MUST match the URL used to fetch the doc (modulo trailing slash) —
   same rule as 8414. This is half of the mix-up defense story (the
   other half being RFC 9207's redirect-time `iss`).
4. **Webfinger** (RFC 7033) is the optional predecessor for *discovering
   the discovery URL itself* from a user identifier. Rarely used in
   practice — most flows assume the client already knows the IdP URL.

## Wire example

```http
GET /.well-known/openid-configuration HTTP/1.1
Host: as.example.com
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=3600

{
  "issuer": "https://as.example.com",
  "authorization_endpoint": "https://as.example.com/authorize",
  "token_endpoint":         "https://as.example.com/api/token",
  "userinfo_endpoint":      "https://as.example.com/userinfo",
  "jwks_uri":               "https://as.example.com/.well-known/jwks.json",
  "registration_endpoint":  "https://as.example.com/apps/dcr",

  "scopes_supported":          ["openid", "profile", "email", "phone", "address"],
  "response_types_supported":  ["code"],
  "grant_types_supported":     ["authorization_code", "refresh_token",
                                "client_credentials",
                                "urn:ietf:params:oauth:grant-type:device_code",
                                "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                "urn:ietf:params:oauth:grant-type:token-exchange"],
  "code_challenge_methods_supported": ["S256"],
  "subject_types_supported":   ["public"],

  "id_token_signing_alg_values_supported": ["RS256", "ES256"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time",
                       "nonce", "acr", "amr", "azp",
                       "email", "email_verified", "name", "picture"],

  "token_endpoint_auth_methods_supported": [
    "client_secret_basic", "client_secret_post",
    "client_secret_jwt", "private_key_jwt"
  ],
  "token_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256", "HS256"],

  "authorization_response_iss_parameter_supported": true,
  "backchannel_logout_supported": true,
  "backchannel_logout_session_supported": true
}
```

## Where it lands on the OAuth abstraction

- **L7 identity discovery.** Sibling to RFC 8414 — same shape, identity
  fields added on top.
- **T0 (setup).** Discovery is fetched once on client startup or on
  cache miss.
- **Same handler usually serves both URLs.** OneAuth does this via
  `MountASMetadata` — one source of truth, two well-known paths.

## OAuth 2.0 status

OIDC Discovery published 2014. Universal in OIDC-supporting IdPs. Strictly
additive over OAuth — non-OIDC clients ignore the extra fields.

## OAuth 2.1 status

Not directly changed by 2.1. OIDC Discovery and OAuth 2.1 coexist —
2.1's tightening shows up as restricted advertisements (e.g.,
`code_challenge_methods_supported=["S256"]` only) rather than spec
changes to Discovery.

## OneAuth status

| Discovery surface | Status | Where (grep-verified) | Notes |
|---|---|---|---|
| `/.well-known/openid-configuration` endpoint | **Implemented** | `apiauth/as_metadata.go:153` `MountASMetadata` registers it | Same handler serves both paths |
| `/.well-known/oauth-authorization-server` co-serving | **Implemented** | Same | One JSON, two URLs |
| `issuer` field | **Implemented** | `ASServerMetadata.Issuer` (`apiauth/as_metadata.go:22`) | — |
| `authorization_endpoint` | **Implemented** | `as_metadata.go:29` | — |
| `userinfo_endpoint` | **Implemented (advertised)** | `as_metadata.go:33` | Field present; underlying handler is a gap (see [`OIDC_Core.md`](OIDC_Core.md)) |
| `id_token_signing_alg_values_supported` | **Field present**, partial wiring | `as_metadata.go` carries the field | — |
| `subject_types_supported` | **Implemented** | `as_metadata.go:64` | Typically `["public"]` |
| `claims_supported` | **Implemented** | `as_metadata.go:48` | Per-deployment config |
| `authorization_response_iss_parameter_supported` (RFC 9207) | **Implemented** | `as_metadata.go:78` | — |
| `backchannel_logout_supported` | **Implemented** | `as_metadata.go:86` | — |
| `request_parameter_supported`, `request_uri_parameter_supported` | **Gap** | — | Tracked under [`RFC_9101.md`](RFC_9101.md) JAR |
| `pushed_authorization_request_endpoint` | **Gap** | — | Tracked under [`RFC_9126.md`](RFC_9126.md) PAR |
| `dpop_signing_alg_values_supported` | **Gap** | — | Tracked under [`RFC_9449.md`](RFC_9449.md) DPoP |

## Related specs

- [OIDC Core](OIDC_Core.md) — the identity layer Discovery describes
- [RFC 8414](RFC_8414.md) — OAuth AS metadata; same content, different URL
- [RFC 7517](RFC_7517.md) — JWKS; `jwks_uri` points here
- [RFC 7033](https://datatracker.ietf.org/doc/rfc7033/) — Webfinger; the predecessor for "find the discovery URL"

## Spec links

- [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OIDC Specifications](https://openid.net/specs/)
