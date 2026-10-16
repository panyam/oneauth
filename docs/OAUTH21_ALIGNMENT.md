# OneAuth: OAuth 2.1 Alignment Baseline

Audit of OneAuth against the [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/), first filed under issue 140 and brought up to date for 0.2.1. It records where OneAuth stands and what is left, and the per-RFC docs under `docs/oauth/` defer to it for the 2.1 verdict.

**Headline:** OneAuth is compliant by default on all 9 rows below. Two OAuth 2.0 paths that 2.1 removes stay available as opt-ins: the password grant (ROPC) and bearer tokens in the query string. Both are off unless a deployment wires them, and `OneAuthConfig.FAPI2` refuses the password grant outright. The reference server (`cmd/oneauth-server`) still wires the password grant unless `fapi2: true` is set.

The library has a full authorization endpoint (`apiauth.MountAuthorize`, PR 297), so the PKCE, redirect and implicit rows are enforced by code rather than satisfied by the endpoint's absence.

---

## Audit table

| # | OAuth 2.1 requirement | OneAuth state | Verdict | Action |
|---|---|---|---|---|
| 1 | PKCE required for all authorization code flows | `/authorize` refuses a request without `code_challenge` and checks its shape; the token endpoint requires `code_verifier`, checks its shape and verifies it. The client SDK sends S256 and refuses an AS that doesn't advertise it. | **Compliant.** | None. |
| 2 | Implicit grant removed | `/authorize` accepts only `response_type=code`. The reference server advertises `response_types_supported: ["code"]`, and only with `code_flow` on. | **Compliant.** | None. |
| 3 | ROPC removed (no `grant_type=password`) | The token endpoint answers `unsupported_grant_type` while `OneAuthConfig.PasswordGranter` is nil, and always under `FAPI2`. | **Compliant by default.** Opt-in retained for OAuth 2.0 deployments. | The reference server wires the granter outside `fapi2`; it has no config switch for it yet. |
| 4 | Exact redirect URI matching (no wildcards, no substring) | `/authorize` compares against the client's registered URIs with `RedirectURIMatches`. A loopback `http` redirect matches on any port (RFC 8252 §7.3). With no client registry, `/authorize` refuses every request unless `AllowAnyRedirectURI` is set. | **Compliant.** | None. |
| 5 | PKCE method MUST be S256 (reject `plain`) | `/authorize` refuses `plain`, and a missing method, unless `OneAuthConfig.AllowPlainPKCE` is set. AS metadata advertises `S256` only. | **Compliant by default.** Opt-in retained (issue 345). | None. |
| 6 | HTTPS for redirect URIs (loopback exception) | DCR refuses non-loopback `http`, userinfo, fragments, relative URIs and an https URI with no host, answering `invalid_redirect_uri`. | **Compliant.** | None. |
| 7 | Bearer tokens NOT in query string | `APIMiddleware.LegacyQueryParamBearer` is empty by default. When set, the named query parameter is accepted and a log line warns at first use. | **Compliant by default.** Opt-in retained (issue 295). | None. Per capability-gating umbrella #344. |
| 8 | Refresh token rotation | Rotation with reuse detection and family revocation in every store. The grant checks the presenting client. Rotation can be turned off for FAPI 2.0. | **Compliant.** | None. |
| 9 | Authorization codes single use | A redeemed code is kept, marked used, until its access token expires. A second redemption is refused and revokes what the first one issued. | **Compliant.** | None. |

## Per-row analysis

### 1. PKCE: compliant

OAuth 2.1 requires PKCE from every client, public and confidential, on the authorization code flow.

On the server, `AuthorizationHandler.ValidateValues` (`apiauth/authorize.go`) refuses a request without `code_challenge` with `invalid_request`. Since 0.1.49 it also checks the RFC 7636 shape: an S256 challenge is exactly 43 base64url characters, and a plain challenge 43 to 128 unreserved characters. At the token endpoint, `authorizationCodeGranter.AuthorizationCodeGrant` (`apiauth/authorize_granter.go`) requires `code_verifier`, refuses one outside the 43 to 128 character shape, and compares it with `core.VerifyPKCE`.

On the client, `AuthClient.LoginWithBrowser` (`client/browser_login.go`) refuses an AS whose metadata lacks `S256` in `code_challenge_methods_supported`, and `buildAuthorizationURL` always sends `code_challenge_method=S256`.

### 2. Implicit grant: compliant

`AuthorizationHandler.ValidateValues` answers any `response_type` other than `code` with `unsupported_response_type`. Since 0.1.51 the reference server's metadata (`serverASMetadata` in `cmd/oneauth-server/metadata.go`) lists `code` and RFC 9207 `iss` only when `code_flow` is enabled, and no longer advertises the `token` response type it used to list for its resource-token shape.

### 3. ROPC: compliant by default, opt-in retained

`TokenEndpointHandler.handlePassword` (`apiauth/token_endpoint.go`) answers `unsupported_grant_type` when `OneAuthConfig.PasswordGranter` is nil or `FAPI2` is set. A deployment that still needs the grant for OAuth 2.0 clients sets `PasswordGranter` to `NewPasswordGranter(...)`, which logs a warning that this is the legacy path (issue 294). The documented alternative is `localauth/` HTTP login with a cookie session.

The reference server wires `NewPasswordGranter` in `cmd/oneauth-server/main.go`, so it serves the grant unless `fapi2: true`. Under `fapi2` the token endpoint refuses it and `baseGrantTypes` leaves `password` out of metadata.

### 4. Exact redirect URI matching: compliant

OAuth 2.1 requires exact string matching of redirect URIs at the authorization endpoint. `AuthorizationHandler.validateRedirectURI` checks the requested URI against the client's registration (or a `RedirectURIValidator`) with `apiauth.RedirectURIMatches`. Scheme, host, path and query match exactly. The one relaxation is the port of an `http` redirect on `127.0.0.1`, `[::1]` or `localhost`, which RFC 8252 §7.3 requires so native apps can bind any free port (0.1.38).

With neither an `AppStore` nor a `RedirectURIValidator`, `/authorize` refuses every request unless `AllowAnyRedirectURI` is set on `AuthorizationHandler` or `AuthorizeMountConfig` (0.1.49). Tests set it; production mounts should not.

Registration is the other half; see row 6.

### 5. PKCE S256-only: compliant by default

`AuthorizationHandler.ValidateValues` refuses a missing `code_challenge_method` and refuses `plain` unless `OneAuthConfig.AllowPlainPKCE` is set (issue 345). With the flag on, the first plain challenge logs a warning. The reference server's metadata advertises `code_challenge_methods_supported: ["S256"]`.

### 6. HTTPS redirect URIs: compliant

OAuth 2.1 requires `https` redirect URIs, with the RFC 8252 §7.3 loopback exemption for native apps.

`validateRedirectURIs` in `admin/registrar.go`, called from `Register` and `UpdateRegistration`, refuses an empty, relative or unparseable URI, a fragment, userinfo, an https URI with no host, and `http` on anything but `127.0.0.1`, `::1` or `localhost`. A reverse-DNS private-use scheme (RFC 8252 §7.1) is allowed. Since 0.1.50 every redirect problem answers `invalid_redirect_uri` (`admin.ErrInvalidRedirectURI`, which wraps `ErrInvalidClientMetadata`), and DCR refuses an `authorization_code` registration with no redirect URI.

### 7. Bearer in query string: compliant by default, opt-in retained

OAuth 2.1 retired bearer tokens in query strings (RFC 6750 §2.3 had deprecated this in 2012). The query-string carry attacks:

- Tokens land in browser history and server access logs.
- `Referer` headers leak them across origins.
- Caches and CDNs persist them.

`APIMiddleware` (`apiauth/middleware.go`) consults `LegacyQueryParamBearer` only when no `Authorization` header is present. The field is empty by default. When an operator sets it, a log line at first use says this is the legacy OAuth 2.0 path and points at `docs/DEMOS.md` for three header-clean alternatives.

The original audit planned to remove the path. The capability-gating umbrella #344 kept it as an opt-in instead, because the WebSocket upgrade case (where the initial GET can't carry an `Authorization` header) has no single replacement. Issue 295 renamed the field and documented the alternatives.

### 8. Refresh token rotation: compliant

OAuth 2.1 asks for sender-constrained refresh tokens or rotation for public clients. OneAuth rotates by default: every store implements `RotateRefreshToken` (in-memory, FS, GORM, GAE), and the refresh path in `apiauth/token_validator.go` treats `core.ErrTokenReused` as reuse and calls `RevokeTokenFamily`. `apiauth/auth_test.go` covers the reuse path.

Since then:

- **Client binding (0.1.41).** The token must belong to the `client_id` that presents it, or the grant answers `invalid_grant` before rotating. A confidential owner must authenticate, or the request gets 401 `invalid_client`.
- **Rotation can be turned off (0.1.43).** `OneAuthConfig.DisableRefreshTokenRotation` keeps one refresh token in use, as FAPI 2.0 §5.3.2.1 asks. `FAPI2` sets it. The default still rotates.
- **Atomic rotation (0.1.45).** GORM's `RotateRefreshToken` is a compare-and-set on the unrevoked row, so two concurrent refreshes can't both succeed, and rotation keeps the family's original expiry in every store.

DPoP-bound refresh tokens (RFC 9449) are carried forward on rotation and refused without their key.

### 9. Authorization codes single use: compliant

OAuth 2.1 says a code is used once, and RFC 6749 §4.1.2 adds that the AS should revoke tokens issued from a reused code. Since 0.1.57 (issue 429), `AuthorizationCodeStore.ConsumeAuthorizationCode` marks a code used instead of deleting it, and the record stays until its access token expires. `authorizationCodeGranter.refuseReuse` answers a second redemption with `invalid_grant`, revokes the refresh family, and blacklists the access token's `jti` when `OneAuthConfig.Blacklist` is set. A reuse racing the first redemption makes that one refuse too.

---

## Filed follow-ups

The original audit framed issues 294 and 295 as removals. The capability-gating umbrella **#344** rescoped them into per-deployment opt-ins: a nil handler for grants, flags for policies, and per-client DCR `grant_types`.

| Issue | Scope | Status |
|---|---|---|
| #344 (umbrella) | OAuth 2.0/2.1 capability gating: nil handler for grants, flags for policies | Open |
| issue 294 | `PasswordGranter` peer interface; ROPC off by default through a nil handler | Closed |
| issue 295 | Rename `TokenQueryParam` to `LegacyQueryParamBearer`; deprecation log; WebSocket alternatives in `docs/DEMOS.md` | Closed |
| issue 345 | `AllowPlainPKCE` flag for OAuth 2.0 plain PKCE on `/authorize` | Closed |
| #346 | Enforce per-client DCR `grant_types` at token endpoint dispatch | Open |

## What this audit does NOT cover

- **Sender-constrained tokens.** DPoP (RFC 9449) ships end to end; see [`docs/oauth/RFC_9449.md`](oauth/RFC_9449.md) and [`docs/SECURITY_AUDIT.md`](SECURITY_AUDIT.md). mTLS (RFC 8705) is #335.
- **FAPI 2.0.** `OneAuthConfig.FAPI2` applies the Security Profile on top of this baseline; [`docs/SECURITY_AUDIT.md`](SECURITY_AUDIT.md) walks it.
- **OAuth 2.1 §5.3** (Access Token Privilege Restriction): resource indicators (RFC 8707) are a separate enhancement.
- **OIDC.** ID tokens, `nonce` and userinfo are #339.

## Related work

- Issue 116 (closed as a duplicate of #339). `/authorize` shipped in PR 297; ID tokens and userinfo are #339.
- #163: Authlete-superset spec coverage meta.
- Issues 197 and 202 (closed): OIDF conformance harness wiring. A first run is mission #98.
- Issue 140: this audit's home.
