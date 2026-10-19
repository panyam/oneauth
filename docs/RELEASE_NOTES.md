# OneAuth Release Notes

> Versions 0.1.7 through 0.1.36 shipped tag-only; this file picks up again at
> 0.1.37. Use `git log v0.1.<n-1>..v0.1.<n>` for anything in that range.

## Version 0.2.5

The OIDF FAPI 2.0 Security Profile plan now runs clean against the
reference server: 41 of 46 modules pass, the four that expect an error page
end in REVIEW with the right refusal, and the RS256 module is skipped since
FAPI clients use ES256 (issue 330). `make testoidf` enforces it (mission 98).

### PAR and client assertions (issue 439, PR 446)

- **PAR answered `unauthorized_client` for an unregistered `redirect_uri`.** It is now
  `invalid_request` (RFC 9126 §2.3), as the OIDF plan expects.
- **Client assertions tolerate 10 seconds of clock skew** on `iat`, `nbf`
  and `exp` (`ClientAssertionClockSkew`, FAPI 2.0 §5.3.2.1), and `iat` is
  checked against the clock.

### Refresh binding and PKCE errors (issue 443, PR 448)

- **A confidential client's refresh token is no longer bound to its DPoP
  key.** RFC 9449 §5 binds only a public client's refresh token, since a
  confidential client authenticates every refresh. Before, a confidential
  client that rotated its DPoP key couldn't refresh. Access tokens stay
  bound, and public clients are unchanged.
- **A missing `code_verifier` is `invalid_grant`** (RFC 7636 §4.6), not
  `invalid_request`.
- `/authorize`'s default error page carries `id="authorize-error"`.

### The FAPI 2.0 plan in the ratchet (issue 447, PR 449)

- Every module is judged against `tests/conformance/known-gaps.yaml`, which
  gains whole-module `expected-review` (with `evidence` the captured page
  must contain) and `expected-skip` statuses for external suites.
- `make testoidf` runs the plan next to the discovery test, and it no longer
  hangs waiting on the discovery server over plain http.
- `make exercise-fapi2 MODULE=<substring>` runs matching modules only.

### FAPI signing on the reference server (issue 441, PR 450)

- **`jwt.ephemeral_signing_key` follows `signing_alg`**: P-256 for ES256,
  where it used to make an RSA key that ES256 refused at startup.
- **`fapi2: true` refuses any `jwt.signing_alg` but ES256**, the default
  HS256 included (FAPI 2.0 §5.4.1).
- `deploy-examples/fapi-dpop.yaml` signs ES256 from `JWT_PRIVATE_KEY_PATH`
  or a startup key, so its JWKS is no longer empty.

### Upgrading

- `cmd/oneauth-server` with `fapi2: true` needs `jwt.signing_alg: ES256`
  plus `jwt.private_key_path` or `jwt.ephemeral_signing_key: true`, or it
  refuses to start.
- Code that matched `invalid_request` for a missing `code_verifier` should
  match `invalid_grant`.
- Refresh tokens already issued to confidential clients stay bound until
  they expire; new ones are unbound.

## Version 0.2.4

### Reference server TLS follows BCP 195 (issue 440, PR 445)

- **TLS 1.2 accepted suites outside BCP 195.** With `tls.enabled`, the
  server used Go's default `tls.Config`, which on TLS 1.2 still accepts the
  ECDHE CBC and ChaCha20 suites. It now requires TLS 1.2 or later and, on
  1.2, only RFC 9325 §4.2's ECDHE + AES-GCM suites (FAPI 2.0 §5.2.1). TLS
  1.3 is unchanged.
- The FAPI 2.0 exercise registers its second client with the query suffix
  the plan adds to that client's redirect URI. It now passes 35 of 46
  modules, `happy-flow` among them.

### Upgrading

- Only `cmd/oneauth-server` with `tls.enabled`: a TLS 1.2 client offering
  only CBC suites can no longer connect. The library is unchanged.

## Version 0.2.3

### Reference server: the browser code flow works end to end (issue 438, PR 444)

- **Login dropped `next`.** `/authorize` sends an unauthenticated user to
  `/auth/login?next=…`, and `cmd/oneauth-server` always redirected a
  browser login to `/dashboard`, so the code flow never reached consent.
  The form now carries `next` and follows it when it's a path on this site
  (`httpauth.LocalRedirect`); anything else still goes to `/dashboard`.
- **Code and device-code redemption answered `unsupported_grant_type`.** The
  server attached its code store, device store and AppStore to `OneAuth`
  after `NewOneAuth` had built the granters, so they were never read. They
  are now in `OneAuthConfig`.
- **`/api/*` refused the server's own RS256 / ES256 tokens.** The middleware
  knew only the HS256 secret; it now uses `oa.Validator`.
- `main()` is split into `buildServer(cfg)` so tests drive the real server
  in-process. The OIDF FAPI 2.0 exercise (`make exercise-fapi2`) goes from
  10 of 46 modules passing to 33.

### Upgrading

- Library code is unchanged. Only `cmd/oneauth-server` deployments with
  `code_flow` or `device_flow` enabled see different behavior: codes now
  redeem, and the client authenticator checks each client's registered
  `token_endpoint_auth_method`.
- The OIDF harness keeps MongoDB in a named volume; an old
  `tests/oidf-conformance/mongo/` directory can be deleted.

## Version 0.2.2

### Introspection `cnf`; FAPI2 assertion grants (issue 434, PR 437)

- **Security: HTTP introspection omitted `cnf`.** `IntrospectionHandler`
  never copied the token's confirmation into its JSON, so a resource server
  validating through `POST /oauth/introspect` accepted a DPoP-bound token
  presented as Bearer (RFC 9449 §6.2, §7.2). Bound tokens now carry `cnf`;
  unbound ones carry none. Every version since 0.1.37 is affected.
- **Security: `FAPI2` let assertion grants skip client authentication.** A
  jwt-bearer or token-exchange request with no `client_id` returned from the
  confidential-client gate before its FAPI checks and got a token. Under
  `FAPI2` such a request now authenticates the client its credentials name
  (private_key_jwt's `iss`), which must be registered as confidential.
- **Docs.** Every guide under `docs/oauth/`, plus `CONFORMANCE.md` and
  `OAUTH21_ALIGNMENT.md`, is checked against the code and cites symbols
  rather than line numbers (PR 435).

### Upgrading

- Resource servers that introspect now enforce DPoP binding: a bound token
  sent as Bearer gets 401.
- `FAPI2` deployments: jwt-bearer and token-exchange requests without client
  authentication get 401 `invalid_client`.
- Revoking a refresh token still leaves its access tokens valid until they
  expire (#436).

## Version 0.2.1

### `DPoPKey.ProofWithNonce` (PR 432)

- **Callers with their own transport can answer a nonce challenge.**
  `AuthClient` retries `use_dpop_nonce` itself, but a caller that sets
  `Authorization` per request (mcpkit's MCP transports) had only `Proof()`,
  which takes no nonce. `ProofWithNonce(method, url, token, nonce)` mints the
  retry's proof with the server's `DPoP-Nonce` (RFC 9449 §8 / §9). An empty
  nonce is the same as `Proof`. Additive; nothing else changes.

## Version 0.2.0

The code is 0.1.57's. The minor version marks the breaking changes that
shipped across 0.1.38 to 0.1.57: exported API changes (`AuthorizationCodeStore`,
`NewAuthorizationCodeGranter`, `oauth2` cookie arguments, the PAR and
verification-token store responses) and defaults that now fail closed. Each
version's "Upgrading" section below lists them, and the GitHub release for
v0.2.0 collects them in one place. It is the first GitHub release since
0.1.37.

## Version 0.1.57

### Reused authorization codes revoke their tokens (issue 429, PR 431)

- **RFC 6749 §4.1.2.** A redeemed code is marked used rather than deleted
  and kept until its access token expires. Presenting it again blacklists
  that token's `jti` (with `OneAuthConfig.Blacklist`) and revokes the
  refresh family; a reuse racing the first redemption makes that one
  refuse too.
- `AuthorizationCodeStore` gains `ConsumeAuthorizationCode`
  (`ErrAuthorizationCodeUsed`) and `RecordAuthorizationCodeTokens`;
  in-memory and GORM implement both. `CreateAccessTokenResponse` carries
  `TokenID` and `ExpiresAt`.
- **GAE store tests run in CI** (`gae` job, `make testds`, which now waits
  for the emulator rather than sleeping).

### Upgrading

- Custom `AuthorizationCodeStore` implementations need the two new methods.
- `NewAuthorizationCodeGranter` takes a `core.TokenBlacklist`.
- GORM adds five columns to `authorization_codes` through AutoMigrate, and
  used rows stay until their token expires.

## Version 0.1.56

### Security audit closed (issue 88, PR 430)

- Docs only; code is identical to 0.1.55.
- `docs/SECURITY_AUDIT.md` opens with a summary: FAPI 2.0 Security Profile
  readiness and its caveats, every finding by severity with the PR that
  fixed it, the remaining gaps sized and linked to issues, and which test
  layers run where.

## Version 0.1.55

### HTTP-surface follow-ups (issue 408, PR 428)

- **Signup doesn't reveal existing accounts** when `RequireEmailVerification`
  is on: a taken email gets the same "check your email" answer as a fresh
  one (no `user_id` in either), and the owner is told through the optional
  `AccountExistsEmailSender`.
- **DCR initial access tokens (RFC 7591 §3).** `admin.InitialAccessTokenAuth`
  as `AppRegistrar.RegistrationAuth` admits `POST /apps/dcr` without the
  admin key and opens nothing else; reference server:
  `admin_auth.dcr_initial_access_tokens` (32 bytes minimum).
- **CSRF.** `CSRFMiddleware` refuses same-site and cross-site posts
  (`Sec-Fetch-Site`, `Origin`, `TrustedOrigins`), and with `SessionID`
  signs tokens over the session. The reference server binds them to the
  login session with an HMAC-derived key and marks the cookie Secure
  behind an https `public_url`.

### Upgrading

- The verification-required signup response no longer carries `user_id`.
- Form posts from another origin need `TrustedOrigins`.
- Library users setting `CSRFMiddleware.SessionID` across instances need a
  shared `Secret`.

## Version 0.1.54

### Reference server runs FAPI 2.0 (issue 88, PR 427)

- **PAR on the reference server.** `code_flow.par.enabled` mounts
  `POST /par` on the code store's backend; `required` refuses direct
  `/authorize`; metadata advertises `pushed_authorization_request_endpoint`
  and `require_pushed_authorization_requests`.
- **`fapi2: true`** sets `OneAuthConfig.FAPI2`. The server refuses to start
  without `dpop.enabled`, or with `code_flow` but no PAR; metadata lists
  `private_key_jwt` / ES256 only and no password grant.
  `deploy-examples/fapi-dpop.yaml` runs the whole profile.
- **FAPI assertion algorithms.** `AuthenticateClientRequest.AllowedAssertionAlgs`;
  under `FAPI2` only PS256 / ES256 / EdDSA client assertions pass (ES256 is
  the one oneauth can register today).
- **Keycloak parity.** A revocation interop test pins the cross-client and
  missing-token answers.

### Upgrading

- `FAPI2` with RS256 `private_key_jwt` clients: switch them to ES256 keys.
- `fapi-dpop.yaml` now runs the full profile (private_key_jwt only, no
  password grant, PAR for `/authorize`).

## Version 0.1.53

Docs only; the code is v0.1.52's. This tag was cut early by mistake, before
PR 427 (the reference server's PAR endpoint and `fapi2` switch) had merged;
that work ships in 0.1.54.

## Version 0.1.52

### FAPI 2.0 profile; client-assertion audiences (issue 88, PR 426)

- **Security: a caller could choose the audience its client assertion was
  checked against.** The expected `aud` came from `X-Forwarded-Host` /
  `X-Forwarded-Proto`, so an assertion minted for another authorization
  server (same client key) was accepted. Audiences now come from `r.TLS`
  and `r.Host` only, and the token endpoint also accepts the issuer by
  default (RFC 7523 §3). The reference server sets `AcceptedAudiences` from
  `jwt.issuer` and `public_url`.
- **`OneAuthConfig.FAPI2`** turns on the FAPI 2.0 Security Profile §5.3.2:
  DPoP required, rotation off, `private_key_jwt` only with the issuer as a
  string `aud`, no password grant, no public or unregistered clients, and a
  PAR-only `MountAuthorize` with capped code / `request_uri` lifetimes.

### Upgrading

- Behind a TLS proxy, set `AcceptedAudiences` if clients put the https
  token-endpoint URL in `aud`; forwarded headers no longer supply it.

## Version 0.1.51

### FS key collisions, server metadata, multi-AS resource metadata (issue 88, PR 425)

- **Security: FS identity and channel stores could serve one account's
  records for another key.** File names are lossy (`filepath.Base` for
  identities, `safeName` for channels), so `x/email:victim@example.com`
  read and, on save, overwrote the victim's identity, and
  `email:a:b@example.com` read `email:a_b@example.com`'s password hash.
  Both stores now check that a file's record belongs to the requested key,
  on read and write, and return `fs.ErrKeyCollision` otherwise. Every
  earlier version using the FS stores is affected; file names don't change.
- **Reference server metadata** advertises `code`, RFC 9207 `iss` and the
  `none` auth method only with `code_flow`, drops the implicit `token`
  response type, mounts the advertised `POST /oauth/revoke`, and emits
  `iss` on authorize redirects.
- **`MountProtectedResource`** mounts each pattern once, so several
  authorization servers no longer panic.

### Upgrading

- FS deployments: an email that collides with an existing identity's file
  is refused with `ErrKeyCollision`.
- Reference-server clients see `iss` on authorization responses.

## Version 0.1.50

### DCR validation and per-client PAR (issue 88, PR 424)

- **Redirect URIs** with userinfo or no https host are refused, and every
  redirect problem answers `invalid_redirect_uri` (`ErrInvalidRedirectURI`,
  which wraps `ErrInvalidClientMetadata`).
- **Auth methods and grant types** are checked against what the token
  endpoint supports and against each other, on register and update.
- **Default auth method** is `client_secret_basic` (RFC 7591 §2), stored
  and echoed alike; a `none` client gets no secret.
- **DCR server errors** are logged, not returned.
- **`require_pushed_authorization_requests`** (RFC 9126 §6) through DCR,
  `core.AppRegistration`, the FS / GORM / GAE app stores and the client
  SDK; `/authorize` enforces it.

### Upgrading

- Registrations with bad redirect URIs, unknown methods or grants, or
  `authorization_code` without a redirect URI are refused.
- The echoed default method is `client_secret_basic`.
- GORM adds a `require_pushed_authorization_requests` column on migrate.

## Version 0.1.49

### Authorize, PAR, PKCE and the device flow (issue 88, PR 423)

- **PAR works through the consent screen.** The consent form round-trips
  `request_uri`, so Approve resolves the pushed payload; before, it re-read
  the hidden inputs as a fresh request, never spent the reference, and
  failed outright with `RequirePushedRequests`.
- **One code per pushed request.** `IssueCode` spends the reference before
  minting; `ConsumePushedAuthorizationRequestResponse.Consumed` is true for
  exactly one caller.
- **`request_uri` requires `client_id`** (RFC 9126 §4).
- **PKCE shape** (RFC 7636): an S256 challenge is 43 base64url characters;
  a plain challenge and every verifier 43 to 128 unreserved characters.
- **Registered scope** applies at `/authorize` (`invalid_scope` on the
  redirect) and device authorization (400).
- **`/authorize` without a client registry refuses** unless
  `AllowAnyRedirectURI` (on `AuthorizationHandler` or
  `AuthorizeMountConfig`).

### Upgrading

- Custom consent templates must post `request_uri` back.
- Mounts with neither `AppStore` nor `RedirectURIValidator` need one, or
  `AllowAnyRedirectURI` in tests.
- Custom `PushedAuthorizationRequestStore`s must set `Consumed`.
- Malformed PKCE values are refused.

## Version 0.1.48

### Input validation at the token endpoint (issue 88, PR 422)

- **Registered scope and RAR types are enforced.** With an `AppStore`,
  `client_credentials` and the password grant answer 400 `invalid_scope`
  for a scope outside `AppRegistration.Scope` (and grant the registered
  scope when none is asked for), and 400 `invalid_authorization_details`
  for an unregistered type. A registration without either places no limit;
  a store error fails closed.
- **`client_credentials` tokens carry `client_id`.**
- **RFC 6749 §5.2 errors.** Wrong credentials are 400 `invalid_grant`;
  malformed `authorization_details` on the password grant is 400, not 500;
  an `invalid_client` 401 carries `WWW-Authenticate: Basic`; a
  `server_error` logs its detail and sends "internal server error".
- **Bodies are bounded at 64 KiB** on the token endpoint (413) and, via
  `httpauth.CapRequestBody`, on every other handler that reads one.

### Upgrading

- Clients registered with a `scope` that ask for something else get 400.
- A wrong password on the password grant is 400, not 401.
- Request bodies over 64 KiB are refused.

## Version 0.1.47

### Key management, part two (issue 88, PR 420)

- **Rotation grace periods work.** `OneAuthConfig.KidStore` sits behind
  `KeyStore` in the validator's lookup, so a token signed with a rotated
  key verifies until its grace period ends. The reference server builds a
  kid store on the key store's backend (FS under `<path>/kids`), gives it to
  `AppRegistrar` and `OneAuth`, and sweeps expired keys every 10 minutes.
  Before, it had none, and `grace_period` was accepted and ignored.
- **Retired keys are encrypted.** `EncryptedKidStorage` applies
  `EncryptedKeyStorage`'s format and rules to `KidStorage`; the reference
  server wraps its kid store under the same master key.
- **RSA keys under 2048 bits are refused at load** (`utils.CheckRSAKeySize`
  in the PEM and JWK parsers), remote JWKS included.
- **JWKS 304s** keep `ETag` and `Cache-Control`, and `If-None-Match` takes
  lists, `*` and weak tags.
- **`make audit`** runs gitleaks, govulncheck and gosec at pinned versions
  via `go run`; CI pins govulncheck too.
- **Deploy examples** `memory.yaml` and `fapi-dpop.yaml` let `jwt.issuer`
  follow `public_url`.

### Upgrading

- **Short RSA keys** (under 2048 bits) fail when loaded, including keys a
  remote JWKS publishes.
- **Reference server with `fs` keys** writes retired keys under
  `<path>/kids`.
- **`memory.yaml` / `fapi-dpop.yaml`** issue tokens with the public URL as
  `iss` unless `JWT_ISSUER` is set.
- Retired asymmetric keys aren't yet published in JWKS during their grace
  period (#421).

## Version 0.1.46

### Keys, ID tokens and CodeQL (issue 88, PRs 417 to 419)

- **Encrypted key storage fails closed.** `EncryptedKeyStorage` returns
  `keys.ErrKeyDecrypt` for a record it can't open, where it used to return
  the stored bytes as the key. Records are written as `oaenc1:` + nonce +
  AES-256-GCM with AAD over client, alg and kid, so a ciphertext copied into
  another record won't open. Plaintext secrets need `AllowLegacyPlaintext`,
  and `MigrateLegacy` rewrites old records. The reference server runs it
  once with `key_store.migrate_legacy` (`KEYSTORE_MIGRATE_LEGACY=true`).
- **OIDC ID tokens aren't access tokens.** Keycloak signs ID tokens with
  the same key, header and `aud` as access tokens; a `typ` claim other than
  `Bearer` / `DPoP` is now refused.
- **Cookies.** Every cookie in `oauth2`, `federatedauth` and the demo app,
  deletes included, is Secure + HttpOnly + SameSite=Lax, and `httpauth`'s
  `loggedInSubject` is HttpOnly. `LocalRedirect` rebuilds its target from
  the parsed path, query and fragment.
- **Workflows** run with a read-only `GITHUB_TOKEN`.

### Upgrading

- **Encrypted key stores holding plaintext secrets:** start once with
  `key_store.migrate_legacy: true`, or set `AllowLegacyPlaintext` and call
  `MigrateLegacy`. Until then those clients fail with `ErrKeyDecrypt`.
  Records written now can't be read by older versions.
- **`oauth2`:** drop `BaseOAuth2.SecureCookies` and the `secure` argument to
  `OauthRedirectorWithPKCE` / `SetPKCECookie`. Social login over plain http
  works only on localhost.
- **Pages reading `loggedInSubject` from script** no longer can.
- **Non-oneauth issuers** whose access tokens carry a `typ` claim other than
  `Bearer` / `DPoP` are refused.

## Version 0.1.45

### Token audit (issue 88, PRs 414 to 416)

Issue 88's third slice walked token validation, revocation and
introspection. The matrix is the "Tokens and keys" section of
`docs/SECURITY_AUDIT.md`.

- **Validation.** `exp` is required. An empty HMAC key never signs or
  verifies. Logout tokens, ID-JAGs and sessions are refused as access tokens
  by `typ` header and `type` claim. A key registered to a client verifies
  only tokens carrying that `client_id`, and a token with the validator's own
  `kid` is checked with its own key (it used to be checked against the
  named client's key and fail). `CustomClaims` can't set `nbf`, `scope`,
  `azp`, `sid`, `act` or `may_act`.
- **Challenges.** `invalid_token` only when a token was presented, 403
  `insufficient_scope` with `scope` for a missing scope, and
  `resource_metadata` from `APIMiddleware.ResourceMetadataURL`.
- **Revocation.** A client revokes only its own tokens (`ErrRevokeNotOwner`,
  400 `invalid_request`, as Keycloak answers). Access tokens are verified
  before their `jti` is blacklisted, a missing `token` is 400, and every
  token type is searched whatever the hint.
- **Introspection.** `token_type` is `Bearer` / `DPoP`, and refresh tokens
  can be introspected (`NewTokenIntrospectorWithRefreshStore`, wired by
  `OneAuth`).
- **Grants.** jwt-bearer assertions need `exp` and a configured audience,
  and one with a `jti` is single-use. A code redeemed by two requests at
  once gives the loser `invalid_grant`, and tokens from a code carry
  `client_id`.
- **Refresh tokens.** GORM rotation is a compare-and-set, and rotation keeps
  the family's expiry in every store.
- **Sessions.** `httpauth` and the reference server accept only
  `type: session` JWTs as logins. The reference server refuses a
  `jwt.secret_key` under 32 bytes.
- **CodeQL.** The three error-level alerts are fixed: no token prefix in
  `httpauth`'s log, and no unverified JWT parse in the revoker or the
  server's `/api/revoke`.

### Upgrading

- **Tokens without `exp`** no longer validate. oneauth always set it.
- **Missing scope** is 403, not 401.
- **Reference server:** `jwt.secret_key` (`JWT_SECRET_KEY`) must be at least
  32 bytes, in every signing mode.
- **Tenant-minted tokens** must carry their own `client_id`.
- **Refresh sessions** end `TokenExpiryRefreshToken` (7 days) after login,
  however often they're refreshed.
- **jwt-bearer / token-exchange:** set `TrustedAssertionIssuer.Audiences` or
  the AS issuer URL, or every assertion is refused.
- **Introspection consumers** reading `token_type` see `Bearer` / `DPoP`.
- **Revocation** without `token` is 400.

## Version 0.1.44

### HTTP-surface audit (issue 88, PRs 403 to 407)

Issue 88's second slice walked transport and headers, sessions and the admin
interface after the first ZAP scan. The matrix is in `docs/SECURITY_AUDIT.md`.

- **Credentials on the wire.** `Cache-Control: no-store` on every response
  that carries a secret: DCR, admin read / list / rotate, API-key creation,
  token and device errors, the authorize redirect, the reset form. The admin
  view no longer returns clients' `registration_access_token`. DCR builds
  `registration_client_uri` from `AppRegistrar.IssuerBaseURL`, never a
  non-loopback `Host` header.
- **Sessions.** `httpauth` login cookies are Secure (opt-out
  `InsecureCookies`), SameSite=Lax and, for the JWT, HttpOnly. The session
  is renewed at login and logout, every cookie domain is served, and session
  JWTs carry `type: session` so APIs refuse them as Bearer tokens. A missing
  secret now means a random per-process one, where it used to be a fixed
  public string. Logout is POST, and logout / post-login redirects only go
  to local paths. `httpauth.DenyFraming` keeps the consent, device and
  password pages out of other sites' frames.
- **Brute force.** `core.ClientIP` believes `X-Forwarded-For` only from
  configured `TrustedProxies`. The password grant has a lockout
  (`TokenEndpointHandler.Lockout`), signup and forgot-password are limited,
  and `MountDeviceFlow` always limits user-code entry.
- **Fail-closed defaults.** A nil `AdminAuth` answers 401. Admin bodies are
  capped at 64 KiB, admin requests are rate limited before the key is
  checked, and a rotation grace period is at most 7 days.
- **Password reset.** Every store keeps verification tokens as SHA-256
  hashes, a link works once even when two requests race, a reset applies
  the signup password policy, and `AfterPasswordReset`
  (`NewRevokeSessionsOnReset`) ends the account's other sessions.
- **Reference server.** Rate limiting is on by default (`rate_limit`,
  `server.trusted_proxies`). The server won't start with an unset
  `admin_auth.type`, with `none` unless `allow_open: true`, or with a
  plain-http public URL on a non-loopback host unless `allow_insecure_http`.
  `jwt.issuer` defaults to the public URL. Pages load a prebuilt stylesheet
  (`make server-css`), and the CSP allows only `'self'`.

### Upgrading

- **`AdminAuth`:** pass `NewNoAuth()` for open admin routes; nil now refuses.
- **DCR behind a real host:** set `AppRegistrar.IssuerBaseURL`, or registration
  answers 500.
- **`httpauth`:** set `ONEAUTH_JWT_SECRET_KEY` (or `JWTSecretKey`), or
  sessions end on restart. Use `InsecureCookies` for plain-http development
  away from localhost. Link to `/logout` with a POST form.
- **Reference server:** set `admin_auth.type`, and an https `public_url` (or
  `allow_insecure_http` on a private network). List your proxies in
  `server.trusted_proxies`.
- **Custom `VerificationTokenStore`s** must set
  `DeleteVerificationTokenResponse.Deleted`. Reset links issued before the
  upgrade stop working.
- **`iss`:** tokens from the reference server carry the public URL unless
  `jwt.issuer` is set.

## Version 0.1.43

### DPoP and FAPI follow-ups (issue 395, PRs 400 to 402)

- **The SDK's automatic refresh works against any RFC 8414 server.** With AS
  metadata (`WithASMetadata`) it posts the standard refresh form to the
  discovered token endpoint instead of oneauth's own `/auth/cli/token`, which
  Keycloak and others don't serve.
- **`client.WithClientSecret(secret)`** lets the automatic refresh
  authenticate a confidential client, which the refresh grant has required
  since 0.1.41. The secret stays in memory and never reaches the credential
  store.
- **A request retried after a refresh keeps its body.** One whose body can't
  be rewound gets the 401 back instead of being resent empty.
- **EdDSA (Ed25519) DPoP proofs** are accepted by default and by
  `FAPIDPoPAlgs()`, now ES256, EdDSA and PS256. `utils` handles RFC 8037 OKP
  keys, and the SDK has `NewEd25519DPoPKey` / `NewDPoPKeyFromEd25519`.
  Keycloak computes the same thumbprint.
- **`OneAuthConfig.DisableRefreshTokenRotation`** keeps a refresh token in use
  across refreshes, as FAPI 2.0 §5.3.2.1 asks. The response then carries no
  `refresh_token`. The default still rotates.
- **`cmd/oneauth-server` can turn DPoP on**, with a `dpop:` block (profile or
  algs, require at the token endpoint and at the API, nonces with a shared
  secret) and `jwt.disable_refresh_token_rotation`.
  `deploy-examples/fapi-dpop.yaml` turns all of it on.

### Repo

- The GAE store tests are deterministic. The Datastore emulator now starts
  with `--consistency=1.0`; at its default of 0.9, 9 of 10 `make testds` runs
  failed.
- Every Go file is gofmt-clean and CI checks it. `make fmt` fixes;
  `.git-blame-ignore-revs` keeps the cleanup commit out of blame.

### Upgrading

- **`DPoPKey` callers:** no exported API changed, but a validator using the
  default algorithm list now also accepts Ed25519 proofs. Set
  `DPoPConfig.AllowedAlgs` to refuse them.
- **SDK clients with AS metadata** now auto-refresh against the discovered
  endpoint. A confidential client needs `WithClientSecret` to do so.

## Version 0.1.42

### Fixes found by comparing with Keycloak (issue 88, PR 398)

New full-stack e2e tests and a suite that sends the same requests to Keycloak
and to oneauth turned up three bugs.

- **`LoginWithBrowser` with a DPoP key can log in.** It sent `dpop_jkt`, which
  binds the code to the key, then exchanged the code without a proof, so
  oneauth and Keycloak both refused every DPoP browser login. The exchange now
  carries a proof and answers nonce challenges, still through the caller's
  `HTTPClient`.
- **Refresh `invalid_grant` is 400**, as RFC 6749 §5.2 has it. It was 401.
- **A refresh naming no client** for a token that has one gets 401
  `invalid_client`, and one naming a different client gets `invalid_grant`
  before any credentials are asked for. Both match Keycloak.
- **SDK DCR** carries `DPoPBoundAccessTokens` on `ClientRegistrationRequest`
  and `ClientRegistrationResponse` (RFC 9449 §5.2).

Where oneauth and Keycloak still answer differently, `docs/SECURITY_AUDIT.md`
says which and why.

### Upgrading

- **Code that branches on the refresh grant's status** sees 400 instead of
  401 for a refused token. Only `invalid_client` is 401.

### CI

The ZAP baseline scan runs again. Its pinned action version didn't exist, so
the job had failed at setup on every push to main. It now reports to the run's
`zap_scan` artifact rather than opening issues.

## Version 0.1.41

### DPoP audit and requiring DPoP (issue 88, PR 396)

We walked RFC 9449 and the DPoP parts of FAPI 2.0 against the code, one
requirement at a time. The matrix is in `docs/SECURITY_AUDIT.md`, also on the
site under Conformance. The walk turned up a few bugs and one missing feature.

- **Requiring DPoP.** `OneAuthConfig.RequireDPoP` makes the token endpoint
  refuse any request without a proof (FAPI 2.0 §5.3.2.1). A client registered
  with `dpop_bound_access_tokens` (RFC 9449 §5.2) is held to it on its own.
  The field is on `core.AppRegistration` and DCR. Either way a missing proof
  gets 400 `invalid_dpop_proof`, never a bearer token.
- **PAR with a shared validator.** `/par` checks a proof's `htu` against its
  own URL, so `MountAuthorize` giving it the token endpoint's validator works.
  Before, every correct PAR proof failed behind a proxy, and a proof made for
  the token endpoint was accepted at `/par`. PAR also answers a nonce
  challenge with `use_dpop_nonce` and `DPoP-Nonce`.
- **`htu` comparison** follows RFC 3986 §6.2 normalization (case, default
  ports, percent-encoding, dot segments).
- RSA proof keys under 2048 bits are refused, `jti` is capped at 256 bytes, and
  `apiauth.FAPIDPoPAlgs()` returns ES256 and PS256.
- **SDK.** The automatic refresh now carries a proof, so a DPoP client can
  redeem its own bound refresh token. A `DPoP-Nonce` on any response is kept
  for the next request.
- **GORM and GAE app stores** now persist `dpop_bound_access_tokens`, and the
  `backchannel_logout_uri` / `backchannel_logout_session_required` settings
  they used to drop, which switched off back-channel logout after a restart.

### The refresh grant checks the client (issue 395, PR 397)

The refresh grant used to check only the token, so a leaked refresh token
redeemed under any `client_id`, or none, and a confidential client's token
redeemed without its secret (RFC 6749 §6).

- If the token's owner is registered confidential, the request has to
  authenticate as a client, or it gets 401 `invalid_client`.
- The token must belong to the presenting `client_id`, or the grant answers
  `invalid_grant` before rotating, so a refused attempt doesn't use up the
  owner's token. A token stored with no client still redeems.
- `RefreshGrantRequest.ClientID` carries the presenting client for library
  callers of `TokenIssuer.RefreshGrant`.
- The shared confidential-client check treats an AppStore error other than
  not-found as a 500, where it used to treat the client as public. This also
  reaches jwt-bearer, token-exchange and PAR.
- **SDK.** `ServerCredential.ClientID` records which client a credential was
  issued to, and the automatic refresh sends it instead of `"cli"`.

### Upgrading

- **GORM deployments need `AutoMigrate`** for the new app-registration columns
  (`dpop_bound_access_tokens` and the two back-channel logout fields).
- **Refresh callers must send their `client_id`**, and confidential clients
  their credentials. Callers that left `client_id` off, or sent another one,
  are now refused.
- **The SDK's automatic refresh sends no client secret**, so a confidential
  client logged in with `LoginWithBrowser` and a `ClientSecret` can't
  auto-refresh. Call `RefreshToken` with the secret (issue 395 item 4).

## Version 0.1.40

### Typed login and token errors (issues 392, 393, PR 394)

A caller can now tell why a login failed without matching on text. That's
what mcpkit needs to re-register a client the server has forgotten, without
showing the consent page again to someone who clicked Deny.

- **`LoginWithBrowser`** returns `*AuthorizeError` (the AS refused
  `/authorize`), `*CallbackError` (`?error=` on the redirect, e.g.
  `access_denied`), `*TokenError` (the code exchange failed),
  `*BrowserOpenError` (the opener failed, unwrapping to its cause) and
  `ErrLoginTimeout`. Use `errors.As` / `errors.Is`. The messages are the same
  as before.
- **`*TokenError` from every grant**: `Login`, `ClientCredentials`,
  `RefreshToken`, `JwtBearerGrant`, `TokenExchange`, `DeviceAuthorization`,
  and `PollDeviceToken` for codes other than its four RFC 8628 sentinels.
  A token endpoint that answers with a non-JSON error page now reports its
  status instead of a JSON decode error.
- **JSON `/authorize` errors.** oneauth's error page for an unknown client or
  unregistered `redirect_uri` answers with the RFC 6749 §5.2 JSON object
  when `Accept` lists `application/json`. `FollowRedirects` and
  `ApproveConsent` send `Accept: text/html, application/json;q=0.9`, so they
  get `AuthorizeError.Code` from oneauth and from Keycloak. For servers that
  only send HTML, `AuthorizeError.Body` is the page's visible text.

## Version 0.1.39

Documentation only; the code is the same as 0.1.38. The client SDK guide
covers the caller-owned listener, `RedirectURI`, `ApproveConsent` and the
fail-fast `FollowRedirects`, and its browser-login snippets use the current
`LoginWithBrowser(ctx, &BrowserLoginRequest{...})` signature.
`CAPABILITIES.md`, the roadmap and the Keycloak test README are brought up to
date, and these notes now cover 0.1.38.

## Version 0.1.38

### DPoP, the rest of RFC 9449

0.1.37 shipped DPoP-bound tokens on both sides. This release finishes the
spec and gives the client SDK the means to use it.

- **`dpop_jkt` on `/authorize` (PR 378).** The authorization code is bound to
  the client's DPoP key, so an intercepted code can't be redeemed with a
  different one (§10). A missing proof against a bound code is
  `invalid_grant`.
- **Client SDK proofs (PR 379).** `client.DPoPKey` (ES256) mints a proof per
  request, and `WithDPoPKey` attaches proofs to token requests, presents
  tokens under the `DPoP` scheme with `ath`, and sends `dpop_jkt` on browser
  login.
- **The nonce protocol (PR 384).** `DPoPConfig.NoncePolicy` with a stateless
  HMAC `NonceSource` lets the AS (§8) and the resource server (§9) demand a
  server-supplied nonce; the SDK retries `use_dpop_nonce` automatically. Off
  by default.
- **Keycloak interop (PR 385).** OneAuth's middleware accepts a
  Keycloak-issued bound token and refuses it presented as Bearer.

### Pushed authorization requests (RFC 9126, PR 381)

`POST /par` stores the authorization request and returns a `request_uri`, and
`/authorize` accepts a request carrying only `client_id` + `request_uri`.
Mounted by `MountAuthorize` when `AuthorizeMountConfig.PushedStore` is set,
with in-memory and GORM stores. A push may carry a DPoP key in its header or
as `dpop_jkt` (RFC 9449 §10.1).

### Loopback redirects for native clients (PR 388)

- **Caller-owned listener (issue 387).** `BrowserLoginRequest.Listener` takes
  a loopback listener the caller already bound, and
  `LoopbackRedirectURI(addr)` names the redirect the login will send. A
  client that registers via DCR first registers exactly that string, so an AS
  that matches `redirect_uri` byte-for-byte accepts it, and nothing can take
  the port between registration and login. `LoginWithBrowser` closes the
  listener when it returns.
- **`RedirectURI`** sends a registered redirect verbatim (an IP literal, a
  path other than `/callback`). It must be loopback `http` with an explicit
  port matching the listener, checked before the browser opens.
- **`FollowRedirects` fails fast.** A 400-or-worse from `/authorize` now
  returns the AS's `error` / `error_description`. Before, `LoginWithBrowser`
  sat out its timeout (five minutes by default) waiting for a callback that
  was never coming.
- **`ApproveConsent`** is a headless opener for demo servers that answer
  `/authorize` with a consent form. It posts the approve button and refuses a
  form without one.
- **Behavior change on the AS (issue 389).** `/authorize` now ignores the port
  when matching an `http` redirect on 127.0.0.1, [::1] or localhost, as
  RFC 8252 §7.3 requires; scheme, host, path and query still match exactly.
  Deployments relying on the old exact port match for loopback clients will
  now accept any port. `apiauth.RedirectURIMatches` is exported for custom
  `RedirectURIValidator`s.

### Tooling and CI

- The Go directive is 1.26.9 across all modules (GO-2026-6617, an HTTP/2
  HPACK race in `net/http`), with `golang.org/x/net` v0.60.0 where it's
  pulled in (PR 388). `go.opentelemetry.io/otel/sdk` 1.45.0 (PR 376).
- The Keycloak interop workflow runs `make testkcl` and triggers on relevant
  PRs (PR 390). It had never got past starting Keycloak before. The test
  realm defines Keycloak's `basic` scope so tokens carry `sub` on 25+, and
  `test-confidential` names itself in `aud` so 26.x lets it introspect.
- The docs site renders mermaid diagrams and publishes the spec library and
  guides (PR 383).

## Version 0.1.37

### DPoP — sender-constrained access and refresh tokens (RFC 9449)

A token can now be bound to a key the client holds, so a leaked token is
unusable by whoever leaks it. Both halves ship together: the authorization
server binds the token, and the resource server refuses to honor it unless the
presenter proves the key.

Everything here is off by default. An existing deployment that wires neither
side behaves exactly as it did in 0.1.36.

**Issuance (PR 370).** Set `OneAuthConfig.DPoP` to a `DPoPProofValidator` and
the token endpoint starts accepting a `DPoP` proof header on any grant. A
request that carries a valid proof gets `cnf.jkt` in the access token,
`token_type: DPoP` in the response, and a refresh token only that key can
rotate. A request with no proof gets exactly what it got before.

- Proof validation per §4.3: `typ`, an asymmetric `alg` allow-list (ES256,
  RS256, PS256 by default; symmetric algorithms can never be enabled), the
  embedded public `jwk` with private members rejected, the signature, `htm`,
  `htu`, an `iat` window, and `jti` replay through the existing `JTIStore`.
- Refresh-token binding persists in all three backends (FS, GORM, Datastore)
  and is carried forward on rotation. A bound refresh token presented without
  its key is `invalid_grant`.
- `dpop_signing_alg_values_supported` on authorization-server metadata.

**Enforcement (PR 372).** Set `APIMiddleware.DPoP` and the resource server
accepts `Authorization: DPoP <token>` with a per-request proof, checks the
proof's `ath` against the presented token, and matches the proof key against
the token's `cnf.jkt`.

- A bound token presented under the `Bearer` scheme is refused, per §7.2.
  Without that check a thief drops the `DPoP` header and the binding buys
  nothing.
- `WWW-Authenticate` advertises both schemes, with error information on the
  scheme the client actually used.
- `APIMiddleware.RequireDPoP` refuses bearer presentations outright, backing
  `dpop_bound_access_tokens_required` on protected-resource metadata
  (RFC 9728), which lands alongside `dpop_signing_alg_values_supported`.
- Introspection responses carry `cnf`, so a resource server that validates
  remotely enforces the same binding as one validating the JWT locally.

**Rollout order.** A resource server with `APIMiddleware.DPoP` unset accepts a
bound token as an ordinary bearer token, which RFC 9449 §7.2 both predicts and
permits. Wire enforcement at the resource servers first, then start issuing
bound tokens. The reverse order leaves a window where the binding protects
nothing.

**Deployment note (GORM).** The `refresh_tokens` table gains a
`confirmation_jkt` column. Run `AutoMigrate` before deploying. The column is
empty for existing rows, which reads back as an unbound token, so current
behavior is preserved. Datastore adds an equivalent optional property and
needs no migration.

**API additions.** `core.Confirmation` (the RFC 7800 `cnf` claim as a type),
`CreateAccessTokenRequest.Confirmation`, `CreateAccessTokenResponse.TokenType`,
`RefreshGrantRequest.Confirmation` and the same field on each grant request
type, `TokenInfo.Confirmation`, `IntrospectionResult.Cnf`, and
`IntrospectionValidator.ValidateInfo`. The confirmation is a struct rather
than a bare thumbprint string so that mTLS certificate binding (`x5t#S256`,
issue 335) adds a field instead of a second parameter on every issuance path.

**One behavior change without a flag.** `cnf` is now a standard claim, so it
no longer appears in `TokenInfo.CustomClaims`. Code reading `cnf` out of the
custom-claims bag should read `TokenInfo.Confirmation` instead. This also stops
a deployment's `CustomClaimsFunc` from writing a binding the server never
verified.

**Conformance.** Validated against the RFC's own published vectors: the
Figure 2 proof and the Figure 9 thumbprint it produces, plus the Figure 13
access token and the Figure 14 `ath` computed from it.

Closes issue 336. Remaining RFC 9449 surface: the nonce protocol (§8, §9) and
`dpop_jkt` on the authorization request (§10). Keycloak interop for the
resource-server half is issue 371.

### Documentation

Coverage tables that still listed DPoP as a gap are corrected (`RFC_9449.md`,
`RFC_9728.md`, the Authlete gap analysis, the FAPI readiness note), and
`ROADMAP.md` records the two PRs with the design decisions behind them
(PR 373). `CAPABILITIES.md` gains the `dpop-sender-constrained-tokens` entry.
`testutil`'s `WithConfidentialClient` is documented in its sidecar (PR 367).

### Dependencies

Grouped `go_modules` security bumps across the workspace (PRs 368, 369).

---

## Version 0.1.6

### Convention closure for issues 175 + 172

The `(ctx, *XRequest) → (*XResponse, error)` convention adopted across the library (CLAUDE.md "gRPC-shape convention everywhere") is now closed-loop for `apiauth/` and `admin/`:

- **`apiauth/`**: all five transport-agnostic interfaces (`TokenIssuer`, `TokenValidator`, `TokenIntrospector`, `TokenRevoker`, `ClientAuthenticator`) follow the convention. HTTP handlers are thin wrappers. Four legacy positional methods on `APIAuth` — `CreateAccessToken`, `ValidateAccessToken`, `ValidateAccessTokenFull`, `VerifyTokenFunc` — are now marked `// Deprecated:` and point at the canonical interface methods. They remain as the internal implementation backing the HTTP handlers; consolidation + outright removal is tracked under issue 218.
- **`admin/`**: `ClientRegistrar` interface (Register / RegisterLegacy / ListClients / GetClient / DeleteClient / RotateSecret) is in shape, implemented on `AppRegistrar`, and covered by pure-Go interface tests (`client_admin_test.go`) that bypass HTTP entirely. `ClientRegistrationManager` (RFC 7592 self-service) already adopted the convention via issues 168/169/170.

Documentation updated: `apiauth/SUMMARY.md` now carries the convention paragraph that `admin/SUMMARY.md` already had.

Closes 175, 172. Follow-up consolidation tracked under 218. Client SDK migration tracked under 217.

---

## Version 0.1.5

### Client SDK — RFC 8693 token exchange + RFC 7523 §2.1 JWT bearer grant

Two new general-purpose OAuth primitives on `AuthClient`. Both are additive — no existing behavior changes.

**`AuthClient.TokenExchange(*TokenExchangeRequest)` — RFC 8693.** Exchange a subject token (plus optional actor token / requested type / audience / resource / scope) for a freshly issued token. Returns `TokenExchangeResponse` including `IssuedTokenType` (required by RFC 8693 §2.2). Useful for bridging trust domains — e.g. exchanging an upstream-IdP ID token for an internal ID-JAG.

**`AuthClient.JwtBearerGrant(*JwtBearerGrantRequest)` — RFC 7523 §2.1.** Present a signed JWT (typically the output of a prior token exchange or trusted upstream issuance) as `assertion` at the token endpoint to obtain an access token. Distinct from the `private_key_jwt` client authentication method, which authenticates the client itself — both can coexist in the same request.

Both methods reuse the existing `AuthClient` client-authentication negotiation: `client_secret_basic`, `client_secret_post`, and `private_key_jwt` (via `ClientAssertionConfig`) all work transparently.

**Wire shape:** `application/x-www-form-urlencoded` with the appropriate `grant_type` value. `audience` and `resource` are emitted as repeated form values per RFC 8693 §2.1 / RFC 8707 §2. `scope` is space-delimited per RFC 6749 §3.3.

**Tests:** 5 unit tests covering wire shape + minimal request omission + all three client-auth methods, plus 2 e2e tests against the in-process `testutil.TestAuthServer` with `TrustedAssertionIssuers` configured.

Near-term consumer: mcpkit's SEP-990 enterprise-managed authorization (mcpkit issue 448), which chains these two primitives in an `EnterpriseManagedTokenSource` with two-stage caching.

See issue 213.

---

## Version 0.1.4 (PR 2b — Subject vocab consumer-side rename)

### Subject vocabulary — phase 2: consumers, helpers, transports

**Breaking.** Completes the rename started in v0.1.3 (PR 2a). All Go API surfaces that handle the *principal-of-a-token* concept now use **Subject** — context helpers, scope callbacks, response types, HTTP middleware methods, gRPC functions, gRPC metadata header, and the session cookie key. Account-model types (`accounts.User`, `accounts.Identity.UserID`, `accounts.Username.UserID`, etc.) stay as **UserID** — see v0.1.3 notes.

**Go API renames:**

| Before | After |
|---|---|
| `core.GetUserIDFromContext(ctx)` | `core.GetSubjectFromContext(ctx)` |
| `core.SetUserIDInContext(ctx, ...)` | `core.SetSubjectInContext(ctx, ...)` |
| `core.DefaultUserParamName = "loggedInUserId"` | `core.DefaultSubjectParamName = "loggedInSubject"` |
| `core.GetUserScopesFunc` / `DefaultGetUserScopes` | `core.GetSubjectScopesFunc` / `DefaultGetSubjectScopes` |
| `apiauth.APIAuth.GetUserScopes` | `apiauth.APIAuth.GetSubjectScopes` |
| `apiauth.OneAuthConfig.GetUserScopes` | `apiauth.OneAuthConfig.GetSubjectScopes` |
| `apiauth.JWTIssuerConfig.GetUserScopes` | `apiauth.JWTIssuerConfig.GetSubjectScopes` |
| `apiauth.PasswordGrantResponse.UserID` | `.Subject` |
| `apiauth.TokenInfo.UserID` | `.Subject` |
| `apiauth.GetUserIDFromAPIContext(ctx)` | `GetSubjectFromAPIContext(ctx)` |
| `httpauth.Middleware.UserParamName` | `SubjectParamName` |
| `httpauth.Middleware.GetLoggedInUserId(r)` | `GetLoggedInSubject(r)` |
| `httpauth.OneAuth.SetLoggedInUserID(...)` | `SetLoggedInSubject(...)` |
| `grpc.UserIDFromContext` / `UserIDFromContextWithConfig` | `SubjectFromContext` / `SubjectFromContextWithConfig` |
| `grpc.UserIDToOutgoingContext` / `WithKey` | `SubjectToOutgoingContext` / `WithKey` |
| `grpc.DefaultMetadataKeyUserID = "x-user-id"` | `DefaultMetadataKeySubject = "x-subject"` |
| `grpc.Config.MetadataKeyUserID` | `MetadataKeySubject` |

**Active sessions invalidated.** The session-cookie key flipped from `loggedInUserId` to `loggedInSubject`. Cookies issued by v0.1.3 and earlier are not recognised by v0.1.4 — affected users will be prompted to log in again. No code or data migration needed; the new cookies are issued on next login.

**gRPC clients/servers must upgrade in lock-step.** The metadata header changed from `x-user-id` to `x-subject`. A v0.1.4 server will not see subjects sent by a v0.1.3 client (and vice versa).

**`SwitchUser*` stays.** `grpc.SwitchUserToOutgoingContext`, `SwitchUserToOutgoingContextWithKey`, `MetadataKeySwitchUser`, and `DefaultMetadataKeySwitchUser = "x-switch-user"` are unchanged — impersonation is human-user-scoped by nature.

Combined with v0.1.3, this completes the Subject vocab rename across the library.

---

## Version 0.1.3 (PR 2a — token Subject foundation)

### Subject vocabulary — phase 1: token-bearing types

**Breaking.** The token-bearing types in `core/` and `localauth/` now use **Subject** (RFC 7519 `sub`) for the principal field, replacing **UserID**. Motivation: in `client_credentials` flows the principal is a service account, not a human user — `UserID` was misleading. `Subject` is what the JWT `sub` claim, RFC 7662 introspection, RFC 8693 token exchange, and Spring Security / JWT / X.509 idiom all call this concept. Account-model types (`accounts.User`, `accounts.Identity.UserID`, `accounts.Username.UserID`) stay as **UserID** — those are application user records, not OAuth subjects.

**Go API renames:**

| Before | After |
|---|---|
| `core.RefreshToken.UserID` (`json:"user_id"`) | `core.RefreshToken.Subject` (`json:"subject"`) |
| `core.APIKey.UserID` (`json:"user_id"`) | `core.APIKey.Subject` (`json:"subject"`) |
| `localauth.VerificationToken.UserID` (`json:"user_id"`) | `localauth.VerificationToken.Subject` (`json:"subject"`) |
| `RefreshTokenStore.CreateRefreshToken(userID, ...)` | `CreateRefreshToken(subject, ...)` |
| `RefreshTokenStore.RevokeUserTokens(userID)` | `RevokeSubjectTokens(subject)` |
| `RefreshTokenStore.GetUserTokens(userID)` | `GetSubjectTokens(subject)` |
| `APIKeyStore.CreateAPIKey(userID, ...)` | `CreateAPIKey(subject, ...)` |
| `APIKeyStore.ListUserAPIKeys(userID)` | `ListSubjectAPIKeys(subject)` |
| `VerificationTokenStore.CreateToken(userID, ...)` | `CreateToken(subject, ...)` |
| `VerificationTokenStore.DeleteUserTokens(userID, ...)` | `DeleteSubjectTokens(subject, ...)` |

All three backends (`stores/fs`, `stores/gorm`, `stores/gae`) updated. Models renamed in lock-step.

**Storage migration required.** GORM column renames: `refresh_tokens.user_id` → `subject`, `api_keys.user_id` → `subject`, `auth_tokens.user_id` → `subject`. FS JSON storage: `user_id` → `subject` on the three token kinds. GAE Datastore: same field renames. Existing data must be migrated or the affected stores reset — see `docs/MIGRATION.md`.

**Out of scope (deferred to PR 2b):**
- `core.GetUserIDFromContext` / `SetUserIDInContext` / `DefaultUserParamName="loggedInUserId"`
- `core.GetUserScopesFunc`
- `apiauth.PasswordGrantResponse.UserID` / `TokenInfo.UserID` / `GetUserIDFromAPIContext`
- `httpauth.Middleware.GetLoggedInUserId` / `OneAuth.SetLoggedInUserID` (public surface stays — internals flip in PR 2b)
- `grpc.UserIDFromContext` / `DefaultMetadataKeyUserID="x-user-id"`
- Session cookie key `loggedInUserId` (PR 2b invalidates active sessions)

See issue tracker for PR 2b.

---

## Version 0.1.2

### Client SDK — gRPC-shape `ClientCredentials` + RFC 8707 / RFC 9396 plumbing

**New `AuthClient.ClientCredentials(req *ClientCredentialsRequest)`.** Consolidated entry point for the client_credentials grant. Single request struct carries `ClientID`, `ClientSecret`, optional `ClientAssertion` (private_key_jwt), `Scopes`, `Resources []string` (RFC 8707 resource indicators — emitted as repeated `resource` form values per §2), and `AuthorizationDetails []core.AuthorizationDetail` (RFC 9396 — JSON-encoded into the `authorization_details` form value per §6.1). Extends the `(ctx, *XRequest) → (*XResponse, error)` convention adopted by `apiauth/` (#175) and `admin/` (#172) into the client SDK.

**`ClientCredentialsToken` and `ClientCredentialsTokenWithAssertion`** now wrap `ClientCredentials` — existing callers unaffected. New code should target the request struct directly to access `Resources` / `AuthorizationDetails`.

**`ClientCredentialsSource.Resources` and `.AuthorizationDetails`** restored as live fields, this time actually wired into the underlying token request. Resolves the dead-field gap that #211 flagged when removing the previous (non-functional) versions.

End-to-end coverage: `TestRAR_ClientCredentials_SDKForm` in the e2e suite exercises the full SDK → AS round-trip with both RFCs in play.

Follow-up to #211.

---

## Version 0.1.1

### Client SDK — `private_key_jwt` ergonomics

**`ClientAssertionConfig.Audience` (additive).** New field on `ClientAssertionConfig` overrides the `aud` claim of a minted assertion. When empty, behaviour is unchanged (positional argument — typically the token endpoint URL — per OIDC Core §9). Set the field when targeting an RFC 7523bis-strict AS that requires `aud` to be the issuer identifier. `MintClientAssertion` and `ClientCredentialsTokenWithAssertion` both honour the override.

**`ClientCredentialsSource.ClientAssertion` (additive).** New `*ClientAssertionConfig` field on `ClientCredentialsSource`. When non-nil, the source routes through `ClientCredentialsTokenWithAssertion` instead of `ClientCredentialsToken`, applying the same caching, OnToken, and `ProactiveRefresher` machinery as the secret-based path. `ClientSecret` is ignored when `ClientAssertion` is set.

**Cleanup — dead fields removed (breaking).** Removed `ClientCredentialsSource.Audience` (RFC 8707 resource indicator) and `ClientCredentialsSource.AuthorizationDetails` (RFC 9396). Both fields were declared on the struct but **never** wired into the underlying token request, making them silent no-ops. No internal caller and no downstream consumer (mcpkit, goapplib, projects/*) set these fields. Proper RFC 8707 / RFC 9396 plumbing for client_credentials is tracked as a follow-up — the right home is the token-request layer, not the cached source.

Unblocks SEP-1046 conformance work in mcpkit issue 447 (umbrella 439).

See: issue 211.

---

## Version 0.0.32

### APIMiddleware Enhancements

**Query-parameter token fallback**: Added configurable `TokenQueryParam` field to `APIMiddleware`. WebSocket clients often cannot set Authorization headers, so this enables `GET /ws?token=<jwt>` as a fallback. The Authorization header always takes precedence when both are present.

**Custom claims in request context**: Custom (non-standard) JWT claims are now stored in the request context during validation. Use the new `GetCustomClaimsFromContext(ctx)` helper to retrieve them downstream.

**Internal changes**: `validateRequest` and `validateJWT` now return custom claims alongside standard fields. All middleware methods (`ValidateToken`, `RequireScopes`, `Optional`) propagate custom claims into the request context.

---

## Version 0.0.31

### App Registration API & Reference Server

- **`AdminAuth` interface** with `APIKeyAuth` and `NoAuth` implementations for protecting admin endpoints
- **`AppRegistrar` HTTP handler** providing full App CRUD: register, list, get, delete, and rotate secret
- **`MintResourceToken` helper** for issuing resource-scoped JWTs with app/subject claims
- **Config-driven reference server** in `cmd/oneauth-server/` with YAML config and environment variable substitution
- Deployable to **GAE, Docker Compose, and Kubernetes**
- **Integration tests** (pytest) covering the full app registration lifecycle

---

## Version 0.0.30

### Redirect Mode for Password Reset Flows

`LocalAuth` now supports redirect-based password reset for server-rendered apps. New fields `ForgotPasswordURL` and `ResetPasswordURL` control the behavior: when set, GET requests redirect to the app's themed page, and POST requests redirect with query params (`?sent=true`, `?success=true`, `?error=...`). When empty (default), handlers behave as before (HTML form / JSON response).

### Bug Fix: Multipart Form Parsing

`HandleForgotPassword` and `HandleResetPassword` now correctly parse both `application/x-www-form-urlencoded` and `multipart/form-data` bodies. Previously, JavaScript `new FormData(form)` submissions returned 400 errors.

---

## Version 0.0.29

### Bug Fix: Password Reset for OAuth-Only Users

`NewUpdatePasswordFunc` now creates a local channel on-demand when one doesn't exist, enabling OAuth-only users to set a password via the standard reset flow. Previously these users received "local auth not configured" errors.

---

## Version 0.2.0

### API Authentication & Store Reorganization

Major release adding API authentication (JWT access tokens, refresh tokens with rotation and theft detection, API keys, scopes) and new store backends.

**New endpoints**: `/api/login`, `/api/logout`, `/api/logout-all`, `/api/keys` (CRUD).

**APIMiddleware**: `ValidateToken`, `RequireScopes`, and `Optional` handlers for protecting API routes. Supports both JWT and API key authentication.

**Store reorganization**: Stores moved to `stores/fs`, `stores/gorm`, and `stores/gae` subdirectories. GORM provides full SQL database support; GAE provides Google Cloud Datastore support.

**New store interfaces**: `RefreshTokenStore` and `APIKeyStore`.

**Breaking change**: Import paths changed from `github.com/panyam/oneauth/stores` to `github.com/panyam/oneauth/stores/{fs,gorm,gae}`.

**New dependencies**: `github.com/golang-jwt/jwt/v5`, `gorm.io/gorm` (optional), `cloud.google.com/go/datastore` (optional).

---

## Version 0.1.0 (Initial Release)

### Overview

Initial release of OneAuth, a Go authentication library providing unified local and OAuth-based authentication with multi-method account linking.

### Core Features

- **Three-layer model**: Users, Identities, and Channels with global identity verification
- **Local auth**: Email/phone + password with bcrypt hashing, configurable validation
- **OAuth integration**: Google, GitHub, etc. with automatic identity unification across providers
- **Email verification**: Token-based flow with configurable expiry and extensible sender interface
- **Password reset**: Secure token-based flow with anti-enumeration (always returns success)
- **Session management**: Callback-based (`HandleUser`) supporting cookies, JWTs, or custom schemes

### Storage

- **File-based stores** (FS): JSON file storage for Users, Identities, Channels, and Tokens. Suitable for development and small-scale use (<1000 users).
- **Database-agnostic interfaces**: `UserStore`, `IdentityStore`, `ChannelStore`, `TokenStore` for production implementations.

### HTTP Endpoints

`/auth/login`, `/auth/signup`, `/auth/verify-email`, `/auth/forgot-password`, `/auth/reset-password`. Accepts form-encoded and JSON bodies; returns JSON responses.

### Helper Functions

`NewCreateUserFunc`, `NewCredentialsValidator`, `NewVerifyEmailFunc`, `NewUpdatePasswordFunc`, `DetectUsernameType`, `DefaultSignupValidator`, `GenerateSecureToken`.

### Known Limitations

File-based stores not recommended at scale. No built-in rate limiting, CSRF protection, or session storage (application responsibility). Console email sender only.

### Dependencies

`golang.org/x/crypto/bcrypt`, `golang.org/x/oauth2` (optional).
