# Security & RFC compliance audit

This is the compliance matrix asked for in [issue 88](https://github.com/panyam/oneauth/issues/88).
Issue 88 covers a lot of ground (RFC 6749 through RFC 9728, the security checklist, FAPI 2.0),
so we're doing it one area at a time, and each area gets a section here once it's been walked
requirement by requirement. So far that's DPoP and the HTTP surface (transport and headers,
authentication and sessions, the admin interface).

How to read the tables:

- **Status** is what the code does today, checked by reading it, not by trusting the docs.
  *Pass* means the requirement holds. *Partial* means it holds for some inputs and not others.
  *Open* means it doesn't hold yet and has an issue.
- **Test** names the test that fails if the behavior is removed. For the rows marked with an
  asterisk we checked that by deleting the behavior and watching the test go red, since a test
  that stays green without the feature isn't covering it.
- Code references are `file:line` on the commit that added the section, so they drift. The
  function names don't.

## DPoP (RFC 9449, and the DPoP parts of FAPI 2.0)

Audited October 2026. DPoP had already shipped across issues 336, 374, 375 and 377. Most of
RFC 9449 held up, but the walk turned up three real bugs and a FAPI requirement nothing
implemented. They're fixed in the same PR as this section, and the leftovers are in
[issue 395](https://github.com/panyam/oneauth/issues/395).

### RFC 9449

| § | Requirement | Level | Role | Status | Code | Test |
|---|---|---|---|---|---|---|
| 4.2 | Proof has `typ`, a public `jwk`, a fresh `jti`, `htm`, `htu`, `iat`, and `ath` with a token | MUST | client | Pass | `client/dpop.go:175` `proofWithNonce` | `client/dpop_test.go` ProofShape, EveryProofHasAFreshJTI, ProofBindsToTheAccessToken |
| 4.2 | Client `htu` has no query or fragment | MUST | client | Pass | `client/dpop.go:235` `canonicalHTU` | HTUDropsQueryAndFragment |
| 4.3(2) | Exactly one `DPoP` header | MUST | AS, RS | Pass | `apiauth/dpop.go:402` `Confirm`, `:490` `ConfirmResource` | ConfirmRejectsMultipleHeaders, ConfirmResourceRejectsMultipleHeaders\* |
| 4.3(4) | `jti`, `htm`, `htu`, `iat` all present | MUST | AS, RS | Pass | `apiauth/dpop.go:274` `Validate` | RejectsMissingJTI, RejectsMissingRequiredClaims |
| 4.3(5) | `typ` is `dpop+jwt` | MUST | AS, RS | Pass | `Validate` | RejectsWrongTyp |
| 4.3(6) | Asymmetric `alg` only, never `none` or HS\* | MUST | AS, RS | Pass | `Validate` (`jwt.WithValidMethods`) | RejectsSymmetricAlg, RejectsAlgNone |
| 4.3(7) | Signature verifies under the embedded `jwk` | MUST | AS, RS | Pass | `Validate` | RejectsTamperedSignature |
| 4.3(8) | `jwk` carries no private key | MUST | AS, RS | Pass | `apiauth/dpop.go:522` `publicKeyFromProofHeader` | RejectsPrivateKeyInJWKHeader |
| 4.3(9) | `htm` matches the method | MUST | AS, RS | Pass | `Validate` | RejectsMethodAndURIMismatch |
| 4.3(9) | `htu` matches, ignoring query and fragment | MUST | AS, RS | Pass | `apiauth/dpop.go:561` `sameHTU` | IgnoresQueryAndFragmentInHTU |
| 4.3, 11.8 | `htu` compared after RFC 3986 §6.2.2 / §6.2.3 normalization | SHOULD | AS, RS | Pass (was Partial) | `apiauth/dpop.go:578` `normalizeHTU` | `dpop_htu_test.go` HTUNormalization\*, ResourceHTUKeepsEncodedPath\* |
| 4.3(10) | `nonce` matches when the server demanded one | MUST | AS, RS | Pass | `apiauth/dpop.go:366` `checkNonce` | `dpop_nonce_test.go` |
| 4.3(11) | `iat` inside a window in both directions | MUST | AS, RS | Pass (±30s) | `Validate`, `defaultDPoPMaxAge` | RejectsStaleAndFutureIAT, FAPIFutureIATEdges\* |
| 4.3(12), 7.1 | `ath` matches the presented token | MUST | RS | Pass | `ConfirmResource` | ChecksAccessTokenHash |
| 7.1 | Token's `cnf.jkt` equals the proof key | MUST | RS | Pass | `apiauth/middleware.go:428` `enforceBinding` | RejectsProofFromAnotherKey; Keycloak interop |
| 11.1 | `jti` remembered for the whole window; bounded in size | SHOULD | AS, RS | Pass (size cap added) | `Validate`, `maxDPoPJTILength` | RejectsReplayedJTI, RejectsOversizedJTI\* |
| 5 | `token_type: DPoP` on a bound token | MUST | AS | Pass | `apiauth/dpop.go:693` `tokenTypeFor` | ClientCredentialsBindsAccessToken |
| 5 | A bad proof fails the request, never falls back to Bearer | MUST | AS | Pass | `apiauth/token_endpoint.go:442` `dpopConfirmation` | InvalidProofRejectsTheRequest |
| 5 | Public client's refresh token bound to its key, checked on use | MUST | AS | Pass | `token_validator.go` refresh grant | BoundRefreshTokenRequiresItsOwnKey |
| 5 | Binding survives FS / GORM / GAE stores | — | AS | Pass | `stores/*` | e2e (FS), `stores/gorm/refreshtoken_binding_test.go`, `stores/gae/refreshtoken_binding_test.go` (`make testds`) |
| 5 | Client's automatic refresh carries a proof | MUST | client | Pass (was Fail) | `client/client.go` `refreshTokenLocked` → `requestTokenForm` / `requestToken` → `executeTokenRequest` | RefreshThenRetryMintsAFreshProof\*, e2e SDKAutoRefreshKeepsTheBinding\*; Keycloak SDKRefreshKeepsTheBinding |
| 5.1 | `dpop_signing_alg_values_supported` in AS metadata | SHOULD | AS | Pass | `apiauth/as_metadata.go:79` | e2e MetadataAdvertisesSigningAlgs |
| 5.2 | `dpop_bound_access_tokens` client metadata, enforced | MUST if supported | AS | Pass (was not implemented) | `apiauth/token_endpoint.go:478` `requireDPoP`; `core.AppRegistration`; DCR; all app stores | `dpop_require_test.go`\*, `admin/dcr_dpop_test.go`\*, `appstoretest` AllFieldsRoundTrip\*, e2e DCRRegisteredDPoPBoundClient\* |
| 6.1 | `cnf.jkt` in the JWT, not forgeable through custom claims | MUST | AS | Pass | `token_validator.go:432` | CustomClaimsCannotForgeCnf |
| 6.2 | `cnf` in introspection, enforced by an RS that introspects | MUST | AS, RS | Pass | `token_introspector.go`, `introspection_client.go` | IntrospectionReportsConfirmation, EnforcesCnfFromIntrospection\* |
| 7.1 | `Authorization: DPoP`; 401 with `WWW-Authenticate: DPoP` and `algs` | MUST | RS | Pass | `apiauth/middleware.go:728` `challenge` | ChallengeAdvertisesBothSchemes, ChallengeParamsAreCommaSeparated |
| 7.2 | Bound token refused under the Bearer scheme | MUST | RS | Pass | `enforceBinding` | RejectsBoundTokenPresentedAsBearer; Keycloak interop |
| 8 | `use_dpop_nonce` + `DPoP-Nonce` at the token endpoint | MUST | AS | Pass | `dpopConfirmation` | TestNonce_TokenEndpointChallenge |
| 8 | Same at the PAR endpoint | MUST | AS | Pass (was Fail) | `apiauth/par.go:221` `resolveDPoPBinding` | `par_dpop_shared_test.go` NonceChallenge\* |
| 8.2, 9 | Client uses a `DPoP-Nonce` from any response | expected | client | Pass (was Partial) | `client/client.go:760` `rememberNonce` | UsesANonceFromASuccessful{Token,Resource}Response\*, e2e SDKFollowsTheNonceProtocol\* |
| 9 | `use_dpop_nonce` at the RS (401) | MUST | RS | Pass | `enforceBinding` | TestNonce_ResourceServerChallenge |
| 10 | Code bound by `dpop_jkt` refuses another key or no proof | MUST | AS | Pass | `authorize_granter.go:113` | `dpop_jkt_test.go` |
| 10 | Client that sent `dpop_jkt` proves the key on the code exchange | MUST | client | Pass (was Fail) | `client/browser_login.go` `exchangeCode` → `doTokenRequest` | e2e BrowserLoginWithDPoP\*; Keycloak SDKBrowserLogin\* |
| 10.1 | PAR takes `dpop_jkt` or a proof, rejects a mismatch, checks its own `htu` | MUST | AS | Pass (was Fail with a shared validator) | `resolveDPoPBinding` | `TestPARDPoP_*`, MountAuthorize_PARSharesTheTokenEndpointValidator\*, e2e PARWithDPoP\* |
| RFC 9728 | `dpop_bound_access_tokens_required` advertised and enforced | — | RS | Pass | `protected_resource.go:56`, `APIMiddleware.RequireDPoP` | RequireDPoPRefusesBearer |

### FAPI 2.0 Security Profile (final), DPoP requirements

| § | Requirement | Status | How |
|---|---|---|---|
| 5.3.2.1 #4 | AS shall only issue sender-constrained access tokens | Pass (was not possible) | `OneAuthConfig.RequireDPoP` |
| 5.3.2.1 #12 | AS supports binding the authorization code to the DPoP key | Pass | `dpop_jkt` (RFC 9449 §10) |
| 5.3.2.1 #13 | Accept `iat` up to 10s ahead, reject more than 60s ahead | Pass | ±30s window; FAPIFutureIATEdges |
| 5.3.4 #5 | RS shall only accept sender-constrained tokens | Pass | `APIMiddleware.RequireDPoP` |
| 5.4.1 | Proof algs limited to PS256 / ES256 / EdDSA | Pass (was Partial) | `apiauth.FAPIDPoPAlgs()` gives ES256, EdDSA (Ed25519, RFC 8037) and PS256; `client.NewEd25519DPoPKey`; DPoPEdDSA\*, Ed25519MatchesRFC8037; Keycloak Ed25519KeyAgreesOnTheThumbprint |
| 5.4.1 | RSA keys at least 2048 bits | Pass (was Fail) | `minDPoPRSABits`; RejectsShortRSAKey\* |
| 5.3.2.1 #9 | No refresh-token rotation | Pass (was Open) | `OneAuthConfig.DisableRefreshTokenRotation`, opt-in; the default still rotates (RFC 9700 §4.14). RefreshRotationOff\* |
| — | Reference server can be configured for all of the above | Pass (was not possible) | `cmd/oneauth-server` `dpop:` block and `jwt.disable_refresh_token_rotation`; `deploy-examples/fapi-dpop.yaml`; `cmd/oneauth-server/dpop_test.go` |

### What the walk found

Fixed alongside this section:

- **The AS couldn't be made to require DPoP.** A client that left the proof off always got a
  bearer token. `RequireDPoP` covers every client and §5.2 `dpop_bound_access_tokens` covers
  one, and both refuse with 400 `invalid_dpop_proof`.
- **`MountAuthorize` broke PAR behind a proxy.** It gives `/par` the token endpoint's validator,
  whose `EndpointURL` names `/api/token`, so every PAR proof failed and a proof made for the
  token endpoint was accepted at `/par`. PAR also turned a nonce challenge into a plain
  rejection with no `DPoP-Nonce`, which a client can't recover from.
- **The SDK's automatic refresh sent no proof.** It used the legacy JSON path, which skipped
  the DPoP code entirely, so a DPoP client couldn't refresh its own bound token.
- **`htu` comparison only lowercased scheme and host.** `:443`, `https://h` vs `https://h/`,
  `%2f` vs `%2F` and dot segments were all wrong rejections, and the RS built the expected
  URL from the decoded path, so `/a%2Fb` was checked as `/a/b`.
- No RSA key-size floor, no `jti` length bound, a client that ignored a `DPoP-Nonce` unless it
  came with a challenge, and a FAPI alg preset that didn't exist.
- **GORM and GAE app stores dropped back-channel logout settings.** Not DPoP, but the same
  code we had to touch for §5.2: `backchannel_logout_uri` and
  `backchannel_logout_session_required` weren't persisted, so logout dispatch stopped working
  after a restart on those backends.

Items 1 to 5 of [issue 395](https://github.com/panyam/oneauth/issues/395) are done: EdDSA proofs, the no-rotation option, the reference server's DPoP config, and the two SDK refresh-path fixes.

The walk also turned up a gap bigger than DPoP, fixed separately: the refresh grant didn't
authenticate the client or check the token belonged to the `client_id` sent with it
(RFC 6749 §6). It does both now (`refreshingClient` in `token_endpoint.go`, and the
`ClientID` match in `RefreshGrant`). The `dpop_bound_access_tokens` check still follows the
refresh token's owner rather than the request, which is the same client whenever the grant
would succeed.

The e2e and Keycloak tests added after the walk found three more, also fixed:

- **`LoginWithBrowser` with a DPoP key couldn't log in.** It sent `dpop_jkt`, which binds the
  code, and then exchanged the code without a proof, so both oneauth and Keycloak refused it.
- **The refresh grant answered `invalid_grant` with 401.** RFC 6749 §5.2 sends every error
  with 400 except `invalid_client`. Keycloak uses 400.
- **A refresh naming no client, for a token that has one, got `invalid_grant`.** It now gets
  401 `invalid_client` ("no client authentication included", §5.2), and a request naming
  another client gets `invalid_grant` before any credentials are asked for. Both match
  Keycloak.

### Compared with Keycloak

`tests/keycloak/refresh_dpop_interop_test.go` sends the same requests to Keycloak and to a
oneauth AS registered with the same clients, and asserts on both answers. They agree on every
status. Where the codes or verdicts differ, the test pins both, and we keep ours for the
reasons below.

| Case | Keycloak | oneauth | Why we keep ours |
|---|---|---|---|
| Confidential client, missing or wrong secret, on refresh | 401 `unauthorized_client` | 401 `invalid_client` | §5.2 names `invalid_client` for failed client authentication. |
| DPoP-bound client sends no proof | 400 `invalid_request` | 400 `invalid_dpop_proof` | RFC 9449 names no code for this. Keycloak also uses `invalid_request` for a wrong `htu`, where §5 does name `invalid_dpop_proof`, and the SDK keys its retry advice on that code. |
| `htu` with a fragment | refused | accepted | §4.3 says to ignore the fragment. |
| `htu` with `%2D` for `-`, or a `/./` segment | refused | accepted | §4.3 compares after RFC 3986 §6.2.2 normalization, under which these name the same URL. |

Things that are deliberate rather than gaps:

- **Confidential clients' refresh tokens are key-bound too.** §5 only requires it for public
  clients, since a confidential client's refresh token is already bound by client
  authentication. Binding them anyway is stricter. The cost is that a confidential client
  can't switch DPoP keys halfway through a session.
- **The default `JTIStore` is in-memory.** That's right for one node and wrong for a fleet,
  where a proof replayed against a different node isn't seen. `DPoPConfig.JTIStore` takes a
  shared store.
- **Nonces are off by default.** §8 leaves the policy to the server, and demanding one on every
  request breaks clients that haven't implemented the retry. See `DPoPConfig.NoncePolicy`.

## HTTP surface (transport, sessions, admin)

Audited October 2026, after the first ZAP baseline scan of the reference server. The checklist
is issue 88's "Transport & Headers", "Authentication & Session" and "Admin Interface" sections.
The fixes land across several PRs; the Status column says which rows are done.

### Transport and headers

| Requirement | Ref | Status | Code | Test |
|---|---|---|---|---|
| `redirect_uri` is https except on loopback | RFC 6749 §3.1.2.1, RFC 8252 §7.3 | Pass | `admin/registrar.go` `validateRedirectURI` | `admin/redirect_uri_validation_test.go` |
| `Cache-Control: no-store` on token responses | RFC 6749 §5.1 | Pass | `apiauth/token_endpoint.go` `writeTokens` | existing |
| ... and on token and device errors | OAuth 2.1 §3.2.4 | Pass (was Fail) | `writeError`, `writeOAuthError` | `credential_no_store_test.go`\* |
| ... and on DCR, admin read / list / rotate, API key creation | RFC 7591 §3.2.1 → RFC 6749 §5.1 | Pass (was Fail) | `admin/no_store.go`, `apiauth/apikeys.go` | `admin/credential_responses_test.go`\*, `credential_no_store_test.go`\* |
| ... on the authorize redirect carrying a code, and the reset-password form | RFC 6749 §10.5 | Pass (was Fail) | `issueAndRedirect`, `HandleResetPasswordForm` | `authorize_no_store_test.go`\*, `reset_no_store_test.go`\* |
| `registration_client_uri` not built from the request's `Host` | CWE-644 | Pass (was Fail) | `AppRegistrar.IssuerBaseURL`; loopback-only fallback in `DCRHandler.issuerBase` | RegistrationURIIgnoresForeignHost\* |
| Admin view doesn't return clients' `registration_access_token` | RFC 7592 §3 | Pass (was Fail) | `ListClients` / `GetClient` clear it | AdminViewOmitsRegistrationAccessToken\* |
| Anti-framing on consent, device and login pages | RFC 6749 §10.13 | Open | only the reference server's `SecurityHeaders` wrapper | sessions PR |
| CSP without third-party script or `unsafe-inline` | — | Open | reference server loads the Tailwind Play CDN | server hardening PR |
| HTTPS enforcement for a non-loopback deployment | OAuth 2.1 §1.5 | Open | nothing refuses plain HTTP | server hardening PR |
| CORS | — | Pass | no CORS on the token endpoint; no `Allow-Credentials` anywhere | — |

### Authentication and sessions

| Requirement | Status | Notes |
|---|---|---|
| Constant-time compares for secrets | Pass | client secrets, admin key, CSRF, PKCE, RFC 7592 token, DPoP nonce MAC |
| Password hashing | Pass | bcrypt cost 10, over-72-byte passwords refused, dummy hash for unknown users |
| API keys, refresh tokens, device codes stored hashed | Pass | bcrypt / SHA-256 |
| Password-reset tokens stored hashed, single use | Open | stored and looked up in plaintext; reset PR |
| Cookie flags (`HttpOnly`, `Secure`, `SameSite`) | Open | `httpauth` session JWT cookie has none; `oa_token` lacks `Secure` |
| Session ID renewed on login | Open | `httpauth` never calls `RenewToken` |
| Session JWTs not usable as API access tokens | Open | tokens with no `type` claim pass `APIMiddleware` |
| CSRF | Partial | double-submit with `SameSite=Strict`; `GET /auth/logout` is CSRF-able |
| Brute-force limits on login, password grant, user-code entry | Open | limiters exist but nothing wires them by default; `X-Forwarded-For` is trusted unconditionally |

### Admin interface

| Requirement | Status | Notes |
|---|---|---|
| RFC 7592 token scoped to its own client | Pass | constant-time compare against that client's stored token |
| Admin API key compared in constant time | Pass | `admin/auth.go` |
| JWKS exposes only public keys | Pass | symmetric keys skipped |
| A nil `AdminAuth` fails closed | Open | nil skips the check |
| Reference server refuses `admin_auth: none` | Open | it logs a warning and serves an open admin API |
| Body limits and rate limiting on admin routes | Open | body limits only in the reference server's wrapper |
| Bulk eviction endpoint | Not applicable | no such endpoint exists |

