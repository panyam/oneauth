# Security & RFC compliance audit

This is the compliance matrix asked for in [issue 88](https://github.com/panyam/oneauth/issues/88).
Issue 88 covers a lot of ground (RFC 6749 through RFC 9728, the security checklist, FAPI 2.0),
so we did it one area at a time, and each area got a section here once it had been walked
requirement by requirement: DPoP, the HTTP surface (transport and headers, authentication and
sessions, the admin interface), input validation, and tokens and keys, with FAPI 2.0 alongside
DPoP. The summary below pulls the results together.

How to read the tables:

- **Status** is what the code does today, checked by reading it, not by trusting the docs.
  *Pass* means the requirement holds. *Partial* means it holds for some inputs and not others.
  *Open* means it doesn't hold yet and has an issue.
- **Test** names the test that fails if the behavior is removed. For the rows marked with an
  asterisk we checked that by deleting the behavior and watching the test go red, since a test
  that stays green without the feature isn't covering it.
- Code references are `file:line` on the commit that added the section, so they drift. The
  function names don't.

## Summary (October 2026)

Every area issue 88 asked for has been walked: DPoP, the HTTP surface, tokens and keys, input
validation, and FAPI 2.0. The fixes shipped in v0.1.40 through v0.1.55 (PRs #394 to #428). The
last Open row, revoking tokens from a reused authorization code, was closed afterwards by #429,
so every row in the tables below is Pass, with the caveats each row gives.

### FAPI 2.0 readiness

oneauth meets the FAPI 2.0 Security Profile's authorization-server and resource-server
requirements (§5.3.2, §5.3.4) through `OneAuthConfig.FAPI2`, and the reference server runs the
profile with `deploy-examples/fapi-dpop.yaml`. Three caveats:

- **Sender constraint is DPoP only.** FAPI allows MTLS or DPoP, and oneauth implements DPoP
  (RFC 9449 end to end). MTLS is #335.
- **Client assertions are ES256.** FAPI allows PS256, ES256 and EdDSA; oneauth can register
  ES256 client keys today. PS256 is #330 and EdDSA client keys #331 (EdDSA DPoP proofs already
  work).
- **Not run against the OpenID conformance suite.** The OIDF workflow exists but has never run
  (#201, #290). Everything here is checked by our own tests and, where Keycloak supports the
  feature, side by side with Keycloak 26.

What FAPI 2.0 *Message Signing* adds (JARM, signed introspection, HTTP message signatures) is not
supported, and neither is FAPI 1.0's `s_hash`, which rides on OIDC ID tokens oneauth doesn't
issue. Those are below.

### What the audit found, by severity

The bugs, not the hardening: each of these let something through that the spec or common sense
says shouldn't pass.

| Severity | Finding | Fixed in |
|---|---|---|
| Critical | `httpauth` signed sessions with a fixed public secret when none was configured, so anyone could mint a session for any user | #404 |
| High | FS identity store: a crafted email read and overwrote another account's identity; channel keys read another key's password hash | #425 |
| High | Client-assertion audience taken from `X-Forwarded-Host`, so an assertion minted for another server was accepted | #426 |
| High | An empty HMAC key verified tokens signed with the empty key (middleware with no secret) | #414 |
| High | A tenant's registered key could sign tokens for any subject, with no `client_id` | #414 |
| High | `EncryptedKeyStorage` returned ciphertext, or a planted plaintext secret, as the key | #419 |
| High | A nil `AdminAuth` and the server default `admin_auth: none` left the admin API open | #406 |
| Medium | Any client could revoke any other client's tokens, and an unsigned token naming a `jti` revoked it | #416 |
| Medium | Keycloak ID tokens (and oneauth's own logout tokens, ID-JAGs, sessions) passed as access tokens | #414, #418 |
| Medium | `X-Forwarded-For` from anyone reset rate-limit buckets | #405 |
| Medium | Open redirects on logout and the federated callback | #404 |
| Medium | Reset tokens stored in plaintext, and one link could reset twice under a race | #407 |
| Medium | PAR broke at the consent screen; a pushed request could issue several codes | #423 |
| Medium | Registered scope and RAR types were never enforced | #422, #423 |
| Medium | Signup and CSRF: account enumeration, and same-site posts passing double-submit | #428 |
| Low | Store errors (hosts, database users) in `error_description` | #422, #424 |
| Low | GORM refresh rotation could hand out two tokens under a race | #416 |
| Low | Rotation grace periods were accepted and ignored in the reference server | #420 |

### Gaps, with rough size

S is a day or two, M a week, L more.

| Gap | Issue | Size |
|---|---|---|
| Retired asymmetric keys published in JWKS during their grace period | #421 | M |
| PS256 and EdDSA client keys | #330, #331 | S each |
| `typ: at+jwt` on mint and required on verify (RFC 9068) | #328, #329 | S |
| MTLS client authentication and certificate-bound tokens (RFC 8705) | #335 | L |
| OIDC ID tokens, which `s_hash` (FAPI 1.0) needs | #339 | L |
| JARM (FAPI 2.0 Message Signing) | #151, mission #409 | M |
| HTTP Message Signatures (RFC 9421) | #152 | L |
| A first run of the OIDF conformance suite | #201, #290 | M |
| Signup enumeration with email verification off: a fresh signup logs in and a taken one can't, so it stays visible | — (by design) | — |

### Test coverage

| Layer | What runs | Where it runs |
|---|---|---|
| Unit | `apiauth`, `admin`, `keys`, `httpauth`, `localauth`, `core`, `utils`, every store; the `*_hardening_test.go` and `*_test.go` files named in the tables above | CI (`go test -race ./...` in every module) |
| Store contracts | `appstoretest`, `authcodetest`, `deviceauthtest`, `keystoretest`, `kidstoretest`, `partest` over memory, FS, GORM (SQLite) and GAE, also through `EncryptedKeyStorage` / `EncryptedKidStorage` | CI; GAE in the `gae` job, against the Datastore emulator (`make testds`) |
| End to end | `tests/e2e`: the full stack in process, including DCR, PAR, DPoP, device flow, revocation | CI (`make e2e` locally, with the race detector) |
| Keycloak interop | `tests/keycloak`: JWKS validation, DPoP, refresh comparisons, revocation parity, ID tokens refused as access tokens | the Keycloak workflow on PRs touching `apiauth/`, `client/`, `keys/`, `core/`, `cmd/oneauth-server/` |
| Reference server | `cmd/oneauth-server` tests, plus probes against the built binary recorded in each PR | CI |
| Scans | CodeQL on every PR (0 open alerts, two dismissed with a reason); govulncheck, gitleaks, gosec (`make audit`); ZAP baseline on main | CI and `make audit` |
| OIDF conformance | `tests/oidf-conformance` | never run (#201, #290) |

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

### FAPI 2.0 Security Profile (final), the rest of §5.3.2

`OneAuthConfig.FAPI2` turns the profile on as one switch instead of several (issue 88).

| § | Requirement | Status | How |
|---|---|---|---|
| 5.3.2.1 #2 | Reject the resource owner password grant | Pass (was opt-in) | `FAPI2` answers `unsupported_grant_type` even when a `PasswordGranter` is wired. DPoPRequiredAndNoPasswordGrant\* |
| 5.3.2.1 #3 | Confidential clients only | Pass (was not possible) | the confidential-client gate refuses public and unregistered clients under `FAPI2` |
| 5.3.2.1 #6 | Client authentication by `private_key_jwt` (or MTLS) | Pass (was not possible) | `fapiClientAuthenticator` refuses client secrets; MTLS isn't implemented. ClientAuthentication\* |
| 5.3.2.1 #8 | Accept only the issuer, as a string, as the client assertion's `aud` | Pass (was not possible) | `AcceptedAudiences` pinned to the issuer and `RequireStringAudience`. ClientAuthentication\* |
| — | A caller can't choose the audience its assertion is checked against | Pass (was Fail, every deployment) | `derivedAudience` read `X-Forwarded-Host` / `-Proto` from anyone, so an assertion minted for another server passed. It now uses `r.TLS` and `r.Host` only, and the token endpoint also accepts the issuer by default (RFC 7523 §3). ForwardedHeadersDontChooseTheAudience\* |
| 5.3.2.1 #4, #9 | Sender-constrained tokens, no rotation | Pass | `FAPI2` sets `RequireDPoP` and `DisableRefreshTokenRotation` |
| 5.3.2.2 #1 | PAR only | Pass | `MountAuthorize` sets `RequirePushedRequests` under `FAPI2`, and panics without a `PushedStore` |
| 5.3.2.2 | Codes at most 60s, `request_uri` under 600s | Pass | defaults already were; `FAPI2` caps longer configured values. LifetimeCaps |
| 5.4.1 | Client assertions signed with PS256, ES256 or EdDSA | Pass (was Fail) | `FAPI2` refuses other algorithms through `AuthenticateClientRequest.AllowedAssertionAlgs`. oneauth verifies ES256 assertions; PS256 and EdDSA client keys can't be registered yet. ClientAuthentication\* |
| — | Reference server can run the whole profile | Pass (was not possible) | `fapi2: true` and `code_flow.par` in `deploy-examples/fapi-dpop.yaml`; the server refuses `fapi2` without DPoP, or with `/authorize` but no PAR; metadata lists `private_key_jwt` / ES256 only, the PAR endpoint, `require_pushed_authorization_requests`, and no password grant. `cmd/oneauth-server/fapi_test.go`\* |

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
| Revoke another client's token (RFC 7009) | 400 `invalid_request` | 400 `invalid_request` | Same answer; pinned by `TestKeycloakCompare_Revocation`. |
| Revoke with no `token` | 400 `invalid_request` | 400 `invalid_request` | Same answer. |

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
| Anti-framing on consent, device and password pages | RFC 6749 §10.13 | Pass (was Fail) | `httpauth.DenyFraming` in the authorize, device and localauth page handlers; keeps a deployment's own CSP | `framing_test.go`\*, `authorize_framing_test.go`\* |
| CSP without third-party script or `unsafe-inline` | CWE-829 | Pass (was Fail) | reference server serves a prebuilt, embedded `static/app.css` (`make server-css`); `serverCSP` allows only `'self'` | `hardening_test.go` PagesLoadNoThirdPartyScript\* |
| HTTPS enforcement for a non-loopback deployment | OAuth 2.1 §1.5, CWE-319 | Pass (was Fail) | reference server refuses a plain-http `public_url` on a non-loopback host unless `allow_insecure_http` | PlainHTTPOnAPublicHostRefused\* |
| Token `iss` matches the metadata issuer | RFC 8414 §3.3 | Pass (was Fail) | `jwt.issuer` defaults to the public URL instead of `"oneauth"` | IssuerDefaultsToThePublicURL\* |
| CORS | — | Pass | no CORS on the token endpoint; no `Allow-Credentials` anywhere | — |

### Authentication and sessions

| Requirement | Status | Notes |
|---|---|---|
| Constant-time compares for secrets | Pass | client secrets, admin key, CSRF, PKCE, RFC 7592 token, DPoP nonce MAC |
| Password hashing | Pass | bcrypt cost 10, over-72-byte passwords refused, dummy hash for unknown users |
| API keys, refresh tokens, device codes stored hashed | Pass | bcrypt / SHA-256 |
| Password-reset and verification tokens stored hashed | Pass (was Fail) | every store keys them by `localauth.HashVerificationToken` (SHA-256) and never writes the raw value (CWE-256) |
| A reset link works once, even under a race | Pass (was Fail) | the token is consumed (`DeleteToken` → `Deleted`) before the password changes (CWE-367) |
| A reset applies the signup password policy | Pass (was Fail) | it used a hard-coded 8 |
| A reset ends the account's other sessions | Pass (was Fail) | `AfterPasswordReset`; `NewRevokeSessionsOnReset` revokes its refresh tokens, wired in the reference server (CWE-613) |
| Signup doesn't reveal which emails have accounts | Pass with `RequireEmailVerification` (was Open) | a taken email gets the same "check your email" answer as a fresh one (no `user_id` in either), and the owner is mailed through `AccountExistsEmailSender` (CWE-204). Without verification a fresh signup logs in and a taken one can't, so it stays visible. TakenEmailLooksLikeAFreshOne\* (issue 408) |
| Cookie flags (`HttpOnly`, `Secure`, `SameSite`) | Pass (was Fail) | `httpauth` login cookies are Secure (opt-out `InsecureCookies`), Lax and HttpOnly, `loggedInSubject` included; `oa_token` is Secure behind https; the `oauth2` and `federatedauth` cookies (`oauthstate`, `oauthCallbackURL`, `pkce_verifier`, and their deletes) are Secure + HttpOnly + Lax |
| Session ID renewed on login and logout | Pass (was Fail) | `SetLoggedInSubject` calls `RenewToken` (CWE-384) |
| Session JWTs not usable as API access tokens | Pass (was Fail) | session JWTs carry `type: session`, which `APIMiddleware` refuses; `iat` no longer an hour in the future |
| No hard-coded session signing secret | Pass (was Fail) | `httpauth` fell back to a fixed public secret; now a random per-process one with a warning (CWE-798), and HS256 is pinned |
| Logout is POST with CSRF | Pass (was Fail) | `httpauth` `/logout` and the reference server's `/auth/logout` |
| Post-login and logout redirects stay on this site | Pass (was Fail) | `httpauth.LocalRedirect` on `?to=` and the federated `callbackURL` (CWE-601) |
| Login cookies set on every configured cookie domain | Pass (was Fail) | `SetLoggedInSubject` returned after the first domain |
| CSRF | Pass (was Partial) | double-submit with `SameSite=Strict`, plus `Sec-Fetch-Site` / `Origin` checks that refuse same-site and cross-site posts, and with `SessionID` set tokens signed over the session (OWASP signed double-submit). The reference server binds to the login session with a key derived from `jwt.secret_key`, and marks the cookie Secure behind an https `public_url`. `csrf_binding_test.go`\* (issue 408) |
| Rate-limit keys can't be reset with a spoofed `X-Forwarded-For` | Pass (was Fail) | `core.ClientIP` reads it only from configured `TrustedProxies`, right to left (CWE-348) |
| Brute-force limits on login and the password grant | Pass (was Partial) | per address + username, plus a per-username lockout the password grant now has too; on by default in the reference server (`rate_limit`) |
| Limits on signup and forgot-password | Pass (was Fail) | per address, and forgot-password per email too (CWE-770) |
| Device user-code guessing limited | Pass (was Fail) | `MountDeviceFlow` always installs a per-address limiter (RFC 8628 §5.1) |

### Admin interface

| Requirement | Status | Notes |
|---|---|---|
| RFC 7592 token scoped to its own client | Pass | constant-time compare against that client's stored token |
| Admin API key compared in constant time | Pass | `admin/auth.go` |
| JWKS exposes only public keys | Pass | symmetric keys skipped |
| A nil `AdminAuth` fails closed | Pass (was Fail) | nil now answers 401; open access is `NewNoAuth()` on purpose (CWE-306) |
| Reference server refuses `admin_auth: none` | Pass (was Fail) | `none` needs `allow_open: true`, and an unset type is an error |
| DCR registration without the admin key | Pass (was not possible) | `admin.InitialAccessTokenAuth` (RFC 7591 §3) as `AppRegistrar.RegistrationAuth` admits `POST /apps/dcr` and nothing else; `admin_auth.dcr_initial_access_tokens` in the reference server, 32 bytes minimum. `dcr_initial_access_token_test.go`\* (issue 408) |
| Body limits and rate limiting on admin routes | Pass (was Fail) | 64 KiB on DCR and rotate; `AuthRateLimiter` per address, before the key is checked |
| Rotation grace period bounded | Pass (was Fail) | at most `MaxRotationGracePeriod` (7 days); an unparseable value is a 400 |
| Dashboard doesn't list every client to any user | Pass (was Fail) | the list is admin-API only |
| Bulk eviction endpoint | Not applicable | no such endpoint exists |

## Input validation

Audited October 2026, against issue 88's "Input Validation" section and the RFC 6749 §5.2 error
rows. The token endpoint and request bodies came first, then `/authorize`, PAR, PKCE and the
device flow; DCR and metadata follow.

| Requirement | Ref | Status | Notes |
|---|---|---|---|
| A client gets only its registered scope | RFC 6749 §3.3, RFC 7591 §2 | Pass (was Fail) | `client_credentials` and the password grant refuse a scope outside the registration with 400 `invalid_scope`, and grant the registered scope when none is asked for. A registration without `scope` places no limit. `token_input_hardening_test.go`\* |
| A client uses only its registered RAR types | RFC 9396 §5 | Pass (was Fail) | `authorization_details_types` checked on the same grants; 400 `invalid_authorization_details` |
| A registration lookup failure fails closed | — | Pass | a store error is `server_error`, not "no registration", so an outage can't lift a client's limits |
| `client_credentials` tokens name their client | RFC 9068 §2.2 | Pass (was Fail) | `client_id` claim, which revocation ownership and the tenant check read |
| `invalid_grant` is 400 | RFC 6749 §5.2 | Pass (was Fail) | the password grant answered a wrong password with 401; Keycloak answers 400 too |
| Malformed `authorization_details` is the client's error | RFC 9396 §5 | Pass (was Fail) | the password grant turned it into a 500 |
| `invalid_client` 401 carries `WWW-Authenticate` | RFC 6749 §5.2 | Pass (was Fail) | `Basic realm="token"` |
| Server errors say nothing internal | CWE-209 | Pass (was Fail) | the token endpoint logs a `server_error`'s detail and sends "internal server error"; store errors (hosts, users) used to reach the client |
| Request bodies are bounded | CWE-770 | Pass (was Fail) | 64 KiB on the token endpoint (413) and, via `httpauth.CapRequestBody`, on introspection, revocation, PAR, device authorization and verification, `/authorize` POST, sessions, API keys, and the login, signup, forgot / reset password and link-credentials forms. Go read up to 10 MB of form, any amount of JSON, and spooled multipart to disk. `body_limit_test.go`\* |


### Authorization endpoint, PAR, PKCE, device flow

| Requirement | Ref | Status | Notes |
|---|---|---|---|
| A pushed request survives the consent screen | RFC 9126 §4 | Pass (was Fail) | the consent form dropped `request_uri`, so Approve re-read the hidden inputs as a fresh request: the reference was never spent, and with `RequirePushedRequests` Approve was refused. The form now carries it. PushedRequestSurvivesConsentAndIsSpentOnce\* |
| A pushed request issues one code | RFC 9126 §4, CWE-367 | Pass (was Fail) | `IssueCode` spends the reference before minting; `ConsumePushedAuthorizationRequestResponse.Consumed` is true for exactly one caller (GORM: compare-and-set). It used to consume after minting and only log a failure. PushedRequestIssuesOneCode\*, `partest` ConsumeSucceedsOnce |
| `request_uri` comes with `client_id` | RFC 9126 §4 | Pass (was Fail) | RequestURINeedsClientID\* |
| PKCE challenge and verifier have the RFC shape | RFC 7636 §4.1, §4.2 | Pass (was Fail) | S256 challenge: 43 base64url characters; plain challenge and every verifier: 43 to 128 unreserved. A short verifier verified against its own challenge. CodeChallengeShape\*, CodeVerifierShape\* |
| The registered scope bounds `/authorize` and device authorization | RFC 6749 §3.3 | Pass (was Fail) | `invalid_scope` on the redirect (or 400 at the device endpoint); the registered default when none is asked for. RegisteredScopeIsEnforced\*, DeviceAuthorizationHonorsTheRegisteredScope\* |
| `/authorize` without a client registry fails closed | RFC 6749 §3.1.2, CWE-601 | Pass (was Fail) | with neither `AppStore` nor `RedirectURIValidator` it sent codes to any `redirect_uri`; now it refuses unless `AllowAnyRedirectURI` (test fixtures). NoRegistryFailsClosed\* |
| A client can be required to use PAR | RFC 9126 §6 | Pass (was not implemented) | `require_pushed_authorization_requests` in DCR, `core.AppRegistration` and every app store; `/authorize` refuses that client's direct requests. RegisteredRequirementIsEnforced\*, `appstoretest` AllFieldsRoundTrip |

### Dynamic client registration

| Requirement | Ref | Status | Notes |
|---|---|---|---|
| Redirect URIs are real URLs, refused as `invalid_redirect_uri` | RFC 7591 §3.2.2, RFC 6749 §3.1.2 | Pass (was Partial) | userinfo and an empty https host are refused too, and every redirect problem answers `invalid_redirect_uri` (was `invalid_client_metadata`). BadRedirectURIs\* |
| Only supported auth methods and grant types | RFC 7591 §2 | Pass (was Fail) | an unknown method or grant is `invalid_client_metadata`; a public client can't take `client_credentials`; `authorization_code` needs a `redirect_uri`. UnknownAuthMethodAndGrantType\* |
| The stored auth method is the echoed one | RFC 7591 §2 | Pass (was Fail) | the response said `client_secret_post` while `""` was stored, so a client reading its registration back (RFC 7592) saw a different method from the one it was told. Both are now `client_secret_basic`, the RFC default. EchoedAuthMethodIsTheStoredOne\* |
| A public client gets no secret | RFC 7591 §2 | Pass (was Fail) | `none` used to be issued (and stored) a secret. PublicClientGetsNoSecret\* |
| DCR server errors say nothing internal | CWE-209 | Pass (was Fail) | logged, with "internal server error" in the response |

### Metadata, resource metadata, FS stores

| Requirement | Ref | Status | Notes |
|---|---|---|---|
| Metadata advertises only supported response types | RFC 8414 §2 | Pass (was Fail) | the reference server listed `token` (implicit); now `code` only, and only with `code_flow` on. `serverASMetadata`, `cmd/oneauth-server/metadata_test.go`\* |
| The advertised revocation endpoint is served | RFC 8414 §2, RFC 7009 | Pass (was Fail) | the server advertised `/oauth/revoke` and answered 404; it now mounts `oa.RevocationHTTPHandler()` |
| RFC 9207 `iss` on the authorization response | RFC 9207 §2, FAPI 2.0 §5.3.2.1 | Pass (was Fail) | the server never turned it on; with `code_flow` it now emits and advertises it |
| `none` advertised when public clients exist | RFC 8414 §2 | Pass (was Fail) | listed with `code_flow` on, where DCR can register public clients |
| Resource metadata with several authorization servers | RFC 9728 §2 | Pass (was Fail) | `MountProtectedResource` registered the same pattern twice and panicked; each pattern is now mounted once. SeveralAuthorizationServers\* |
| FS identity and channel files never serve another key | CWE-706 | Pass (was Fail) | file names are lossy (`filepath.Base`, `safeName`), so `x/email:victim@example.com` read and overwrote the victim's identity, and `a:b@` read `a_b@`'s password hash. Both stores now check the record's own key and return `fs.ErrKeyCollision`. `key_collision_test.go`\* |

## Tokens and keys

Audited October 2026, against issue 88's "Token Security" and "Key Management" sections, RFC
8725 (JWT best practices), RFC 6750 and RFC 7009. Like the HTTP surface, the fixes land across
several PRs, and rows still Open name the part of issue 88 they're waiting on.

### Access tokens

| Requirement | Ref | Status | Code | Test |
|---|---|---|---|---|
| Algorithm pinned per key, `none` refused | RFC 8725 §3.1, CVE-2015-9235 | Pass | `jwtValidator` / `APIMiddleware` check the method against the key's alg | `security_test.go` AlgNone, AlgConfusion |
| An empty HMAC key never verifies or signs | RFC 7518 §3.2, CWE-347 | Pass (was Fail) | `jwtValidator`, the middleware's inline path and `CreateAccessToken` refuse a zero-length key; the reference server refuses a `jwt.secret_key` under 32 bytes (`checkSigningSecret`) | EmptyHMACKeyNeverVerifies\*, HS256SecretMustBeLongEnough\* |
| `exp` required | RFC 8725 §3.10, RFC 9068 §2.2 | Pass (was Fail) | `accessTokenParserOptions` (`jwt.WithExpirationRequired`) | ExpIsRequired\* |
| Other JWTs from the same key aren't access tokens | RFC 8725 §3.11, §3.12 | Pass (was Fail) | `checkAccessTokenKind` refuses a `typ` other than `JWT` / `at+jwt` and a `type` claim other than `access`, so logout tokens, ID-JAGs and sessions fail | OtherJWTKindsAreNotAccessTokens\* |
| An OIDC provider's ID tokens aren't access tokens | RFC 8725 §3.11, RFC 9068 §4 | Pass (was Fail) | Keycloak signs ID tokens with the access token's key, header `typ` and `aud`; `checkAccessTokenKind` refuses a `typ` claim other than `Bearer` / `DPoP` | Keycloak OnlyTheAccessTokenIsAnAccessToken\*, OtherJWTKindsAreNotAccessTokens\* |
| A tenant's key signs only for that tenant | CWE-347 | Pass (was Fail) | `checkTenantKey`: a key registered to a client needs a matching `client_id` claim | TenantKeySignsOnlyForItsTenant\* |
| Custom claims can't set authorization claims | RFC 9068 §2.2 | Pass (was Partial) | `issuanceReservedClaims` adds `nbf`, `scope`, `azp`, `sid`, `act`, `may_act`; `client_id` only when the grant had none | CustomClaimsCannotOverrideAuthorizationClaims\* |
| `WWW-Authenticate` per RFC 6750 | RFC 6750 §3, §3.1 | Pass (was Partial) | no `error` without a token, `invalid_token` for a refused one, 403 `insufficient_scope` with `scope`, and `resource_metadata` (RFC 9728 §5.1) | BearerChallenges\* |
| Session cookies aren't accepted as access tokens, and access tokens aren't accepted as sessions | RFC 8725 §3.11 | Pass (was Fail) | `httpauth` `verifyJWT` and the reference server's `parseJWTCookie` require `type: session` (and `exp`, HS256 in the server) | `session_type_test.go`\*, AccessTokenIsNotASessionCookie\* |
| A token the AS signed verifies with the AS's key | — | Pass (was Fail) | `resolveKey` uses the validator's own key for its own `kid`; it used to fall back to the `client_id` claim and check against that client's key | ASTokenNamingARegisteredClientVerifies\* |
| Revocation only for the client the token was issued to | RFC 7009 §2.1, CWE-639 | Pass (was Fail) | `RevokeRequest.ClientID`, `ErrRevokeNotOwner` → 400 `invalid_request` (as Keycloak answers) | AccessTokenOfAnotherClientIsRefused\*, RefreshTokenOfAnotherClientIsRefused\* |
| Revocation verifies an access token before blacklisting its `jti` | CWE-347 | Pass (was Fail) | `TokenRevokerConfig.Validator` | UnverifiedTokenNeverReachesTheBlacklist\* |
| Revocation needs `token`, and searches every type whatever the hint | RFC 7009 §2.1 | Pass (was Fail) | missing `token` is 400 `invalid_request` (as Keycloak answers); a `refresh_token` hint no longer stops the access-token search | MissingTokenIsInvalidRequest\*, `revocation_test.go` EmptyToken |
| Introspection `token_type` is the access-token type | RFC 7662 §2.2 | Pass (was Fail) | `Bearer` / `DPoP`, was the literal `access_token` | TokenTypeIsTheAccessTokenType\* |
| Introspection covers refresh tokens | RFC 7662 §2.1 | Pass (was not implemented) | `NewTokenIntrospectorWithRefreshStore`; `token_type_hint` orders the search | Introspection_RefreshTokens\* |
| jwt-bearer assertions need `exp` and a configured audience | RFC 7523 §3 | Pass (was Fail) | `ValidateAssertion` requires `exp` and refuses when it has no audience to compare (it used to accept any `aud`) | ExpIsRequired\*, NoAudienceConfiguredRefuses\* |
| A jwt-bearer assertion with a `jti` is single-use | RFC 7523 §3, CWE-294 | Pass (was Fail) | keyed by `iss` + `jti` in the granter's `ReplayStore` | AssertionWithJTIIsSingleUse\* |
| An authorization code redeemed twice at once yields tokens once | RFC 6749 §4.1.2, CWE-367 | Pass (was Partial) | the store's delete is the gate, and the loser now gets `invalid_grant` instead of 500 | RacingRedemptionIsInvalidGrant\* |
| Tokens from a redeemed code name their client | RFC 9068 §2.2 | Pass (was Fail) | `client_id` was missing, so revocation ownership and tenant checks couldn't see it | AccessTokenNamesTheClient\* |
| Tokens from a code redeemed twice are revoked | RFC 6749 §4.1.2 (SHOULD), RFC 9700 §4.5 | Pass (was Open, #429) | a redeemed code is marked used and kept until its access token expires; a second presentation blacklists that token's `jti` and revokes the refresh family, and a reuse racing the first redemption makes that one refuse too | AuthCodeReuse\*, ConsumeOnce / ReuseBeforeRecord (`authcodetest`) |
| Refresh rotation has one winner in GORM | RFC 9700 §4.14.2, CWE-367 | Pass (was Fail) | the revoke is a compare-and-set on `revoked` | RotationRaceHasOneWinner\* |
| Refresh families have an absolute lifetime | RFC 9700 §4.14.2 | Pass (was Fail) | rotation keeps the family's `ExpiresAt` in FS, GORM and GAE, so a family lasts at most `TokenExpiryRefreshToken` (7 days) | RotationKeepsTheFamilyExpiry\* (all three stores; GAE under `make testds`) |

### Keys

| Requirement | Ref | Status | Notes |
|---|---|---|---|
| Thumbprint kid per RFC 7638 | RFC 7638 §3.1 | Pass | pinned to the RFC's example (`NzbLsXh8…`) by `utils/jwk_rfc7638_test.go` |
| `EncryptedKeyStorage` fails closed | CWE-311, CWE-354 | Pass (was Fail) | `ErrKeyDecrypt` for a wrong master key, tampering, or plaintext without `AllowLegacyPlaintext`; it used to return the stored bytes as the key. `encrypted_failclosed_test.go`\* |
| A stored ciphertext opens only for its own record | NIST SP 800-38D §5.2.1.1 | Pass (was Fail) | `oaenc1:` records carry AAD over client, alg and kid. CiphertextOnlyOpensForItsRecord\* |
| Retired keys encrypted at rest | CWE-312 | Pass (was Fail) | `EncryptedKidStorage`, the same format and failure rules as `EncryptedKeyStorage`; the reference server wraps its kid store under the key store's master key. `encrypted_kid_test.go`\*, `cmd/oneauth-server/kidstore_test.go` |
| A rotation's grace period keeps the old key verifying | RFC 7517 §4.5 | Pass (was Fail in the reference server) | `OneAuthConfig.KidStore` sits behind `KeyStore` in the validator's lookup; the reference server builds one and gives it to `AppRegistrar`, which used to have none, so `grace_period` was accepted and ignored. RetiredKeyVerifiesDuringItsGracePeriod\* |
| Expired grace-period keys are swept | — | Pass (was Fail) | the reference server calls `CleanExpired` every 10 minutes; lookups already skip expired kids |
| RSA signing keys at least 2048 bits | RFC 7518 §3.3, FAPI 2.0 §5.4.1 | Pass (was Fail) | `utils.CheckRSAKeySize` in `ParsePublicKeyPEM`, `ParsePrivateKeyPEM` and the JWK parser, so a short key fails when it's loaded, remote JWKS included. ShortKeysAreRefusedOnLoad\* |
| JWKS 304 carries ETag and Cache-Control | RFC 9110 §15.4.5 | Pass (was Fail) | and `If-None-Match` takes lists, `*` and weak tags (§13.1.2). NotModifiedKeepsCacheHeaders\* |
| JWKS `use` and `key_ops` | RFC 7517 §4.3 | Pass | both are sent (`sig`, `["verify"]`); §4.3 discourages that but allows it when they agree, which they do, and existing tests pin `key_ops` |

### Scans

- `govulncheck ./...` (v1.9.0): no reachable vulnerabilities.
- gitleaks v8.21.2 over 498 commits: no leaks.
- gosec: v2.21.4 and v2.22.4 don't build under Go 1.27, and v2.29.0 only runs its AST rules
  (type checking fails on export data version 5). Those report 23 G101 "hardcoded credentials"
  hits, all on constants such as grant-type URNs and header names.
- `make audit` runs all three at those pinned versions through `go run`, so it needs nothing
  installed. CI's govulncheck uses the same pin.
- CodeQL: no open alerts. Two are dismissed with a reason: the OIDF harness's
  `InsecureSkipVerify` (test code), and SHA-256 over an HMAC secret to derive its kid (not
  password storage; the HS256 signature is already an equal offline oracle).

