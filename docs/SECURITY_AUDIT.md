# Security & RFC compliance audit

This is the compliance matrix asked for in [issue 88](https://github.com/panyam/oneauth/issues/88).
Issue 88 covers a lot of ground (RFC 6749 through RFC 9728, the security checklist, FAPI 2.0),
so we're doing it one area at a time, and each area gets a section here once it's been walked
requirement by requirement. So far that's DPoP.

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
| 5 | Client's automatic refresh carries a proof | MUST | client | Pass (was Fail) | `client/client.go` `requestToken` → `executeTokenRequest` | RefreshThenRetryMintsAFreshProof\* |
| 5.1 | `dpop_signing_alg_values_supported` in AS metadata | SHOULD | AS | Pass | `apiauth/as_metadata.go:79` | e2e MetadataAdvertisesSigningAlgs |
| 5.2 | `dpop_bound_access_tokens` client metadata, enforced | MUST if supported | AS | Pass (was not implemented) | `apiauth/token_endpoint.go:478` `requireDPoP`; `core.AppRegistration`; DCR; all app stores | `dpop_require_test.go`\*, `admin/dcr_dpop_test.go`\*, `appstoretest` AllFieldsRoundTrip\* |
| 6.1 | `cnf.jkt` in the JWT, not forgeable through custom claims | MUST | AS | Pass | `token_validator.go:432` | CustomClaimsCannotForgeCnf |
| 6.2 | `cnf` in introspection, enforced by an RS that introspects | MUST | AS, RS | Pass | `token_introspector.go`, `introspection_client.go` | IntrospectionReportsConfirmation, EnforcesCnfFromIntrospection\* |
| 7.1 | `Authorization: DPoP`; 401 with `WWW-Authenticate: DPoP` and `algs` | MUST | RS | Pass | `apiauth/middleware.go:728` `challenge` | ChallengeAdvertisesBothSchemes, ChallengeParamsAreCommaSeparated |
| 7.2 | Bound token refused under the Bearer scheme | MUST | RS | Pass | `enforceBinding` | RejectsBoundTokenPresentedAsBearer; Keycloak interop |
| 8 | `use_dpop_nonce` + `DPoP-Nonce` at the token endpoint | MUST | AS | Pass | `dpopConfirmation` | TestNonce_TokenEndpointChallenge |
| 8 | Same at the PAR endpoint | MUST | AS | Pass (was Fail) | `apiauth/par.go:221` `resolveDPoPBinding` | `par_dpop_shared_test.go` NonceChallenge\* |
| 8.2, 9 | Client uses a `DPoP-Nonce` from any response | expected | client | Pass (was Partial) | `client/client.go:760` `rememberNonce` | UsesANonceFromASuccessful{Token,Resource}Response\* |
| 9 | `use_dpop_nonce` at the RS (401) | MUST | RS | Pass | `enforceBinding` | TestNonce_ResourceServerChallenge |
| 10 | Code bound by `dpop_jkt` refuses another key or no proof | MUST | AS | Pass | `authorize_granter.go:113` | `dpop_jkt_test.go` |
| 10.1 | PAR takes `dpop_jkt` or a proof, rejects a mismatch, checks its own `htu` | MUST | AS | Pass (was Fail with a shared validator) | `resolveDPoPBinding` | `TestPARDPoP_*`, MountAuthorize_PARSharesTheTokenEndpointValidator\* |
| RFC 9728 | `dpop_bound_access_tokens_required` advertised and enforced | — | RS | Pass | `protected_resource.go:56`, `APIMiddleware.RequireDPoP` | RequireDPoPRefusesBearer |

### FAPI 2.0 Security Profile (final), DPoP requirements

| § | Requirement | Status | How |
|---|---|---|---|
| 5.3.2.1 #4 | AS shall only issue sender-constrained access tokens | Pass (was not possible) | `OneAuthConfig.RequireDPoP` |
| 5.3.2.1 #12 | AS supports binding the authorization code to the DPoP key | Pass | `dpop_jkt` (RFC 9449 §10) |
| 5.3.2.1 #13 | Accept `iat` up to 10s ahead, reject more than 60s ahead | Pass | ±30s window; FAPIFutureIATEdges |
| 5.3.4 #5 | RS shall only accept sender-constrained tokens | Pass | `APIMiddleware.RequireDPoP` |
| 5.4.1 | Proof algs limited to PS256 / ES256 / EdDSA | Partial | `apiauth.FAPIDPoPAlgs()` gives ES256 + PS256; EdDSA is [issue 395](https://github.com/panyam/oneauth/issues/395) item 1 |
| 5.4.1 | RSA keys at least 2048 bits | Pass (was Fail) | `minDPoPRSABits`; RejectsShortRSAKey\* |
| 5.3.2.1 #9 | No refresh-token rotation | Open | OneAuth always rotates; [issue 395](https://github.com/panyam/oneauth/issues/395) item 2 |

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

Still open, all in [issue 395](https://github.com/panyam/oneauth/issues/395): EdDSA proofs,
an option to turn off refresh rotation for FAPI, DPoP config in `cmd/oneauth-server`, two
SDK refresh-path issues that aren't DPoP-specific, and one that's bigger than DPoP: the
refresh grant doesn't authenticate the client or check the token belongs to the `client_id`
sent with it (RFC 6749 §6). The DPoP check works around that by following the refresh
token's owner, but the grant itself still needs fixing.

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
