# CLAUDE.md — OneAuth

## What is OneAuth?

Go authentication library with unified local/OAuth auth, multi-tenant JWT, and federated resource server auth. See [README.md](README.md) for full overview.

## Repository Structure

Each subpackage has a `SUMMARY.md` with detailed contents.

| Package | What | Details |
|---------|------|---------|
| `core/` | Foundation types, store interfaces, tokens, scopes, RFC 9396 AuthorizationDetail | [core/SUMMARY.md](core/SUMMARY.md) |
| `keys/` | Key storage, JWKS, EncryptedKeyStorage, KidStore | [keys/SUMMARY.md](keys/SUMMARY.md) |
| `admin/` | AdminAuth, AppRegistrar, DCR (RFC 7591), MintResourceToken | [admin/SUMMARY.md](admin/SUMMARY.md) |
| `apiauth/` | APIAuth, APIMiddleware, OneAuth core, introspection, revocation | [apiauth/SUMMARY.md](apiauth/SUMMARY.md) |
| `localauth/` | Local auth (signup, login, password reset) | [localauth/SUMMARY.md](localauth/SUMMARY.md) |
| `httpauth/` | HTTP middleware, CSRF, session management | [httpauth/SUMMARY.md](httpauth/SUMMARY.md) |
| `client/` | Client SDK (AuthClient, ClientCredentialsSource, discovery) | [client/SUMMARY.md](client/SUMMARY.md) |
| `stores/` | FS, GORM, GAE backend implementations | `stores/*/SUMMARY.md` |
| `sshkeys/` | Ed25519 SSH keypair generator (own go.mod). Returns OpenSSH PEM + `authorized_keys` line; private PEM persists encrypted via `EncryptedKeyStorage` automatically. | [sshkeys/SUMMARY.md](sshkeys/SUMMARY.md) |
| `appstoretest/` / `deviceauthtest/` / `keystoretest/` / `kidstoretest/` | Shared contract test suites — every store backend runs `RunAll(t, factory)` to prove behavioral parity | per-package README |
| `examples/` | 10 progressive interactive examples with demokit | [examples/README.md](examples/README.md) |
| `tests/keycloak/` | Keycloak interop + RAR conformance tests | [tests/keycloak/README.md](tests/keycloak/README.md) |
| `cmd/oneauth-server/` | Config-driven reference server (#194 tracks POC→production-grade ambition) | `cmd/oneauth-server/config.go` |
| `cmd/oneauth/` | Cobra-based client CLI — `oneauth token {browser,client-credentials,password,refresh}` | [cmd/oneauth/SUMMARY.md](cmd/oneauth/SUMMARY.md) |

## Multi-Module Structure

Go workspace with separate sub-modules for heavy backends. See `go.work` for the full list. Sub-modules have `replace` directives for local dev. See [docs/MIGRATION.md](docs/MIGRATION.md) for consumer guide.

## Build & Test

```bash
make test          # Unit tests
make e2e           # E2E tests (in-process)
make testkcl       # Keycloak + RAR issuer interop (auto-starts Docker)
make testall       # Everything (9 stages + report)
make tag V=v0.0.X  # Tag all modules
make pushtag V=v0.0.X  # Push all tags
```

Full command reference: see `Makefile` header comments and `make help` (if available).

## Key Architecture Decisions

- **Client library, not a proxy** — embeddable. `cmd/oneauth-server/` is a reference deployment, not the product.
- **gRPC-shape convention everywhere** — every transport-agnostic interface follows `MethodName(ctx context.Context, req *XRequest) (*XResponse, error)`. Applies to `apiauth/` (`TokenIssuer` / `Validator` / `Introspector` / `Revoker` / `ClientAuthenticator`) and `admin/` (`ClientRegistrationManager` / `ClientRegistrar`). HTTP handlers are thin wrappers. Issue #110 / #175.
- **Storage-agnostic** — interface-based, three backends (FS, GORM, GAE) for KeyStore + UserStore + AppRegistrationStore.
- **Composed interfaces, no god objects** — each impl takes only the deps it needs.
- **Grouped hooks** — `TokenHooks`, `AuthHooks`, `ClientHooks`, `SecurityHooks`. See `apiauth/hooks.go`.
- **`Mount*` helpers for related route groups** — when a feature mounts more than one route on a mux, ship a `apiauth.MountX(mux, cfg)` helper so production and tests share one wire-up. Precedent: `apiauth.MountASMetadata` (RFC 8414), `apiauth.MountDeviceFlow` (RFC 8628). The helper owns route placement and handler construction; callers supply dependencies + integration points (session lookup, CSRF token source, optional middleware). Browser-form routes get the caller's middleware; machine endpoints don't.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for rationale and [docs/ROADMAP.md](docs/ROADMAP.md) for what's shipped vs in flight.

## Standards Compliance

| Endpoint | Handler | RFC |
|----------|---------|-----|
| `POST /api/token` (password / refresh / client_credentials / jwt-bearer / token-exchange / device_code / authorization_code) | `TokenEndpointHandler.ServeHTTP` (dispatches to `TokenIssuer` + `AuthorizationCodeGranter` + `DeviceCodeGranter` + `JwtBearerGranter` + `TokenExchanger`) | RFC 6749, 7523, 8693 |
| `POST /oauth/introspect` | `IntrospectionHandler` | RFC 7662 |
| `POST /oauth/revoke` | `RevocationHandler` | RFC 7009 |
| `GET /.well-known/openid-configuration` | `NewASMetadataHandler` | RFC 8414 |
| `GET /.well-known/jwks.json` | `JWKSHandler` | RFC 7517 |
| `GET /.well-known/oauth-protected-resource` | `NewProtectedResourceHandler` | RFC 9728 |
| `POST /apps/dcr` | `DCRHandler` | RFC 7591 |
| `GET / PUT / DELETE /apps/dcr/{client_id}` | `DCRManagementHandler` | RFC 7592 |
| AS-initiated `POST <backchannel_logout_uri>` with `logout_token` | `BCLDispatcher` + `LogoutTokenIssuer` | OIDC Back-Channel Logout 1.0 |
| `POST /device/authorize` + `POST /api/token` (`grant_type=…:device_code`) | `DeviceAuthorizationHandler` + `DeviceCodeGranter` | RFC 8628 |
| `GET / POST /authorize` + `POST /api/token` (`grant_type=authorization_code`) | `AuthorizationHandler` + `AuthorizeVerificationHandler` + `AuthorizationCodeGranter` (via `MountAuthorize`) | RFC 6749 §4.1 + RFC 7636 (PKCE S256) + RFC 9207 (`iss` on redirect) |
| Authorize-redirect `?iss=` query param | (issuer URL on redirects) | RFC 9207 |
| `DPoP` proof header on `POST /api/token` (`cnf.jkt` + `token_type: DPoP`) | `DPoPProofValidator` (`apiauth/dpop.go`) via `OneAuthConfig.DPoP` | RFC 9449 §5 |
| `Authorization: DPoP <token>` + proof on resource requests (`ath`, `cnf.jkt` match, §7.2 downgrade refusal) | `APIMiddleware.DPoP` + `RequireDPoP` | RFC 9449 §7 |
| `DPoP-Nonce` challenge / retry (`use_dpop_nonce`) | `NonceSource` + `DPoPConfig.NoncePolicy`; client retries automatically | RFC 9449 §8 (AS) / §9 (RS) |
| `dpop_jkt` on `GET / POST /authorize` (binds the code to the key) | `AuthorizationRequest.DPoPJKT` → `AuthorizationCodeGrant` | RFC 9449 §10 |
| `POST /par` + `request_uri` at `/authorize` | `PARHandler` (via `MountAuthorize` when `PushedStore` is set) | RFC 9126 + RFC 9449 §10.1 |
| `traceparent` / `tracestate` inbound + outbound (SEP-414 / #254) | `tracing/` + per-handler `TracerProvider` | [W3C Trace Context](https://www.w3.org/TR/trace-context/) |
| `POST /api/token` (`requested_token_type=...:id-jag` issuance / ID-JAG redemption for MCP EMA) | `TokenExchanger` + `IDJAGIssuer` (`apiauth/id_jag.go`) → `JwtBearerGranter` | draft-ietf-oauth-identity-assertion-authz-grant-04 + MCP EMA / SEP-990 |

ID-JAG issuance is opt-in (`OneAuthConfig.IDJAGIssuer`); redemption rides the jwt-bearer grant with single-use `jti` + `client_id` binding. See [docs/oauth/RFC_8693.md](docs/oauth/RFC_8693.md) and [docs/oauth/RFC_7523.md](docs/oauth/RFC_7523.md).

RFC 9396 (Rich Authorization Requests) supported on token endpoint, introspection, and middleware. See `core/authorization_details.go`. Full Authlete-superset gap analysis: [docs/gaps/AUTHLETE_GAP_ANALYSIS.md](docs/gaps/AUTHLETE_GAP_ANALYSIS.md), tracked under #163.

## Conventions

- Each subpackage has a `SUMMARY.md` for LLM discoverability.
- **Documented-contract bar for store backends.** Every exported method on a `stores/*` (or sibling-submodule) store carries a doc comment capturing the WHY of the contract: error-sentinel mapping (`datastore.ErrNoSuchEntity` → `core.ErrAppNotFound` etc.), idempotency promises, transactional scope, non-obvious dances (Get-then-Delete, family-revoke-outside-transaction). Precedents: `stores/gae/appstore.go` (PR 234), `stores/gae/keystore.go`/`kidstore.go`/`stores.go`/`models.go` (#236 / #288). Match the polished precedent, not the closest one — sparse local style isn't license to ship undocumented public API.
- Security tests must include `// See:` links to RFC/CVE/CWE references.
- `docs/oauth/` guides cite code by symbol (`apiauth/authorize.go` `ParseAndValidate`), never `file.go:NNN`; line numbers drifted by hundreds between June and October 2026.
- Use `GH_TOKEN="$GH_PERSONAL_TOKEN"` for gh CLI.
- Keep new test groups in separate `_test.go` files (don't bloat existing ones).
- Sub-modules need `GOWORK=off` when running outside workspace.
- Examples split into `main.go` (server, `--serve` for real ports) + `walkthrough.go` (demokit client demo). Slim `README.md` + generated `WALKTHROUGH.md` via `make walkthrough`.

## Gotchas

- **The reference server refuses unsafe configs at startup.** It needs an explicit `admin_auth.type` (`none` also needs `allow_open: true`), and refuses a plain-http `public_url` on a non-loopback host unless `server.allow_insecure_http`. Env-only setups pass `PUBLIC_URL`; a new launcher that forgets it fails with a message naming the field.
- **DCR needs `AppRegistrar.IssuerBaseURL` off loopback.** Without it, a request with a non-loopback `Host` gets a 500, since `registration_client_uri` is never built from `Host`. httptest fixtures post with `Host: example.com`, so DCR tests set `IssuerBaseURL = "http://example.com"`.
- **`make server-css` after changing template classes.** The reference server ships a prebuilt Tailwind stylesheet (`cmd/oneauth-server/static/app.css`) under a `'self'`-only CSP, so a class used nowhere when it was last built has no style.
- **Run the Datastore emulator with `--consistency=1.0`.** Its default is 0.9, where a query misses a recent write about one time in ten, and the GAE store tests fail at random (9 runs in 10 before issue 395). `make upds` / `make testds` pass it; a container started some other way may not, so `make downds` first if `testds` turns flaky.
- **gofmt is a CI gate.** The `gofmt` step in `ci.yml` checks every tracked `.go` file in every module; `make fmt` fixes, `make fmtcheck` checks. The one-time cleanup commit is in `.git-blame-ignore-revs` (`git config blame.ignoreRevsFile .git-blame-ignore-revs`).
- **Keycloak port collision**: Default `KC_PORT=8180`, default `RAR_PORT=8181`. `mcpkit-keycloak` (other project) often holds 8180; pass `make upkcl KC_PORT=8281 && make testkcl KC_PORT=8281` to avoid both that and the RAR_PORT clash.
- **RAR test issuer**: lives at `cmd/oneauth-server/deploy-examples/rar-test.yaml`, started inside `make testkcl`. Old `cmd/rar-test-issuer/` is retired.
- **JWKS only exposes asymmetric keys.** HS256 secrets are *correctly* omitted (`keys/jwks_handler.go`). Tests/services that validate via `JWKSKeyStore` must mint RS256/ES256 tokens — set `jwt.signing_alg: RS256` + `jwt.private_key_path` (or `ephemeral_signing_key: true` for tests).
- **Asymmetric signing in cmd/oneauth-server**: `jwt.signing_alg=RS256` requires either `jwt.private_key_path` or `jwt.ephemeral_signing_key: true` — neither set fails loudly. Auto-generated ephemeral keys match the algorithm (RSA-2048 or P-256) and invalidate tokens on restart.
- **Local main can be locked by another worktree**. When working in a stacked branch, cut new branches from `origin/main` directly (`git checkout -b feat/X origin/main`) — don't try to `git checkout main` if the `conformance/` or `rfc-extensions/` worktrees own it.
- **`go.work` Go directive**: stdlib CVEs require keeping the `go` directive across all 9 modules in lock-step (root + workspace + 7 sub-modules). `make vulncheck` is the gate.
- **Backlinks via `#N`**: only when the cross-reference is genuinely the audit trail you want. For background-only references, use plain text (`"issue 123"` not `#123`) — see global `~/.claude/CLAUDE.md` for the full rule.
- **`make testkcl` reuses a running container.** It only starts Keycloak when one is not already up, so a realm edited in `tests/keycloak/realm.json` does not reach a container started earlier. Run `make downkcl` first whenever the realm changed, or the tests run against the old realm and fail in ways that look like code bugs.
- **The test realm has no built-in client scopes.** `tests/keycloak/realm.json` lists `clientScopes` explicitly, which replaces Keycloak's defaults, so `openid` / `email` / `profile` referenced by clients don't exist (Keycloak logs "Referenced client scope ... doesn't exist. Ignoring"). Since Keycloak 25 `sub` comes from the `basic` scope, which the realm now defines itself; a new client needs `basic` in its `defaultClientScopes` or its tokens carry no `sub`. Keycloak 26.x also refuses to introspect a token unless the calling client is in its `aud` (the log says "is not in the token audience"), hence the `self-audience` mapper on `test-confidential`.
- **Keycloak's DPoP is a preview feature.** `upkcl` / `testkcl` pass `--features=dpop`. A `services:` block in GitHub Actions has no slot for arguments to the container's command, so `keycloak-interop.yml` runs `make testkcl` (an explicit `docker run`) rather than declaring Keycloak as a service.
- **Keycloak answers `/authorize` errors with JSON when `Accept` lists `application/json`**, which the headless openers send. It puts its message in `error` (`{"error":"Invalid parameter: redirect_uri"}`), so `AuthorizeError.Code` against Keycloak is a sentence rather than a registered RFC 6749 code. oneauth's own `/authorize` negotiates the same way (`acceptsJSON` in `apiauth/authorize_verification_handler.go`).
- **`err.Error()` from `LoginWithBrowser` contains the whole authorize URL** when the opener fails (`BrowserOpenError`), so `Contains(err.Error(), "redirect_uri")` or `"client_id"` passes for any opener failure. Assert on the typed error's fields (`errors.As(err, &ae)`) instead. The old Keycloak test only passed that way.
- **The OIDF workflow is `workflow_dispatch` only and has never run.** There is no CI baseline for it. The Keycloak workflow runs `make testkcl` on PRs touching `apiauth/`, `client/`, `keys/`, `core/`, `cmd/oneauth-server/` or `tests/keycloak/`, and on pushes to main.
- **Diagrams are validated, not eyeballed.** `docs/site` renders ```mermaid fences with a pinned mermaid module; a fence with a syntax error becomes an error box on the live site. Parse every block with the real parser before pushing (`mermaid.parse` under jsdom). Two blocks in `AUTH_FLOWS.md` were broken for months because nothing rendered them: a bare `"` in a sequence message, and `;` in a note, each of which truncates a statement.
- **Publishing a doc needs a content shim plus a nav entry.** `docs/site/content/<section>/<slug>.html` carries front matter and one `renderMarkdownFile` call; `HeaderNavLinks.json` carries the link. The 34 pages under `specs/` were generated by a script run by hand, so a new `docs/oauth/` file is not published until someone regenerates them.
- **A DPoP proof is single-use, so retry paths mint a new one.** Its `jti` is consumed on first use and its `ath` names one specific access token, so any code that retries a request (the SDK's refresh-then-retry in `client/client.go` is the live case) must mint a fresh proof rather than resend. Reusing one looks fine against a single-node server with an in-memory `JTIStore`, which is exactly why it ships.
- **`AuthClient` defaults to `/auth/cli/token`** for `Login` and the automatic refresh whenever it has no AS metadata. A test pointing the SDK at an `apiauth` fixture mounted on `/api/token` needs `client.WithASMetadata(&client.ASMetadata{TokenEndpoint: server.URL + "/api/token"})`, or the client posts to a path the mux does not serve and the JSON decode fails with a confusing parse error.
- **DPoP `htu` behind a proxy.** The validator derives scheme from `r.TLS` and deliberately ignores `X-Forwarded-Proto` (trusting it would let a client choose the scheme its own proof is checked against). Behind a TLS-terminating proxy set `DPoPConfig.EndpointURL` (token endpoint, one exact URL) or `BaseURL` (resource server, joined to each request path), or every proof fails.
- **`WWW-Authenticate` params are comma-separated** (RFC 9110 §11.6.1, and RFC 9449 Figure 16). Space-separated params parse as one malformed parameter and a conforming client drops the error. A `Contains(header, 'error="invalid_token"')` assertion passes either way — assert the separator, or capture the real header.
- **`/authorize` without a client registry refuses every request** unless `AllowAnyRedirectURI` is set (on `AuthorizationHandler` or `AuthorizeMountConfig`). The shared e2e fixture (`tests/e2e/authserver_test.go`) and `testutil/server.go` set it, so a headless test there can't catch a redirect-matching bug. `tests/e2e/loopback_listener_test.go` builds its own server with the AppStore DCR writes into; copy that when the redirect itself is under test.
- **PKCE values must have the RFC 7636 shape.** An S256 `code_challenge` is exactly 43 base64url characters, and a `code_verifier` (or plain challenge) 43 to 128 unreserved characters. Fixtures with values like `"any-challenge"` or `"wrong-verifier"` now fail on shape before they reach the check they meant to test.
- **A redeemed authorization code stays in the store, marked used.** `ConsumeAuthorizationCode` replaced the delete, and the record lives until its access token expires so a reused code can revoke that token and the refresh family (issue 429). A test expecting `GetAuthorizationCode` to miss after redemption now finds it with `UsedAt` set. A custom `AuthorizationCodeStore` needs `ConsumeAuthorizationCode` and `RecordAuthorizationCodeTokens`, each atomic per record, and the access token is revoked only with `OneAuthConfig.Blacklist` set.
- **The GAE store tests run in CI's `gae` job** via `make testds`, which waits for the emulator to answer rather than sleeping. A container started by hand still needs `--consistency=1.0`.
- **A custom consent template must post `request_uri` back** (`authorizeConsentData.RequestURI`), or a pushed request loses its stored payload at Approve.
- **A refresh request has to name the token's client.** Since issue 395 the refresh grant refuses a token presented without its owner's `client_id` (and, for a confidential owner, its credentials). A test that mints a refresh token with a `ClientID` and redeems it with only `grant_type` + `refresh_token` now fails; only a token stored with no client redeems that way.
- **A `LoginWithBrowser` test against Keycloak** needs an opener that fills in Keycloak's login form: `keycloakPasswordLogin` in `tests/keycloak/refresh_dpop_interop_test.go`. `FollowRedirects` and `ApproveConsent` stop at that form on purpose.
- **The SDK's own loopback listener binds `localhost`.** `LoginWithBrowser` without a `Listener` sends `http://localhost:<port>/callback`, and `/authorize` relaxes only the port, so a DCR registration for it must say `localhost`, not `127.0.0.1`.
- **Hand-minted test tokens need `exp`, and test HMAC secrets need 32 bytes.** Since issue 88's token slice the validator requires `exp`, refuses an empty key, and the reference server refuses a `jwt.secret_key` under 32 bytes. A test helper that mints without `exp` gets a 401 that looks like a key mismatch.
- **A token kind is told apart by `typ` header, `type` claim and Keycloak's `typ` claim.** Logout tokens (`logout+jwt`), ID-JAGs, `type: session` JWTs and Keycloak ID tokens (`typ` claim `ID`) are refused as access tokens; a token with no `type` passes, because Keycloak's access tokens have none (their `typ` claim is `Bearer` or `DPoP`). A new JWT kind signed with the AS key needs its own `typ` or `type`, or it validates as an access token.
- **CodeQL reports errors as PR checks.** `ParseUnverified` on anything a request supplied is flagged even after the token was verified elsewhere, and so is SHA-256 over a field named like a secret. Take claims from the validator's `TokenInfo` (`ClientID`, `TokenID`, `ExpiresAt`), and compare keys directly instead of hashing them. A PR that sends user input into old flagged code gets that alert charged to it.
- **`EncryptedKeyStorage` refuses plaintext secrets.** A record that won't decrypt is `keys.ErrKeyDecrypt`, and a plaintext HMAC secret or private PEM in an encrypted store counts. A test that writes a secret to the inner store and reads it through the wrapper needs `AllowLegacyPlaintext`; a deployment turning encryption on over existing keys starts once with `key_store.migrate_legacy: true` (`KEYSTORE_MIGRATE_LEGACY=true`).
- **A key rotation's grace period needs a KidStore on both sides.** `AppRegistrar.KidStore` keeps the old key and `OneAuthConfig.KidStore` lets the validator find it; with either missing, `grace_period` is accepted and the old key stops verifying at once. The reference server builds one on the key store's backend (FS under `<path>/kids`) and sweeps it.
- **Deploy examples leave `jwt.issuer` empty so it follows `public_url`.** A pinned issuer disagrees with discovery as soon as `PUBLIC_URL` is overridden, and every token a client mints against the discovered issuer fails. `rar-test.yaml` pins its issuer on purpose for the Keycloak suite.
- **RSA keys under 2048 bits fail at load.** `ParsePublicKeyPEM`, `ParsePrivateKeyPEM` and the JWK parser refuse them, so a test fixture generating 1024-bit keys fails before any token is verified.
- **A registered client's `scope` limits what the token endpoint grants.** With an `AppStore`, `client_credentials` and the password grant answer 400 `invalid_scope` for a scope outside `AppRegistration.Scope`, and grant the registered scope when none is asked for. A test that registers a client with a scope and asks for another now fails; one that leaves `Scope` empty is unaffected.
- **Wrong credentials on the password grant are 400 `invalid_grant`** (RFC 6749 §5.2, and Keycloak agrees), not 401.
- **DCR stores `client_secret_basic` when no auth method is sent**, and echoes the same; a `none` client gets no secret. DCR also refuses unknown methods and grant types, and `authorization_code` without a `redirect_uri`, so a fixture registering `{"grant_types":["authorization_code"]}` alone now fails.
- **FS identity and channel stores refuse a key whose file holds another key's record** (`fs.ErrKeyCollision`). File names are lossy, so two keys can share one; before issue 88 the second key read and overwrote the first.
- **Client-assertion audiences don't come from forwarded headers.** `derivedAudience` uses `r.TLS` and `r.Host` only (like DPoP `htu`), and the token endpoint also accepts the issuer. Behind a TLS proxy set `OneAuthConfig.AcceptedAudiences`; the reference server sets it from `public_url`.
- **`OneAuthConfig.FAPI2`** is the FAPI 2.0 Security Profile switch: DPoP required, rotation off, `private_key_jwt` only with the issuer as a string `aud`, no password grant, no public clients (jwt-bearer and token-exchange authenticate the client even without a `client_id`), and `MountAuthorize` PAR-only with capped lifetimes (it panics without a `PushedStore`). It needs `DPoP` set, or every token request fails.
- **The reference server serves PAR with `code_flow.par.enabled`** (`required` refuses direct `/authorize`), on the code store's backend (memory or gorm). `fapi2: true` needs `dpop.enabled`, `jwt.signing_alg: ES256` and, with `code_flow` on, PAR; the server refuses to start otherwise. `deploy-examples/fapi-dpop.yaml` runs the whole profile.
- **FAPI client keys are ES256.** Under `FAPI2` only PS256 / ES256 / EdDSA client assertions pass, and oneauth can register only ES256 of those today, so an RS256 `private_key_jwt` client stops authenticating when FAPI is turned on.
- **CSRF refuses same-site posts.** `CSRFMiddleware` checks `Sec-Fetch-Site` and `Origin` on unsafe methods before the token; a test posting with `Origin` set to another host gets 403 even with a valid token. With `SessionID` set, a token minted before login stops validating after it (the next GET mints a new one).
- **Signup with verification answers the same for a taken email.** `{"message": "Check your email to finish signing up."}`, no `user_id`. Code that read `user_id` from that response needs another way to find the user.
- **`buildServer(cfg)` is the whole reference server.** `main()` only loads the config, runs the startup checks and listens. A test in `cmd/oneauth-server` builds the real handler with `buildServer` on an `httptest.NewUnstartedServer` (its listener address gives `public_url`); `newLoginFixture` in `login_next_test.go` adds a signed-up user and a DCR client. Anything `NewOneAuth` reads (stores, `AppStore`, keys) has to be in `OneAuthConfig`, since the granters are built at construction and a field set on `OneAuth` afterwards is never read (issue 438).
- **The OIDF harness bind-mounts `certs/` from the checkout that ran `make upoidf`.** Run `make downoidf` before removing that worktree, or the harness loses its truststore. MongoDB is in the `oidf-conformance_mongo-data` volume since issue 438, and nginx answers as `localhost.emobix.co.uk` inside the compose network so the harness's own browser reaches its callback.
- **`make testoidf` runs the whole FAPI 2.0 plan too**, 46 modules against a fresh server it starts on `:8889`, so it takes a while and refuses to run while something else holds that port. A module that should end in REVIEW or be skipped needs a whole-module `expected-review` (with `evidence`) or `expected-skip` entry in `known-gaps.yaml`; anything else must pass. `make exercise-fapi2 MODULE=<substring>` runs one module.
- **The reference server's own TLS is BCP 195** (`serverTLSConfig` in `cmd/oneauth-server/tls.go`): TLS 1.2 minimum, and on 1.2 only the four ECDHE + AES-GCM suites. A test client pinned to a CBC or ChaCha20 suite on TLS 1.2 fails the handshake.
- **Client assertions allow 10 seconds of clock skew** (`ClientAssertionClockSkew`, FAPI 2.0 §5.3.2.1) on `iat`, `nbf` and `exp`, and `iat` is checked against the clock. A test expecting an assertion expired by a few seconds to fail needs it more than 10 seconds past `exp`.
- **httptest URL needed before mount.** When a handler config requires the server's base URL (e.g., RFC 8628 `VerificationURI`), use `httptest.NewUnstartedServer(mux)` → read `server.URL` → mount → `server.Start()`. Avoids post-hoc handler mutation. Pattern in `tests/e2e/device_flow_test.go`.

## Issues and missions

Work is ranked by mission (labels and blocked-by links; `~/.claude/skills/retriage/queue.sh` prints the queue). No mission is active. The last one, #98 (the OIDF FAPI 2.0 Security Profile run), closed in v0.2.5, and `make testoidf` keeps its result from regressing. JARM (#409) is parked. A new issue gets a priority (`P0` to `P3`) and either a mission link or `waiting` with its trigger.

## Gap analyses

- [docs/gaps/AUTH0_GAP_ANALYSIS.md](docs/gaps/AUTH0_GAP_ANALYSIS.md) — vs Auth0 (full IdP-as-a-service)
- [docs/gaps/AUTHLETE_GAP_ANALYSIS.md](docs/gaps/AUTHLETE_GAP_ANALYSIS.md) — vs Authlete (semi-hosted OAuth backend); meta-tracker issue #163

## Federated Auth Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) or the [examples/README.md](examples/README.md) Cast of Characters for the full picture. Three projects collaborate: oneauth (auth library), massrelay (WebSocket relay), excaliframe (document app).

## Memories

Design lessons from past sessions in `memories/`. See `memories/MEMORY.md` for index. Always save memories to `memories/` (not `~/.claude/`).
