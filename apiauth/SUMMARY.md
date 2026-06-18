# apiauth/ — API Token Authentication

JWT-based API authentication: token issuance (login/refresh/client_credentials), validation middleware, API key support, and multi-tenant JWT verification.

## Contents
- **auth.go** — `APIAuth` (login/logout/refresh/client_credentials handlers, `CreateAccessToken`, `ValidateAccessToken`), `APIMiddleware` (`ValidateToken`, `RequireScopes`, `Optional`), context helpers (`GetUserIDFromAPIContext`, etc.)
- **as_metadata.go** — `ASServerMetadata` struct + `NewASMetadataHandler` for RFC 8414 / OIDC Discovery
- **logout_token.go** — `LogoutTokenIssuer` mints signed OIDC Back-Channel Logout 1.0 `logout_token` JWTs (events + sub/sid claim shape, `typ=logout+jwt` header) (issue 261)
- **bcl_dispatcher.go** — `BCLDispatcher` looks up clients with a registered `backchannel_logout_uri`, mints one logout_token per client, and POSTs application/x-www-form-urlencoded to each receiver. Async by default; SyncForTest flag for deterministic tests (issue 261)
- **device_auth_grant.go** — RFC 8628 Device Authorization Grant. `DeviceCodeGrantType` constant, `DeviceAuthorizationHandler` (`POST /device/authorize`: client validation, code mint, persistence), `APIAuth.handleDeviceCodeGrant` (`POST /api/token` branch: status mapping → `authorization_pending` / `slow_down` / `access_denied` / `expired_token` / token-issuance), `APIAuth.ApproveDeviceAuthorization` / `DenyDeviceAuthorization` programmatic helpers for the consent UI to wire (issue 117)
- **authorize.go** — RFC 6749 §4.1 Authorization Code Grant. `AuthorizationCodeGrantType` constant, `AuthorizationHandler` (request parsing, §4.1.2.1 error taxonomy splitting "MUST display" vs "MAY redirect", S256 PKCE enforcement, RFC 9207 `iss` emission with optional `RedirectOverride` conformance hook). `IssueCode` mints + persists the binding (client_id / redirect_uri / scope / subject / code_challenge / code_challenge_method), `SuccessRedirect` / `ErrorRedirect` build the §4.1.2 redirects (issue 297)
- **authorize_verification_handler.go** — Consent UI: `GET /authorize` validates the request, renders consent screen with client_name + scopes (or auto-approves for conformance fixtures via `AutoApproveSubject`), `POST /authorize` re-validates and either mints + redirects with code (Approve) or redirects with `error=access_denied` (Deny). Mirrors `DeviceVerificationHandler` (issue 297)
- **authorize_mount.go** — `MountAuthorize(mux, cfg)` symmetric with `MountDeviceFlow`. Stamps `GET /authorize` + `POST /authorize` onto a mux with browser middleware wrap, login-redirect knobs, and the conformance `RedirectOverride` hook (issue 297)
- **authorize_grant.go** — `APIAuth.handleAuthorizationCodeGrant` (`POST /api/token` branch). RFC 6749 §4.1.3 binding checks (client_id, redirect_uri), RFC 7636 §4.6 S256 PKCE verification via `oauth2.VerifyPKCE`, single-use semantics (consume on success), confidential-client enforcement via AppStore + ClientAuthenticator (matches device-grant precedent issue 266) (issue 297)
- **consent_helpers.go** — `loginURLWithNext` + `lookupClientName` shared between `DeviceVerificationHandler` and `AuthorizeVerificationHandler` so the auth-required redirect and the AppStore→client_name fallback behave uniformly across both consent surfaces (issue 297)
- **introspection.go** — `IntrospectionHandler` for RFC 7662 token introspection (server side)
- **introspection_client.go** — `IntrospectionValidator` for RFC 7662 token introspection (client side, with caching)
- **protected_resource.go** — `ProtectedResourceMetadata` struct + `NewProtectedResourceHandler` for RFC 9728 discovery

## Transport-Independent Core (OneAuth)

All transport-agnostic interfaces in this package follow the gRPC-shape convention `MethodName(ctx context.Context, req *XRequest) (*XResponse, error)` — `TokenIssuer`, `TokenValidator`, `TokenIntrospector`, `TokenRevoker`, `ClientAuthenticator`. HTTP handlers are thin wrappers that construct the request type from the HTTP message and format the response. The same shape is used in `admin/` (`ClientRegistrar`, `ClientRegistrationManager`). Convention rationale: issue #110; apiauth adoption: issues #175 and #218.

`APIAuth` exposes `Issuer() TokenIssuer` and `Validator() TokenValidator` accessors that lazy-build the gRPC-shape implementations from APIAuth's configuration fields — internal HTTP handlers and consumer tests both go through these. The previous positional methods (`CreateAccessToken`, `ValidateAccessToken`, `ValidateAccessTokenFull`, `VerifyTokenFunc`) were removed in issue #218.

The `OneAuth` struct composes focused interfaces for all auth operations without HTTP:
- **interfaces.go** — `TokenIssuer`, `TokenValidator`, `TokenIntrospector`, `TokenRevoker`, `ClientAuthenticator`, `TokenInfo`
- **hooks.go** — `Hooks` (grouped: `TokenHooks`, `AuthHooks`, `ClientHooks`, `SecurityHooks`)
- **token_validator.go** — `jwtValidator` + `jwtIssuer` implementations
- **token_introspector.go** — `tokenIntrospector` (delegates to `TokenValidator`)
- **token_revoker.go** — `tokenRevoker` (blacklist + refresh store)
- **client_authenticator.go** — `clientAuthenticator` (`client_secret_*` constant-time comparison + RFC 7521 §4.2 / RFC 7523 §2.2 / OIDC Core §9 `private_key_jwt` assertion validation: signature against registered client public key, alg-confusion lock via `WithValidMethods`, iss == sub == client_id, audience match, exp + lifetime cap, jti replay-block via `JTIStore`)
- **jti_store.go** — `JTIStore` interface + `inMemoryJTIStore` (TTL-based, lazy GC). Pluggable for distributed deployments.
- **client_credentials.go** — `extractClientCredentials` (Basic / form-body / assertion channels) shared by token + introspection + revocation handlers; `derivedAudience` fallback URL when handler `AcceptedAudiences` is empty.
- **oneauth.go** — `OneAuth` composite, `NewOneAuth()` constructor, HTTP convenience methods (`IntrospectionHTTPHandler`, `RevocationHTTPHandler`, `HTTPMiddleware`)

HTTP handlers (`IntrospectionHandler`, `RevocationHandler`) delegate to core interfaces. `APIMiddleware` delegates to `TokenValidator` when `KeyStore` is set.

## Tracing (SEP-414 / #254)

`APIAuth`, `IntrospectionHandler`, `RevocationHandler`, `APIMiddleware`, and `IntrospectionValidator` all accept an optional `*trace.TracerProvider`. When set:

- `APIAuth.ServeHTTP` extracts the inbound `traceparent` and emits `oneauth.token.issue` (attr `oauth.grant_type`). `NewIntrospectionHandler` / `NewRevocationHandler` inherit this TP.
- `IntrospectionHandler.ServeHTTP` emits `oneauth.introspect` (attr `oauth.token_active`).
- `RevocationHandler.ServeHTTP` emits `oneauth.revoke`.
- `jwtValidator.ValidateToken` (the resource-server hot path) emits `oneauth.signature_verify` (attrs `jwt.alg`, `jwt.kid`).
- `IntrospectionValidator.ValidateWithContext` / `ValidateForMiddlewareWithContext` inject a `traceparent` on the outbound introspection HTTP request and emit `oneauth.introspection_client.request`. The non-context variants remain for back-compat but lose trace propagation.

`nil` keeps every path on the no-op tracer with zero allocation cost. The same TP should be wired across the AS handlers + the resource-server middleware so all spans nest under a single trace.

## Recent Changes
- **Authorization Code Grant + PKCE + RFC 9207 (issue 297)** — `GET / POST /authorize` mounted via `apiauth.MountAuthorize`. Validates request per RFC 6749 §4.1.1 (§4.1.2.1 "MUST display vs MAY redirect" error taxonomy), renders consent screen with client_name + scopes (auto-approve hook for conformance fixtures), 302-redirects with `code` + `state` + optional RFC 9207 `iss`. Token endpoint accepts `grant_type=authorization_code` with redirect_uri + S256 PKCE binding checks, consumes the code on success (single-use), and reuses the device-flow confidential-client enforcement pattern. AS metadata advertises `authorization_endpoint` + `code` in response types + `authorization_code` in grants. New `core.AuthorizationCodeStore` interface with in-memory backend (FS/GORM/GAE backends deferred to follow-ups under the same staging as DeviceAuthStore — issues 269/270). `RedirectOverride` conformance hook lets test fixtures drive misbehaving-AS branches (suppress / inject / corrupt `iss`) that a correct production AS cannot simulate. Reference deployment `cmd/oneauth-server` gains a `code_flow:` yaml block.
- **Device Authorization Grant — RFC 8628 (issue 117)** — `POST /device/authorize` mints `device_code` + `user_code` (XXXX-XXXX user-typeable form, RFC 8628 §6.1 charset) and persists a pending `core.DeviceAuthorization`. Token endpoint accepts `grant_type=urn:ietf:params:oauth:grant-type:device_code` and maps store status + polling clock to the §3.5 error taxonomy (`authorization_pending` / `slow_down` / `access_denied` / `expired_token`). `APIAuth.ApproveDeviceAuthorization` / `DenyDeviceAuthorization` are the programmatic helpers a future consent UI plugs into. AS metadata advertises `device_authorization_endpoint`. New storage interface `core.DeviceAuthorizationStore` with in-memory + FS backends (GORM/GAE deferred).
- **Confidential client auth on device redemption (issue 266)** — when `APIAuth.AppStore` is wired and the registered client's `token_endpoint_auth_method != "none"`, the device-code redemption path REQUIRES credentials and runs them through the same `ClientAuthenticator` the rest of the token endpoint uses. The authenticated client_id drives the §3.4 binding check, so a stolen device_code cannot redeem without the registered client's `client_secret` / `client_assertion`. Public clients (`none`) keep the form-`client_id`-only path.
- **Device verification consent UI (issue 267)** — `DeviceVerificationHandler` serves the four HTML pages bridging `/device/authorize` and the user's consent decision: GET /device (code entry form) → POST /device (verify code, redirect to login or consent) → GET /device/approve (consent screen with client_name + scopes) → POST /device/approve (calls `APIAuth.ApproveDeviceAuthorization` / `DenyDeviceAuthorization`). Built-in plain HTML templates overridable via `DeviceTemplates`. Narrow function-type fields for CSRF + session integration so apiauth keeps its no-httpauth-import invariant. Closes the device-flow arc end-to-end.
- **OIDC Back-Channel Logout 1.0 push (issue 261)** — AS-initiated logout notification. New `LogoutTokenIssuer` + `BCLDispatcher` in `apiauth/`; new `BackchannelLogoutURI` / `BackchannelLogoutSessionRequired` fields on `core.AppRegistration` and `admin/dcr` types. `HandleLogoutAll` fires `TokenHooks.OnSubjectRevoked`; the RFC 7009 revoker and `HandleLogout` fire `TokenHooks.OnTokenRevoked` with the captured `(subject, family-as-sid, client_id)`. AS metadata advertises `backchannel_logout_supported` / `backchannel_logout_session_supported`. `sid` claim maps to the refresh-token family ID.
- **AS metadata `claims_supported` (issue 200)** — `ASServerMetadata` exposes a new `ClaimsSupported []string` field (OIDC Discovery 1.0 §3). The reference deployments (`cmd/oneauth-server`, `testutil`) now populate `scopes_supported` + `claims_supported` by default, clearing two warnings from the OIDF discovery test (`oidcc-discovery-endpoint-verification`).
- **`private_key_jwt` client auth (#158)** — `ClientAuthenticator` now accepts RFC 7523 §2.2 / OIDC Core §9 signed-JWT client authentication. Token + introspection + revocation handlers all route through a shared `extractClientCredentials` helper covering `client_secret_basic` / `client_secret_post` / `private_key_jwt`. AS metadata advertises `private_key_jwt` and the new `token_endpoint_auth_signing_alg_values_supported` field. Closes the previously expected-fail `introspection/post_auth_accepted` ratchet entry as a side effect.
- **Token revocation** — `RevocationHandler` at `POST /oauth/revoke` (RFC 7009). Always returns 200. Supports `token_type_hint`.
- **RFC 9396 Rich Authorization Requests** — `authorization_details` on token requests, JWT claims, introspection, middleware enforcement via `RequireAuthorizationDetails`.
- **client_credentials grant** — `APIAuth.ClientKeyStore` enables machine-to-machine auth via `grant_type=client_credentials` (RFC 6749 §4.4).
- **Protected Resource Metadata** — `NewProtectedResourceHandler` serves RFC 9728 metadata at `/.well-known/oauth-protected-resource`, enabling clients to auto-discover resource server capabilities
- **Audience validation** — `ValidateAccessToken` checks `aud` claim against expected audiences; handles both string and array formats (RFC 7519 §4.1.3, #52)
- **Token blacklist** — `APIAuth.Blacklist` and `APIMiddleware.Blacklist` fields enable jti-based token revocation via `core.TokenBlacklist`. All tokens now include a `jti` claim.
- **RateLimiter moved to core** — the `RateLimiter` interface was extracted from `apiauth` to `core/` so it can be shared across packages (e.g., `localauth`)

## Dependencies
`core/` for store interfaces, token types, scopes, rate limiting. `keys/` for `KeyLookup`. `utils/` for JWT helpers.
