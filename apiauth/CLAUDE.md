# apiauth — token endpoint, authorize, DPoP, OIDC

## Standards compliance

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
| `id_token` from `POST /api/token` (`authorization_code` with `openid`) + `GET / POST /userinfo` | `IDTokenIssuer` + `OneAuth.UserinfoHTTPHandler` (`apiauth/oidc*.go`), opt-in via `OneAuthConfig.OIDC`; the SDK checks one with `client.VerifyIDToken` / `BrowserLoginRequest.VerifyIDToken` | OIDC Core 1.0 |
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

## Gotchas

**Test fixtures**
- **Hand-minted test tokens need `exp`, and HMAC secrets need 32 bytes.** The validator requires `exp` and refuses an empty key; a helper minting without `exp` gets a 401 that looks like a key mismatch.
- **PKCE values must have the RFC 7636 shape**: an S256 `code_challenge` is exactly 43 base64url characters, a `code_verifier` 43 to 128 unreserved characters. Fixtures like `"wrong-verifier"` fail on shape first.
- **httptest URL before mount.** When a handler needs the base URL (RFC 8628 `VerificationURI`), use `httptest.NewUnstartedServer(mux)`, read `server.URL`, mount, then `Start()`. See `tests/e2e/device_flow_test.go`.
- **DCR needs `AppRegistrar.IssuerBaseURL` off loopback**, or a non-loopback `Host` gets a 500. httptest fixtures post with `Host: example.com`, so DCR tests set `IssuerBaseURL = "http://example.com"`.
- **`/authorize` without a client registry refuses every request** unless `AllowAnyRedirectURI` is set. The shared e2e fixture and `testutil/server.go` set it, so they can't catch a redirect-matching bug; `tests/e2e/loopback_listener_test.go` builds a server with the DCR AppStore.

**Token endpoint behaviour**
- **A refresh request has to name the token's client** (issue 395): its `client_id`, plus credentials for a confidential owner. Only a token stored with no client redeems with `grant_type` + `refresh_token` alone.
- **A refresh token carries the access tokens issued with it** (issue 436). RFC 7009 revocation of any member revokes the family and blacklists its unexpired access tokens. A test fake whose `RevokeTokenFamily` is a no-op leaves the token live.
- **A redeemed authorization code stays in the store, marked used** (`UsedAt`) until its access token expires, so reuse can revoke that token and family (issue 429). The access token is revoked only with `OneAuthConfig.Blacklist`.
- **A registered client's `scope` limits grants.** With an `AppStore`, `client_credentials` and password grants answer 400 `invalid_scope` outside `AppRegistration.Scope`, and grant the registered scope when none is asked.
- **Wrong credentials on the password grant are 400 `invalid_grant`** (RFC 6749 §5.2), not 401.
- **DCR stores `client_secret_basic` when no auth method is sent**; a `none` client gets no secret. DCR refuses unknown methods and grant types, and `authorization_code` without a `redirect_uri`.
- **Token kinds are told apart by `typ` header, `type` claim and Keycloak's `typ` claim.** Logout tokens, ID-JAGs, `type: session` JWTs and ID tokens (`typ` claim `ID`) are refused as access tokens; a token with no `type` passes (Keycloak's access tokens have none). A new JWT kind signed with the AS key needs its own marker.
- **A custom consent template must post `request_uri` back** (`authorizeConsentData.RequestURI`), or a pushed request loses its payload at Approve.
- **OIDC needs an asymmetric key.** `NewOneAuth` panics with `OIDC` set and an HS256 secret.

**Behind a proxy**
- **DPoP `htu` ignores `X-Forwarded-Proto`**; the scheme comes from `r.TLS`. Behind TLS termination set `DPoPConfig.EndpointURL` (token endpoint) or `BaseURL` (resource server).
- **Client-assertion audiences** use `r.TLS` and `r.Host` only (plus the issuer). Behind a proxy set `OneAuthConfig.AcceptedAudiences`.
- **`WWW-Authenticate` params are comma-separated** (RFC 9110 §11.6.1). A `Contains(header, 'error="invalid_token"')` assertion passes either way, so assert the separator.

**FAPI 2.0**
- **`OneAuthConfig.FAPI2`**: DPoP required, rotation off, `private_key_jwt` only with the issuer as a string `aud`, no password grant, no public clients, `MountAuthorize` PAR-only (panics without a `PushedStore`). It needs `DPoP` set, or every token request fails.
- **FAPI client keys are ES256.** Only PS256 / ES256 / EdDSA assertions pass, and oneauth registers only ES256 of those, so an RS256 `private_key_jwt` client stops authenticating under FAPI.
- **Client assertions allow 10 seconds of clock skew** (`ClientAssertionClockSkew`) on `iat`, `nbf`, `exp`. An "expired" test assertion must be more than 10 seconds past `exp`.
