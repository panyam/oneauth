---
package: apiauth
purpose: Transport-independent OAuth 2.0 authorization-server and resource-server core — token issuance, validation, introspection, revocation, and client authentication — plus thin HTTP bindings (token/introspect/revoke endpoints, discovery metadata, and bearer middleware).
last_rebuilt: ca8a742623b748f06d2564dce90465d1eeb10c6d
entities:
  - name: OneAuth
    kind: struct
    role: Composition root holding the five operation interfaces (Issuer/Validator/Introspector/Revoker/Authenticator) plus shared stores and grouped Hooks; NewOneAuth wires them from one config.
    why: Deliberately a bag of focused interfaces, not a god object — each impl receives only its deps so callers can swap or test any one operation in isolation (issue 110, Option A).
  - name: OneAuthConfig
    kind: struct
    role: Single dependency bundle consumed by NewOneAuth that fans out to the per-interface constructors.
    why: Centralizes wiring so the SigningAlg default (HS256) and "KeyStorage satisfies KeyLookup" coupling live in one place rather than at every call site.
  - name: TokenIssuer
    kind: interface
    role: Mints access tokens via CreateAccessToken plus the client_credentials, refresh_token, and password grants.
    why: PasswordGrant intentionally does NOT create a refresh token — that is the caller's job because refresh tokens carry transport-specific metadata (device, IP) the core has no business knowing.
  - name: TokenValidator
    kind: interface
    role: Parses/verifies a token (signature, expiry, issuer, audience, blacklist) and checks scope and RFC 9396 authorization_details requirements.
    why: CheckScopes/CheckAuthorizationDetails return empty response structs — they are pure pass/fail via error, wrapped only to honor the gRPC-shape convention and leave forward-compat headroom.
  - name: TokenIntrospector
    kind: interface
    role: RFC 7662 introspection; returns {Active:false} for any invalid token rather than an error.
    why: Never reveals *why* a token is invalid (RFC 7662 §2.2 confidentiality) — distinguishing reasons would leak an oracle to an attacker.
  - name: TokenRevoker
    kind: interface
    role: RFC 7009 revocation; the TokenTypeHint steers which store is consulted first.
    why: Empty hint tries refresh first (cheaper lookup) then access, so a missing/wrong hint never causes a silent miss.
  - name: ClientAuthenticator
    kind: interface
    role: Verifies client credentials across client_secret_basic/post and private_key_jwt; routes by which request fields are populated.
    why: Single method spans three RFC auth methods so transport bindings stay credential-agnostic; when both secret and assertion are present the assertion wins (the stronger credential, RFC 6749 §2.3.1).
  - name: AuthenticateClientRequest
    kind: struct
    role: Input to ClientAuthenticator carrying either the secret pair or the assertion pair plus an Audiences allow-list.
    why: Audiences accepts BOTH token-endpoint URL and issuer URL because Auth0/Keycloak/Authlete disagree on which to send — interop demands accepting either (OIDC Core §9).
  - name: TokenInfo
    kind: struct
    role: Validated claims returned wrapped in ValidateTokenResponse (subject, scopes, authorization_details, custom claims, auth type).
    why: Splits custom claims from standard ones via the standardClaims set so downstream consumers get a clean extension bag without the registered JWT claims.
  - name: clientAuthenticator
    kind: struct (impl)
    role: Default ClientAuthenticator — secret path uses constant-time compare; assertion path verifies a JWT signed by the client's registered key.
    why: Locks the verify parser to the client's registered alg (jwt.WithValidMethods) to block the RS256→HS256 algorithm-confusion attack (CVE-2016-10555 class) where the public key is abused as an HMAC secret.
  - name: JTIStore
    kind: interface
    role: At-most-once replay guard for client-assertion jti values; SeenWithin is an atomic check-and-set.
    why: Single-method by design so a distributed backend (Redis SETNX) swaps in without touching call sites; multi-node deployments MUST replace the in-memory default or replay protection is per-process only.
  - name: inMemoryJTIStore
    kind: struct (impl)
    role: TTL map with lazy GC amortized across SeenWithin calls (no background goroutine).
    why: Bounded because client-assertion lifetimes are capped at MaxClientAssertionLifetime (5m); empty jti returns "not seen" defensively so two empty-jti bugs aren't treated as a replay pair.
  - name: MaxClientAssertionLifetime
    kind: const
    role: 5-minute ceiling on a client assertion's exp−iat span.
    why: RFC 7523 leaves the upper bound to the AS; capping it matches major IdPs and bounds JTIStore memory.
  - name: jwtIssuer
    kind: struct (impl)
    role: TokenIssuer backed by JWT signing; RefreshGrant rotates tokens and performs theft detection.
    why: A revoked-then-reused refresh token revokes the entire token family — reuse is treated as theft, not a benign retry.
  - name: jwtValidator
    kind: struct (impl)
    role: Local JWT TokenValidator with kid-first / client_id-fallback key resolution.
    why: resolveKey cross-checks the kid's owning client against the client_id claim to stop app A from signing a token claiming client_id=B, and fires OnAlgorithmMismatch when header alg ≠ stored key alg.
  - name: APIAuth
    kind: struct
    role: Legacy all-in-one token endpoint (ServeHTTP) plus session/API-key handlers and the CreateAccessToken/ValidateAccessToken pair predating the OneAuth interface split.
    why: Retained for backward compat; lazyAuthenticator is cached via sync.Once specifically because a per-request authenticator would mean a per-request JTIStore, silently defeating private_key_jwt replay protection.
  - name: APIMiddleware
    kind: struct
    role: Bearer-token HTTP middleware (ValidateToken/RequireScopes/Optional/RequireAuthorizationDetails) validating JWTs, API keys, or via remote introspection.
    why: Delegates to a TokenValidator when a KeyStore is present but keeps validateJWTInline for the single-tenant JWTSecretKey case the interface validator can't serve; "oa_"-prefixed tokens short-circuit to API-key validation.
  - name: IntrospectionValidator
    kind: struct
    role: Resource-server-side client that validates tokens by calling a remote RFC 7662 endpoint, with optional response caching.
    why: Caching trades correctness for load — a revoked token can read as active for up to CacheTTL, an explicitly accepted staleness window.
  - name: IntrospectionHandler
    kind: struct
    role: HTTP wrapper for POST /oauth/introspect over TokenIntrospector + ClientAuthenticator.
    why: AcceptedAudiences falls back to the request URL when unset, which silently breaks behind path-rewriting proxies — production must set it explicitly.
  - name: RevocationHandler
    kind: struct
    role: HTTP wrapper for POST /oauth/revoke over TokenRevoker + ClientAuthenticator.
    why: Always returns 200 even for unknown/garbage tokens (RFC 7009 §2.2) so the endpoint can't be used to probe token existence.
  - name: ASServerMetadata / NewASMetadataHandler / MountASMetadata
    kind: struct + funcs
    role: RFC 8414 / OIDC discovery metadata served (byte-identical) at both well-known paths.
    why: Pointer-typed AuthorizationResponseIssParameterSupported distinguishes "omit" from explicit false; advertising capabilities the AS doesn't actually emit is a spec violation that breaks clients keying off the advertisement.
  - name: ASMetadataProxy
    kind: struct
    role: Lazily fetches and caches a remote AS's discovery doc and re-serves it at the RFC 8414 path.
    why: Bridges OIDC-only providers (Keycloak) for clients (e.g. VS Code) that only attempt RFC 8414 and never fall back to openid-configuration.
  - name: ProtectedResourceMetadata / MountProtectedResource
    kind: struct + func
    role: RFC 9728 protected-resource metadata, optionally co-mounting an ASMetadataProxy per trusted AS.
    why: The co-mount exists so a client that discovers the PRM, tries RFC 8414 at the AS, and 404s on an OIDC-only provider can retry at the resource server and still succeed.
  - name: TrustedAssertionIssuer / validateAssertion
    kind: struct + func
    role: Describes an upstream IdP and validates its signed JWTs; shared by the jwt-bearer (RFC 7523 §2.1) and token-exchange (RFC 8693) grants.
    why: KeyFunc wins over a static PublicKey to support JWKS-by-kid rotation; set AcceptedAlgorithms in production or alg-confusion is only loosely guarded, and an absent audience config logs loudly rather than silently accepting any aud.
  - name: handleJwtBearerGrant / handleTokenExchangeGrant
    kind: methods
    role: APIAuth grant handlers for RFC 7523 §2.1 and RFC 8693.
    why: jwt-bearer issues no refresh token (the assertion is itself the renewable credential); token-exchange must encode issued_token_type inline because the shared tokenResponse helper omits that REQUIRED field, and audience/resource are currently advisory-only (logged gap).
  - name: Hooks / TokenHooks / AuthHooks / ClientHooks / SecurityHooks
    kind: structs
    role: Grouped, all-optional lifecycle callbacks; each impl gets only its concern's group.
    why: SecurityHooks.OnAlgorithmMismatch and OnBlacklistHit exist as named intrusion-detection signals (alg-confusion attempts, post-revocation reuse) rather than buried log lines.
  - name: extractClientCredentials
    kind: func
    role: Pulls client credentials from the three OAuth channels in precedence order (assertion > basic > post).
    why: RFC 6749 §2.3 forbids combining methods; a confused/malicious client sending several gets the strongest signal picked and the rest ignored rather than a rejection.
  - name: matchesAudience / standardClaims / parseAuthorizationDetailsFromClaims
    kind: funcs + var
    role: Cross-cutting helpers — multi-form aud matching (RFC 7519 §4.1.3), the un-overridable claim set, and RFC 9396 claim parsing.
    why: standardClaims is the single guard preventing CustomClaimsFunc from forging sub/iss/scopes etc.; matchesAudience handles aud as both string and array because real tokens use both.
depends_on:
  - folder: core
    entities: [APIKeyStore, AuthorizationDetail, ContainsAllScopes, CredentialsValidator, DetectUsernameType, ErrAPIKeyNotFound, ErrTokenNotFound, ErrTokenReused, GenerateSecureToken, GetUserIDFromContext, GetUserScopesFunc, IntersectScopes, JoinScopes, ParseScopes, RateLimiter, RefreshTokenStore, ScopeOffline, ScopeProfile, ScopeRead, ScopeWrite, SetUserIDInContext, TokenBlacklist, TokenError, TokenExpiryAccessToken, TokenPair, TokenRequest, ValidateAll]
  - folder: keys
    entities: [KeyLookup, KeyStorage]
  - folder: utils
    entities: [ComputeKid, DecodeVerifyKey, IsAsymmetricAlg, SigningMethodForAlg]
---

# apiauth design notes

## Two generations, one package
The package contains two overlapping designs that coexist deliberately:

1. **The interface core** (`interfaces.go`, `oneauth.go`, `token_validator.go`, `token_introspector.go`, `token_revoker.go`, `client_authenticator.go`) — the gRPC-shape `MethodName(ctx, *Req) (*Resp, error)` interfaces and their default JWT implementations, wired by `NewOneAuth`. This is the forward direction (issues 110 / 175).
2. **The legacy `APIAuth`/`APIMiddleware`** (`auth.go`) — a monolithic token endpoint and middleware that predate the split. They are kept working and are progressively delegating inward: `APIMiddleware` builds a `TokenValidator` lazily when a `KeyStore` is present, and `APIAuth` lazily builds a `ClientAuthenticator`. `validateJWTInline` is explicitly marked "removed in Phase 3."

When reasoning about behavior, note the duplication: token-type/issuer/audience/blacklist checks exist in `jwtValidator.ValidateToken`, `APIAuth.ValidateAccessToken(Full)`, and `APIMiddleware.validateJWTInline`. They are intended to be equivalent; divergence between them is a bug.

## Convention: wrapped request/response everywhere
Every interface method takes `*XRequest` and returns `*XResponse`, even when the response is empty (`CheckScopesResponse{}`, `RevokeResponse{}`). The `ctx` is mostly unused today but is the reserved extension point for typed contexts / async-store cancellation (issue 175). `PasswordGrantResult` is a type alias bridge for the renamed `PasswordGrantResponse`.

## Security-load-bearing details (do not "simplify" away)
- **Algorithm pinning**: both `clientAuthenticator.authenticateAssertion` and `jwtValidator.resolveKey` lock the verify alg to the client's registered alg. This is the anti-alg-confusion guard (CVE-2016-10555 class). The `jwtKeyFunc` in `APIAuth` does the equivalent via Go type-switch on the key type.
- **kid ↔ client_id cross-check**: prevents a client that legitimately owns kid K from minting tokens asserting a different `client_id`. Skipped only when the key record carries no ClientID (e.g. a bare JWKS key store).
- **JTIStore caching**: the `sync.Once`-cached `lazyAuthenticator` in `APIAuth` and the in-memory default in `NewClientAuthenticator` exist so the assertion replay window survives across requests. A fresh store per request = no replay protection.
- **Constant-time secret compare**: `constantTimeEqual` (length-leak is accepted, content is not).
- **RFC confidentiality**: introspection returns `{active:false}` and revocation returns `200` for any token, good or bad, so neither endpoint becomes a token-existence oracle.

## Discovery / proxy bridging
`ASMetadataProxy` and the `MountProtectedResource(..., proxyASMetadata=true)` co-mount exist purely to paper over OIDC-only authorization servers (Keycloak/Auth0) for MCP-style clients that only know RFC 8414 and won't fall back to `openid-configuration`. The path-splitting in `splitASOriginPath`/`buildASDiscoveryURLs` handles realm-style path-based issuers.

## Known gaps surfaced in code
- Token-exchange `audience`/`resource` params are accepted but advisory — the issued token still carries the AS default audience (logged).
- `client_secret_jwt` (symmetric assertion) is not implemented; only `private_key_jwt` (asymmetric) — symmetric-keyed clients are rejected on the assertion path (tracked as #159).
- `validateJWTInline` is slated for removal once all callers route through `TokenValidator`.
