// Package apiauth is the transport-independent OAuth 2.0 core of OneAuth —
// token issuance, validation, introspection, revocation, and client
// authentication — together with thin HTTP bindings for the token endpoint,
// the RFC 7662 / 7009 handlers, AS/PRM discovery metadata, and resource-server
// middleware.
//
// <!-- design:start -->
// AUTO-GENERATED — DO NOT EDIT BETWEEN THESE MARKERS. Regenerate with /design-rebuild-go.
//
// The package owns OneAuth, the composition root that wires five focused
// interfaces (TokenIssuer, TokenValidator, TokenIntrospector, TokenRevoker,
// ClientAuthenticator) plus shared stores and grouped Hooks. This is the
// "Option A" design: no god object, each implementation receives only the
// dependencies it needs, and HTTP/gRPC/MCP bindings are thin wrappers over the
// interfaces (every method follows the (ctx, *Req) -> (*Resp, error)
// convention). Two large legacy structs predate this decomposition and remain
// the wired-up entry points: APIAuth, an all-in-one /api/token handler covering
// every grant plus logout/session/API-key endpoints, and APIMiddleware, the
// resource-server middleware. Both lazily build (and cache) the newer
// interfaces internally — caching matters because a fresh ClientAuthenticator
// would carry a fresh in-memory JTIStore and defeat assertion replay
// protection. The package supports password, refresh_token, client_credentials,
// jwt-bearer (RFC 7523 §2.1), and token-exchange (RFC 8693) grants;
// client_secret_basic / client_secret_post / private_key_jwt client auth;
// RFC 9396 authorization_details end to end; and discovery via RFC 8414, OIDC
// Discovery, and RFC 9728. It does NOT own key storage or the user/refresh
// stores (those are the keys/ and core/ packages, reached only through
// interfaces).
//
// # ENTITIES
//
// OneAuth — composition root holding Issuer/Validator/Introspector/Revoker/
// Authenticator, shared KeyStore/Blacklist/RefreshStore, and Hooks; build with
// NewOneAuth(OneAuthConfig) and mount via its IntrospectionHTTPHandler,
// RevocationHTTPHandler, and HTTPMiddleware convenience methods.
//
// TokenIssuer — interface minting access tokens via CreateAccessToken,
// ClientCredentials, RefreshGrant, and PasswordGrant. PasswordGrant
// deliberately does not create a refresh token, since refresh tokens carry
// transport-specific metadata (device, IP) the caller owns.
//
// TokenValidator — interface that parses and verifies a token (signature,
// expiry, issuer, audience, blacklist) and checks scope / RFC 9396 detail
// requirements. CheckScopes and CheckAuthorizationDetails return empty response
// structs — pure success/failure signalled via error.
//
// TokenIntrospector — interface for RFC 7662 introspection; returns
// {Active:false} for any invalid token and never reveals why (RFC 7662 §2.2
// confidentiality).
//
// TokenRevoker — interface for RFC 7009 revocation; the token_type_hint guides
// which store to check first, and an empty hint tries refresh (cheaper) then
// access.
//
// ClientAuthenticator — interface verifying client credentials via
// client_secret_basic/post or a private_key_jwt assertion; routes by which
// request fields are set. The assertion path is the entire reason it is plumbed
// into the token, introspection, and revocation endpoints.
//
// APIAuth — legacy all-in-one HTTP handler for POST /api/token (dispatching all
// five grants) plus logout, session listing, and API-key management, with
// CreateAccessToken / ValidateAccessToken JWT helpers. It lazily builds and
// caches a ClientAuthenticator over its ClientKeyStore so legacy callers gain
// private_key_jwt support without re-wiring.
//
// APIMiddleware — resource-server middleware that validates Bearer JWTs or
// oa_-prefixed API keys, exposes ValidateToken / RequireScopes / Optional /
// RequireAuthorizationDetails, and falls back to remote introspection when
// local validation fails. It lazily builds a TokenValidator from KeyStore;
// single-tenant JWTSecretKey deployments use the inline validateJWTInline path
// (slated for removal in Phase 3).
//
// jwtIssuer — TokenIssuer implementation that signs JWTs and runs the
// client_credentials / refresh / password grant logic. Its refresh grant does
// theft detection: a presented-but-already-revoked token revokes the entire
// token family.
//
// jwtValidator — TokenValidator implementation that resolves keys by kid then
// by client_id claim and fires SecurityHooks. It locks the token alg to the
// stored key's alg and cross-checks the kid owner against the client_id claim
// to block algorithm-confusion and cross-app forgery.
//
// clientAuthenticator — ClientAuthenticator implementation; the secret path
// uses constant-time comparison, the assertion path validates a private_key_jwt
// JWT enforcing iss==sub==client_id, alg lock, audience match, bounded lifetime
// (MaxClientAssertionLifetime), and jti replay protection via a JTIStore.
//
// JTIStore — interface tracking client-assertion jti claims with at-most-once
// semantics (SeenWithin is an atomic check-and-set). The default in-memory
// implementation uses lazy GC and no background goroutine; the narrow interface
// lets a Redis-backed store swap in for multi-node deployments.
//
// IntrospectionValidator — remote-introspection HTTP client (RFC 7662) used as
// the APIMiddleware fallback for opaque tokens or centralized blacklist checks.
// Its optional response cache means a revoked token may read as active for up
// to CacheTTL.
//
// IntrospectionResult — parsed RFC 7662 response shared by the local
// TokenIntrospector and the remote IntrospectionValidator, keeping callers
// agnostic to which path produced it.
//
// IntrospectionHandler — thin HTTP wrapper for POST /oauth/introspect over
// TokenIntrospector and ClientAuthenticator; authenticates the caller first and
// surfaces authorization_details from raw claims (RFC 9396 §9.1).
//
// RevocationHandler — thin HTTP wrapper for POST /oauth/revoke over TokenRevoker
// and ClientAuthenticator; always returns 200 OK per RFC 7009 §2.2 except on
// client-auth failure.
//
// Hooks — lifecycle callbacks grouped into Token, Auth, Client, and Security;
// each implementation receives only its relevant group and every callback is
// nil-safe via fire* helpers.
//
// SecurityHooks — security-event callbacks (OnTokenRejected, OnBlacklistHit,
// OnAlgorithmMismatch); OnAlgorithmMismatch is the CVE-2015-9235 attack-vector
// signal.
//
// TrustedAssertionIssuer — upstream-IdP configuration (PublicKey or KeyFunc,
// Audiences, AcceptedAlgorithms) consumed by the jwt-bearer and token-exchange
// grants. Set AcceptedAlgorithms in production to lock out alg-confusion; iss is
// matched verbatim against the assertion.
//
// ASServerMetadata — RFC 8414 / OIDC Discovery authorization-server metadata
// document, served via NewASMetadataHandler or MountASMetadata (both
// well-known paths). Metadata-only: advertising endpoints does not make the
// server a full OIDC provider.
//
// ASMetadataProxy — fetches and caches an upstream AS's discovery document and
// re-serves it at the RFC 8414 well-known path, bridging OIDC-only providers
// (Keycloak) for MCP clients that only try RFC 8414.
//
// ProtectedResourceMetadata — RFC 9728 protected-resource metadata, served via
// MountProtectedResource or NewProtectedResourceHandler; MountProtectedResource
// can also proxy AS metadata so RFC-8414-only clients discover the AS through
// the resource server.
//
// TokenInfo — validated-claims carrier (subject, scopes, RFC 9396 details,
// custom claims, auth type) returned by TokenValidator. Custom claims are
// everything not in standardClaims; authorization_details travel through the
// middleware under the private __authz_details key before being lifted into a
// dedicated context value.
//
// JwtBearerGrantType / TokenExchangeGrantType — grant-type URN constants for
// RFC 7523 §2.1 and RFC 8693. Both share validateAssertion against the
// configured TrustedAssertionIssuers; token-exchange Phase 1 supports only a
// JWT subject_token producing an access token and treats audience/resource as
// advisory.
//
// # FLOWS
//
// See diagrams.md for sequence diagrams of the token-endpoint grant dispatch,
// the private_key_jwt client-assertion authentication path, resource-server
// middleware validation with introspection fallback, and RFC 7009 revocation.
// <!-- design:end -->
package apiauth
