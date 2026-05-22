---
package: testutil
purpose: Reusable, t.Fatal-based test infrastructure — an in-process RSA-signing authorization server plus standalone OAuth/JWT helpers — importable by oneauth's own suites and downstream projects.
last_rebuilt: ca8a742623b748f06d2564dce90465d1eeb10c6d
entities:
  - name: TestAuthServer
    kind: struct
    role: In-process httptest-backed OAuth AS that generates an RSA-2048 key, serves JWKS/token/introspection/metadata/registration endpoints, and mints tokens.
    why: Lets integration tests exercise the full RFC-compliant surface without Docker or Keycloak; exposes APIAuth/KeyStore/Registrar fields directly so tests can poke internals the HTTP API doesn't reach.
  - name: NewTestAuthServer
    kind: function
    role: Test constructor — wraps NewAuthServer and registers shutdown via t.Cleanup.
    why: Callers never call Close manually; the t.Cleanup contract is the whole reason a separate test-only constructor exists alongside NewAuthServer.
  - name: NewAuthServer
    kind: function
    role: Non-test constructor returning (*TestAuthServer, error) for examples/benchmarks that lack *testing.T.
    why: Splits the testing.T dependency out so the harness is usable in standalone main() contexts; the caller owns Close() here.
  - name: Option
    kind: type (func(*config))
    role: Functional option mutating the unexported config before server start.
    why: Keeps config unexported so the only way to configure is through reviewed, documented options — no struct-literal foot-guns.
  - name: WithTrustedAssertionIssuers
    kind: function (Option)
    role: Registers upstream IdPs for jwt-bearer (RFC 7523) and token-exchange (RFC 8693) grants.
    why: Side-effect that auto-extends grant_types_supported only when the caller hasn't pinned it — last-option-wins, and metadata advertisement alone does NOT enable the handler.
  - name: WithGrantTypesSupported
    kind: function (Option)
    role: Replaces the advertised grant_types_supported list.
    why: Values REPLACE rather than append, so callers wanting client_credentials kept must re-list it; advertising a grant does not wire its handler.
  - name: WithIssParameterSupported
    kind: function (Option)
    role: Sets the RFC 9207 authorization_response_iss_parameter_supported metadata flag.
    why: Advertisement-only — the server has no authorization endpoint, so setting true does not actually emit iss= in redirects (would be a spec violation on a real AS).
  - name: WithAudience
    kind: function (Option)
    role: Sets the aud claim on minted tokens.
    why: Empty default means no audience restriction; minting code only adds aud when this is non-empty.
  - name: WithIssuer
    kind: function (Option)
    role: Sets JWT iss and metadata issuer.
    why: Sentinel default "testutil-issuer" is silently overridden to the live server URL after start, so issuer matches the real listening address.
  - name: WithScopes / WithAdminKey / WithClaimsSupported
    kind: functions (Option)
    role: Set scopes_supported, the app-registration admin key, and claims_supported metadata respectively.
    why: Claims default to exactly what OneAuth's bearer tokens already emit, so advertisement stays honest by default.
  - name: MintToken
    kind: method
    role: Fast-path RS256 JWT minting with standard claims (sub/iss/type/scopes/iat/exp/jti), no HTTP round-trip.
    why: Bypasses the token endpoint for speed; note it emits "scopes" (array) and type:"access", differing from MintTokenForSubject's "scope" (space-joined string).
  - name: MintTokenWithClaims
    kind: method
    role: Mints an RS256 JWT from an arbitrary claims map, filling iss/iat/exp defaults only when absent.
    why: Defaults are overridable so tests can forge edge cases (wrong issuer, expired, missing claims); kid header is always set regardless.
  - name: MintTokenForSubject
    kind: method
    role: Convenience minting for standalone (non-T) callers, delegating to MintTokenWithClaims.
    why: Uses space-joined "scope" string (OAuth-wire shape) rather than MintToken's "scopes" array — pick based on what the validator expects.
  - name: signToken
    kind: method (unexported)
    role: Central RS256 signer that sets the kid header via utils.ComputeKid.
    why: Single chokepoint guarantees every minted token carries a kid matching the JWKS-published key, so JWKS-based verification resolves.
  - name: OIDCConfig
    kind: struct
    role: Parsed RFC 8414 AS metadata document returned by DiscoverOIDC.
    why: A deliberately partial mirror of the spec's fields — only what tests assert on — kept separate from the production client's metadata type.
  - name: TokenResponse
    kind: struct
    role: Decoded RFC 6749 §5.1 token endpoint response.
    why: Shared return type for every grant helper so tests read one shape regardless of grant.
  - name: DiscoverOIDC
    kind: function
    role: Fetches and decodes /.well-known/openid-configuration, t.Fatal on error.
    why: Works against any compliant AS (TestAuthServer, Keycloak, Auth0); intentionally simpler than client.DiscoverAS with no retries.
  - name: GetClientCredentialsToken / GetPasswordToken
    kind: functions
    role: Acquire tokens via client_credentials (RFC 6749 §4.4) and password (§4.3) grants.
    why: Both delegate to PostTokenEndpoint; GetPasswordToken is test-only with no production equivalent.
  - name: PostTokenEndpoint
    kind: function
    role: Low-level form-POST to any token endpoint decoding into TokenResponse.
    why: The shared primitive grant helpers route through — extend here for new grants rather than duplicating HTTP plumbing.
  - name: FetchJWKS
    kind: function
    role: Fetches raw JWKS JSON as map[string]any.
    why: Returns an untyped map deliberately so tests can assert on raw key-set structure without a JWK type dependency.
  - name: ParseJWTClaims / ParseJWTHeader
    kind: functions
    role: Base64url-decode JWT payload/header WITHOUT signature verification.
    why: Test-introspection only with no production equivalent — explicitly never for production use since signature is unverified.
depends_on:
  - folder: admin
    entities: [AppRegistrar, NewAppRegistrar, NewAPIKeyAuth]
  - folder: apiauth
    entities: [APIAuth, ASServerMetadata, MountASMetadata, NewIntrospectionHandler, TrustedAssertionIssuer, JwtBearerGrantType, TokenExchangeGrantType]
  - folder: core
    entities: [GenerateSecureToken]
  - folder: httpauth
    entities: [LimitBody, DefaultMaxBodySize]
  - folder: keys
    entities: [JWKSHandler, KeyRecord, KeyStorage, NewInMemoryKeyStore]
  - folder: utils
    entities: [ComputeKid, EncodePublicKeyPEM]
---

## Shared test helpers

This package is the consolidated home for two helper categories that were extracted out of `tests/e2e/` and `tests/keycloak/` (SUMMARY notes #68). It is published as part of the public module surface so downstream consumers (mcpkit, relay) reuse the same harness rather than re-rolling their own.

**Server harness.** `TestAuthServer` (server.go) is the centerpiece: a single `http.ServeMux` over `httptest.NewServer`, wiring `apiauth.APIAuth.ServeHTTP` as the token endpoint, an `IntrospectionHandler`, a `keys.JWKSHandler`, and an `admin.AppRegistrar` (behind `httpauth.LimitBody`) for `/apps/` and `/apps`. The RSA-2048 public key is stored in an in-memory `keys.NewInMemoryKeyStore` under the issuer's ClientID with a computed kid; metadata is mounted via `apiauth.MountASMetadata`. The defining constraint across the harness: when the issuer is left at the `defaultIssuer` sentinel, both `apiAuth.JWTIssuer` and the metadata issuer are rewritten to the live `server.URL` after start, so tokens and discovery agree on a real address.

**Token minting.** Minting lives across server.go (`MintTokenForSubject`) and token.go (`MintToken`, `MintTokenWithClaims`, `signToken`). All paths funnel through the unexported `signToken`, which is the only place RS256 signing and `kid` header assignment happen — that single chokepoint is what keeps every minted token verifiable against the JWKS-published key. Watch the scope-claim split: `MintToken` writes a `"scopes"` array, while `MintTokenForSubject`/`MintTokenWithClaims` follow the OAuth-wire `"scope"` space-joined string. Choose the minting method to match what the code under test reads.

**Note:** `server_test.go` in this folder is the package's own test suite (a fixture exercising the harness), not part of the reusable surface.
