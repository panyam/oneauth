# testutil/ — Reusable Test Infrastructure

**Import:** `github.com/panyam/oneauth/testutil`

Exported test helpers for oneauth integration tests, importable by downstream projects (mcpkit, relay, etc.).

## TestAuthServer (server.go, token.go)

In-process authorization server with RSA 2048 keys, JWKS, token endpoint, and AS metadata. Starts via `httptest.NewServer`, cleaned up via `t.Cleanup`.

```go
srv := testutil.NewTestAuthServer(t, testutil.WithAudience("my-api"))
token, _ := srv.MintToken("user-42", []string{"read", "write"})
```

**Endpoints:** `/_ah/health`, `/api/token`, `/oauth/introspect`, `/.well-known/jwks.json`, `/.well-known/openid-configuration`, `/apps/register`, `/apps/dcr`

**Options:** `WithAdminKey`, `WithIssuer`, `WithAudience`, `WithScopes`

**Token minting:** `MintToken(userID, scopes)` and `MintTokenWithClaims(claims)` — direct RS256 JWT creation, no HTTP round-trip.

## Shared OAuth Helpers (helpers.go)

Standalone functions that work against any RFC-compliant OAuth server (TestAuthServer, Keycloak, Auth0, etc.). All take `*testing.T` and call `t.Fatal` on error for test ergonomics.

| Function | RFC |
|----------|-----|
| `DiscoverOIDC(t, issuerURL)` | RFC 8414 |
| `GetClientCredentialsToken(t, endpoint, id, secret, scopes...)` | RFC 6749 §4.4 |
| `GetPasswordToken(t, endpoint, id, secret, user, pass)` | RFC 6749 §4.3 |
| `FetchJWKS(t, jwksURI)` | RFC 7517 |
| `ParseJWTClaims(t, token)` | Unverified decode |
| `ParseJWTHeader(t, token)` | Unverified decode |

**Note:** The `client/` package has production-grade equivalents (`client.DiscoverAS`, `client.AuthClient.ClientCredentialsToken`). These testutil helpers are intentionally simpler `t.Fatal`-based wrappers for test ergonomics, plus test-only functions (`ParseJWTClaims`, `GetPasswordToken`) with no production equivalent.

## Exported Types

- `OIDCConfig` — discovered OIDC endpoints
- `TokenResponse` — token endpoint response
- `TestAuthServer` — in-process auth server
- `Option` — functional option for TestAuthServer

## Version History

- **0.0.64** — Initial extraction from `tests/e2e/` and `tests/keycloak/` (#68)
