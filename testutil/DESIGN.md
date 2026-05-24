# testutil

In-process OAuth authorization server plus standalone OAuth/JWT helpers used across oneauth integration tests. The package centers on `TestAuthServer`, an `httptest.Server` wired to a fresh RSA 2048 key pair that serves JWKS, AS metadata (RFC 8414), token (`client_credentials` and — when configured — `jwt-bearer` / `token-exchange`), introspection (RFC 7662), and app-registration (RFC 7591) endpoints. Alongside the server, the package exposes lightweight helpers that fetch discovery documents, POST grants, parse JWTs, and read JWKS so tests can avoid hand-rolling boilerplate.

## Contents

- [Entities](#entities)
- [Flows](#flows)
- [Gotchas](#gotchas)
- [Depends on](#depends-on)

## Entities

| Entity | Kind | Role | Why |
|---|---|---|---|
| `TestAuthServer` | struct | In-process httptest-backed OAuth AS with RSA keys, JWKS, token, introspection, AS metadata, and app registration endpoints. | Centerpiece of the package; gives downstream test suites a real oneauth stack on a random port. |
| `NewTestAuthServer` | func | Builds a `TestAuthServer` bound to `*testing.T` with automatic `t.Cleanup` shutdown. | Preferred entry point for tests; removes the need for manual `Close` calls. |
| `NewAuthServer` | func | Builds a `TestAuthServer` without `*testing.T`; caller must `Close`. | Lets examples, benchmarks, and non-test code reuse the same server. |
| `Option` | type | Functional option type for configuring a `TestAuthServer`. | Keeps `NewAuthServer`'s signature stable as new knobs are added. |
| `WithAdminKey` | func | Sets the admin API key guarding `/apps` endpoints. | Overrides the default `"testutil-admin-key"` when a test asserts a specific key. |
| `WithIssuer` | func | Sets the JWT issuer and AS-metadata issuer. | Default sentinel is replaced with the live server URL after start; override pins a value. |
| `WithAudience` | func | Sets the JWT audience claim on minted tokens. | Empty default leaves tokens unrestricted; tests asserting audience must opt in. |
| `WithScopes` | func | Sets `scopes_supported` in AS metadata (advertisement only). | Lets tests advertise custom scopes without changing server behavior. |
| `WithClaimsSupported` | func | Sets `claims_supported` in AS metadata. | Default lists the claims oneauth tokens actually emit; override only when asserting other claims. |
| `WithGrantTypesSupported` | func | Replaces the advertised `grant_types_supported` list. | Advertising a grant does NOT enable its handler; pair with `WithTrustedAssertionIssuers` to actually serve it. |
| `WithIssParameterSupported` | func | Sets the RFC 9207 iss-parameter flag in AS metadata. | Metadata-only; no authorization endpoint drives the actual behavior yet. |
| `WithTrustedAssertionIssuers` | func | Enables jwt-bearer (RFC 7523) and token-exchange (RFC 8693) grants and auto-extends advertised grants. | Only Option that turns advertisement into real behavior; later `WithGrantTypesSupported` can still override. |
| `TestAuthServer.MintToken` | method | Mints a standard RS256 access JWT directly, bypassing the HTTP token endpoint. | Fast path with no network round-trip; kid header matches JWKS for verification. |
| `TestAuthServer.MintTokenWithClaims` | method | Mints an RS256 JWT from an arbitrary claims map with overridable iss/iat/exp defaults. | Enables negative tests (wrong issuer, expired, missing claims). |
| `TestAuthServer.MintTokenForSubject` | method | Convenience minting for a subject and scopes; no `*testing.T` needed. | Aimed at non-test example code that still wants a signed token. |
| `TestAuthServer.URL` | method | Returns the server base URL. | Only known after the random httptest port binds. |
| `TestAuthServer.JWKSURL` | method | Returns the JWKS endpoint URL. | Lets tests point JWKS-aware clients at the live server. |
| `TestAuthServer.TokenEndpoint` | method | Returns the token endpoint URL. | Lets tests POST grants directly when bypassing discovery. |
| `TestAuthServer.AdminKey` | method | Returns the configured admin API key. | Tests need it to call `/apps` endpoints. |
| `TestAuthServer.Issuer` | method | Returns the resolved JWT issuer. | Reads the server URL when the default sentinel was used. |
| `TestAuthServer.Close` | method | Stops the underlying `httptest` server; nil-safe. | Called automatically via `t.Cleanup` when `NewTestAuthServer` is used. |
| `OIDCConfig` | struct | Parsed OAuth/OIDC AS metadata document (RFC 8414). | Decode target for `DiscoverOIDC` and a typed view onto the discovery doc. |
| `TokenResponse` | struct | Parsed OAuth token endpoint response (RFC 6749 §5.1). | Common return type for the grant helpers. |
| `DiscoverOIDC` | func | Fetches and parses the `.well-known/openid-configuration` document. | Works against any compliant AS; fails via `t.Fatal` for test ergonomics. |
| `GetClientCredentialsToken` | func | Acquires a token via the `client_credentials` grant (RFC 6749 §4.4). | Thin wrapper that delegates to `PostTokenEndpoint` with the right form fields. |
| `GetPasswordToken` | func | Acquires a token via the resource owner password grant (RFC 6749 §4.3). | Test-only helper with no production equivalent. |
| `PostTokenEndpoint` | func | Sends a form POST to a token endpoint and decodes the JSON `TokenResponse`. | Shared core that the grant helpers delegate to; reusable for custom grants. |
| `FetchJWKS` | func | Fetches raw JWKS JSON as an untyped map (RFC 7517). | Lets tests inspect the JWKS without pulling in a JWK library. |
| `ParseJWTClaims` | func | Base64url-decodes a JWT payload without verifying the signature. | Test introspection only; never use in production. |
| `ParseJWTHeader` | func | Base64url-decodes a JWT header without verifying the signature. | Test introspection only; never use in production. |

## Flows

### Starting an in-process AS (`NewAuthServer` / `NewTestAuthServer`)

1. Apply functional options onto a `config` seeded with `defaultAdminKey`, `defaultIssuer` sentinel, default scopes, and default claims.
2. Generate a fresh RSA 2048 key pair, encode the public key as PEM, compute the kid (RFC 7638 thumbprint), and store the `KeyRecord` in an `InMemoryKeyStore` under the configured issuer's `client_id`.
3. Construct an `admin.AppRegistrar` guarded by `admin.APIKeyAuth(adminKey)`, an `apiauth.APIAuth` (RS256, private + public key, optional trusted assertion issuers), an `apiauth.IntrospectionHandler`, and a `keys.JWKSHandler` over the same key store.
4. Build the `http.ServeMux`, mount `/_ah/health`, `/api/token`, `/oauth/introspect`, `/.well-known/jwks.json`, and `/apps[/]` (wrapped with `httpauth.LimitBody`), then start `httptest.NewServer`.
5. Once the random port binds, if the issuer is still the default sentinel, swap it for the live server URL and patch `APIAuth.JWTIssuer`.
6. Resolve advertised `grant_types_supported` (caller override → default `["client_credentials"]`) and call `apiauth.MountASMetadata` to register `/.well-known/openid-configuration`.
7. Return the `TestAuthServer`. `NewTestAuthServer` additionally registers `s.Close` via `t.Cleanup`.

### Minting a JWT (`MintToken` / `MintTokenWithClaims` / `MintTokenForSubject`)

1. Build a `jwt.MapClaims` map — `MintToken` fills `sub`/`iss`/`type`/`scopes`/`iat`/`exp`/`jti` (and optional `aud`); `MintTokenWithClaims` only applies defaults for `iss`/`iat`/`exp` that the caller has not already set; `MintTokenForSubject` derives claims and delegates to `MintTokenWithClaims`.
2. Construct `jwt.NewWithClaims(SigningMethodRS256, claims)`, recompute the kid from the private key (matches the value JWKS publishes), and set it on the header.
3. Sign with the server's RSA private key and return the compact JWT.

## Gotchas

- **Random port**: `httptest.NewServer` binds an ephemeral port — tests must read `URL()`/`JWKSURL()`/`TokenEndpoint()` rather than hard-coding ports.
- **Issuer sentinel rewrite**: with the default `defaultIssuer`, both the metadata's `issuer` field and `APIAuth.JWTIssuer` are overwritten with the live server URL after start; pass `WithIssuer` to pin a value.
- **`WithAudience` is opt-in**: with the empty default, minted tokens do not include `aud`; downstream `aud` validation must either set `WithAudience` or accept tokens without it.
- **Advertise vs. enable**: `WithGrantTypesSupported` only edits metadata. To actually serve `jwt-bearer` / `token-exchange`, configure `WithTrustedAssertionIssuers` (which also auto-extends the advertised list unless a later `WithGrantTypesSupported` replaces it).
- **`WithIssParameterSupported` is metadata-only**: there is no authorization endpoint yet, so flipping the flag asserts a behavior the server does not currently emit.
- **JWKS exposes only the asymmetric key**: tokens signed with HS256 keys registered via `/apps/register` are NOT verifiable via JWKS — RS256-only by design.
- **Cleanup**: `NewTestAuthServer` registers `Close` via `t.Cleanup`; callers of `NewAuthServer` must invoke `Close` themselves.
- **`ParseJWTClaims` / `ParseJWTHeader` skip signature verification**: test-only — never call from production code paths.
- **Helpers `t.Fatal` on error**: `DiscoverOIDC`, `PostTokenEndpoint`, `GetClientCredentialsToken`, `GetPasswordToken`, `FetchJWKS`, `ParseJWT*` all abort the test on failure; they are not safe to call from non-test contexts.

## Depends on

- [`core/`](../core/DESIGN.md) — `GenerateSecureToken`
- [`keys/`](../keys/DESIGN.md) — `KeyStorage`, `KeyRecord`, `InMemoryKeyStore`, `NewInMemoryKeyStore`, `JWKSHandler`
- [`admin/`](../admin/DESIGN.md) — `AppRegistrar`, `NewAppRegistrar`, `APIKeyAuth`
- [`apiauth/`](../apiauth/DESIGN.md) — `APIAuth`, `NewIntrospectionHandler`, `MountASMetadata`, `ASServerMetadata`, `TrustedAssertionIssuer`, `JwtBearerGrantType`, `TokenExchangeGrantType`
- [`httpauth/`](../httpauth/DESIGN.md) — `LimitBody`, `DefaultMaxBodySize`
- [`utils/`](../utils/DESIGN.md) — `EncodePublicKeyPEM`, `ComputeKid`
