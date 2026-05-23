// Package testutil provides an in-process OAuth authorization server and
// standalone OAuth/JWT helpers for oneauth integration tests.
//
// The package owns shared test infrastructure: a real oneauth stack wired
// into an httptest.Server, plus a set of grant and JWT helpers tuned for
// test ergonomics. It does NOT own production auth logic — the client/
// package holds the hardened equivalents with retries, error handling, and
// credential storage. Helpers here take *testing.T and call t.Fatal on
// error; the server binds a random port and registers t.Cleanup. Two
// helpers (ParseJWTClaims, GetPasswordToken) are test-only and have no
// production counterpart.
//
// TestAuthServer generates an RSA 2048 key pair, signs RS256 JWTs, serves
// JWKS, exposes RFC 7662 introspection, and publishes RFC 8414 AS
// metadata. Construct it with NewTestAuthServer (auto-cleanup) or
// NewAuthServer (caller closes). A subtlety in the metadata Options:
// WithGrantTypesSupported and WithIssParameterSupported change only the
// advertised metadata, not server behavior. WithTrustedAssertionIssuers is
// the only Option that actually enables the jwt-bearer (RFC 7523) and
// token-exchange (RFC 8693) grants; it auto-extends the advertised grant
// list unless a later WithGrantTypesSupported overrides it (last-option-
// wins on the slice).
//
// Token minting (MintToken, MintTokenWithClaims, MintTokenForSubject) is a
// fast path that signs RS256 JWTs directly with the server key, bypassing
// the HTTP token endpoint, while still setting a kid header that matches
// the JWKS-published key. MintTokenWithClaims sets iss/iat/exp defaults
// that the caller may override, which makes negative tests (wrong issuer,
// expired, missing claims) easy to express.
//
// The standalone helpers (DiscoverOIDC, GetClientCredentialsToken,
// GetPasswordToken, PostTokenEndpoint, FetchJWKS, ParseJWTClaims,
// ParseJWTHeader) target the HTTP surface of any RFC-compliant server,
// not just TestAuthServer. The JWT parsers decode without verifying
// signatures and are for test introspection only.
//
// ENTITIES
//
// TestAuthServer — in-process httptest-backed OAuth AS with RSA keys,
// JWKS, token, introspection, AS metadata, and app registration
// endpoints. Centerpiece of the package; gives downstream test suites a
// real oneauth stack on a random port.
//
// NewTestAuthServer — builds a TestAuthServer bound to *testing.T with
// automatic t.Cleanup shutdown. Preferred entry point for tests; removes
// the need for manual Close calls.
//
// NewAuthServer — builds a TestAuthServer without *testing.T; caller must
// Close. Lets examples, benchmarks, and non-test code reuse the same
// server.
//
// Option — functional option type for configuring a TestAuthServer.
// Keeps NewAuthServer's signature stable as new knobs are added.
//
// WithAdminKey — sets the admin API key guarding /apps endpoints.
// Overrides the default "testutil-admin-key" when a test asserts a
// specific key.
//
// WithIssuer — sets the JWT issuer and AS-metadata issuer. Default
// sentinel is replaced with the live server URL after start; override
// pins a value.
//
// WithAudience — sets the JWT audience claim on minted tokens. Empty
// default leaves tokens unrestricted; tests asserting audience must opt
// in.
//
// WithScopes — sets scopes_supported in AS metadata (advertisement
// only). Lets tests advertise custom scopes without changing server
// behavior.
//
// WithClaimsSupported — sets claims_supported in AS metadata. Default
// lists the claims oneauth tokens actually emit; override only when
// asserting other claims.
//
// WithGrantTypesSupported — replaces the advertised grant_types_supported
// list. Advertising a grant does NOT enable its handler; pair with
// WithTrustedAssertionIssuers to actually serve it.
//
// WithIssParameterSupported — sets the RFC 9207 iss-parameter flag in AS
// metadata. Metadata-only; no authorization endpoint drives the actual
// behavior yet.
//
// WithTrustedAssertionIssuers — enables jwt-bearer (RFC 7523) and
// token-exchange (RFC 8693) grants and auto-extends advertised grants.
// Only Option that turns advertisement into real behavior; later
// WithGrantTypesSupported can still override.
//
// MintToken — mints a standard RS256 access JWT directly, bypassing the
// HTTP token endpoint. Fast path with no network round-trip; kid header
// matches JWKS for verification.
//
// MintTokenWithClaims — mints an RS256 JWT from an arbitrary claims map
// with overridable iss/iat/exp defaults. Enables negative tests (wrong
// issuer, expired, missing claims).
//
// MintTokenForSubject — convenience minting for a subject and scopes; no
// *testing.T needed. Aimed at non-test example code that still wants a
// signed token.
//
// URL — returns the server base URL. Only known after the random
// httptest port binds.
//
// JWKSURL — returns the JWKS endpoint URL. Lets tests point JWKS-aware
// clients at the live server.
//
// TokenEndpoint — returns the token endpoint URL. Lets tests POST grants
// directly when bypassing discovery.
//
// AdminKey — returns the configured admin API key. Tests need it to call
// /apps endpoints.
//
// Issuer — returns the resolved JWT issuer. Reads the server URL when
// the default sentinel was used.
//
// Close — stops the underlying httptest server; nil-safe. Called
// automatically via t.Cleanup when NewTestAuthServer is used.
//
// OIDCConfig — parsed OAuth/OIDC AS metadata document (RFC 8414).
// Decode target for DiscoverOIDC and a typed view onto the discovery
// doc.
//
// TokenResponse — parsed OAuth token endpoint response (RFC 6749 §5.1).
// Common return type for the grant helpers.
//
// DiscoverOIDC — fetches and parses the .well-known/openid-configuration
// document. Works against any compliant AS; fails via t.Fatal for test
// ergonomics.
//
// GetClientCredentialsToken — acquires a token via the client_credentials
// grant (RFC 6749 §4.4). Thin wrapper that delegates to PostTokenEndpoint
// with the right form fields.
//
// GetPasswordToken — acquires a token via the resource owner password
// grant (RFC 6749 §4.3). Test-only helper with no production equivalent.
//
// PostTokenEndpoint — sends a form POST to a token endpoint and decodes
// the JSON TokenResponse. Shared core that the grant helpers delegate
// to; reusable for custom grants.
//
// FetchJWKS — fetches raw JWKS JSON as an untyped map (RFC 7517). Lets
// tests inspect the JWKS without pulling in a JWK library.
//
// ParseJWTClaims — base64url-decodes a JWT payload without verifying the
// signature. Test introspection only; never use in production.
//
// ParseJWTHeader — base64url-decodes a JWT header without verifying the
// signature. Test introspection only; never use in production.
//
// FLOWS
//
// See [diagrams.md](diagrams.md) for sequence diagrams of: server
// construction, HTTP-grant token acquisition, and direct JWT minting.
package testutil
