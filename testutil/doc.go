// Package testutil provides reusable test infrastructure for oneauth
// integration tests. It is intended to be imported by downstream projects
// (mcpkit, relay, etc.) as well as oneauth's own test suites.
//
// Two categories of helpers:
//
//  1. TestAuthServer — an in-process authorization server with RSA keys,
//     JWKS, token endpoint, and AS metadata (RFC 8414).
//
//  2. Shared OAuth helpers — standalone functions that work against any
//     RFC-compliant OAuth server (TestAuthServer, Keycloak, Auth0, etc.).
//
// Note: The client/ package has production-grade equivalents (client.DiscoverAS,
// client.AuthClient.ClientCredentialsToken) with proper error handling, retries,
// and credential storage. These testutil helpers are intentionally simpler:
// they take *testing.T, call t.Fatal on error, and return plain structs for
// test ergonomics. They also include test-only functions (ParseJWTClaims,
// GetPasswordToken) that have no production equivalent.
//
// <!-- design:start -->
// This package owns shared test infrastructure: an in-process authorization
// server and standalone OAuth/JWT helpers. It does NOT own production auth
// logic — the client/ package holds the hardened equivalents with retries,
// error handling, and credential storage. Everything here is tuned for test
// ergonomics: helpers take *testing.T and call t.Fatal, the server binds a
// random httptest port, and cleanup is automatic. Two test-only functions
// (ParseJWTClaims, GetPasswordToken) have no production counterpart.
//
// TestAuthServer is the centerpiece: a real oneauth stack (RSA 2048 key,
// RS256 signing, JWKS, token endpoint, RFC 7662 introspection, app
// registration, and RFC 8414 AS metadata) wired into an httptest.Server.
// Construct it with NewTestAuthServer (registers t.Cleanup) or NewAuthServer
// (no *testing.T; caller must Close). Both accept functional Options.
//
// A subtlety in the metadata Options: WithGrantTypesSupported and
// WithIssParameterSupported change only the advertised metadata, not server
// behavior — advertising a grant does not enable its handler, and there is
// no authorization endpoint to honor RFC 9207's iss= parameter.
// WithTrustedAssertionIssuers is the option that actually enables the
// jwt-bearer (RFC 7523) and token-exchange (RFC 8693) grants, and it
// auto-extends the advertised grant list unless a later
// WithGrantTypesSupported overrides it (last-option-wins on the slice).
//
// Token minting (MintToken, MintTokenWithClaims, MintTokenForSubject) is a
// fast path that signs RS256 JWTs directly with the server key, bypassing
// the HTTP token endpoint and any network round-trip, while still setting a
// kid header that matches the JWKS-published key. MintTokenWithClaims sets
// iss/iat/exp defaults the caller may override, which is what makes negative
// tests (wrong issuer, expired, missing claims) easy to express.
//
// The standalone helpers (DiscoverOIDC, GetClientCredentialsToken,
// GetPasswordToken, PostTokenEndpoint, FetchJWKS, ParseJWTClaims,
// ParseJWTHeader) target the HTTP surface of any RFC-compliant server, not
// just TestAuthServer. The JWT parsers decode without verifying signatures
// and are for test introspection only.
//
// # ENTITIES
//
// TestAuthServer — in-process httptest-backed OAuth AS exposing health,
// token, introspection, JWKS, AS-metadata, and app-registration endpoints.
//
// NewTestAuthServer — builds a TestAuthServer bound to *testing.T with
// automatic t.Cleanup shutdown; the preferred entry point for tests.
//
// NewAuthServer — builds a TestAuthServer without *testing.T for examples
// and benchmarks; the caller must call Close.
//
// Option — functional option type for configuring a TestAuthServer.
//
// WithAdminKey — sets the admin API key guarding the /apps endpoints
// (default "testutil-admin-key").
//
// WithIssuer — sets the JWT issuer and AS-metadata issuer; the sentinel
// default is replaced with the live server URL after start.
//
// WithAudience — sets the JWT audience claim (empty means unrestricted).
//
// WithScopes — sets scopes_supported in AS metadata (advertisement only).
//
// WithClaimsSupported — sets claims_supported in AS metadata, defaulting to
// the claims oneauth bearer tokens actually emit.
//
// WithGrantTypesSupported — replaces the advertised grant_types_supported
// list; advertising a grant does not enable its handler.
//
// WithIssParameterSupported — sets the RFC 9207 iss-parameter flag in
// metadata only; no authorization endpoint drives the actual behavior.
//
// WithTrustedAssertionIssuers — enables jwt-bearer (RFC 7523) and
// token-exchange (RFC 8693) grants and auto-extends advertised grants unless
// a later WithGrantTypesSupported overrides them.
//
// MintToken — mints a standard RS256 access JWT directly, bypassing the HTTP
// token endpoint; the kid header matches the JWKS key.
//
// MintTokenWithClaims — mints an RS256 JWT from an arbitrary claims map with
// overridable iss/iat/exp defaults, enabling negative tests.
//
// MintTokenForSubject — convenience minting for a subject and scopes,
// aimed at non-*testing.T example code.
//
// URL — returns the server base URL (only known after the random port binds).
//
// JWKSURL — returns the JWKS endpoint URL.
//
// TokenEndpoint — returns the token endpoint URL.
//
// AdminKey — returns the configured admin API key.
//
// Issuer — returns the resolved JWT issuer (server URL when the default was
// used).
//
// Close — stops the underlying httptest server; nil-safe.
//
// OIDCConfig — parsed OAuth/OIDC AS metadata document (RFC 8414); the decode
// target for DiscoverOIDC.
//
// TokenResponse — parsed OAuth token endpoint response (RFC 6749 §5.1).
//
// DiscoverOIDC — fetches and parses the .well-known/openid-configuration
// document against any compliant AS, failing via t.Fatal.
//
// GetClientCredentialsToken — acquires a token via the client_credentials
// grant (RFC 6749 §4.4), delegating to PostTokenEndpoint.
//
// GetPasswordToken — acquires a token via the resource owner password grant
// (RFC 6749 §4.3); test-only with no production equivalent.
//
// PostTokenEndpoint — sends a form POST to a token endpoint and decodes the
// JSON TokenResponse; shared core for the grant helpers.
//
// FetchJWKS — fetches raw JWKS JSON as an untyped map (RFC 7517).
//
// ParseJWTClaims — base64url-decodes a JWT payload without verifying the
// signature; test introspection only.
//
// ParseJWTHeader — base64url-decodes a JWT header without verifying the
// signature; test introspection only.
// <!-- design:end -->
package testutil
