// Package as_metadata holds conformance fixtures for OAuth Authorization
// Server / OIDC Provider metadata discovery.
//
// See:
//   - RFC 8414 §3 — AS metadata at /.well-known/oauth-authorization-server
//   - OpenID Connect Discovery 1.0 §4 — same metadata at
//     /.well-known/openid-configuration
//
// RFC 8414 §3 requires that an AS which also serves OIDC discovery make
// the metadata available at *both* paths so legacy OAuth-only clients
// (which look up RFC 8414) and OIDC clients (which look up
// openid-configuration) can both discover the server.
package as_metadata
