// Package client_auth holds conformance fixtures for token-endpoint
// client authentication methods.
//
// See:
//   - RFC 6749 §2.3 — token endpoint client authentication baseline
//   - RFC 7521 §3 / §4.2 — assertion framework + client_assertion_type URN
//   - RFC 7523 §2.2 / §3 — JWT for client authentication; mandatory claims
//   - OpenID Connect Core §9 — private_key_jwt / client_secret_jwt
//   - RFC 8414 §2 — token_endpoint_auth_methods_supported metadata
//
// These tests pin the wire-format requirements that any AS claiming to
// support `private_key_jwt` (issue 158) MUST satisfy: assertion type
// URN exact-match, iss == sub, audience match, exp present, jti
// replay-protection, alg-confusion resistance.
package client_auth
