// Package introspection holds RFC 7662 (OAuth 2.0 Token Introspection)
// conformance fixtures.
//
// See:
//   - RFC 7662 — https://www.rfc-editor.org/rfc/rfc7662
//   - RFC 7662 §2.1 — Introspection request (endpoint shape, client auth,
//     token + token_type_hint parameters)
//   - RFC 7662 §2.2 — Introspection response (active semantics, optional
//     members, MUST-NOT-leak fields when active=false)
//   - RFC 7662 §4 — Security considerations (Cache-Control: no-store, etc.)
//   - RFC 9396 §11 — RAR introspection extension (authorization_details
//     echoed in active response when the token carries them)
//   - RFC 8414 §2 — token_endpoint_auth_methods_supported applies to any
//     endpoint requiring client authentication, including introspection
//
// These tests are written against an in-process OneAuth AS (via testutil),
// but the assertion shape is intended to be portable to other ASes
// once the suite gains a discovery-driven configuration mode.
package introspection
