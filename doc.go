// Package oneauth provides a unified authentication framework for Go applications.
//
// OneAuth is organized into subpackages:
//
//   - core/       — Foundation types: User, Identity, Channel, store interfaces, tokens, credentials, scopes
//   - keys/       — Key storage, KID tracking, JWKS serving/fetching, encrypted key storage
//   - admin/      — Admin auth, app registration API, resource token minting
//   - apiauth/    — API token auth (JWT + API keys), validation middleware
//   - localauth/  — Local username/password auth: signup, login, email verify, password reset
//   - httpauth/   — HTTP middleware, CSRF protection, session-based auth mux
//   - stores/     — Storage backends: fs/, gorm/, gae/
//   - utils/      — Crypto helpers (PEM, JWK, key generation)
//   - client/     — Client SDK
//   - oauth2/     — OAuth2 provider implementations
//   - grpc/       — gRPC auth interceptors
//
// See each subpackage's SUMMARY.md for details.
package oneauth
