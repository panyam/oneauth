# OneAuth Developer Guide

OneAuth is a Go authentication library that provides a unified interface for local and OAuth-based authentication. It separates concerns between users, identities, and authentication channels to support multiple authentication methods per user.

## Documentation

### Getting Started
- **[GETTING_STARTED.md](GETTING_STARTED.md)** — Installation, store setup, LocalAuth config, route mounting (5-minute quickstart)

### Core Guides
- **[BROWSER_AUTH.md](BROWSER_AUTH.md)** — OAuth integration, channel linking, session management, validation, error handling
- **[API_AUTH.md](API_AUTH.md)** — JWT tokens, APIAuth setup, APIMiddleware, API keys, scopes, custom claims, multi-tenant KeyStore
- **[GRPC.md](GRPC.md)** — gRPC context utilities and auth interceptors
- **[STORES.md](STORES.md)** — Store interfaces, FS/GORM/GAE implementations, KeyStore, keystoretest suite

### Reference
- **[TESTING.md](TESTING.md)** — Testing patterns, security considerations, troubleshooting, migration guide
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — Design decisions, data model, component overview, federated auth flow
- **[AUTH_FLOWS.md](AUTH_FLOWS.md)** — Detailed authentication flow diagrams
- **[USER_GUIDE.md](USER_GUIDE.md)** — End-user facing guide
- **[RELEASE_NOTES.md](RELEASE_NOTES.md)** — Version history and changelog
