# OneAuth Architecture

## Overview

OneAuth is a Go authentication library that provides unified local and OAuth-based authentication, multi-tenant JWT management, and federated auth for distributed services. It's designed as an embeddable library (not a standalone service) that integrates directly into Go applications. A reference server (`cmd/oneauth-server/`) is provided for standalone deployment.

**Go version**: 1.24.0+

## Core Design Principles

1. **Separation of Concerns**: Users, Identities, and Channels as distinct layers
2. **Framework Agnostic**: Works with net/http and any router
3. **Storage Agnostic**: Interface-based stores with multiple implementations
4. **Callback-Based**: Application controls session management, email delivery, etc.

## Three-Layer Data Model

```
┌─────────────────────────────────────────────────────────┐
│                         User                            │
│  - Unique account in the system                         │
│  - Contains profile data                                │
│  - Has multiple identities                              │
└────────────────────────┬────────────────────────────────┘
                         │
           ┌─────────────┼──────────────┐
           │             │              │
           ▼             ▼              ▼
┌──────────────┐ ┌──────────────┐  ┌──────────────┐
│   Identity   │ │   Identity   │  │   Identity   │
│  email:...   │ │  phone:...   │  │  email:...   │
│  (verified)  │ │ (unverified) │  │  (verified)  │
└──────┬───────┘ └──────────────┘  └──────┬───────┘
       │                                  │
       │         ┌────────────────────────┤
       │         │                        │
       ▼         ▼                        ▼
┌──────────┐ ┌──────────┐          ┌──────────┐
│ Channel  │ │ Channel  │          │ Channel  │
│  local   │ │  google  │          │  github  │
│(password)│ │ (oauth)  │          │ (oauth)  │
└──────────┘ └──────────┘          └──────────┘
```

- **User**: Unique account identified by user ID. Contains profile information.
- **Identity**: Contact method (email, phone) with verification status. Shared across auth channels.
- **Channel**: Authentication mechanism (local, google, github) with provider-specific credentials.
- **UsernameStore** (Optional): Username uniqueness enforcement and username-based login.

Multiple channels can point to the same user via shared email identity, enabling multi-provider login.

## Three Authentication Modes

OneAuth supports three authentication modes, each targeting a different client type:

```
┌─────────────────────┬───────────────────────┬───────────────────────────┐
│   Browser Auth      │   API Auth            │   Federated Auth          │
│   (LocalAuth)       │   (APIAuth)           │   (AppRegistrar +         │
│                     │                       │    MintResourceToken)     │
│   Form login/signup │   JWT access tokens   │   App registers,          │
│   Email verify      │   Refresh tokens      │   mints scoped JWTs,      │
│   Password reset    │   API keys            │   resource server         │
│   Session cookies   │   Scope enforcement   │   validates via KeyStore  │
└─────────────────────┴───────────────────────┴───────────────────────────┘
```

Each mode has its own detailed documentation:

- **[Browser Auth](BROWSER_AUTH.md)** — Form-based login/signup, OAuth integration, channel linking, email verification, password reset, session management, validation, and error handling
- **[API Auth](API_AUTH.md)** — JWT access tokens, refresh tokens with rotation and theft detection, API keys, scope-based access control, custom claims, multi-tenant JWT validation via KeyStore
- **[Federated Auth](FEDERATED_AUTH.md)** — App Registration API (AdminAuth, AppRegistrar), resource token minting (MintResourceToken), multi-service architecture with shared KeyStore
- **[Auth Flows](AUTH_FLOWS.md)** — Detailed decision trees for login/signup, provider linking matrix, user journeys, edge cases

## Store Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Store Interfaces                       │
│  UserStore | IdentityStore | ChannelStore | TokenStore      │
│  RefreshTokenStore | APIKeyStore | UsernameStore (opt)      │
│  KeyStore | WritableKeyStore (multi-tenant JWT)             │
└──────────────────────────┬──────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│   stores/fs   │   │  stores/gorm  │   │  stores/gae   │
│  File-based   │   │  SQL (GORM)   │   │  Datastore    │
│  Development  │   │  Production   │   │  Google Cloud │
└───────────────┘   └───────────────┘   └───────────────┘
```

For store interfaces, implementations, and KeyStore details, see **[Stores](STORES.md)**.

## Demos

See **[DEMOS.md](DEMOS.md)** for runnable demos that exercise key scenarios end-to-end, including what each demo simplifies vs. production usage.

## Client SDK

For CLI tools and programmatic clients consuming oneauth-protected APIs:

```
AuthClient → Login/Logout → CredentialStore (persists tokens)
           → HTTPClient() → refreshTransport (auto-refresh on 401)
```

See **[Client SDK](CLIENT_SDK.md)** for full details.

## Security Architecture

### Password Security
- bcrypt hashing with cost 10
- Constant-time comparison

### Token Security
- Cryptographically secure random generation (32 bytes)
- Single-use verification tokens (deleted after use)
- Expiry enforcement with lazy cleanup

### JWT Security
- HS256, RS256, and ES256 signing (per-app algorithm choice, all coexist in the same KeyStore)
- Asymmetric signing: apps keep private keys, register only public keys; resource servers verify without knowing signing secrets
- Audience and issuer validation
- Algorithm confusion prevention via `GetExpectedAlg`
- `utils.DecodeVerifyKey` converts stored PEM bytes to `crypto.PublicKey` at read time

### Refresh Token Security
- Rotation on use
- Family-based theft detection (reuse → revoke entire family)
- Immediate revocation capability

## Extension Points

| Extension | Purpose | Doc |
|-----------|---------|-----|
| `SignupPolicy` | Configurable signup requirements | [Browser Auth](BROWSER_AUTH.md#signuppolicy-recommended) |
| `OnSignupError` / `OnLoginError` | Custom error handlers | [Browser Auth](BROWSER_AUTH.md#custom-error-handlers) |
| `ValidateSignup` (legacy) | Custom signup validation | [Browser Auth](BROWSER_AUTH.md#custom-validator-legacy) |
| `GetUserScopes` | Custom scope resolution | [API Auth](API_AUTH.md#scopes) |
| `CustomClaimsFunc` | Inject custom JWT claims | [API Auth](API_AUTH.md#custom-claims) |
| `EmailSender` | Custom email delivery | [Browser Auth](BROWSER_AUTH.md#email-integration) |
| `AdminAuth` | Pluggable admin authentication | [Federated Auth](FEDERATED_AUTH.md#adminauth-interface) |
| Store interfaces | Custom database backends | [Stores](STORES.md#custom-store-implementation) |

## Positioning

OneAuth differentiates from alternatives by being:

- **Embeddable library** (not a service to run)
- **Go-native** (not language-agnostic)
- **Simple model** (User → Identity → Channel)
- **Multiple store options** (file, SQL, NoSQL)
- **Callback-based** (app controls sessions)
- **Federated-ready** (multi-tenant KeyStore, app registration, resource token minting)

Closest alternatives:
- `go-pkgz/auth` — Similar middleware focus, less flexible model
- `Ory Kratos` — Full IAM platform, more complex
- `Authelia` — Reverse proxy companion, different architecture

## Documentation Index

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | This file — high-level overview |
| [BROWSER_AUTH.md](BROWSER_AUTH.md) | Browser-based authentication (LocalAuth, OAuth, sessions) |
| [API_AUTH.md](API_AUTH.md) | API authentication (JWT, refresh tokens, API keys, KeyStore) |
| [FEDERATED_AUTH.md](FEDERATED_AUTH.md) | Federated auth (AppRegistrar, MintResourceToken, AdminAuth) |
| [AUTH_FLOWS.md](AUTH_FLOWS.md) | Detailed decision trees, user journeys, edge cases |
| [CLIENT_SDK.md](CLIENT_SDK.md) | Client SDK for CLI/programmatic access |
| [STORES.md](STORES.md) | Store interfaces and implementations |
| [GETTING_STARTED.md](GETTING_STARTED.md) | Quick start guide |
| [USER_GUIDE.md](USER_GUIDE.md) | User guide |
| [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) | Developer guide |
| [DEMOS.md](DEMOS.md) | Runnable demos & production vs. demo comparison |
| [TESTING.md](TESTING.md) | Testing guide |
| [GRPC.md](GRPC.md) | gRPC integration |
