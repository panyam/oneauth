# OneAuth Architecture

## Overview

OneAuth is a Go authentication library that provides unified local and OAuth-based authentication. It's designed as an embeddable library (not a standalone service) that integrates directly into Go applications.

## Core Design Principles

1. **Separation of Concerns**: Users, Identities, and Channels as distinct layers
2. **Framework Agnostic**: Works with net/http and any router
3. **Storage Agnostic**: Interface-based stores with multiple implementations
4. **Callback-Based**: Application controls session management, email delivery, etc.

## Three-Layer Data Model

```
┌─────────────────────────────────────────────────────────┐
│                         User                             │
│  - Unique account in the system                         │
│  - Contains profile data                                │
│  - Has multiple identities                              │
└────────────────────────┬────────────────────────────────┘
                         │
           ┌─────────────┼─────────────┐
           │             │             │
           ▼             ▼             ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│   Identity   │ │   Identity   │ │   Identity   │
│  email:...   │ │  phone:...   │ │  email:...   │
│  (verified)  │ │ (unverified) │ │  (verified)  │
└──────┬───────┘ └──────────────┘ └──────┬───────┘
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

### User
- Unique account identified by user ID
- Contains profile information (name, avatar, etc.)
- Application-controlled creation and management

### Identity
- Contact method (email, phone)
- Has verification status
- Links to user account
- Shared across authentication channels

### Channel
- Authentication mechanism (local, google, github)
- Stores provider-specific credentials
- Password hash for local, OAuth tokens for OAuth providers

## Authentication Modes

### Browser Authentication (LocalAuth)

Traditional web authentication with sessions:

```
Browser → POST /auth/login → LocalAuth → HandleUser callback → Session cookie
```

- Form-based login/signup
- Email verification flow
- Password reset flow
- Session management via callback

### API Authentication (APIAuth)

Token-based authentication for programmatic access:

```
Client → POST /api/login → APIAuth → JWT + Refresh Token
Client → GET /api/resource (Bearer token) → APIMiddleware → Handler
```

- JWT access tokens (stateless, 15 min)
- Refresh tokens (database, 7 days, rotating)
- API keys (long-lived, for automation)
- Scope-based access control

## Token Architecture

### Access Tokens (JWT)
- Short-lived (15 min default)
- Stateless validation
- Contains: user ID, scopes, issuer, audience, expiry
- Signed with HS256

### Refresh Tokens
- Long-lived (7 days default)
- Stored in database
- Rotated on each use
- Family tracking for theft detection
- Revocable

### API Keys
- Long-lived (optional expiry)
- Stored as bcrypt hash
- Prefixed with `oa_` for identification
- User-manageable

## Store Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Store Interfaces                      │
│  UserStore | IdentityStore | ChannelStore | TokenStore  │
│  RefreshTokenStore | APIKeyStore                        │
└─────────────────────────────┬───────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│   stores/fs   │    │  stores/gorm  │    │  stores/gae   │
│  File-based   │    │  SQL (GORM)   │    │  Datastore    │
│  Development  │    │  Production   │    │  Google Cloud │
└───────────────┘    └───────────────┘    └───────────────┘
```

### File-Based Stores (stores/fs)
- JSON files on disk
- Suitable for development and <1000 users
- Atomic writes for consistency
- No external dependencies

### GORM Stores (stores/gorm)
- SQL databases (PostgreSQL, MySQL, SQLite)
- Production-ready
- Auto-migration support
- Connection pooling via GORM

### GAE Stores (stores/gae)
- Google Cloud Datastore
- Namespace support for multi-tenancy
- Serverless-friendly
- Automatic scaling

## Security Architecture

### Password Security
- bcrypt hashing with cost 10
- No plain-text storage
- Constant-time comparison

### Token Security
- Cryptographically secure random generation (32 bytes)
- Single-use verification tokens
- Expiry enforcement
- Lazy cleanup on access

### JWT Security
- HS256 signing
- Audience and issuer validation
- Expiry validation
- Secret key rotation support

### Refresh Token Security
- Rotation on use
- Family-based theft detection
- Immediate revocation capability
- Device tracking support

## Request Flow

### Browser Login
```
1. POST /auth/login (email, password)
2. LocalAuth.ServeHTTP
3. ValidateCredentials callback
4. Channel lookup → password verification
5. Identity lookup → user lookup
6. HandleUser callback → session creation
```

### API Login
```
1. POST /api/login (grant_type=password, username, password)
2. APIAuth.HandleLogin
3. ValidateCredentials callback
4. Generate JWT access token
5. Create refresh token in store
6. Return token pair
```

### API Request
```
1. GET /api/resource (Authorization: Bearer <jwt>)
2. APIMiddleware.ValidateToken
3. Parse and validate JWT
4. Extract user ID and scopes
5. Add to request context
6. Call handler
```

### Token Refresh
```
1. POST /api/login (grant_type=refresh_token, refresh_token)
2. APIAuth.HandleLogin
3. Get refresh token from store
4. Rotate token (invalidate old, create new)
5. Generate new JWT
6. Return new token pair
```

## Scope Model

```go
const (
    ScopeRead    = "read"     // Read user data
    ScopeWrite   = "write"    // Modify user data
    ScopeProfile = "profile"  // Access profile info
    ScopeOffline = "offline"  // Enable refresh tokens
)
```

### Scope Resolution
1. User logs in, requests scopes
2. GetUserScopes callback returns allowed scopes
3. Intersection granted to token
4. Middleware validates endpoint requires subset

## Extension Points

### Custom Validation
```go
localAuth.ValidateSignup = func(creds *Credentials) error {
    // Custom rules
}
```

### Custom Scope Resolution
```go
apiAuth.GetUserScopes = func(userID string) ([]string, error) {
    // Lookup roles, permissions, etc.
}
```

### Custom Email Sender
```go
type SMTPSender struct{}
func (s *SMTPSender) SendVerificationEmail(to, link string) error
func (s *SMTPSender) SendPasswordResetEmail(to, link string) error
```

### Custom Stores
Implement the six store interfaces for any database.

## Positioning

OneAuth differentiates from alternatives by being:

- **Embeddable library** (not a service to run)
- **Go-native** (not language-agnostic)
- **Simple model** (User → Identity → Channel)
- **Multiple store options** (file, SQL, NoSQL)
- **Callback-based** (app controls sessions)

Closest alternatives:
- `go-pkgz/auth` - Similar middleware focus, less flexible model
- `Ory Kratos` - Full IAM platform, more complex
- `Authelia` - Reverse proxy companion, different architecture
