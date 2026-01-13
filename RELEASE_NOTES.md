# OneAuth Release Notes

## Version 0.2.0

### Overview

Major release adding API authentication support for mobile apps, SPAs, CLI tools, and service-to-service communication. Also includes store reorganization with GORM and GAE/Datastore implementations.

### New Features

#### API Authentication

- **JWT Access Tokens**: Short-lived (15 min default) stateless tokens for API authentication
- **Refresh Tokens**: Long-lived (7 days default) opaque tokens with rotation and theft detection
- **API Keys**: Long-lived keys for CI/CD, scripts, and automation
- **Token Rotation**: Automatic rotation on refresh with family-based theft detection
- **Scopes**: Fine-grained access control with built-in scopes (read, write, profile, offline)

#### New Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/login` | POST | Password grant and refresh token grant |
| `/api/logout` | POST | Revoke single refresh token |
| `/api/logout-all` | POST | Revoke all user sessions |
| `/api/keys` | GET | List user's API keys |
| `/api/keys` | POST | Create new API key |
| `/api/keys/:id` | DELETE | Revoke API key |

#### APIMiddleware

New middleware for protecting API endpoints:

```go
middleware := &oneauth.APIMiddleware{
    JWTSecretKey: "secret",
    APIKeyStore:  apiKeyStore,
}

// Require valid token
mux.Handle("/api/protected", middleware.ValidateToken(handler))

// Require specific scopes
mux.Handle("/api/write", middleware.RequireScopes("write")(handler))

// Optional authentication
mux.Handle("/api/public", middleware.Optional(handler))
```

#### Store Reorganization

Stores moved to subdirectories for better organization:

- `github.com/panyam/oneauth/stores/fs` - File-based stores
- `github.com/panyam/oneauth/stores/gorm` - GORM stores for SQL databases
- `github.com/panyam/oneauth/stores/gae` - Google App Engine/Datastore stores

#### New Store Interfaces

- **RefreshTokenStore**: Manage refresh tokens with rotation and revocation
- **APIKeyStore**: Manage API keys with creation, validation, and revocation

#### GORM Store Implementation

Complete SQL database support via GORM:

```go
import "github.com/panyam/oneauth/stores/gorm"

userStore := gorm.NewGORMUserStore(db)
// ... all six stores available
gorm.AutoMigrate(db)
```

#### GAE/Datastore Store Implementation

Complete Google Cloud Datastore support:

```go
import "github.com/panyam/oneauth/stores/gae"

userStore := gae.NewUserStore(client, namespace)
// ... all six stores available
```

### Breaking Changes

#### Import Path Changes

```go
// Old
import "github.com/panyam/oneauth/stores"
stores.NewFSUserStore(path)

// New
import "github.com/panyam/oneauth/stores/fs"
fs.NewFSUserStore(path)
```

### Migration Guide

1. Update imports from `github.com/panyam/oneauth/stores` to `github.com/panyam/oneauth/stores/fs`
2. Change `stores.` prefix to `fs.` for all store constructors
3. Run `go mod tidy` to update dependencies

### New Dependencies

- `github.com/golang-jwt/jwt/v5` - JWT token handling
- `gorm.io/gorm` - GORM ORM (optional, for GORM stores)
- `cloud.google.com/go/datastore` - Google Cloud Datastore (optional, for GAE stores)

### Testing

New comprehensive test coverage for API authentication:

- `api_auth_test.go` - Tests for password grant, refresh tokens, token rotation, theft detection, JWT validation, scope enforcement, API key authentication, and API key management

### Documentation

- Updated README.md with API authentication section
- Updated DEVELOPER_GUIDE.md with detailed API auth integration guide
- Updated USER_GUIDE.md with API access instructions for technical users

---

## Version 0.1.0 (Initial Release)

### Overview

Initial release of OneAuth, a Go authentication library providing unified local and OAuth-based authentication with support for multiple authentication methods per user account.

### Features

#### Core Architecture

- Three-layer separation of concerns: Users, Identities, and Channels
- Support for multiple authentication methods per user (password, Google, GitHub, etc.)
- Global identity verification across authentication channels
- Flexible credential management with provider-specific data storage

#### Authentication Methods

**Local Authentication**
- Username and password authentication
- Email or phone as primary identity
- Configurable username type auto-detection
- bcrypt password hashing with default cost

**OAuth Integration**
- Support for OAuth2 providers (Google, GitHub, etc.)
- Automatic identity unification across providers
- OAuth token storage in channels
- Provider-specific profile data storage

#### User Registration

- Customizable signup validation
- Default validator with sensible rules (username 3-20 chars, password 8+ chars)
- Optional email verification with token-based flow
- Automatic login after successful signup (configurable)
- Profile data collection (username, email, phone)

#### Email Verification

- Token-based email verification
- Configurable token expiry (default 24 hours)
- Single-use verification tokens
- Automatic token cleanup on expiry
- Console email sender for development
- Extensible email sender interface for production

#### Password Management

- Secure password reset flow
- Token-based password reset (default 1 hour expiry)
- Password update functionality
- Security: Always returns success for forgot password to prevent user enumeration

#### Session Management

- Flexible session handling through HandleUser callback
- Support for cookie-based sessions
- Support for JWT-based sessions
- Provider information passed to session handler
- OAuth tokens available for external API calls

### Storage

#### File-Based Stores

- FSUserStore: JSON file storage for users
- FSIdentityStore: JSON file storage for identities
- FSChannelStore: JSON file storage for authentication channels
- FSTokenStore: JSON file storage for verification and reset tokens
- Atomic file writes for data consistency
- Suitable for development and small-scale applications

#### Store Interfaces

- UserStore: User account management
- IdentityStore: Contact information and verification status
- ChannelStore: Authentication method and credential storage
- TokenStore: Verification and password reset token management
- Database-agnostic interface design for production implementations

### HTTP Handlers

#### Endpoints

- `/auth/login` (POST): Username/password authentication
- `/auth/signup` (POST): User registration
- `/auth/verify-email` (GET): Email verification via token
- `/auth/forgot-password` (GET/POST): Password reset request
- `/auth/reset-password` (GET/POST): Password reset with token

#### Request Formats

- Form-encoded data (application/x-www-form-urlencoded)
- JSON request bodies (application/json)
- Configurable field names for frontend integration

#### Response Formats

- JSON responses for API clients
- Appropriate HTTP status codes (200, 400, 401, 500)
- Structured error messages

### Validation

#### Default Rules

- Username: 3-20 characters, alphanumeric with underscore and hyphen
- Email: RFC-compliant email format validation
- Phone: Minimum 10 digits after cleaning
- Password: Minimum 8 characters
- At least one of email or phone required for signup

#### Extensibility

- Custom validator function support
- Per-application validation rules
- Cross-field validation capability

### Helper Functions

- `NewCreateUserFunc`: Creates user creation callback from stores
- `NewCredentialsValidator`: Creates credential validation callback from stores
- `NewVerifyEmailFunc`: Creates email verification callback from stores
- `NewUpdatePasswordFunc`: Creates password update callback from stores
- `DetectUsernameType`: Auto-detection of username type (email, phone, username)
- `DefaultSignupValidator`: Built-in signup validation
- `GenerateSecureToken`: Cryptographic token generation

### Security

#### Password Security

- bcrypt hashing with default cost (10)
- No plain-text password storage
- Password validation during authentication
- Secure password reset flow

#### Token Security

- Cryptographically secure random token generation (32 bytes)
- Hex-encoded tokens (64 characters)
- Configurable expiry times
- Single-use token consumption
- Lazy cleanup of expired tokens (deleted when accessed)

#### Session Security

- Callback-based session management
- CSRF protection responsibility delegated to applications
- No built-in session storage to prevent lock-in

### Testing

- Comprehensive test suite covering all authentication flows
- Tests use httptest for isolated HTTP handler testing
- Temporary storage directories for test isolation
- No running server required for testing
- Test coverage for signup, login, verification, and password reset

### Documentation

- Developer guide with architecture overview and integration instructions
- User guide for end-user authentication workflows
- API documentation with godoc comments
- Migration guide from password-only authentication
- Security best practices
- Troubleshooting guide

### Dependencies

- `golang.org/x/crypto/bcrypt`: Password hashing
- `golang.org/x/oauth2`: OAuth2 support (optional, for OAuth providers)

### Known Limitations

#### Current Release

- File-based stores not recommended for production scale (>1000 users)
- Username-based login not yet implemented (email/phone only)
- No built-in rate limiting (application responsibility)
- No built-in CSRF protection (application responsibility)
- No built-in session management (application responsibility)
- Console email sender only (production email sender requires implementation)

#### Workarounds

- Implement database-backed stores for production use
- Use email or phone for login instead of username
- Add rate limiting at HTTP handler level
- Implement CSRF protection in application middleware
- Use established session libraries (scs, gorilla/sessions, etc.)
- Implement SendEmail interface for production email delivery

### Migration Path

Applications using password-only authentication can migrate to OneAuth by:

1. Implementing store interfaces for existing database schema
2. Migrating user records to identity/channel model
3. Updating authentication handlers to use OneAuth
4. Optionally adding OAuth providers
5. Updating frontend to support multiple authentication methods

See DEVELOPER_GUIDE.md for detailed migration instructions.

### Browser Support

OneAuth works with all modern browsers supporting:
- JavaScript enabled
- Cookies enabled
- HTTPS connections
- Standard HTML form submissions

### Platform Support

- Go 1.21 or later
- Linux, macOS, Windows
- Docker containers
- Cloud platforms (AWS, GCP, Azure)

### Performance

#### File-Based Stores

- Suitable for <1000 users
- Linear lookup performance
- Atomic writes for consistency
- No indexing or caching

#### Database Stores

When implementing database-backed stores:
- Add indexes on identity values (email, phone)
- Add indexes on channel provider + identity key
- Add indexes on token values
- Implement connection pooling
- Consider read replicas for high traffic

### Backward Compatibility

As an initial release, no backward compatibility guarantees yet. Semantic versioning will be followed starting with v1.0.0.

### Future Roadmap

Planned for future releases:
- Username-based login implementation
- Built-in rate limiting middleware
- Multi-factor authentication support
- Account lockout after failed attempts
- Audit logging interface
- Remember me token support
- Account deletion and data export (GDPR compliance)
- Social provider profile synchronization
- Database store reference implementations (PostgreSQL, MySQL)

### Contributing

Contributions are welcome. See CONTRIBUTING.md for guidelines on:
- Code style and formatting
- Test requirements
- Documentation standards
- Pull request process

### License

See LICENSE file for terms and conditions.

### Support

- Report issues: GitHub Issues
- Documentation: DEVELOPER_GUIDE.md and USER_GUIDE.md
- Examples: See test files (local_test.go, auth_flows_test.go) for usage patterns

### Acknowledgments

OneAuth builds on established patterns from:
- OAuth 2.0 specification (RFC 6749)
- bcrypt password hashing
- Industry best practices for authentication

### Breaking Changes

None (initial release)

### Upgrade Notes

Not applicable (initial release)

### Changelog Format

This project follows Keep a Changelog format with semantic versioning.
