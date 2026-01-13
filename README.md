# OneAuth

A Go authentication library providing unified local and OAuth-based authentication with support for multiple authentication methods per user account.

## Features

- **Unified authentication**: Password and OAuth through a single interface
- **Multi-provider support**: One account accessible via password, Google, GitHub, etc.
- **API authentication**: JWT access tokens, refresh tokens, and API keys for programmatic access
- **Separation of concerns**: Users, identities, and authentication channels as distinct concepts
- **Flexible storage**: Database-agnostic store interfaces with file-based, GORM, and GAE/Datastore implementations
- **Email workflows**: Built-in email verification and password reset flows
- **Security focused**: bcrypt password hashing, JWT tokens, secure token generation, single-use tokens
- **Scopes & permissions**: Fine-grained access control with scope validation
- **Testing friendly**: No HTTP server required, uses httptest for isolated testing
- **gRPC support**: Authentication context utilities and interceptors for gRPC services
- **Production ready**: Flexible validation with sensible defaults, comprehensive error handling, and documentation

## Quick Start

Install the package:

```bash
go get github.com/panyam/oneauth
```

Set up stores and authentication:

```go
import (
    "github.com/panyam/oneauth"
    "github.com/panyam/oneauth/stores/fs"
)

// Initialize stores
storagePath := "/path/to/storage"
userStore := fs.NewFSUserStore(storagePath)
identityStore := fs.NewFSIdentityStore(storagePath)
channelStore := fs.NewFSChannelStore(storagePath)
tokenStore := fs.NewFSTokenStore(storagePath)

// Create authentication callbacks
createUser := oneauth.NewCreateUserFunc(userStore, identityStore, channelStore)
validateCreds := oneauth.NewCredentialsValidator(identityStore, channelStore, userStore)
verifyEmail := oneauth.NewVerifyEmailFunc(identityStore, tokenStore)
updatePassword := oneauth.NewUpdatePasswordFunc(identityStore, channelStore)

// Configure local authentication
localAuth := &oneauth.LocalAuth{
    CreateUser:          createUser,
    ValidateCredentials: validateCreds,
    EmailSender:         &oneauth.ConsoleEmailSender{},
    TokenStore:          tokenStore,
    BaseURL:             "https://yourapp.com",
    VerifyEmail:         verifyEmail,
    UpdatePassword:      updatePassword,
    HandleUser:          yourSessionHandler,
}

// Set up HTTP routes
mux := http.NewServeMux()
mux.Handle("/auth/login", localAuth)
mux.Handle("/auth/signup", http.HandlerFunc(localAuth.HandleSignup))
mux.Handle("/auth/verify-email", http.HandlerFunc(localAuth.HandleVerifyEmail))
mux.Handle("/auth/forgot-password", http.HandlerFunc(localAuth.HandleForgotPassword))
mux.Handle("/auth/reset-password", http.HandlerFunc(localAuth.HandleResetPassword))
```

## Architecture

OneAuth separates authentication into three layers:

**User**: A unique account containing profile information.

**Identity**: An email address or phone number with verification status. Identities can be used across multiple authentication channels.

**Channel**: An authentication mechanism (password, Google, GitHub) storing provider-specific credentials.

This design allows users to sign in with multiple methods while maintaining a single account.

## Core Concepts

### Multiple Authentication Methods

A user can authenticate via different methods using the same email:

```
User: john@example.com
├── Channel: local (password authentication)
├── Channel: google (OAuth)
└── Channel: github (OAuth)
```

All three channels access the same account and data.

### Global Identity Verification

Verifying an email through any channel verifies it for all channels:

- Sign up with password → email unverified
- Log in with Google → email automatically verified for both password and Google login

### Provider-Specific Data

Each channel stores its own credentials and profile:

- Local channel: bcrypt password hash, username
- Google channel: OAuth tokens, Google profile data
- GitHub channel: OAuth tokens, GitHub profile data

## gRPC Authentication

OneAuth provides gRPC authentication utilities in the `grpc` subpackage for passing user identity between HTTP gateways and gRPC services.

### Context Utilities

```go
import oagrpc "github.com/panyam/oneauth/grpc"

// In your gRPC gateway, inject user ID into metadata
md := metadata.Pairs(oagrpc.DefaultMetadataKeyUserID, userID)
ctx = metadata.NewOutgoingContext(ctx, md)

// In your gRPC service, extract user ID from context
userID := oagrpc.UserIDFromContext(ctx)
if userID == "" {
    return nil, status.Error(codes.Unauthenticated, "not authenticated")
}
```

### Auth Interceptors

```go
import oagrpc "github.com/panyam/oneauth/grpc"

// Require authentication for all methods
server := grpc.NewServer(
    grpc.UnaryInterceptor(oagrpc.UnaryAuthInterceptor(nil)),
    grpc.StreamInterceptor(oagrpc.StreamAuthInterceptor(nil)),
)

// Allow some methods to be public
config := oagrpc.NewPublicMethodsConfig(
    "/pkg.Service/PublicMethod",
    "/pkg.Service/AnotherPublicMethod",
)
server := grpc.NewServer(
    grpc.UnaryInterceptor(oagrpc.UnaryAuthInterceptor(config)),
)

// Optional auth (allow unauthenticated requests)
server := grpc.NewServer(
    grpc.UnaryInterceptor(oagrpc.UnaryAuthInterceptor(oagrpc.OptionalAuthConfig())),
)
```

See the Developer Guide for complete gRPC integration documentation.

## API Authentication

OneAuth provides a complete API authentication system for mobile apps, SPAs, CLI tools, and service-to-service communication.

### Token Architecture

- **Access Tokens**: Short-lived JWTs (15 min default) for stateless API authentication
- **Refresh Tokens**: Long-lived opaque tokens (7 days) for obtaining new access tokens
- **API Keys**: Long-lived keys for CI/CD, scripts, and automation

### API Login

```go
import (
    "github.com/panyam/oneauth"
    "github.com/panyam/oneauth/stores/fs"
)

// Setup stores
storagePath := "/path/to/storage"
refreshTokenStore := fs.NewFSRefreshTokenStore(storagePath)
apiKeyStore := fs.NewFSAPIKeyStore(storagePath)

// Configure API authentication
apiAuth := &oneauth.APIAuth{
    ValidateCredentials: validateCreds,
    RefreshTokenStore:   refreshTokenStore,
    APIKeyStore:         apiKeyStore,
    JWTSecretKey:        "your-secret-key",
    JWTIssuer:           "yourapp.com",
    GetUserScopes: func(userID string) ([]string, error) {
        return []string{"read", "write", "profile"}, nil
    },
}

// Mount API routes
mux.Handle("/api/login", http.HandlerFunc(apiAuth.HandleLogin))
mux.Handle("/api/logout", http.HandlerFunc(apiAuth.HandleLogout))
mux.Handle("/api/keys", http.HandlerFunc(apiAuth.HandleAPIKeys))
```

### API Middleware

Protect your API endpoints with JWT validation:

```go
middleware := &oneauth.APIMiddleware{
    JWTSecretKey: "your-secret-key",
    JWTIssuer:    "yourapp.com",
    APIKeyStore:  apiKeyStore,
}

// Require authentication
mux.Handle("/api/protected", middleware.ValidateToken(protectedHandler))

// Require specific scopes
mux.Handle("/api/write", middleware.RequireScopes("write")(writeHandler))

// Optional authentication
mux.Handle("/api/public", middleware.Optional(publicHandler))
```

### API Requests

```bash
# Login with password
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"password","username":"user@example.com","password":"secret"}'

# Response: {"access_token":"eyJ...", "refresh_token":"abc123...", "token_type":"Bearer"}

# Use access token
curl http://localhost:8080/api/protected \
  -H "Authorization: Bearer eyJ..."

# Refresh tokens
curl -X POST http://localhost:8080/api/login \
  -d '{"grant_type":"refresh_token","refresh_token":"abc123..."}'

# Create API key
curl -X POST http://localhost:8080/api/keys \
  -H "Authorization: Bearer eyJ..." \
  -d '{"name":"CI Key","scopes":["read"]}'
```

## Documentation

- **[Developer Guide](DEVELOPER_GUIDE.md)**: Complete integration instructions, architecture details, and API reference
- **[User Guide](USER_GUIDE.md)**: End-user documentation for applications using OneAuth
- **[Release Notes](RELEASE_NOTES.md)**: Version history, features, and known limitations
- **[API Documentation](https://pkg.go.dev/github.com/panyam/oneauth)**: Generated godoc reference

## Store Interfaces

OneAuth defines six store interfaces for data persistence:

### UserStore

Manages user accounts with profile data.

```go
type UserStore interface {
    CreateUser(userId string, isActive bool, profile map[string]any) (User, error)
    GetUserById(userId string) (User, error)
    SaveUser(user User) error
}
```

### IdentityStore

Manages contact information and verification status.

```go
type IdentityStore interface {
    GetIdentity(identityType, identityValue string, createIfMissing bool) (*Identity, bool, error)
    SaveIdentity(identity *Identity) error
    SetUserForIdentity(identityType, identityValue string, newUserId string) error
    MarkIdentityVerified(identityType, identityValue string) error
    GetUserIdentities(userId string) ([]*Identity, error)
}
```

### ChannelStore

Manages authentication methods and credentials.

```go
type ChannelStore interface {
    GetChannel(provider, identityKey string, createIfMissing bool) (*Channel, bool, error)
    SaveChannel(channel *Channel) error
    GetChannelsByIdentity(identityKey string) ([]*Channel, error)
}
```

### TokenStore

Manages verification and password reset tokens.

```go
type TokenStore interface {
    CreateToken(userID, email string, tokenType TokenType, expiryDuration time.Duration) (*AuthToken, error)
    GetToken(token string) (*AuthToken, error)
    DeleteToken(token string) error
    DeleteUserTokens(userID string, tokenType TokenType) error
}
```

### RefreshTokenStore

Manages refresh tokens for API authentication.

```go
type RefreshTokenStore interface {
    CreateRefreshToken(userID, clientID string, deviceInfo map[string]any, scopes []string, expiresIn time.Duration) (*RefreshToken, error)
    GetRefreshToken(token string) (*RefreshToken, error)
    RotateRefreshToken(oldToken string, expiresIn time.Duration) (*RefreshToken, error)
    RevokeRefreshToken(token string) error
    RevokeUserTokens(userID string) error
    RevokeTokenFamily(family string) error
}
```

### APIKeyStore

Manages API keys for long-lived programmatic access.

```go
type APIKeyStore interface {
    CreateAPIKey(userID, name string, scopes []string, expiresAt *time.Time) (fullKey string, apiKey *APIKey, err error)
    GetAPIKeyByID(keyID string) (*APIKey, error)
    ValidateAPIKey(fullKey string) (*APIKey, error)
    RevokeAPIKey(keyID string) error
    ListUserAPIKeys(userID string) ([]*APIKey, error)
}
```

## Store Implementations

OneAuth provides three store implementations:

### File-Based Stores

For development and small applications (< 1000 users):

```go
import "github.com/panyam/oneauth/stores/fs"

storagePath := "/path/to/storage"
userStore := fs.NewFSUserStore(storagePath)
identityStore := fs.NewFSIdentityStore(storagePath)
channelStore := fs.NewFSChannelStore(storagePath)
tokenStore := fs.NewFSTokenStore(storagePath)
refreshTokenStore := fs.NewFSRefreshTokenStore(storagePath)
apiKeyStore := fs.NewFSAPIKeyStore(storagePath)
```

### GORM Stores

For SQL databases (PostgreSQL, MySQL, SQLite):

```go
import (
    "github.com/panyam/oneauth/stores/gorm"
    gormdb "gorm.io/gorm"
)

db, _ := gormdb.Open(postgres.Open(dsn), &gormdb.Config{})

userStore := gorm.NewGORMUserStore(db)
identityStore := gorm.NewGORMIdentityStore(db)
channelStore := gorm.NewGORMChannelStore(db)
tokenStore := gorm.NewGORMTokenStore(db)
refreshTokenStore := gorm.NewGORMRefreshTokenStore(db)
apiKeyStore := gorm.NewGORMAPIKeyStore(db)

// Auto-migrate tables
gorm.AutoMigrate(db)
```

### GAE/Datastore Stores

For Google App Engine and Cloud Datastore:

```go
import (
    "github.com/panyam/oneauth/stores/gae"
    "cloud.google.com/go/datastore"
)

client, _ := datastore.NewClient(ctx, projectID)
namespace := "myapp"

userStore := gae.NewUserStore(client, namespace)
identityStore := gae.NewIdentityStore(client, namespace)
channelStore := gae.NewChannelStore(client, namespace)
tokenStore := gae.NewTokenStore(client, namespace)
refreshTokenStore := gae.NewRefreshTokenStore(client, namespace)
apiKeyStore := gae.NewAPIKeyStore(client, namespace)
```

## Authentication Flows

### User Registration

```http
POST /auth/signup
Content-Type: application/x-www-form-urlencoded

username=johndoe&email=john@example.com&password=secret123
```

Response:
```json
{
  "success": true,
  "user": {
    "username": "johndoe",
    "email": "john@example.com"
  }
}
```

### User Login

```http
POST /auth/login
Content-Type: application/x-www-form-urlencoded

email=john@example.com&password=secret123
```

Response:
```json
{
  "success": true,
  "user": {
    "username": "johndoe"
  }
}
```

### Email Verification

```http
GET /auth/verify-email?token=abc123...
```

Response:
```json
{
  "success": true,
  "message": "Email verified successfully"
}
```

### Password Reset Request

```http
POST /auth/forgot-password
Content-Type: application/x-www-form-urlencoded

email=john@example.com
```

Response:
```json
{
  "success": true,
  "message": "If that email exists, a reset link has been sent"
}
```

### Password Reset

```http
POST /auth/reset-password
Content-Type: application/x-www-form-urlencoded

token=xyz789...&password=newsecret456
```

Response:
```json
{
  "success": true,
  "message": "Password reset successfully",
  "email": "john@example.com"
}
```

## Validation

### Default Rules

- Username: 3-20 characters, alphanumeric with underscore and hyphen
- Email: Valid email format
- Phone: Minimum 10 digits
- Password: Minimum 8 characters
- At least one of email or phone required

### Custom Validation

```go
localAuth.ValidateSignup = func(creds *oneauth.Credentials) error {
    if len(creds.Password) < 12 {
        return fmt.Errorf("password must be at least 12 characters")
    }
    // Add custom validation logic
    return nil
}
```

## Email Integration

### Development

Use the console email sender for development:

```go
localAuth.EmailSender = &oneauth.ConsoleEmailSender{}
```

Emails are printed to stdout instead of being sent.

### Production

Implement the `SendEmail` interface for your email service:

```go
type SendEmail interface {
    SendVerificationEmail(to string, verificationLink string) error
    SendPasswordResetEmail(to string, resetLink string) error
}
```

Example with SMTP:

```go
type SMTPSender struct {
    host, username, password string
    port int
}

func (s *SMTPSender) SendVerificationEmail(to, link string) error {
    // SMTP implementation
}

func (s *SMTPSender) SendPasswordResetEmail(to, link string) error {
    // SMTP implementation
}
```

## Session Management

The `HandleUser` callback is invoked after successful authentication:

```go
HandleUser: func(authtype, provider string, token *oauth2.Token,
                userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
    // token is nil for local auth, populated for OAuth

    sessionID := generateSessionID()
    sessionStore.Save(sessionID, userInfo)

    http.SetCookie(w, &http.Cookie{
        Name:     "session_id",
        Value:    sessionID,
        HttpOnly: true,
        Secure:   true,
    })

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]any{
        "success": true,
        "user":    userInfo,
    })
}
```

## Testing

Test handlers without a running server:

```go
func TestLogin(t *testing.T) {
    tmpDir, _ := os.MkdirTemp("", "test-*")
    defer os.RemoveAll(tmpDir)

    // Set up stores and auth
    userStore := fs.NewFSUserStore(tmpDir)
    // ... configure localAuth

    // Create request
    form := url.Values{}
    form.Set("email", "test@example.com")
    form.Set("password", "password123")

    req := httptest.NewRequest(http.MethodPost, "/auth/login",
                                strings.NewReader(form.Encode()))
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    rr := httptest.NewRecorder()
    localAuth.ServeHTTP(rr, req)

    if rr.Code != http.StatusOK {
        t.Errorf("Expected 200, got %d", rr.Code)
    }
}
```

## Security

### Password Storage

Passwords are hashed using bcrypt with default cost. Plain-text passwords are never stored.

### Token Security

- Verification tokens: 32 bytes, hex-encoded (64 characters)
- Expiry: 24 hours for email verification, 1 hour for password reset
- Single-use tokens automatically deleted after consumption
- Expired tokens rejected and cleaned up automatically

### Best Practices

1. Use HTTPS in production
2. Implement rate limiting at the HTTP handler level
3. Add CSRF protection in application middleware
4. Implement session timeouts
5. Log authentication events
6. Store secrets in environment variables or secret managers

## Examples

Complete example applications are planned for a future release. See the test files for usage examples:

- `local_test.go`, `auth_flows_test.go`: Browser-based authentication flows
- `api_auth_test.go`: API authentication with JWT, refresh tokens, and API keys
- `grpc/context_test.go`, `grpc/interceptor_test.go`: gRPC integration patterns

## Limitations & Extensibility

OneAuth is designed to be flexible and extensible. Some features are intentionally left to the application layer:

### Store Options

- **File-based stores**: Suitable for development and <1000 users
- **GORM stores**: For production SQL databases
- **GAE stores**: For Google Cloud deployments
- **Custom stores**: Implement interfaces for other databases

### Application Responsibilities

The following are intentionally not provided by OneAuth and should be implemented at the application level:

- **Rate limiting**: Protect authentication endpoints from brute force attacks
- **CSRF protection**: Add CSRF tokens to forms and validate them in your middleware
- **Session management**: Use established session libraries (scs, gorilla/sessions, etc.)
- **Account lockout**: Implement after repeated failed login attempts
- **Email service**: Provide production email sender (ConsoleEmailSender is for development only)

See the Developer Guide for implementation patterns and best practices.

## Requirements

- Go 1.21 or later
- `golang.org/x/crypto/bcrypt` for password hashing (required)
- `github.com/golang-jwt/jwt/v5` for JWT tokens (required for API auth)
- `golang.org/x/oauth2` for OAuth providers (optional)
- `gorm.io/gorm` for GORM stores (optional)
- `cloud.google.com/go/datastore` for GAE stores (optional)

## License

See LICENSE file for terms and conditions.

## Contributing

Contributions are welcome. Please read CONTRIBUTING.md for guidelines.

## Support

- Documentation: DEVELOPER_GUIDE.md and USER_GUIDE.md
- Issues: GitHub Issues
- Discussions: GitHub Discussions
