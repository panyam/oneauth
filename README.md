# OneAuth

A Go authentication library providing unified local and OAuth-based authentication with support for multiple authentication methods per user account.

## Features

- **Unified authentication**: Password and OAuth through a single interface
- **Multi-provider support**: One account accessible via password, Google, GitHub, etc.
- **Separation of concerns**: Users, identities, and authentication channels as distinct concepts
- **Flexible storage**: Database-agnostic store interfaces with file-based reference implementation
- **Email workflows**: Built-in email verification and password reset flows
- **Security focused**: bcrypt password hashing, secure token generation, single-use tokens
- **Testing friendly**: No HTTP server required, uses httptest for isolated testing
- **gRPC support**: Authentication context utilities and interceptors for gRPC services
- **Production ready**: Flexible validation with sensible defaults, comprehensive error handling, and documentation (use database-backed stores for production scale)

## Quick Start

Install the package:

```bash
go get github.com/panyam/oneauth
```

Set up stores and authentication:

```go
import (
    "github.com/panyam/oneauth"
    "github.com/panyam/oneauth/stores"
)

// Initialize stores
storagePath := "/path/to/storage"
userStore := stores.NewFSUserStore(storagePath)
identityStore := stores.NewFSIdentityStore(storagePath)
channelStore := stores.NewFSChannelStore(storagePath)
tokenStore := stores.NewFSTokenStore(storagePath)

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

## Documentation

- **[Developer Guide](DEVELOPER_GUIDE.md)**: Complete integration instructions, architecture details, and API reference
- **[User Guide](USER_GUIDE.md)**: End-user documentation for applications using OneAuth
- **[Release Notes](RELEASE_NOTES.md)**: Version history, features, and known limitations
- **[API Documentation](https://pkg.go.dev/github.com/panyam/oneauth)**: Generated godoc reference

## Store Interfaces

OneAuth defines four store interfaces for data persistence:

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

## File-Based Stores

The `stores` package provides file-based implementations suitable for development and small applications:

```go
import "github.com/panyam/oneauth/stores"

userStore := stores.NewFSUserStore("/path/to/storage")
identityStore := stores.NewFSIdentityStore("/path/to/storage")
channelStore := stores.NewFSChannelStore("/path/to/storage")
tokenStore := stores.NewFSTokenStore("/path/to/storage")
```

For production use with larger user bases, implement the store interfaces backed by your database.

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
    userStore := stores.NewFSUserStore(tmpDir)
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

Complete example applications are planned for a future release. See the test files (`local_test.go`, `auth_flows_test.go`) for usage examples in the meantime.

## Limitations & Extensibility

OneAuth is designed to be flexible and extensible. Some features are intentionally left to the application layer:

### File-Based Stores

- **Development & small apps**: Suitable for <1000 users
- **Production**: Implement database-backed stores for larger scale

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
- `golang.org/x/oauth2` for OAuth providers (optional)

## License

See LICENSE file for terms and conditions.

## Contributing

Contributions are welcome. Please read CONTRIBUTING.md for guidelines.

## Support

- Documentation: DEVELOPER_GUIDE.md and USER_GUIDE.md
- Issues: GitHub Issues
- Discussions: GitHub Discussions
