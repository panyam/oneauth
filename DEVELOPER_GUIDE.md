# OneAuth Developer Guide

## Overview

OneAuth is a Go authentication library that provides a unified interface for local and OAuth-based authentication. It separates concerns between users, identities, and authentication channels to support multiple authentication methods per user.

## Architecture

### Core Concepts

**User**: A unique account in your system. Users are identified by a user ID and contain profile information.

**Identity**: A contact method (email address or phone number) that belongs to a user. Identities have a verification status and can be shared across multiple authentication channels.

**Channel**: An authentication mechanism (local password, Google OAuth, GitHub OAuth, etc.) connected to an identity. Channels store provider-specific credentials and profile data.

### Separation of Concerns

This three-layer model enables:

- **Multiple authentication methods per user**: A user can log in with password, Google, or GitHub using the same email address
- **Global identity verification**: Verifying an email via Google OAuth automatically verifies it for local authentication
- **Provider-specific data**: Store OAuth tokens separately from user profiles
- **Flexible credential management**: Change passwords or revoke OAuth access independently

### Data Flow

```
Authentication Request → Channel → Identity → User
```

1. User provides credentials (password or OAuth callback)
2. System looks up the channel (local, google, github)
3. Channel validates credentials and returns identity key
4. Identity maps to user account
5. User session is established

## Installation

```bash
go get github.com/panyam/oneauth
```

## Quick Start

### Setting Up Stores

OneAuth requires four stores: users, identities, channels, and tokens. The library provides file-based implementations:

```go
import (
    "github.com/panyam/oneauth"
    "github.com/panyam/oneauth/stores"
)

storagePath := "/path/to/storage"
userStore := stores.NewFSUserStore(storagePath)
identityStore := stores.NewFSIdentityStore(storagePath)
channelStore := stores.NewFSChannelStore(storagePath)
tokenStore := stores.NewFSTokenStore(storagePath)
```

### Implementing Local Authentication

```go
// Create authentication callbacks using helper functions
createUser := oneauth.NewCreateUserFunc(userStore, identityStore, channelStore)
validateCreds := oneauth.NewCredentialsValidator(identityStore, channelStore, userStore)
verifyEmail := oneauth.NewVerifyEmailFunc(identityStore, tokenStore)
updatePassword := oneauth.NewUpdatePasswordFunc(identityStore, channelStore)

// Configure local authentication
localAuth := &oneauth.LocalAuth{
    CreateUser:          createUser,
    ValidateCredentials: validateCreds,
    ValidateSignup:      nil, // Uses default validator
    EmailSender:         &oneauth.ConsoleEmailSender{},
    TokenStore:          tokenStore,
    BaseURL:             "https://yourapp.com",
    RequireEmailVerification: false,
    UsernameField:       "email",
    VerifyEmail:         verifyEmail,
    UpdatePassword:      updatePassword,
    HandleUser: func(authtype string, provider string, token *oauth2.Token,
                      userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
        // Create session, set cookies, redirect, etc.
    },
}
```

### Setting Up Routes

```go
mux := http.NewServeMux()

// Authentication routes
mux.Handle("/auth/login", localAuth)
mux.Handle("/auth/signup", http.HandlerFunc(localAuth.HandleSignup))
mux.Handle("/auth/verify-email", http.HandlerFunc(localAuth.HandleVerifyEmail))

// Password reset routes
mux.Handle("/auth/forgot-password", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        localAuth.HandleForgotPasswordForm(w, r)
    } else {
        localAuth.HandleForgotPassword(w, r)
    }
}))

mux.Handle("/auth/reset-password", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        localAuth.HandleResetPasswordForm(w, r)
    } else {
        localAuth.HandleResetPassword(w, r)
    }
}))
```

## Store Interfaces

### UserStore

Manages user accounts.

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

Identity types: `"email"`, `"phone"`

### ChannelStore

Manages authentication methods and provider-specific data.

```go
type ChannelStore interface {
    GetChannel(provider string, identityKey string, createIfMissing bool) (*Channel, bool, error)
    SaveChannel(channel *Channel) error
    GetChannelsByIdentity(identityKey string) ([]*Channel, error)
}
```

Providers: `"local"`, `"google"`, `"github"`, etc.

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

Token types: `TokenTypeEmailVerification`, `TokenTypePasswordReset`

## Custom Store Implementation

Implement the store interfaces for your database:

```go
type PostgresUserStore struct {
    db *sql.DB
}

func (s *PostgresUserStore) CreateUser(userId string, isActive bool, profile map[string]any) (oneauth.User, error) {
    profileJSON, _ := json.Marshal(profile)
    _, err := s.db.Exec(
        "INSERT INTO users (id, is_active, profile, created_at) VALUES ($1, $2, $3, NOW())",
        userId, isActive, profileJSON,
    )
    if err != nil {
        return nil, err
    }
    return &PostgresUser{id: userId, profile: profile}, nil
}

// Implement remaining methods...
```

## Validation

### Default Signup Validator

OneAuth provides a default validator with these rules:

- Username: 3-20 characters, alphanumeric plus underscore and hyphen
- Email: Valid email format (if provided)
- Phone: Minimum 10 digits (if provided)
- At least one of email or phone required
- Password: Minimum 8 characters

### Custom Validator

```go
customValidator := func(creds *oneauth.Credentials) error {
    if len(creds.Password) < 12 {
        return fmt.Errorf("password must be at least 12 characters")
    }

    // Check password complexity
    hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(creds.Password)
    hasLower := regexp.MustCompile(`[a-z]`).MatchString(creds.Password)
    hasDigit := regexp.MustCompile(`[0-9]`).MatchString(creds.Password)

    if !hasUpper || !hasLower || !hasDigit {
        return fmt.Errorf("password must contain uppercase, lowercase, and digit")
    }

    return nil
}

localAuth.ValidateSignup = customValidator
```

## Email Integration

### Custom Email Sender

Implement the `SendEmail` interface for production email services:

```go
type SMTPEmailSender struct {
    host     string
    port     int
    username string
    password string
}

func (s *SMTPEmailSender) SendVerificationEmail(to string, verificationLink string) error {
    auth := smtp.PlainAuth("", s.username, s.password, s.host)

    message := fmt.Sprintf("To: %s\r\n"+
        "Subject: Verify your email\r\n"+
        "\r\n"+
        "Please verify your email by clicking: %s\r\n", to, verificationLink)

    addr := fmt.Sprintf("%s:%d", s.host, s.port)
    return smtp.SendMail(addr, auth, s.username, []string{to}, []byte(message))
}

func (s *SMTPEmailSender) SendPasswordResetEmail(to string, resetLink string) error {
    // Similar implementation
}
```

### Console Email Sender

For development, use the built-in console sender:

```go
localAuth.EmailSender = &oneauth.ConsoleEmailSender{}
```

This logs emails to stdout instead of sending them.

## Session Management

The `HandleUser` callback is called after successful authentication. Use it to establish sessions:

```go
HandleUser: func(authtype string, provider string, token *oauth2.Token,
                  userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
    // token is nil for local auth, populated for OAuth

    // Create session
    sessionID := generateSessionID()
    sessionStore.Save(sessionID, userInfo)

    // Set cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "session_id",
        Value:    sessionID,
        Path:     "/",
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
    })

    // Return success response
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]any{
        "success": true,
        "user":    userInfo,
    })
}
```

## OAuth Integration

OneAuth supports OAuth providers through the main `OneAuth` router:

```go
oneauth := oneauth.New("myapp")

// Add OAuth providers
oneauth.AddAuth("/google", oauth2.NewGoogleOAuth2(
    clientID,
    clientSecret,
    callbackURL,
    oneauth.SaveUserAndRedirect,
).Handler())

oneauth.AddAuth("/github", oauth2.NewGithubOAuth2(
    clientID,
    clientSecret,
    callbackURL,
    oneauth.SaveUserAndRedirect,
).Handler())

// Add local auth
oneauth.AddAuth("/login", localAuth)
```

## Helper Functions

OneAuth provides helper functions to create callbacks from stores:

### NewCreateUserFunc

Creates a user creation callback:

```go
createUser := oneauth.NewCreateUserFunc(userStore, identityStore, channelStore)
user, err := createUser(&oneauth.Credentials{
    Username: "johndoe",
    Email:    &email,
    Password: "password123",
})
```

### NewCredentialsValidator

Creates a credentials validation callback:

```go
validateCreds := oneauth.NewCredentialsValidator(identityStore, channelStore, userStore)
user, err := validateCreds("john@example.com", "password123", "email")
```

### NewVerifyEmailFunc

Creates an email verification callback:

```go
verifyEmail := oneauth.NewVerifyEmailFunc(identityStore, tokenStore)
err := verifyEmail(tokenString)
```

### NewUpdatePasswordFunc

Creates a password update callback:

```go
updatePassword := oneauth.NewUpdatePasswordFunc(identityStore, channelStore)
err := updatePassword("john@example.com", "newpassword456")
```

## Testing

OneAuth handlers can be tested without a running HTTP server using `httptest`:

```go
func TestSignup(t *testing.T) {
    // Setup
    tmpDir, _ := os.MkdirTemp("", "test-*")
    defer os.RemoveAll(tmpDir)

    userStore := stores.NewFSUserStore(tmpDir)
    identityStore := stores.NewFSIdentityStore(tmpDir)
    channelStore := stores.NewFSChannelStore(tmpDir)

    createUser := oneauth.NewCreateUserFunc(userStore, identityStore, channelStore)

    localAuth := &oneauth.LocalAuth{
        CreateUser: createUser,
        HandleUser: func(authtype, provider string, token *oauth2.Token,
                        userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
            w.WriteHeader(http.StatusOK)
            json.NewEncoder(w).Encode(map[string]any{"success": true})
        },
    }

    // Create request
    form := url.Values{}
    form.Set("username", "testuser")
    form.Set("email", "test@example.com")
    form.Set("password", "password123")

    req := httptest.NewRequest(http.MethodPost, "/auth/signup",
                                strings.NewReader(form.Encode()))
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    rr := httptest.NewRecorder()

    // Test
    localAuth.HandleSignup(rr, req)

    // Assert
    if rr.Code != http.StatusOK {
        t.Errorf("Expected status 200, got %d", rr.Code)
    }
}
```

## Security Considerations

### Password Storage

OneAuth uses bcrypt with default cost for password hashing. Passwords are never stored in plain text.

### Token Security

- Verification tokens: 32 bytes, hex-encoded (64 characters)
- Default expiry: 24 hours for email verification, 1 hour for password reset
- Tokens are single-use and deleted after consumption
- Expired tokens are automatically rejected

### Form Field Configuration

Configure form field names to match your frontend:

```go
localAuth.UsernameField = "email"      // For login
localAuth.PasswordField = "password"
localAuth.EmailField = "email"         // For signup
localAuth.PhoneField = "phone"
```

### Rate Limiting

Implement rate limiting at the HTTP handler level:

```go
rateLimiter := ratelimit.New(10, time.Minute) // 10 requests per minute

mux.Handle("/auth/login", rateLimiter.Wrap(localAuth))
```

## Error Handling

Authentication handlers return appropriate HTTP status codes:

- `200 OK`: Successful authentication
- `400 Bad Request`: Invalid input or validation failure
- `401 Unauthorized`: Invalid credentials
- `500 Internal Server Error`: Server-side error

Error responses are JSON-formatted:

```json
{"error": "Invalid credentials"}
```

## Migration Guide

### From Password-Only to Multi-Auth

1. Deploy identity/channel store schema
2. Migrate existing users to new schema
3. Update authentication handlers
4. Add OAuth routes
5. Update frontend to show multiple login options

### Example Migration Script

```go
func migrateUsers(oldDB *sql.DB, userStore UserStore, identityStore IdentityStore,
                  channelStore ChannelStore) error {
    rows, err := oldDB.Query("SELECT id, email, password_hash FROM old_users")
    if err != nil {
        return err
    }
    defer rows.Close()

    for rows.Next() {
        var userID, email, passwordHash string
        rows.Scan(&userID, &email, &passwordHash)

        // Create user
        profile := map[string]any{"email": email}
        userStore.CreateUser(userID, true, profile)

        // Create identity
        identity := &Identity{
            Type:     "email",
            Value:    email,
            UserID:   userID,
            Verified: true, // Assume existing users are verified
        }
        identityStore.SaveIdentity(identity)

        // Create channel
        identityKey := IdentityKey("email", email)
        channel := &Channel{
            Provider:    "local",
            IdentityKey: identityKey,
            Credentials: map[string]any{"password_hash": passwordHash},
        }
        channelStore.SaveChannel(channel)
    }

    return nil
}
```

## Performance Considerations

### File-Based Stores

The provided file-based stores are suitable for:
- Development environments
- Small applications (< 1000 users)
- Prototypes and MVPs

For production with larger user bases, implement database-backed stores.

### Caching

Implement caching in your store implementations:

```go
type CachedUserStore struct {
    underlying UserStore
    cache      *lru.Cache
}

func (s *CachedUserStore) GetUserById(userId string) (User, error) {
    if cached, ok := s.cache.Get(userId); ok {
        return cached.(User), nil
    }

    user, err := s.underlying.GetUserById(userId)
    if err == nil {
        s.cache.Add(userId, user)
    }
    return user, err
}
```

## Troubleshooting

### "Invalid credentials" on correct password

Check that `UsernameField` is configured correctly for login:

```go
// If your login form uses "email" field
localAuth.UsernameField = "email"

// If your login form uses "username" field
localAuth.UsernameField = "username"
```

### Email verification not working

Ensure all required fields are configured:

```go
localAuth.EmailSender = yourEmailSender  // Must not be nil
localAuth.TokenStore = tokenStore        // Must not be nil
localAuth.BaseURL = "https://yourapp.com" // Must be set
localAuth.VerifyEmail = verifyFunc       // Must be set
```

### Token expired errors

Check token expiry durations:

```go
// Use longer expiry for email verification
token, _ := tokenStore.CreateToken(userID, email,
    oneauth.TokenTypeEmailVerification,
    48 * time.Hour)  // 48 hours instead of default 24
```

## Best Practices

1. **Use HTTPS in production**: Protect credentials in transit
2. **Implement session timeouts**: Expire inactive sessions
3. **Log authentication events**: Track failed login attempts
4. **Validate redirects**: Prevent open redirect vulnerabilities
5. **Use CSRF protection**: Protect state-changing operations
6. **Implement account lockout**: After repeated failed attempts
7. **Store secrets securely**: Use environment variables or secret managers
8. **Regular security updates**: Keep dependencies up to date

## Examples

See the `examples/` directory for complete applications:

- `examples/basic/`: Minimal local authentication
- `examples/oauth/`: Local + OAuth integration
- `examples/production/`: Production-ready setup with database stores
