# Browser Authentication

OAuth integration, channel linking, session management, validation, and error handling for browser-based authentication flows.

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

## Channel Linking (Multiple Auth Methods)

OneAuth supports linking multiple authentication methods to the same user account. A user can sign up with email/password and later link their Google account, or vice versa.

### How Channels Work

Multiple channels can point to the same user via shared email:

```
User (id: abc123)
├── Identity: email → user@example.com (verified)
├── Channel: local → email:user@example.com (has password_hash)
├── Channel: google → email:user@example.com (has oauth profile)
└── Channel: github → email:user@example.com (has oauth profile)
```

The user profile tracks linked providers: `profile["channels"] = ["local", "google", "github"]`

### Setting Up Channel-Aware User Creation

Use `NewEnsureAuthUserFunc` for OAuth callbacks that automatically link channels:

```go
config := oneauth.EnsureAuthUserConfig{
    UserStore:     userStore,
    IdentityStore: identityStore,
    ChannelStore:  channelStore,
    UsernameStore: usernameStore, // Optional
}

ensureUser := oneauth.NewEnsureAuthUserFunc(config)

// Use with OAuth
oneauth.UserStore = &myAuthUserStore{ensureUser: ensureUser}
```

When a user logs in with Google:
1. If no user exists with that email, create new user + Google channel
2. If user exists (signed up with password), link Google channel to existing user

### Adding Password to OAuth User

Allow OAuth-only users to add email/password login:

```go
// Mount the handler
linkConfig := oneauth.LinkCredentialsConfig{
    UserStore:     userStore,
    IdentityStore: identityStore,
    ChannelStore:  channelStore,
    UsernameStore: usernameStore, // Optional
}

getUser := func(r *http.Request) (string, error) {
    return getLoggedInUserIDFromSession(r), nil
}

mux.Handle("POST /auth/link-credentials",
    localAuth.HandleLinkCredentials(linkConfig, getUser))
```

Frontend form:
```html
<form action="/auth/link-credentials" method="POST">
    <input name="username" placeholder="Username (optional)">
    <input name="password" type="password" placeholder="Password" required>
    <button type="submit">Add Password Login</button>
</form>
```

### Adding OAuth to Password User

Allow password-only users to link OAuth providers:

```go
// Step 1: Start linking flow
func handleLinkGoogle(w http.ResponseWriter, r *http.Request) {
    userID := getLoggedInUserID(r)
    oneAuth.StartLinkOAuth(r, userID)
    http.Redirect(w, r, "/auth/google/", http.StatusFound)
}

// Step 2: In your OAuth callback, detect linking mode
func googleCallback(w http.ResponseWriter, r *http.Request) {
    // ... exchange code for token, get userInfo ...

    // Check if this is a linking flow
    linkingUserID := oneAuth.GetLinkingUserID(r)
    if linkingUserID != "" {
        // Linking flow - add OAuth to existing user
        linkConfig := oneauth.LinkOAuthConfig{
            UserStore:     userStore,
            IdentityStore: identityStore,
            ChannelStore:  channelStore,
        }
        oneAuth.HandleLinkOAuthCallback(linkConfig, linkingUserID, "google", userInfo, w, r)
        return
    }

    // Normal login/signup flow
    oneAuth.SaveUserAndRedirect("oauth", "google", token, userInfo, w, r)
}
```

### Username-Based Login

Enable login with username (in addition to email):

```go
// Use the username-aware validator
validateCreds := oneauth.NewCredentialsValidatorWithUsername(
    identityStore,
    channelStore,
    userStore,
    usernameStore, // Required for username login
)

localAuth := &oneauth.LocalAuth{
    ValidateCredentials: validateCreds,
    // ...
}
```

Users can then login with either:
- Email: `user@example.com` + password
- Username: `johndoe` + password

### Programmatic Channel Linking

Link credentials programmatically (e.g., from a profile settings handler):

```go
config := oneauth.EnsureAuthUserConfig{
    UserStore:     userStore,
    IdentityStore: identityStore,
    ChannelStore:  channelStore,
    UsernameStore: usernameStore,
}

// Add password to OAuth user
err := oneauth.LinkLocalCredentials(config, userID, "newusername", "password123", userEmail)
if err != nil {
    // Handle error: "local credentials already exist", "username taken", etc.
}
```

### Channel Linking Security

1. **Email Matching**: OAuth linking verifies the OAuth email matches the user's existing email
2. **Cannot Link Different Emails**: Users cannot link an OAuth account with a different email address
3. **Duplicate Prevention**: The same provider can only be linked once per identity

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

## Validation

### SignupPolicy (Recommended)

OneAuth provides a policy-based validation system with fine-grained control over signup requirements:

```go
// Use a preset policy
localAuth.SignupPolicy = &oneauth.PolicyEmailOnly // Username optional, email required

// Or create a custom policy
localAuth.SignupPolicy = &oneauth.SignupPolicy{
    RequireUsername:       true,  // Is username required?
    RequireEmail:          true,  // Is email required?
    RequirePhone:          false, // Is phone required?
    RequirePassword:       true,  // Is password required?
    EnforceUsernameUnique: true,  // Check UsernameStore?
    EnforceEmailUnique:    true,  // Check IdentityStore?
    MinPasswordLength:     12,    // Minimum password length
    UsernamePattern:       `^[a-z][a-z0-9_]{2,19}$`, // Custom regex
}
```

#### Preset Policies

| Policy | Username | Email | Password | Use Case |
|--------|----------|-------|----------|----------|
| `PolicyEmailOnly` | Optional | Required | Required | Most web apps (email login) |
| `PolicyUsernameRequired` | Required | Required | Required | Apps needing unique usernames |
| `PolicyFlexible` | Optional | Optional | Optional | OAuth-first apps |

#### Custom Username Patterns

The `UsernamePattern` field accepts a regex pattern:

```go
// Lowercase only, 4-16 chars, must start with letter
policy.UsernamePattern = `^[a-z][a-z0-9_]{3,15}$`

// Allow uppercase, 3-20 chars
policy.UsernamePattern = `^[a-zA-Z][a-zA-Z0-9_-]{2,19}$`
```

### Default Signup Validator (Legacy)

For backwards compatibility, the legacy `ValidateSignup` callback is still supported:

- Username: 3-20 characters, alphanumeric plus underscore and hyphen
- Email: Valid email format (if provided)
- Phone: Minimum 10 digits (if provided)
- At least one of email or phone required
- Password: Minimum 8 characters

### Custom Validator (Legacy)

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

**Note:** If `SignupPolicy` is set, it takes precedence over `ValidateSignup`.

## Error Handling

### Structured Errors (AuthError)

OneAuth provides structured errors with field-level information:

```go
type AuthError struct {
    Code    string // "email_exists", "username_taken", "weak_password", etc.
    Message string // Human-readable message
    Field   string // Which form field has the error (e.g., "email", "username")
}
```

#### Error Codes

| Code | Description |
|------|-------------|
| `email_exists` | Email already registered |
| `username_taken` | Username already taken |
| `weak_password` | Password doesn't meet requirements |
| `invalid_username` | Username format invalid |
| `invalid_email` | Email format invalid |
| `invalid_phone` | Phone format invalid |
| `missing_field` | Required field not provided |
| `invalid_credentials` | Wrong email/password combination |

### Custom Error Handlers

Configure custom error handlers for signup and login errors:

```go
localAuth := &oneauth.LocalAuth{
    // ... other config ...

    // Custom signup error handler
    OnSignupError: func(err *oneauth.AuthError, w http.ResponseWriter, r *http.Request) bool {
        // Option 1: Redirect with flash message (using your session library)
        session.SetFlash(r, "error", err.Message)
        session.SetFlash(r, "error_field", err.Field)
        http.Redirect(w, r, "/signup", http.StatusSeeOther)
        return true // Error handled

        // Option 2: Return custom JSON
        // w.WriteHeader(http.StatusUnprocessableEntity)
        // json.NewEncoder(w).Encode(map[string]any{"validation_error": err})
        // return true
    },

    // Custom login error handler
    OnLoginError: func(err *oneauth.AuthError, w http.ResponseWriter, r *http.Request) bool {
        session.SetFlash(r, "login_error", err.Message)
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return true
    },
}
```

If the handler returns `false` (or is nil), OneAuth uses the default JSON response.

### Default JSON Error Response

```json
{
    "error": "Email already registered",
    "code": "email_exists",
    "field": "email"
}
```

### HTTP Status Codes

- `200 OK`: Successful authentication
- `400 Bad Request`: Invalid input or validation failure
- `401 Unauthorized`: Invalid credentials
- `409 Conflict`: Resource already exists (e.g., linking credentials that exist)
- `500 Internal Server Error`: Server-side error

## Password Reset Redirect Mode

Password reset routes support both form rendering and submission:

```go
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

### Form Field Configuration

Configure form field names to match your frontend:

```go
localAuth.UsernameField = "email"      // For login
localAuth.PasswordField = "password"
localAuth.EmailField = "email"         // For signup
localAuth.PhoneField = "phone"
```
