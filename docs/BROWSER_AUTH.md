# Browser Authentication

Form-based login/signup, OAuth integration, channel linking, email verification, password reset, session management, validation, and error handling for browser-based authentication flows.

## How It Works

```
┌──────────┐                  ┌───────────┐                ┌──────────────┐
│  Browser │ ── POST ──────→  │ LocalAuth │ ── callback ─→ │  HandleUser  │
│          │    /auth/login   │           │                │  (app-owned) │
│          │ ←─ cookie ────   │           │                │  set session │
└──────────┘                  └───────────┘                └──────────────┘
```

OneAuth handles credential validation; your application controls session creation via the `HandleUser` callback.

## Setup

```go
import (
    "github.com/panyam/oneauth/core"
    "github.com/panyam/oneauth/localauth"
    "github.com/panyam/oneauth/httpauth"
    oa2 "github.com/panyam/oneauth/oauth2"
    "github.com/panyam/oneauth/stores/fs"
)

storagePath := "/path/to/storage"
userStore := fs.NewFSUserStore(storagePath)
identityStore := fs.NewFSIdentityStore(storagePath)
channelStore := fs.NewFSChannelStore(storagePath)
tokenStore := fs.NewFSTokenStore(storagePath)
usernameStore := fs.NewFSUsernameStore(storagePath)

// Create OneAuth router
oneAuth := httpauth.New("myapp")
oneAuth.HandleUser = localauth.NewEnsureAuthUserFunc(localauth.EnsureAuthUserConfig{
    UserStore:     userStore,
    IdentityStore: identityStore,
    ChannelStore:  channelStore,
    UsernameStore: usernameStore,
})

// Add local auth (email/password)
la := localauth.NewLocalAuth(localauth.LocalAuthConfig{
    Session:       session,
    UserStore:     userStore,
    IdentityStore: identityStore,
    ChannelStore:  channelStore,
    TokenStore:    tokenStore,
    UsernameStore: usernameStore,
    SignupPolicy: &core.SignupPolicy{
        RequireEmail:    true,
        RequirePassword: true,
        MinPasswordLength: 8,
    },
})
oneAuth.AddAuth("/local", la)

// Add OAuth providers
oneAuth.AddAuth("/google", oa2.NewGoogleOAuth2(clientID, clientSecret, callbackURL, oneAuth.SaveUserAndRedirect).Handler())
oneAuth.AddAuth("/github", oa2.NewGithubOAuth2(clientID, clientSecret, callbackURL, oneAuth.SaveUserAndRedirect).Handler())
```

## Request Flows

### Login Flow

```
1. POST /auth/login (email or username, password)
2. LocalAuth.ServeHTTP
3. Auto-detect input: contains "@" → email, otherwise → username
4. If username: UsernameStore.GetUserByUsername → userID → User → email
5. Identity lookup by email
6. Channel lookup (provider=local) → password hash
7. bcrypt.CompareHashAndPassword
8. HandleUser callback → session creation
9. Redirect to callbackURL
```

### Signup Flow

```
1. POST /auth/signup (email, password, optional username)
2. Validate per SignupPolicy
3. Check Identity doesn't exist for email
4. Create User with profile
5. Create Identity (type=email, verified=false)
6. Create Channel (provider=local, password_hash)
7. If UsernameStore configured + username provided: reserve username
8. Optional: send verification email
9. Auto-login → HandleUser callback → session
10. Redirect to callbackURL
```

### Email Verification Flow

```
1. After signup, verification email sent (if EmailSender configured)
2. Email contains link: /auth/verify?token=abc123
3. User clicks link
4. Token validated (exists + not expired)
5. Identity.Verified = true
6. Token deleted (single-use)
```

### Password Reset Flow

```
1. POST /auth/forgot-password (email)
2. Create password reset token (time-limited)
3. Email link: /auth/reset-password?token=abc123
4. User clicks link, enters new password
5. POST /auth/reset-password (token, new_password)
6. Update password hash in local Channel
   (or create local Channel if user is OAuth-only)
7. Token deleted (single-use)
```

## Login Decision Tree

```
LOGIN ATTEMPT
     │
     ├─── OAuth (Google/GitHub) ──────────────────────────────────┐
     │                                                            │
     │    1. Provider authenticates user                          │
     │    2. Callback receives: email, name, avatar               │
     │    3. Look up Identity by email                            │
     │         │                                                  │
     │         ├── NOT found → Create User + Identity + Channel   │
     │         └── FOUND → Get User, add/update OAuth Channel     │
     │                                                            │
     └─── Email/Username + Password ──────────────────────────────┤
               │                                                  │
          Contains "@"?                                           │
               │                                                  │
               ├── YES → Look up Identity by email                │
               │         ├── NOT found → "Invalid credentials"    │
               │         └── FOUND → Get local Channel            │
               │                    ├── No local Channel → error  │
               │                    └── Verify password           │
               │                                                  │
               └── NO → UsernameStore.GetUserByUsername()         │
                        ├── NOT found → "Invalid credentials"     │
                        └── FOUND → resolve to email, continue ───┘
                                                                  │
                                                          LOGIN SUCCESS
                                                          Create Session
```

## Signup Decision Tree

```
SIGNUP ATTEMPT (email + password)
     │
     ▼
Validate SignupPolicy
     │
     ▼
Check Identity exists for email?
     │
     ├── EXISTS → Error: "Email already registered"
     │            → OnSignupError callback
     │
     └── NOT found
              │
              ├── Create User
              ├── Create Identity (verified=false)
              ├── Create Channel (local, password_hash)
              ├── Reserve username (if UsernameStore + username provided)
              ├── Send verification email (if EmailSender configured)
              └── Auto-login → redirect
```

## OAuth Integration

### Adding OAuth Providers

```go
oneAuth.AddAuth("/google", oauth2.NewGoogleOAuth2(
    clientID,
    clientSecret,
    callbackURL,
    oneAuth.SaveUserAndRedirect,
).Handler())

oneAuth.AddAuth("/github", oauth2.NewGithubOAuth2(
    clientID,
    clientSecret,
    callbackURL,
    oneAuth.SaveUserAndRedirect,
).Handler())
```

### PKCE (Proof Key for Code Exchange)

All OAuth2 flows use PKCE (RFC 7636) by default to prevent authorization code interception attacks. This is especially important for public clients (SPAs, mobile apps) where the client secret cannot be securely stored.

```
Authorization redirect:
  → code_challenge=SHA256(verifier) & code_challenge_method=S256
  → verifier stored in HttpOnly cookie (pkce_verifier)

Callback:
  ← reads verifier from cookie
  ← sends code_verifier in token exchange
  ← provider verifies SHA256(verifier) == challenge
```

PKCE is enabled by default. To disable for a provider that doesn't support it:

```go
google := oauth2.NewGoogleOAuth2(clientID, clientSecret, callbackURL, handleUser)
google.DisablePKCE = true  // logs a warning — not recommended
```

See: [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)

## Channel Linking (Multiple Auth Methods)

A user can sign up with email/password and later link their Google account, or vice versa. Multiple channels share the same user via email Identity.

```
User (id: abc123)
├── Identity: email → user@example.com (verified)
├── Channel: local   → email:user@example.com (password_hash)
├── Channel: google  → email:user@example.com (oauth profile)
└── Channel: github  → email:user@example.com (oauth profile)
```

The user profile tracks linked providers: `profile["channels"] = ["local", "google", "github"]`

### Provider Linking Matrix

```
                          │         SECOND AUTH ATTEMPT                  │
                          ├─────────────┬─────────────┬──────────────────┤
                          │ Local Email │   Google    │  Different Email │
                          │  + Password │   OAuth     │                  │
┌─────────────────────────┼─────────────┼─────────────┼──────────────────┤
│  No existing account    │ Create new  │ Create new  │ Create new       │
├─────────────────────────┼─────────────┼─────────────┼──────────────────┤
│  Has Local (same email) │ Login       │ Link OAuth  │ New account      │
├─────────────────────────┼─────────────┼─────────────┼──────────────────┤
│  Has Google (same email)│ Fails*      │ Login       │ New account      │
└─────────────────────────┴─────────────┴─────────────┴──────────────────┘

* "Fails" = Signup fails because Identity exists, but no local Channel.
  User should login via OAuth, then set password via profile or password reset.
```

**Key rule**: Same email = same account (via Identity), regardless of auth method.

### Setting Up Channel-Aware User Creation

Use `NewEnsureAuthUserFunc` for OAuth callbacks that automatically link channels:

```go
config := localauth.EnsureAuthUserConfig{
    UserStore:     userStore,
    IdentityStore: identityStore,
    ChannelStore:  channelStore,
    UsernameStore: usernameStore, // Optional
}

ensureUser := localauth.NewEnsureAuthUserFunc(config)
oneAuth.UserStore = &myAuthUserStore{ensureUser: ensureUser}
```

### Adding Password to OAuth User

```go
linkConfig := localauth.LinkCredentialsConfig{
    UserStore:     userStore,
    IdentityStore: identityStore,
    ChannelStore:  channelStore,
    UsernameStore: usernameStore,
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

    linkingUserID := oneAuth.GetLinkingUserID(r)
    if linkingUserID != "" {
        linkConfig := localauth.LinkOAuthConfig{
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

### Programmatic Channel Linking

```go
err := localauth.LinkLocalCredentials(config, userID, "newusername", "password123", userEmail)
```

### Channel Linking Security

1. **Email Matching**: OAuth linking verifies the OAuth email matches the user's existing email
2. **Cannot Link Different Emails**: Users cannot link an OAuth account with a different email address
3. **Duplicate Prevention**: The same provider can only be linked once per identity

### Username-Based Login

```go
validateCreds := localauth.NewCredentialsValidatorWithUsername(
    identityStore, channelStore, userStore, usernameStore,
)

la := &localauth.LocalAuth{
    ValidateCredentials: validateCreds,
}
```

Users can then login with either `user@example.com` + password or `johndoe` + password.

## User Journeys

### Journey 1: Multiple OAuth Providers (Same Email)

```
Day 1: "Continue with Google" (alice@gmail.com)
  → Create User, Identity, Channel(google)

Day 7: "Continue with GitHub" (alice@gmail.com — same email)
  → Identity exists → same user
  → Create Channel(github) for existing user

Result: Login with Google OR GitHub, same account
```

### Journey 2: OAuth User Adds Password

```
Day 1: "Continue with Google"
  → Create User + Channel(google)

Day 3: Set username "bobsmith" + password
  → Reserve username, create Channel(local)

Result: Login via Google, email+password, or username+password
```

### Journey 3: Email Signup, Then Link OAuth

```
Day 1: Sign up with email + password
  → Create User + Channel(local)

Day 5: "Continue with Google" (same email)
  → Identity exists → add Channel(google)

Result: Login with email+password OR Google
```

### Journey 4: OAuth User Resets Password (No Local Channel)

```
Day 1: "Continue with Google"
  → User has no local Channel

Day 2: "Forgot Password" → enter email → reset link
  → NewUpdatePasswordFunc detects no local Channel
  → Creates Channel(local) with new password

Result: Login via Google OR email+password
```

### Journey 5: Different Emails on Different Providers

```
Day 1: Google login (alice@gmail.com) → User A
Day 3: GitHub login (alice@company.com) → User B (different account!)

By design: different emails = different accounts.
```

## Session Management

The `HandleUser` callback is called after successful authentication:

```go
HandleUser: func(authtype string, provider string, token *oauth2.Token,
                  userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
    // token is nil for local auth, populated for OAuth
    sessionID := generateSessionID()
    sessionStore.Save(sessionID, userInfo)

    http.SetCookie(w, &http.Cookie{
        Name:     "session_id",
        Value:    sessionID,
        Path:     "/",
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
    })

    json.NewEncoder(w).Encode(map[string]any{
        "success": true,
        "user":    userInfo,
    })
}
```

## Email Integration

### Custom Email Sender

```go
type SMTPEmailSender struct {
    host, username, password string
    port                     int
}

func (s *SMTPEmailSender) SendVerificationEmail(to, link string) error {
    auth := smtp.PlainAuth("", s.username, s.password, s.host)
    msg := fmt.Sprintf("To: %s\r\nSubject: Verify your email\r\n\r\nClick: %s\r\n", to, link)
    return smtp.SendMail(fmt.Sprintf("%s:%d", s.host, s.port), auth, s.username, []string{to}, []byte(msg))
}

func (s *SMTPEmailSender) SendPasswordResetEmail(to, link string) error { /* similar */ }
```

### Console Email Sender (Development)

```go
la.EmailSender = &localauth.ConsoleEmailSender{}
```

Logs emails to stdout instead of sending them.

## Validation

### SignupPolicy (Recommended)

```go
la.SignupPolicy = &core.SignupPolicy{
    RequireUsername:       true,
    RequireEmail:          true,
    RequirePassword:       true,
    EnforceUsernameUnique: true,
    EnforceEmailUnique:    true,
    MinPasswordLength:     12,
    UsernamePattern:       `^[a-z][a-z0-9_]{2,19}$`,
}
```

#### Preset Policies

| Policy | Username | Email | Password | Use Case |
|--------|----------|-------|----------|----------|
| `PolicyEmailOnly` | Optional | Required | Required | Most web apps |
| `PolicyUsernameRequired` | Required | Required | Required | Apps needing usernames |
| `PolicyFlexible` | Optional | Optional | Optional | OAuth-first apps |

### Custom Validator (Legacy)

```go
la.ValidateSignup = func(creds *core.Credentials) error {
    if len(creds.Password) < 12 {
        return fmt.Errorf("password must be at least 12 characters")
    }
    return nil
}
```

If `SignupPolicy` is set, it takes precedence over `ValidateSignup`.

## Error Handling

### Structured Errors (AuthError)

```go
type AuthError struct {
    Code    string // "email_exists", "username_taken", etc.
    Message string // Human-readable message
    Field   string // Form field with the error
}
```

| Code | Description |
|------|-------------|
| `email_exists` | Email already registered |
| `username_taken` | Username already taken |
| `weak_password` | Password doesn't meet requirements |
| `invalid_username` | Username format invalid |
| `invalid_email` | Email format invalid |
| `missing_field` | Required field not provided |
| `invalid_credentials` | Wrong email/password |

### Custom Error Handlers

```go
la.OnSignupError = func(err *core.AuthError, w http.ResponseWriter, r *http.Request) bool {
    session.SetFlash(r, "error", err.Message)
    session.SetFlash(r, "error_field", err.Field)
    http.Redirect(w, r, "/signup", http.StatusSeeOther)
    return true // handled
}

la.OnLoginError = func(err *core.AuthError, w http.ResponseWriter, r *http.Request) bool {
    session.SetFlash(r, "login_error", err.Message)
    http.Redirect(w, r, "/login", http.StatusSeeOther)
    return true
}
```

If the handler returns `false` (or is nil), OneAuth returns a default JSON response:
```json
{"error": "Email already registered", "code": "email_exists", "field": "email"}
```

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| `200` | Successful authentication |
| `400` | Invalid input or validation failure |
| `401` | Invalid credentials |
| `409` | Resource already exists |
| `500` | Server-side error |

## Password Reset Redirect Mode

Two response modes for password reset:

| Mode | When | Behavior |
|------|------|----------|
| JSON (default) | `ForgotPasswordURL` / `ResetPasswordURL` empty | GET renders basic HTML form, POST returns JSON |
| Redirect | URLs set | GET redirects to app page, POST redirects with query params |

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

```go
la.UsernameField = "email"
la.PasswordField = "password"
la.EmailField = "email"
la.PhoneField = "phone"
```

## Rate Limiting and Account Lockout

### Rate Limiting

`LocalAuth` supports an optional `RateLimiter` field that throttles login attempts per key (typically per IP or per email). The interface is defined in `core`:

```go
la.RateLimiter = core.NewInMemoryRateLimiter(10, time.Minute) // 10 attempts per minute
```

`core.RateLimiter` is a shared interface used by both `localauth` and `apiauth`.

### Account Lockout

`LocalAuth` supports an optional `Lockout` field (`core.AccountLockout`) that temporarily locks accounts after repeated failed login attempts. Lockouts are auto-expiring — no manual unlock is needed.

```go
la.Lockout = &core.AccountLockout{
    MaxAttempts:    5,
    LockoutWindow:  10 * time.Minute,
    LockoutDuration: 30 * time.Minute,
}
```

### Timing Oracle Fix (CWE-208)

The credential validator now uses constant-time comparison for password validation failures, preventing timing-based user enumeration attacks. When a user is not found, a dummy bcrypt comparison is performed so the response time is indistinguishable from a real password check.

## Security Considerations

| Protection | Implementation |
|------------|---------------|
| Password Hashing | bcrypt with cost 10 |
| Single-Use Tokens | Deleted from TokenStore after use |
| Token Expiration | Time-limited verification/reset tokens |
| Generic Login Errors | "Invalid credentials" (prevents enumeration) |
| Constant-Time Comparison | Via bcrypt internals + dummy hash on missing user (CWE-208 fix) |

### CSRF Protection (CSRFMiddleware)

OneAuth provides a `CSRFMiddleware` using the **double-submit cookie** pattern. It is opt-in — applications wrap their form endpoints to enable protection.

```go
csrf := &httpauth.CSRFMiddleware{Secure: true} // set Secure: true for HTTPS

// Wrap form GET handlers (generates CSRF cookie + injects token into context)
mux.Handle("GET /auth/login", csrf.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    renderTemplate(w, "login.html", map[string]any{
        "CSRFField": httpauth.CSRFTemplateField(r),
    })
})))

// Wrap form POST handlers (validates cookie vs. form field/header)
mux.Handle("POST /auth/login", csrf.Protect(http.HandlerFunc(la.ServeHTTP)))
```

In templates, include the hidden field inside `<form>` tags:

```html
<form method="POST" action="/auth/login">
    {{.CSRFField}}
    <!-- other fields -->
</form>
```

**How it works:**
- **Safe methods** (GET, HEAD, OPTIONS): Generates a random token, stores it in a `csrf_token` cookie (not HttpOnly, so JS can read it for AJAX), and injects it into the request context.
- **Unsafe methods** (POST, PUT, DELETE, PATCH): Validates that the token from the `csrf_token` form field or `X-CSRF-Token` header matches the cookie value using constant-time comparison.
- **Bearer-token requests**: Automatically exempt (not vulnerable to CSRF).
- **Per-session tokens**: Token persists for the cookie lifetime (default: 1 hour). No per-request rotation, so back button and multi-tab usage work.

**Configuration options:**

| Field | Default | Description |
|-------|---------|-------------|
| `CookieName` | `csrf_token` | Cookie name |
| `FieldName` | `csrf_token` | Form field name |
| `HeaderName` | `X-CSRF-Token` | Header name for AJAX |
| `MaxAge` | `3600` (1 hour) | Cookie lifetime in seconds |
| `Secure` | `false` | Set `true` for HTTPS |
| `SameSite` | `Strict` | SameSite cookie attribute |
| `ErrorHandler` | 403 JSON | Custom error handler |
| `ExemptFunc` | Bearer exempt | Custom exemption logic |

**Template helpers:**
- `httpauth.CSRFToken(r)` — extract token string from request context
- `httpauth.CSRFTemplateField(r)` — returns `<input type="hidden" name="csrf_token" value="...">` as `template.HTML`

### Recommended Application-Level Protections

1. ~~**Rate Limiting**: Per-IP and per-account limits on login attempts~~ **Provided** — use `LocalAuth.RateLimiter` and `LocalAuth.Lockout` (see above)
2. ~~**CSRF Tokens**: On all auth forms~~ **Provided** — use `CSRFMiddleware` (see above)
3. **Session Security**: HttpOnly, Secure, SameSite cookies
4. **HTTPS**: Required for OAuth callbacks
5. **Audit Logging**: Log all auth events
