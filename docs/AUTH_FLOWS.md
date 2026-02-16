# OneAuth Authentication Flows

This document describes the authentication flows, data model, and patterns provided by the oneauth library.

## Architecture Overview

### Core Components

| Component | Purpose |
|-----------|---------|
| `OneAuth` | Main auth orchestrator, routes to providers |
| `AuthService` | User/Identity/Channel CRUD operations |
| `UsernameStore` | Optional username → userID mapping |
| `LocalAuth` | Email/password authentication handler |
| `OAuth2` | OAuth2 provider handlers (Google, GitHub, etc.) |
| `TokenStore` | Email verification, password reset tokens |

### Data Model

```
User (id: abc123)
├── Profile: {email, username, nickname, avatar, ...}
├── Identity: email → user@example.com (verified: true/false)
├── Channel: local → email:user@example.com (password_hash)
├── Channel: google → email:user@example.com (oauth_token)
└── Channel: github → email:user@example.com (oauth_token)
```

**Key Concepts:**
- **User**: The account entity with a profile map
- **Identity**: A verified contact method (email, phone) - unique per value
- **Channel**: An authentication method pointing to an Identity
- **Username**: An optional login alias stored in UsernameStore (separate from Identity)

Multiple channels can share the same Identity (email), enabling multi-provider login for the same account.

## Login Decision Tree

When a login attempt occurs, here's how the system determines identity:

```
LOGIN ATTEMPT
     │
     ▼
┌─────────────────────────────────────┐
│ What type of login?                 │
└─────────────────────────────────────┘
     │
     ├─── OAuth (Google/GitHub) ──────────────────────────────────┐
     │                                                             │
     │    ┌─────────────────────────────────────────────────────┐ │
     │    │ 1. OAuth provider authenticates user                │ │
     │    │ 2. Callback receives: email, name, avatar           │ │
     │    │ 3. Look up Identity by email                        │ │
     │    └─────────────────────────────────────────────────────┘ │
     │         │                                                   │
     │         ├── Identity NOT found ────────────────────────────┤
     │         │         │                                        │
     │         │         ▼                                        │
     │         │   Create new User, Identity, Channel             │
     │         │   (New account)                                  │
     │         │                                                  │
     │         └── Identity FOUND ────────────────────────────────┤
     │                   │                                        │
     │                   ▼                                        │
     │             Get User who owns this Identity                │
     │             Add/update OAuth Channel                       │
     │             (Existing account, maybe adding provider)      │
     │                                                            │
     └─── Email/Username + Password ──────────────────────────────┤
                   │                                              │
     ┌─────────────────────────────────────────────────────┐     │
     │ Does input contain "@"?                             │     │
     └─────────────────────────────────────────────────────┘     │
          │                                                       │
          ├── YES (treat as email) ───────────────────────────────┤
          │         │                                             │
          │         ▼                                             │
          │   Look up Identity by email                           │
          │         │                                             │
          │         ├── NOT found → "Invalid credentials"         │
          │         │                                             │
          │         └── FOUND → Get local Channel                 │
          │                         │                             │
          │                         ├── No local Channel          │
          │                         │   → "Invalid credentials"   │
          │                         │   (OAuth-only user)         │
          │                         │                             │
          │                         └── Has local Channel         │
          │                             → Verify password         │
          │                                                       │
          └── NO (treat as username) ─────────────────────────────┤
                    │                                             │
                    ▼                                             │
              UsernameStore.GetUserByUsername()                   │
                    │                                             │
                    ├── NOT found → "Invalid credentials"         │
                    │                                             │
                    └── FOUND → Get userID                        │
                              → Get User                          │
                              → Get email from Profile            │
                              → Continue as email login ──────────┘
                                                                  │
                                                                  ▼
                                                         ┌───────────────┐
                                                         │ LOGIN SUCCESS │
                                                         │ Create Session│
                                                         └───────────────┘
```

## Signup Decision Tree

```
SIGNUP ATTEMPT (email + password)
     │
     ▼
┌─────────────────────────────────────┐
│ Validate SignupPolicy               │
│ - Email required? (configurable)    │
│ - Password min length? (default: 8) │
│ - Username required? (configurable) │
└─────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────┐
│ Check if Identity exists for email  │
└─────────────────────────────────────┘
     │
     ├── Identity EXISTS ──────────────────────────────────────────┐
     │         │                                                   │
     │         ▼                                                   │
     │   ERROR: "Email already registered"                         │
     │   → OnSignupError callback                                  │
     │   → Flash message + redirect (if configured)                │
     │                                                             │
     └── Identity NOT found ───────────────────────────────────────┤
               │                                                   │
               ▼                                                   │
         Create User                                               │
         Profile: {email: "...", username: null}                   │
               │                                                   │
               ▼                                                   │
         Create Identity                                           │
         type: "email", value: "...", verified: false              │
               │                                                   │
               ▼                                                   │
         Create Channel                                            │
         provider: "local", identityKey: "email:...",              │
         credentials: {password_hash: bcrypt(...)}                 │
               │                                                   │
               ▼                                                   │
         (Optional) Send verification email                        │
               │                                                   │
               ▼                                                   │
         Create session, login user                                │
               │                                                   │
               ▼                                                   │
         Redirect to callbackURL or "/" ───────────────────────────┘
```

## Provider Linking Matrix

This shows what happens when a user with existing auth tries another method:

```
                          ┌─────────────────────────────────────────────────────────┐
                          │              SECOND AUTH ATTEMPT                        │
                          ├─────────────┬─────────────┬─────────────┬──────────────┤
                          │ Local Email │   Google    │   GitHub    │  Different   │
                          │  + Password │   OAuth     │   OAuth     │   Email      │
┌─────────────────────────┼─────────────┼─────────────┼─────────────┼──────────────┤
│                         │             │             │             │              │
│  No existing account    │ Create new  │ Create new  │ Create new  │ Create new   │
│                         │ account     │ account     │ account     │ account      │
│                         │             │             │             │              │
├─────────────────────────┼─────────────┼─────────────┼─────────────┼──────────────┤
│                         │             │             │             │              │
│  Has Local (same email) │ Login to    │ Link Google │ Link GitHub │ N/A - diff   │
│                         │ existing    │ to existing │ to existing │ email is     │
│                         │             │             │             │ new account  │
├─────────────────────────┼─────────────┼─────────────┼─────────────┼──────────────┤
│                         │             │             │             │              │
│  Has Google (same email)│ Fails*      │ Login to    │ Link GitHub │ N/A - diff   │
│                         │             │ existing    │ to existing │ email is     │
│                         │             │             │             │ new account  │
├─────────────────────────┼─────────────┼─────────────┼─────────────┼──────────────┤
│                         │             │             │             │              │
│  Has GitHub (same email)│ Fails*      │ Link Google │ Login to    │ N/A - diff   │
│                         │             │ to existing │ existing    │ email is     │
│                         │             │             │             │ new account  │
└─────────────────────────┴─────────────┴─────────────┴─────────────┴──────────────┘

* "Fails" = Signup with email fails because Identity exists, but no local Channel.
  User should use OAuth to login, then set password via Profile page or password reset.
```

**Key insight**: Same email = same account (via Identity), regardless of how you authenticate.

## SignupPolicy Configuration

```go
type SignupPolicy struct {
    RequireUsername       bool   // Is username required at signup?
    RequireEmail          bool   // Is email required?
    RequirePhone          bool   // Is phone required?
    RequirePassword       bool   // Is password required for local auth?
    EnforceUsernameUnique bool   // Check UsernameStore for uniqueness?
    EnforceEmailUnique    bool   // Check IdentityStore for uniqueness?
    MinPasswordLength     int    // Minimum password length
    UsernamePattern       string // Regex pattern for username validation
}

// Preset policies
var PolicyUsernameRequired = SignupPolicy{RequireUsername: true, RequireEmail: true, ...}
var PolicyEmailOnly = SignupPolicy{RequireUsername: false, RequireEmail: true, ...}
var PolicyFlexible = SignupPolicy{RequireUsername: false, RequireEmail: false, ...}
```

## Supported Flows

### 1. Email/Password Signup

**Handler:** `LocalAuth.HandleSignup`

**Flow:**
1. User submits: email, password (and optionally username)
2. Validate per SignupPolicy
3. Create User with profile
4. Create Identity: type=email
5. Create Channel: provider=local with password_hash
6. If UsernameStore configured and username provided, reserve it
7. Auto-login user (session created)
8. Redirect to callbackURL

**Error Handling via callbacks:**
- `OnSignupError`: Called with AuthError, can redirect with flash message
- `OnSignupSuccess`: Called after successful signup

### 2. Email/Password Login

**Handler:** `LocalAuth.HandleLogin`

**Flow:**
1. User submits: email (or username), password
2. Auto-detect input type (contains "@" = email, otherwise username)
3. If username, resolve via UsernameStore to get userID, then email
4. Find Identity by email
5. Find local Channel for that Identity
6. Verify password hash (bcrypt)
7. Create session
8. Redirect to callbackURL

### 3. Username Login (Alias)

When UsernameStore is configured, usernames can be used as login aliases:

1. Input has no "@" symbol → treated as username
2. `UsernameStore.GetUserByUsername(input)` → userID
3. Get User by userID
4. Get email from User.Profile["email"]
5. Continue with standard email/password validation

**Helper:** `NewCredentialsValidatorWithUsername` creates a validator that auto-detects email vs username.

### 4. OAuth2 Login

**Handlers:** OAuth2 provider handlers (Google, GitHub, etc.)

**Flow (New User):**
1. User initiates OAuth flow
2. Provider authenticates and returns userInfo (email, name, picture)
3. Check if Identity exists for this email
4. If not: Create User, Identity (verified=true), OAuth Channel
5. Create session
6. Redirect to callbackURL

**Flow (Existing User - Same Email):**
1. OAuth callback finds existing Identity by email
2. Create/update OAuth Channel for existing Identity
3. Login existing user (channels are linked)

### 5. Setting Password (OAuth-Only Users)

**Handler:** `LocalAuth.HandleLinkCredentials`

For users who signed up via OAuth and want to add email/password login:

1. OAuth user is authenticated
2. User submits new password
3. Get email from User.Profile
4. Create local Channel with password_hash
5. User can now login with email/password OR OAuth

### 6. Email Verification

**Handler:** `LocalAuth.HandleVerifyEmail`

1. After signup, verification email sent (if enabled)
2. Email contains link with token
3. User clicks link, token validated
4. Identity.Verified = true

### 7. Password Reset

**Handlers:** `HandleForgotPassword`, `HandleResetPassword`

1. User submits email
2. Create password reset token (time-limited)
3. Email link with token
4. User clicks link, enters new password
5. Update password hash in local Channel (or create local Channel if user is OAuth-only)

**OAuth-Only Users:** If the user signed up via OAuth and has no local Channel,
`NewUpdatePasswordFunc` automatically creates a local Channel with the new password.
This enables OAuth users to add email/password login via the standard password reset flow.

## Channel Linking Summary

| Starting State | Action | Result |
|----------------|--------|--------|
| New user | Email signup | User + local channel |
| New user | OAuth login | User + OAuth channel |
| Local user | OAuth login (same email) | Adds OAuth channel |
| OAuth user | Set password | Adds local channel |
| OAuth user | Password reset | Creates local channel |
| Any user | Set username | Updates UsernameStore |

All channels pointing to the same email Identity = same user account.

## User Journeys

### Journey 1: Multiple OAuth Providers (Same Email)

User logs in with Google, later logs in with GitHub using the same email.

```
Day 1: User clicks "Continue with Google"
  - Email from Google: alice@gmail.com
  - No existing Identity for alice@gmail.com
  - Creates: User(id: user_001), Identity(email: alice@gmail.com), Channel(google)

Day 7: Same user clicks "Continue with GitHub"
  - Email from GitHub: alice@gmail.com (same email)
  - Identity ALREADY EXISTS for alice@gmail.com → belongs to user_001
  - Creates: Channel(github) pointing to same Identity
  - User is logged in as user_001 (SAME account!)

Result: User can now login with Google OR GitHub
Data structure:
  User (id: user_001)
  ├── Profile: {email: "alice@gmail.com"}
  ├── Identity: email → alice@gmail.com
  ├── Channel: google → email:alice@gmail.com
  └── Channel: github → email:alice@gmail.com
```

### Journey 2: OAuth User Adds Username + Password

User logs in with Google, then sets a username and password.

```
Day 1: User clicks "Continue with Google"
  - Creates: User(id: user_002), Identity, Channel(google)
  - Profile: {email: "bob@gmail.com"} -- no username yet!

Day 3: User sets username and password
  Step 1: Reserve username "bobsmith" via UsernameStore
  Step 2: Create local Channel with password_hash

Result: User can now login THREE ways:
  1. Google OAuth button
  2. Email "bob@gmail.com" + password
  3. Username "bobsmith" + password
```

### Journey 3: Email Signup, Then Link OAuth

User signs up with email/password, later links Google account.

```
Day 1: User signs up with email
  - Creates: User, Identity, Channel(local)

Day 5: User clicks "Continue with Google"
  - Email from Google matches existing Identity
  - Creates: Channel(google) pointing to same Identity

Result: User can login with email+password OR Google
```

### Journey 4: Username as Primary Login

```
Setup: User has:
  - Profile: {email: "dave@company.com", username: "davec"}
  - Local channel with password

Login with email:
  - POST /auth/login {email: "dave@company.com", password: "pass"}
  - ✓ Success

Login with username:
  - POST /auth/login {email: "davec", password: "pass"}
  - Input has no "@" → treated as username
  - UsernameStore.GetUserByUsername("davec") → userID
  - Get User profile → email is "dave@company.com"
  - Validate password against local channel
  - ✓ Success (same user!)
```

### Journey 5: Different Emails on Different OAuth Providers

User has personal Gmail and work GitHub with different emails.

```
Day 1: User logs in with Google
  - Email from Google: alice@gmail.com
  - Creates: User(id: user_005), Identity, Channel(google)

Day 3: Same person logs in with GitHub (different email!)
  - Email from GitHub: alice@company.com (work email)
  - No existing Identity for alice@company.com
  - Creates: NEW User(id: user_006), Identity, Channel(github)

Result: TWO SEPARATE ACCOUNTS!
  - user_005 accessible via Google (alice@gmail.com)
  - user_006 accessible via GitHub (alice@company.com)

This is BY DESIGN - we can't assume different emails belong to same person.
```

### Journey 6: Password Change

User changes their existing password.

```
Step 1: User visits profile, enters current password + new password
Step 2: Verify current password matches
Step 3: Update password hash in local Channel
```

### Journey 7: Username Change

User changes their username.

```
Step 1: User has username "oldname"
Step 2: Enter new username "newname"
Step 3: UsernameStore.ChangeUsername("oldname", "newname", userID)
  - This is ATOMIC: reserves new, releases old, or fails entirely
Step 4: Update Profile["username"] = "newname"
Step 5: User can now login with "newname" (not "oldname")
```

### Journey 8: OAuth User Resets Password (No Local Channel)

OAuth-only user uses "Forgot Password" to establish local auth.

```
Day 1: User clicks "Continue with Google"
  - Creates: User(id: user_008), Identity, Channel(google)
  - No local Channel exists (no password set)

Day 2: User clicks "Forgot Password", enters email
  - Reset token created and emailed
  - User clicks link, enters new password
  - NewUpdatePasswordFunc detects no local Channel
  - Creates: Channel(local) with password_hash

Result: User can now login TWO ways:
  1. Google OAuth button
  2. Email + password
```

## Edge Cases

### Race Condition in Username Reservation

Two users try to reserve same username simultaneously.

UsernameStore.ReserveUsername is atomic (database transaction):
- One succeeds, one fails with "already exists"
- No data corruption possible

### Case Sensitivity

**Username handling:**
- Stored lowercase: "BobSmith" → "bobsmith"
- Login input lowercased before lookup
- "BOBSMITH", "bobsmith", "BobSmith" all work

**Email handling:**
- Comparison should be case-insensitive
- "Bob@Gmail.com" and "bob@gmail.com" should match same Identity

### Email Already Registered (Signup)

User tries to sign up with existing email:
1. Check Identity exists for email
2. Identity found → Error via OnSignupError callback
3. User should use "Forgot Password" or login with OAuth if they have it

### OAuth Returns Email That Exists

Someone logs in with OAuth, provider returns email that already exists:
1. Check Identity exists
2. Identity exists, belongs to user_001
3. Create/update OAuth Channel for user_001
4. Login as user_001

This is correct behavior - if you control the email on the OAuth provider, you should have access to the account.

### Concurrent Profile Updates

User has two tabs open, updates username in both:
- Tab A changes "alice" to "alice2" → Success
- Tab B tries to change "alice" to "alice3" (stale view)
- "alice" no longer exists in UsernameStore!
- Error: Username change failed

### Expired Tokens

Verification/reset link from weeks ago:
- Token found but ExpiresAt < now
- Error: "Link has expired"
- User prompted to request new email

### Single-Use Tokens

Tokens are deleted after successful use:
1. Token created, stored in TokenStore
2. User uses token
3. Token DELETED from TokenStore
4. Replay attempt → Token not found → Error

## Security Considerations

### Current Protections

| Protection | Implementation |
|------------|---------------|
| Password Hashing | bcrypt |
| Single-Use Tokens | Deleted after use |
| Token Expiration | Time-limited |
| Generic Login Errors | "Invalid credentials" |

### Recommended for Applications

1. **Rate Limiting**: Per-IP and per-account limits
2. **Account Lockout**: Lock after N failed attempts
3. **CSRF Tokens**: On all auth forms
4. **Session Security**: HttpOnly, Secure, SameSite cookies
5. **HTTPS**: Required for OAuth callbacks
6. **Audit Logging**: Log all auth events

### Attack Vectors to Consider

- **Brute Force**: Rate limit login attempts
- **Enumeration**: Use generic error messages
- **Session Fixation**: Regenerate session on login
- **CSRF**: Use SameSite cookies + CSRF tokens
- **Timing Attacks**: Constant-time password comparison

## Store Interfaces

### UserStore

```go
type UserStore interface {
    Create(user *User) error
    Get(id string) (*User, error)
    Save(user *User) error
    Delete(id string) error
}
```

### IdentityStore

```go
type IdentityStore interface {
    Create(identity *Identity) error
    Get(identityType, value string) (*Identity, error)
    GetByUser(userID string) ([]*Identity, error)
    Save(identity *Identity) error
    Delete(identityType, value string) error
}
```

### ChannelStore

```go
type ChannelStore interface {
    Create(channel *Channel) error
    Get(provider, identityKey string) (*Channel, error)
    GetByIdentity(identityKey string) ([]*Channel, error)
    Save(channel *Channel) error
    Delete(provider, identityKey string) error
}
```

### UsernameStore (Optional)

```go
type UsernameStore interface {
    ReserveUsername(username string, userID string) error
    GetUserByUsername(username string) (userID string, err error)
    ReleaseUsername(username string) error
    ChangeUsername(oldUsername, newUsername, userID string) error
}
```

### TokenStore

```go
type TokenStore interface {
    Create(token *Token) error
    Get(tokenValue string) (*Token, error)
    Delete(tokenValue string) error
    DeleteExpired() error
}
```

## Integration Example

```go
import (
    oa "github.com/panyam/oneauth"
    oagae "github.com/panyam/oneauth/stores/gae"
)

func SetupAuth(dsClient *datastore.Client, session *scs.SessionManager) *oa.OneAuth {
    // Create stores
    userStore := oagae.NewUserStore(dsClient, "myapp")
    identityStore := oagae.NewIdentityStore(dsClient, "myapp")
    channelStore := oagae.NewChannelStore(dsClient, "myapp")
    tokenStore := oagae.NewTokenStore(dsClient, "myapp")
    usernameStore := oagae.NewUsernameStore(dsClient, "myapp")

    // Create OneAuth
    oneauth := oa.New("myapp")
    oneauth.Session = session
    oneauth.UserStore = userStore

    // Create user handler for OAuth
    oneauth.HandleUser = oa.NewEnsureAuthUserFunc(oa.EnsureAuthUserConfig{
        UserStore:     userStore,
        IdentityStore: identityStore,
        ChannelStore:  channelStore,
        UsernameStore: usernameStore,
    })

    // Add local auth
    localAuth := oa.NewLocalAuth(oa.LocalAuthConfig{
        Session:       session,
        UserStore:     userStore,
        IdentityStore: identityStore,
        ChannelStore:  channelStore,
        TokenStore:    tokenStore,
        UsernameStore: usernameStore,
        SignupPolicy: &oa.SignupPolicy{
            RequireEmail:      true,
            RequirePassword:   true,
            RequireUsername:   false,
            MinPasswordLength: 8,
        },
    })
    oneauth.AddAuth("/local", localAuth)

    // Add OAuth providers
    oneauth.AddAuth("/google", oa2.NewGoogleOAuth2(...))
    oneauth.AddAuth("/github", oa2.NewGithubOAuth2(...))

    return oneauth
}
```
