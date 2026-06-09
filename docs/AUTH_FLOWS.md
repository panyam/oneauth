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
     │                                                            │
     │    ┌─────────────────────────────────────────────────────┐ │
     │    │ 1. OAuth provider authenticates user                │ │
     │    │ 2. Callback receives: email, name, avatar           │ │
     │    │ 3. Look up Identity by email                        │ │
     │    └─────────────────────────────────────────────────────┘ │
     │         │                                                  │
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
     ┌─────────────────────────────────────────────────────┐      │
     │ Does input contain "@"?                             │      │
     └─────────────────────────────────────────────────────┘      │
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
                          ┌────────────────────────────────────────────────────────┐
                          │              SECOND AUTH ATTEMPT                       │
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

**Handlers:** `HandleForgotPasswordForm` (GET), `HandleForgotPassword` (POST), `HandleResetPasswordForm` (GET), `HandleResetPassword` (POST)

1. User submits email
2. Create password reset token (time-limited)
3. Email link with token
4. User clicks link, enters new password
5. Update password hash in local Channel (or create local Channel if user is OAuth-only)

**OAuth-Only Users:** If the user signed up via OAuth and has no local Channel,
`NewUpdatePasswordFunc` automatically creates a local Channel with the new password.
This enables OAuth users to add email/password login via the standard password reset flow.

**Two Response Modes:**

| Mode | When | Behavior |
|------|------|----------|
| JSON (default) | `ForgotPasswordURL` / `ResetPasswordURL` empty | GET renders basic HTML form, POST returns JSON |
| Redirect | URLs set | GET redirects to app page, POST redirects with query params |

In redirect mode, the application renders its own themed pages at the configured URLs,
reading query parameters (`?sent=true`, `?token=...`, `?success=true`, `?error=...`) to
determine what state to display. This keeps all presentation in the application layer.

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

## OAuth Grant Flows

Diagrams for the OAuth 2.0 grant flows oneauth ships as an AS and (where applicable) consumes from the CLI / SDK. Distinct from the "Supported Flows" section above — those describe the user-identity-channel lifecycle this library brokers; the diagrams here describe the wire-level grant exchanges with external clients.

### RFC 8628 Device Authorization Grant

The device-flow case: a device with limited input (smart TV, CLI, IoT) gets a token while the user authorizes on a separate device (phone, laptop). What's distinctive about this grant is that the device asking for the token is *not* the device the user authorizes on — there is no redirect URL because the polling device has no browser to redirect *to*, so the AS bridges them via an out-of-band `user_code` that the user transcribes.

The happy path:

```mermaid
sequenceDiagram
    autonumber
    participant D as Device<br/>(e.g. smart TV, CLI)
    participant AS as Authorization<br/>Server (oneauth)
    participant U as User
    participant B as User's browser<br/>(phone / laptop)

    Note over D,AS: Phase 1 — Device initiates the flow
    D->>AS: POST /device/authorize<br/>(client_id, scope)
    AS->>AS: mint device_code (256-bit hex)<br/>mint user_code (WDJB-MJHT)<br/>store as Status=Pending<br/>expires_at = now + 15min
    AS-->>D: 200 OK<br/>{ device_code, user_code,<br/>  verification_uri,<br/>  verification_uri_complete?,<br/>  expires_in: 900, interval: 5 }

    Note over D,U: Phase 2 — Device shows the code; user transcribes
    D->>U: Display "Visit https://as.example/device<br/>and enter WDJB-MJHT"

    Note over D,AS: Phase 3 — Device polls token endpoint while user authorizes
    par Device polls
        loop every `interval` seconds
            D->>AS: POST /api/token<br/>(grant_type=device_code,<br/> device_code, client_id)
            AS-->>D: 400 authorization_pending<br/>(or slow_down on fast re-poll)
        end
    and User authorizes on a different device
        U->>B: open verification_uri<br/>(or scan QR of verification_uri_complete)
        B->>AS: GET /device<br/>(code entry form, CSRF token)
        AS-->>B: HTML form
        U->>B: type WDJB-MJHT, submit
        B->>AS: POST /device<br/>(user_code, csrf_token)
        AS->>AS: lookup user_code →<br/>case/dash-insensitive,<br/>find Status=Pending record
        alt User not yet authenticated
            AS-->>B: 302 redirect to /auth/login
            U->>B: enter password
            B->>AS: POST /auth/login (localauth)
            AS-->>B: session cookie + redirect to /device/approve
        end
        B->>AS: GET /device/approve<br/>(authenticated session)
        AS-->>B: consent screen:<br/>"App XYZ wants: read, write"
        U->>B: click "Approve"
        B->>AS: POST /device/approve
        AS->>AS: ApproveDeviceAuthorization(user_code,<br/> subject=alice, scopes=[read,write])<br/>Status → Approved
        AS-->>B: "You may now return to your device"
    end

    Note over D,AS: Phase 4 — Next poll picks up the approval
    D->>AS: POST /api/token<br/>(grant_type=device_code,<br/> device_code, client_id)
    AS->>AS: status=Approved →<br/>mint access_token (JWT, sub=alice)<br/>mint refresh_token<br/>DELETE device_code<br/>(replay protection)
    AS-->>D: 200 OK<br/>{ access_token, refresh_token,<br/>  token_type: Bearer,<br/>  expires_in: 900 }

    Note over D: Device now uses access_token<br/>against the resource server
```

**Notes the diagram reveals:**

- Steps 7–14 run in parallel with steps 5–6. The device has no idea the user is on a phone entering a code; it just keeps polling and sees `authorization_pending` until step 15 flips the status.
- Step 18 deletes the authorization. This is the consume-on-success replay protection — a leaked `device_code` can't redeem twice. The AS implementation enforces this; see `apiauth.handleDeviceCodeGrant`.
- The login dance in steps 11–13 is optional. If the user is already signed in to the AS (session cookie still valid), steps 11–13 are skipped and the consent screen renders immediately.
- **What's shipped:**
  - The poll loop, token endpoint branch, and token issuance — issue 117 (v0.1.23).
  - Confidential-client authentication on redemption — issue 266 (v0.1.24).
  - The CLI side of the flow (`oneauth token device <issuer>` driving steps 1, 6, 16) — issue 268 (v0.1.25).
  - The HTML pages at steps 7, 9, 12, 15 (`apiauth.DeviceVerificationHandler`) plus the function-type hooks callers wire to their localauth + CSRF middleware — issue 267 (v0.1.26).

**Spec defaults** the diagram is drawn against:

- `expires_in`: 900s (15 min) — RFC 8628 §3.4
- `interval`: 5s baseline; `slow_down` bumps by 5 — RFC 8628 §3.5
- `user_code` charset: `BCDEFGHJKLMNPQRSTVWXZ23456789` (8 chars, displayed as `XXXX-XXXX`) — RFC 8628 §6.1

See: [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628), `apiauth/device_auth_grant.go`, `cmd/oneauth/cmd/token_device.go`.

### RFC 8252 + RFC 7636 Authorization Code with PKCE

The browser flow for desktop apps, CLIs, and mobile apps. What's distinctive is that the redirect comes back to a loopback HTTP server the *client* itself ran on a random port — `redirect_uri=http://127.0.0.1:NNNNN/cb` per RFC 8252 §7.3 — so a confidential server isn't needed. PKCE (RFC 7636) binds the eventual code-for-token exchange to a per-flow secret the client invented, so even if an attacker intercepts the redirect they can't redeem the code.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client app<br/>(CLI / desktop)
    participant L as Loopback HTTP server<br/>(in-process, random port)
    participant B as User's browser
    participant AS as Authorization Server<br/>(oneauth)
    participant U as User

    Note over C: Phase 1 — Generate PKCE pair + start loopback
    C->>C: code_verifier = 43-128 random bytes<br/>code_challenge = base64url(SHA256(code_verifier))<br/>state = random nonce
    C->>L: ListenAndServe on 127.0.0.1:N<br/>(random unprivileged port)

    Note over C,B: Phase 2 — Send user to /authorize
    C->>B: open https://as.example/authorize<br/>?response_type=code&client_id=…&redirect_uri=http://127.0.0.1:N/cb<br/>&code_challenge=X&code_challenge_method=S256<br/>&state=Y&scope=read+write
    B->>AS: GET /authorize?...
    alt User not yet authenticated
        AS-->>B: 302 redirect to /auth/login?next=…
        U->>B: enter password
        B->>AS: POST /auth/login (localauth)
        AS-->>B: session cookie + redirect back to /authorize
    end
    AS-->>B: consent screen (client_name, scopes)
    U->>B: click "Approve"
    B->>AS: POST /authorize (consent)
    AS->>AS: mint authorization_code<br/>store code → { code_challenge, client_id,<br/>scopes, sub, redirect_uri, exp }

    Note over AS,L: Phase 3 — Redirect carries code back to the client's own loopback
    AS-->>B: 302 redirect to<br/>http://127.0.0.1:N/cb?code=AUTHCODE<br/>&state=Y&iss=https://as.example
    B->>L: GET /cb?code=…&state=…&iss=…
    L->>C: pass parsed callback params
    C->>C: validate state == Y (CSRF defence)<br/>validate iss byte-equal to AS metadata<br/>(RFC 9207, byte-strict per issue 246)

    Note over C,AS: Phase 4 — Exchange code for token (the proof)
    C->>AS: POST /api/token<br/>(grant_type=authorization_code,<br/>code, code_verifier, client_id,<br/>redirect_uri)
    AS->>AS: lookup code<br/>verify SHA256(code_verifier) == code_challenge<br/>verify redirect_uri matches stored<br/>verify code not expired<br/>delete code (single-use)
    AS-->>C: 200 OK<br/>{ access_token, refresh_token,<br/>  token_type: Bearer,<br/>  expires_in: 900 }

    Note over C: Client closes loopback server,<br/>uses access_token
```

**Notes the diagram reveals:**

- The loopback server in step 2 is what makes this flow work *without* a public callback URL. A CLI on a developer's laptop has nowhere for the AS to redirect to — except a server it just spun up on `127.0.0.1`. RFC 8252 §7.3 gives this pattern its blessing.
- Step 7 (PKCE verification) is the substantive defence. Even if an attacker captures the redirect (browser extension, malicious app, MITM), they don't have `code_verifier` because the client never put it on the wire — it stayed local. Without `code_verifier`, step 22 fails.
- Step 6 carries `iss=` (RFC 9207). The client validates it *byte-equal* against the AS metadata issuer (no URL normalization — issue 246). This prevents mix-up attacks where a different AS tries to convince the client to exchange the code against the wrong token endpoint.
- The login dance at steps 4–6 is identical to other browser flows. If the user is already authenticated to the AS, those steps collapse.
- **What's shipped:**
  - AS-side `/authorize` endpoint plus consent handling — partially shipped (the consent surface lives in `localauth` + future work tracked under issue 116 for full OIDC).
  - Client-side loopback + PKCE machinery — `client.BrowserLoginRequest`, shipped pre-v0.1.13.
  - `oneauth token browser <issuer>` CLI — shipped in issue 255 (v0.1.21).
  - RFC 9207 `iss=` validation (byte-strict) — shipped in issue 246 (v0.1.22).

**Spec defaults:**

- `code_challenge_method`: `S256` (the only sane choice; `plain` is for legacy compat) — RFC 7636 §4.3
- `code` validity: 10 minutes max — RFC 6749 §4.1.2; oneauth uses 5 minutes by default
- `state` length: ≥ 16 bytes of entropy

See: [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207), `apiauth/auth.go` (`/api/token`), `client/browser_login.go`, `client/validate_iss.go`, `cmd/oneauth/cmd/token_browser.go`.

### RFC 6749 §6 Refresh Token (with family-rotation theft detection)

A short-lived access token expires; the client trades a long-lived refresh token for a fresh access token without dragging the user back through `/authorize`. The interesting part isn't the rotation itself — it's the **theft detection**: every refresh token carries a `family` identifier, and reuse of an already-rotated token is treated as proof of compromise. The AS revokes the whole family and forces re-authentication.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client app
    participant AS as Authorization Server<br/>(oneauth)
    participant RT as RefreshTokenStore

    Note over C,AS: Happy path — rotate
    C->>AS: POST /api/token<br/>(grant_type=refresh_token,<br/>refresh_token=RT-old, client_id)
    AS->>RT: GetRefreshToken(RT-old)
    RT-->>AS: { sub, client_id, family=F, scopes,<br/>revoked: false, exp: future }
    AS->>RT: RotateRefreshToken(RT-old)
    RT->>RT: mark RT-old revoked<br/>mint RT-new with family=F (same)<br/>generation += 1
    RT-->>AS: { token: RT-new }
    AS->>AS: mint access_token (fresh JWT)
    AS-->>C: 200 OK<br/>{ access_token, refresh_token: RT-new,<br/>  expires_in: 900 }

    Note over C,AS: Theft path — replay of an already-rotated token
    C->>AS: POST /api/token<br/>(grant_type=refresh_token,<br/>refresh_token=RT-old, client_id)
    AS->>RT: GetRefreshToken(RT-old)
    RT-->>AS: { sub, family=F, revoked: true }<br/>(RT-old was already rotated!)
    AS->>AS: TOKEN REUSE DETECTED →<br/>presumption of theft
    AS->>RT: RevokeTokenFamily(F)
    RT->>RT: revoke EVERY token where family=F<br/>(RT-new and any descendants)
    AS-->>C: 400 invalid_grant<br/>"Token reuse detected, all sessions revoked"
    Note over C: Both the attacker AND the legitimate<br/>holder now have to re-authenticate.<br/>Legitimate user notices and changes password;<br/>attacker is locked out.
```

**Notes the diagram reveals:**

- The single-token rotation (top half) is the boring case. The interesting case is the **bottom half**: when an old (already-rotated) token is presented, the AS doesn't just reject it — it revokes the *whole family*. That's the substantive defence.
- The legitimate holder gets the disruption *with* the attacker. That's intentional: a forced re-auth surfaces the breach. The alternative — silently letting one side win — leaves the attacker undetected.
- `family` is also what's plumbed into the BCL `sid` claim. A revoked family fires `OnSubjectRevoked` / `OnTokenRevoked` hooks, which the BCL dispatcher consumes to notify every client with a registered `backchannel_logout_uri` (see [OIDC Back-Channel Logout 1.0 (sender)](#oidc-back-channel-logout-10-sender)).
- The `RFC 6749 §6` permits the AS to either return a new refresh token or keep the old one valid. oneauth always rotates — the theft detection above only works if you rotate.
- **What's shipped:**
  - The rotation + family-revoke logic — pre-v0.1.13.
  - The BCL hook fire on family revoke — issue 261 (v0.1.20).
  - `oneauth token refresh <issuer>` CLI — issue 255 (v0.1.21).

**Spec defaults:**

- `refresh_token` lifetime: 7 days (oneauth default; the spec doesn't mandate)
- Family identifier: 16-char hex; generated once, carried through every rotation
- Refresh token storage: see [RFC 7009 Token Revocation](#rfc-7009-token-revocation) for what revocation means at the wire level

See: [RFC 6749 §6](https://www.rfc-editor.org/rfc/rfc6749#section-6), `apiauth/token_validator.go` (`RefreshGrant`), `core/stores.go` (`RefreshTokenStore` interface), `cmd/oneauth/cmd/token_refresh.go`.

### RFC 7009 Token Revocation

The wire surface for "this token is no longer needed." Distinctive: the spec demands the AS *always* return 200, even for unknown / malformed tokens, so an attacker can't probe which token values are live. Behind the 200 façade, the AS does different things depending on whether the token is an access token (blacklist by `jti` until its `exp`) or a refresh token (mark revoked in the store + capture identity for downstream notification).

```mermaid
sequenceDiagram
    autonumber
    participant C as Client / RS
    participant AS as Authorization Server<br/>(oneauth)
    participant BL as Blacklist
    participant RT as RefreshTokenStore
    participant HK as TokenHooks<br/>(BCL dispatcher etc.)

    C->>AS: POST /oauth/revoke<br/>(token, token_type_hint?)
    AS->>AS: extractClientCredentials() →<br/>client_secret_basic / _post / private_key_jwt
    AS->>AS: AuthenticateClient(...)
    alt Hint says refresh, or no hint
        AS->>RT: GetRefreshToken(token)
        alt Found
            AS->>AS: capture (sub, family-as-sid, client_id)<br/>BEFORE revoke fires
            AS->>RT: RevokeRefreshToken(token)
            RT->>RT: mark revoked = true
            AS->>HK: fire OnRevoked(token, hint)<br/>fire OnTokenRevoked(sub, sid, client_id)
            HK-->>HK: BCLDispatcher.Dispatch(...)<br/>(see BCL section)
        else Not found
            Note over AS,RT: Silent — RFC 7009 §2.2:<br/>"no information must be leaked"
        end
    end
    alt Hint says access, or no hint AND refresh path didn't match
        AS->>AS: parse JWT (no signature check —<br/>blacklist is by jti only)
        AS->>BL: Revoke(jti, exp)<br/>(remembers jti until its exp)
        AS->>HK: fire OnRevoked(token, hint)
    end

    AS-->>C: 200 OK (empty body)<br/>(per spec — always 200,<br/>regardless of outcome)
```

**Notes the diagram reveals:**

- The 200-on-everything rule (step 11) is the substantive part. It means a healthcheck-script revoking-the-empty-string returns 200; an attacker enumerating refresh tokens against `/oauth/revoke` learns nothing. The spec is explicit about this in §2.2.
- The `(sub, family-as-sid, client_id)` capture in step 5 happens *before* the revoke. If we waited until after, the hook would have no identity to pass downstream — the refresh-token row would be gone. This was the source of a bug in the BCL sender; see issue 261's PR for the fix.
- The hook fire at step 8 is what the BCL dispatcher subscribes to. A single `POST /oauth/revoke` against a refresh token can fan out to N `POST` calls to N RS endpoints if the affected clients registered `backchannel_logout_uri` (see [OIDC Back-Channel Logout 1.0 (sender)](#oidc-back-channel-logout-10-sender)).
- Access-token revocation is implemented as blacklist-by-`jti`. Validators check the blacklist after signature verification; the blacklist entry expires when the token would have anyway, so the storage doesn't grow unbounded.
- **What's shipped:**
  - `/oauth/revoke` endpoint + blacklist + refresh-store revoke — pre-v0.1.13.
  - `TokenHooks.OnRevoked` + `OnTokenRevoked` (with captured identity) — issue 261 (v0.1.20).
  - Confidential-client authentication on the revoke endpoint — same wiring as `/api/token`.

**Spec defaults:**

- `token_type_hint`: optional; speeds up the lookup but the AS MUST try both kinds when omitted
- HTTP status: always 200 OK regardless of whether the token existed — RFC 7009 §2.2
- Blacklist retention: until the token's own `exp` — no longer needed after

See: [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009), `apiauth/revocation.go`, `apiauth/token_revoker.go`, `apiauth/hooks.go`.

### OIDC Back-Channel Logout 1.0 (sender)

The AS-initiated push that tells already-bootstrapped resource servers a session ended, without polling. Triggered by every revocation path — `/api/logout-all`, single-token `/api/logout`, RFC 7009 `/oauth/revoke`. The dispatcher fans out one signed `logout_token` per affected client and POSTs each to the client's registered `backchannel_logout_uri`.

```mermaid
sequenceDiagram
    autonumber
    participant U as User / Admin
    participant AS as Authorization Server<br/>(oneauth)
    participant D as BCLDispatcher
    participant LT as LogoutTokenIssuer
    participant RA as RS A<br/>(registered BCL URI)
    participant RB as RS B<br/>(registered BCL URI)
    participant RC as RS C<br/>(NO registered URI)

    Note over U,AS: Trigger — user logs out (or admin revokes)
    U->>AS: POST /api/logout-all<br/>(Bearer access_token)
    AS->>AS: capture clientIDs from GetSubjectTokens(alice)<br/>BEFORE revoke
    AS->>AS: RevokeSubjectTokens(alice)
    AS->>AS: fire TokenHooks.OnSubjectRevoked(alice, "", [A, B, C])
    AS->>D: Dispatch({subject: alice, clientIDs: [A, B, C]})

    Note over D,LT: Phase — Filter to clients with a registered BCL URI
    D->>D: AppRegistrationLookup for each client<br/>A → has backchannel_logout_uri ✓<br/>B → has backchannel_logout_uri ✓<br/>C → empty → SKIP

    Note over D,RB: Phase — Mint one logout_token per client + POST
    par For RS A
        D->>LT: CreateLogoutToken(aud=A, sub=alice)
        LT-->>D: signed JWT<br/>{iss, aud=A, sub, sid, iat, jti,<br/>events: {"…backchannel-logout": {}}}<br/>typ=logout+jwt
        D->>D: dial-time SSRF guard:<br/>reject loopback/RFC1918/<br/>link-local IPs (unless opted in)
        D->>RA: POST <backchannel_logout_uri><br/>Content-Type: application/x-www-form-urlencoded<br/>logout_token=<JWT>
        RA->>RA: validate logout_token,<br/>kill its session cookie / cache
        RA-->>D: 200 OK
    and For RS B
        D->>LT: CreateLogoutToken(aud=B, sub=alice)
        LT-->>D: signed JWT (audience=B)
        D->>RB: POST <backchannel_logout_uri><br/>logout_token=<JWT>
        RB-->>D: 200 OK
    end

    AS-->>U: 204 No Content<br/>(by now the POSTs may still be in flight —<br/>async-fire-and-forget by default)
```

**Notes the diagram reveals:**

- The capture-before-revoke in step 2 is load-bearing. `GetSubjectTokens` only returns *active* grants — after `RevokeSubjectTokens` runs, the list is empty. We learned this the hard way; see issue 261's PR for the dance.
- Step 4 passes `clientIDs` through the hook (rather than re-querying inside the dispatcher) so the dispatcher doesn't need the store at all when called from logout-all. The single-token revoke path (`/oauth/revoke`, see [RFC 7009 Token Revocation](#rfc-7009-token-revocation)) populates `clientIDs` from the captured refresh-token row instead.
- The dispatch in steps 9–14 runs asynchronously per client by default — a slow or broken receiver MUST NOT stall the user's logout. Tests flip `SyncForTest = true` to make assertions deterministic.
- The SSRF guard in step 8 closes a classic vulnerability: without it, a client could register `backchannel_logout_uri = http://10.0.0.1/internal/delete` and use *us* to attack the AS's internal network. Validation rejects literal-IP private hosts at DCR; the dialer re-checks at connect time to catch DNS rebinding.
- `logout_token` carries `sub` and `sid` (mapped from the refresh-token `family`). MUST NOT carry a `nonce` — that would make it look like an `id_token`, and §2.6 receivers REJECT a `nonce` claim.
- Client C in the diagram has the same active grant as A and B, but no registered `backchannel_logout_uri` — it's just skipped. The flow only notifies opted-in clients.
- **What's shipped:**
  - Full sender side — `BCLDispatcher`, `LogoutTokenIssuer`, AS metadata advertisement, DCR field, SSRF guard. Issue 261 (v0.1.20).
  - Hook fire from all three revocation paths — same.
  - The receiver side lives downstream in panyam/mcpkit (not oneauth).

**Spec defaults:**

- `logout_token.exp`: 2 minutes (not required by spec, but receivers SHOULD reject stale tokens)
- `events` claim: `{"http://schemas.openid.net/event/backchannel-logout": {}}` — the exact URI is the protocol marker
- POST shape: `application/x-www-form-urlencoded`, body `logout_token=<JWT>`, `Cache-Control: no-store`

See: [OIDC Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html), `apiauth/bcl_dispatcher.go`, `apiauth/logout_token.go`, `apiauth/hooks.go`.

### RFC 7662 Token Introspection

The wire interface a resource server uses to ask the AS "is this token still good, and what's in it?" Useful for opaque tokens (where the RS *can't* inspect them locally) and for revocation-aware validators (RS that would otherwise honor an access token until its `exp` even after the user logged out). The trade-off is latency: per-request network calls have a cost. Cached introspection trades freshness for speed.

```mermaid
sequenceDiagram
    autonumber
    participant App as Client app
    participant RS as Resource Server<br/>(IntrospectionValidator)
    participant Cache as Validator cache<br/>(in-process, TTL)
    participant AS as Authorization Server<br/>(oneauth)

    App->>RS: GET /protected<br/>Authorization: Bearer <token>
    RS->>RS: extract <token> from header
    alt CacheTTL > 0 (configured)
        RS->>Cache: lookup hash(token)
        alt Hit + not expired
            Cache-->>RS: { active, sub, scope, exp, ... }
            RS->>RS: enforce scopes / authorization_details
            RS-->>App: 200 OK (protected resource)
        end
    end

    Note over RS,AS: Cache miss — call the AS
    RS->>AS: POST /oauth/introspect<br/>Authorization: Basic <client_id:secret><br/>token=<token>
    AS->>AS: AuthenticateClient(...)<br/>(client_secret_basic / _post / private_key_jwt)
    AS->>AS: validate token:<br/>1. signature verification<br/>2. expiry check<br/>3. blacklist check (issue 100)<br/>4. issuer + audience check
    alt Token valid
        AS-->>RS: 200 OK<br/>{ "active": true,<br/>  "sub": "alice",<br/>  "scope": "read write",<br/>  "client_id": "x",<br/>  "exp": 1700000000,<br/>  "iss": "...",<br/>  "jti": "...",<br/>  "authorization_details": [...] }
    else Token revoked / expired / unknown
        AS-->>RS: 200 OK<br/>{ "active": false }<br/>(per spec §2.2 — never reveal why)
    end
    RS->>Cache: store result for CacheTTL
    RS->>RS: enforce scopes<br/>(via Middleware.RequireScopes etc.)
    RS-->>App: 200 OK (protected resource)<br/>OR 401 unauthorized / 403 forbidden
```

**Notes the diagram reveals:**

- The `200 + {active: false}` in step 13 is the substantive bit. The spec forbids leaking *why* a token is inactive: revoked tokens, expired tokens, malformed tokens, unknown tokens all look identical from the wire. Attackers learn nothing from probing.
- The cache (steps 3–7) is the operational lever. CacheTTL=0 (default) means every request hits the AS — slow but freshness-guaranteed. CacheTTL>0 means revoked tokens stay "active" in the RS for up to that long. There's no spec answer for the right value; oneauth ships CacheTTL=0 by default and lets operators choose.
- Step 9 routes through the same `ClientAuthenticator` `/api/token` uses, so confidential RSes can authenticate via `private_key_jwt` (issue 158) — not just `client_secret_basic`.
- Issuing AS and validating RS need a trust relationship: the RS needs OAuth credentials of its own, registered at the AS, that it presents on every introspection call. That's what step 8 verifies.
- This is the inverse trade-off of local JWT validation. Local validation: faster, no per-request network call, no revocation awareness without polling. Introspection: slower, network dependency, revocation-aware (up to CacheTTL).
- **What's shipped:**
  - AS `/oauth/introspect` endpoint — issue 47.
  - RS-side `IntrospectionValidator` with optional caching + tracing — issue 47.
  - Confidential-client authentication on the endpoint — issue 158.
  - `oneauth introspect <issuer>` CLI — issue 258 (v0.1.21).

**Spec defaults:**

- HTTP status: always 200 (regardless of `active`'s value) — RFC 7662 §2.2
- `Cache-Control: no-store` on the response — implementation requirement
- `active=false` is the entire failure surface — no `error` claim

See: [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662), `apiauth/introspection.go` (server), `apiauth/introspection_client.go` (RS-side validator), `cmd/oneauth/cmd/introspect.go`.

### RFC 7591 + RFC 7592 Dynamic Client Registration (DCR)

The OAuth client registration surface — apps register themselves at runtime instead of an operator pre-creating each one in an admin UI. Useful for SaaS-onboarding, demos, CI bots, and anywhere the client population is open. RFC 7591 covers initial registration; RFC 7592 covers what to do with that registration afterwards (read / update / delete). The substantive defence is the `registration_access_token` issued at registration time — it's the bearer credential that authorizes every subsequent management call against that specific registration's URL.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client app
    participant AS as Authorization Server<br/>(oneauth)
    participant KS as KeyStore
    participant RG as AppRegistrationStore

    Note over C,AS: Phase 1 — Initial registration (RFC 7591)
    C->>AS: POST /apps/dcr<br/>{ client_name, redirect_uris,<br/>  grant_types, scope,<br/>  token_endpoint_auth_method,<br/>  jwks?, backchannel_logout_uri? }
    AS->>AS: authenticate (initial access token OR X-Admin-Key)<br/>OR open registration (dev mode)
    AS->>AS: generate client_id = "app_" + hex(12 bytes)
    alt token_endpoint_auth_method = private_key_jwt
        AS->>KS: store caller-supplied public JWK as PEM<br/>(no client_secret)
    else default (symmetric)
        AS->>AS: generate client_secret = hex(32 bytes)
        AS->>KS: store client_secret as HS256 key
    end
    AS->>AS: generate registration_access_token = hex(32 bytes)
    AS->>RG: SaveApp(AppRegistration{client_id, …,<br/>registration_access_token, …})
    AS-->>C: 201 Created<br/>{ client_id, client_secret?,<br/>  registration_access_token,<br/>  registration_client_uri:<br/>  https://as.example/apps/dcr/<client_id> }

    Note over C: Persist registration_access_token<br/>+ registration_client_uri<br/>(they are the keys to manage this registration)

    Note over C,AS: Phase 2 — RFC 7592 management (GET / PUT / DELETE)
    C->>AS: GET <registration_client_uri><br/>Authorization: Bearer <registration_access_token>
    AS->>RG: GetApp(client_id from URL path)
    RG-->>AS: stored registration
    AS->>AS: constant-time compare:<br/>req.bearer == stored.registration_access_token
    alt Token matches
        AS-->>C: 200 OK<br/>{ client_id, client_name, redirect_uris, … }<br/>(no client_secret in this response —<br/>secret never leaves the issuance call)
    else Mismatch / missing / unknown client_id
        AS-->>C: 401 Unauthorized<br/>(uniform error per §3 — no info leak)
    end

    Note over C,AS: Update — full replacement (§2.2)
    C->>AS: PUT <registration_client_uri><br/>Authorization: Bearer <registration_access_token><br/>{ client_id, client_name, redirect_uris, … }
    AS->>AS: same auth check as GET
    AS->>AS: replace ALL editable metadata fields<br/>(client_name, uris, grants, scope, etc.)<br/>auth_method is LOCKED (would re-key)
    AS->>AS: ROTATE registration_access_token<br/>(old one is now dead)
    AS->>RG: SaveApp(updated registration)
    AS-->>C: 200 OK<br/>{ …, registration_access_token: <NEW>, … }
    Note over C: MUST persist the rotated token<br/>before discarding the old one

    Note over C,AS: Delete (§2.3)
    C->>AS: DELETE <registration_client_uri><br/>Authorization: Bearer <registration_access_token>
    AS->>RG: DeleteApp(client_id)
    AS->>KS: DeleteKey(client_id)<br/>(invalidates already-issued tokens —<br/>§2.3 mandates this)
    AS-->>C: 204 No Content
```

**Notes the diagram reveals:**

- The `registration_access_token` (issued at step 8, rotated at step 22) is the credential that distinguishes RFC 7592 from "anyone with a stolen client_id can edit the registration." Lose it and you lose the ability to manage the registration; the AS gives no recovery path on purpose.
- The PUT in steps 19–25 is a *full replacement*, not a patch. Field you omit gets blanked. The CLI's `oneauth dcr put` calls this out in its `--help`; this is one of the easier ways to accidentally destroy data.
- Step 27 deletes the *key material* too. After this, every access token previously issued under `client_id` fails signature verification — the spec mandates that revocation effect, because there's no other mechanism to invalidate non-blacklisted JWTs en masse for one client.
- The error responses in step 17 / similar paths uniformly return 401 — wrong token, missing token, unknown client_id all look identical. Same anti-enumeration posture as `/oauth/introspect`.
- The `backchannel_logout_uri` field is what wires this client into [OIDC Back-Channel Logout 1.0 (sender)](#oidc-back-channel-logout-10-sender) at session-revoke time. Validation at registration includes the SSRF guard described in the BCL section.
- **What's shipped:**
  - RFC 7591 register endpoint + `client.RegisterClient` SDK — issue 48.
  - RFC 7592 GET / PUT / DELETE — issues 168 / 169 / 170.
  - Keycloak interop tests — issue 171.
  - `oneauth dcr <register|get|put|delete>` CLI — issue 258 (v0.1.21).
  - `backchannel_logout_uri` DCR field (with SSRF validation) — issue 261 (v0.1.20).

**Spec defaults:**

- `client_id_issued_at`: Unix epoch seconds at registration
- `client_secret_expires_at`: `0` (never expires) — RFC 7591 §3.2.1
- Registration access token: 64-char hex, single token per registration, rotated on PUT
- Management URI: `<issuer>/apps/dcr/<client_id>` (path-based per oneauth convention)

See: [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591), [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592), `admin/dcr.go`, `admin/registrar.go`, `admin/dcr_management.go`, `client/dcr.go`, `cmd/oneauth/cmd/dcr.go`.

### RFC 6749 §4.4 Client Credentials

The machine-to-machine grant — no user involved. A service authenticates with its own `client_id` + credential and gets back an access token bound to that service's identity. Useful for cron jobs, internal services, and any callsite where the principal is the calling code, not a person. Simplest of the seven grants; the value is mostly in being the bottom of the OAuth ladder rather than reinventing it.

```mermaid
sequenceDiagram
    autonumber
    participant A as Service A<br/>(client)
    participant AS as Authorization Server<br/>(oneauth)
    participant CA as ClientAuthenticator
    participant JI as TokenIssuer
    participant B as Service B<br/>(resource server)

    Note over A,AS: Phase 1 — Token request
    A->>AS: POST /api/token<br/>(grant_type=client_credentials,<br/>client_id, client_secret OR client_assertion,<br/>scope?, resource?, audience?)
    AS->>CA: AuthenticateClient(request)
    alt client_secret_basic / _post
        CA->>CA: constant-time compare against KeyStore
    else private_key_jwt
        CA->>CA: parse client_assertion (signed JWT)<br/>verify iss == sub == client_id<br/>verify audience<br/>verify signature against registered public key<br/>verify jti not replayed (JTIStore)<br/>verify exp + lifetime ≤ 5min
    end
    CA-->>AS: { client_id, method }
    AS->>JI: CreateAccessToken(sub=client_id, scopes, audience)
    JI->>JI: mint JWT<br/>{iss, aud, sub=client_id, scopes, jti, iat, exp,<br/> type: "access"}
    JI-->>AS: signed access_token
    AS-->>A: 200 OK<br/>{ access_token, token_type: Bearer,<br/>  expires_in: 900, scope }

    Note over A,B: Phase 2 — Service A calls Service B
    A->>B: GET /api/protected<br/>Authorization: Bearer <access_token>
    alt Service B validates locally (JWT)
        B->>B: verify signature via JWKS<br/>verify iss + aud + exp<br/>check blacklist (if configured)
    else Service B validates via introspection
        B->>AS: POST /oauth/introspect<br/>(see Introspection section)
    end
    B-->>A: 200 OK (resource)
```

**Notes the diagram reveals:**

- The `sub` claim is the `client_id`, not a user. This is what separates client_credentials tokens from password-grant / browser-flow tokens: there is no user identity to carry. Code that consumes tokens needs to know it might see either.
- The `private_key_jwt` path in step 4 is the harder case but the more secure one — the secret never leaves the client. No shared secret means no secret-leak surface. Replay protection via `jti` + the registered key's algorithm lock-down means a captured assertion can't be reused.
- Step 11 (local validation vs introspection) is the standard fork. Local validation is faster but doesn't pick up revocations; introspection is slower but revocation-aware. See [RFC 7662 Token Introspection](#rfc-7662-token-introspection) for the trade-offs.
- The `resource` and `audience` parameters in step 1 narrow the token. RFC 8707 `resource` and OIDC `audience` let the AS issue a token specifically scoped for Service B — useful when Service A talks to multiple downstream services and you want least-privilege per call.
- **What's shipped:**
  - The grant itself — pre-v0.1.13.
  - `private_key_jwt` auth — issue 158.
  - `oneauth token client-credentials <issuer>` CLI — issue 255 (v0.1.21).

**Spec defaults:**

- Access-token lifetime: 15 minutes (oneauth default)
- `scope`: optional in request; AS may grant fewer scopes than asked for
- Refresh tokens: NOT issued for this grant — the client just gets a new access token directly each time (re-presenting credentials is cheap)

See: [RFC 6749 §4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4), [RFC 7521](https://www.rfc-editor.org/rfc/rfc7521), [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523), `apiauth/auth.go` (`handleClientCredentialsGrant`), `apiauth/client_authenticator.go`, `client/client.go` (`ClientCredentials`), `cmd/oneauth/cmd/token_client_credentials.go`.

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
