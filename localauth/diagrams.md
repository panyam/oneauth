# localauth diagrams

Sequence diagrams for the multi-step local-auth flows. Generated from the package
source; see `doc.go` for the entity reference.

### Signup (with optional email verification)

```mermaid
sequenceDiagram
    participant C as Client
    participant H as LocalAuth.HandleSignup
    participant P as SignupPolicy / validator
    participant U as UsernameStore
    participant CU as CreateUser (NewCreateUserFunc)
    participant ES as EmailSender + TokenStore
    participant HU as HandleUser

    C->>H: POST signup form (username/email/phone/password)
    H->>H: parseSignupForm
    H->>P: validateSignupCredentials
    alt invalid
        P-->>C: handleSignupError (JSON / redirect)
    end
    opt UsernameStore + EnforceUsernameUnique
        H->>U: GetUserByUsername
        U-->>H: taken? -> ErrCodeUsernameTaken
    end
    H->>CU: CreateUser(creds)
    CU->>CU: bcrypt hash, create User+Identity(unverified)+local Channel
    CU-->>H: user (or "already registered" -> ErrCodeEmailExists)
    opt UsernameStore set
        H->>U: ReserveUsername (warn-only on failure)
    end
    opt email + EmailSender + TokenStore + BaseURL
        H->>ES: CreateToken(emailVerification) + SendVerificationEmail
    end
    alt RequireEmailVerification AND EmailSender set
        H-->>C: 200 "verify your account" + user_id
    else
        H->>HU: HandleUser(local, provider, nil, userInfo) (auto-login)
    end
```

### Login (rate limit + account lockout)

```mermaid
sequenceDiagram
    participant C as Client
    participant S as LocalAuth.ServeHTTP
    participant RL as RateLimiter
    participant LK as Lockout (AccountLockout)
    participant V as ValidateCredentials
    participant HU as HandleUser

    C->>S: POST login (username, password)
    S->>S: parseLoginForm
    opt RateLimiter set
        S->>RL: Allow(IP:username)
        RL-->>C: 429 + Retry-After (if denied)
    end
    opt Lockout set
        S->>LK: IsLocked(username)
        LK-->>C: 429 account_locked (if locked)
    end
    S->>S: DetectUsernameType(username)
    S->>V: ValidateCredentials(username, password, type)
    alt invalid / nil user
        opt Lockout set
            S->>LK: RecordFailure(username)
        end
        S-->>C: handleLoginError (401, or 400 for field errors)
    else valid
        opt Lockout set
            S->>LK: RecordSuccess(username)
        end
        S->>HU: HandleUser(local, provider, nil, userInfo)
    end
```

Note: `NewCredentialsValidator` runs bcrypt against a dummy hash when the user is not
found, keeping response time constant to defeat the CWE-208 timing oracle.

### Password reset (forgot -> reset)

```mermaid
sequenceDiagram
    participant C as Client
    participant FP as HandleForgotPassword
    participant TS as TokenStore
    participant ES as EmailSender
    participant RP as HandleResetPassword
    participant UP as UpdatePassword (NewUpdatePasswordFunc)

    C->>FP: POST forgot-password (email)
    FP->>TS: CreateToken(passwordReset)
    FP->>ES: SendPasswordResetEmail(resetLink)
    FP-->>C: 200 "if that email exists..." (always success)
    Note over C,FP: Always-success response prevents account enumeration

    C->>RP: POST reset-password (token, new password)
    RP->>TS: GetToken(token)
    RP->>RP: check Type == passwordReset, len >= 8
    RP->>UP: UpdatePassword(email, newPassword)
    UP->>UP: bcrypt hash; get-or-create local channel; SaveChannel
    RP->>TS: DeleteToken (one-time use)
    RP-->>C: 200 success / redirect ?success=true
```

### Channel linking via NewEnsureAuthUserFunc (OAuth or local)

```mermaid
sequenceDiagram
    participant Caller as SaveUserAndRedirect / HandleLinkCredentials
    participant EAU as NewEnsureAuthUserFunc closure
    participant IS as IdentityStore
    participant CS as ChannelStore
    participant US as UserStore

    Caller->>EAU: EnsureAuthUser(authtype, provider, token, userInfo)
    EAU->>EAU: extract email from userInfo (required)
    EAU->>IS: GetIdentity(email)
    alt identity exists with UserID (existing user)
        EAU->>US: GetUserById(identity.UserID)
        EAU->>CS: GetChannel(provider, identityKey, createIfMissing=true)
        EAU->>CS: SaveChannel (merge userInfo into Profile)
        opt provider NOT in profile.channels
            EAU->>EAU: append provider; update name/picture from userInfo
            EAU->>US: SaveUser (updated profile)
        end
        EAU-->>Caller: existing user
    else new user
        EAU->>US: CreateUser(userId, profile{email, channels:[provider]})
        EAU->>IS: SaveIdentity(verified = authtype=="oauth")
        EAU->>CS: SaveChannel(provider, identityKey, Profile=userInfo)
        EAU-->>Caller: new user
    end
```

### Link local credentials to OAuth-only user (LinkLocalCredentials)

```mermaid
sequenceDiagram
    participant C as Client (logged-in OAuth user)
    participant H as LocalAuth.HandleLinkCredentials
    participant G as GetLoggedInUserFunc
    participant LL as LinkLocalCredentials
    participant IS as IdentityStore
    participant CS as ChannelStore
    participant US as UsernameStore
    participant USR as UserStore

    C->>H: POST link-credentials (password, optional username)
    H->>G: getUser(r)
    G-->>H: userID (or 401)
    H->>USR: GetUserById(userID) -> email from profile
    H->>H: validate password (policy MinPasswordLength)
    opt username provided
        H->>H: validate format (policy.GetUsernamePattern)
        opt UsernameStore set
            H->>US: GetUserByUsername(username)
            US-->>H: existing userID != this user -> 400 username_taken
        end
    end
    H->>LL: LinkLocalCredentials(config, userID, username, password, email)
    LL->>IS: GetIdentity(email)
    LL->>LL: assert identity.UserID == userID
    LL->>CS: GetChannel(local, identityKey)
    alt local channel already exists
        LL-->>H: error "already exist" -> 409 Conflict
    else
        LL->>LL: bcrypt hash password
        LL->>CS: SaveChannel(local with password_hash)
        opt username + UsernameStore
            LL->>US: ReserveUsername(username, userID) (warn-only)
        end
        LL->>USR: SaveUser (append "local" to profile.channels)
        LL-->>H: ok
        H-->>C: 200 success
    end
```
