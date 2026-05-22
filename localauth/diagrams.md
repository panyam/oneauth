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
flowchart TD
    A[EnsureAuthUser: authtype, provider, token, userInfo] --> B{email present?}
    B -- no --> E[error: email required]
    B -- yes --> C[IdentityStore.GetIdentity by email]
    C --> D{identity exists with UserID?}
    D -- yes --> F[handleExistingUser]
    F --> F1[get-or-create Channel for provider]
    F1 --> F2[merge userInfo into channel.Profile]
    F2 --> F3{provider in profile.channels?}
    F3 -- no --> F4[append provider, update name/picture, SaveUser]
    F3 -- yes --> F5[no profile change]
    D -- no --> G[handleNewUser]
    G --> G1[CreateUser + Identity verified=oauth + Channel]
```
