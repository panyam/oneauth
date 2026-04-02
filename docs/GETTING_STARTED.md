# Getting Started with OneAuth

Get a Go application running with local authentication in 5 minutes.

## Installation

```bash
go get github.com/panyam/oneauth
```

## Setting Up Stores

OneAuth requires stores for users, identities, channels, and tokens. The library provides file-based implementations for development:

```go
import (
    "github.com/panyam/oneauth/core"
    "github.com/panyam/oneauth/localauth"
    "github.com/panyam/oneauth/stores/fs"
)

storagePath := "/path/to/storage"
userStore := fs.NewFSUserStore(storagePath)
identityStore := fs.NewFSIdentityStore(storagePath)
channelStore := fs.NewFSChannelStore(storagePath)
tokenStore := fs.NewFSTokenStore(storagePath)

// For API authentication
refreshTokenStore := fs.NewFSRefreshTokenStore(storagePath)
apiKeyStore := fs.NewFSAPIKeyStore(storagePath)
```

For production store options (GORM, GAE), see [STORES.md](STORES.md).

## Configuring Local Authentication

```go
// Create authentication callbacks using helper functions
createUser := localauth.NewCreateUserFunc(userStore, identityStore, channelStore)
validateCreds := localauth.NewCredentialsValidator(identityStore, channelStore, userStore)
verifyEmail := localauth.NewVerifyEmailFunc(identityStore, tokenStore)
updatePassword := localauth.NewUpdatePasswordFunc(identityStore, channelStore)

// Configure local authentication
localAuth := &localauth.LocalAuth{
    CreateUser:          createUser,
    ValidateCredentials: validateCreds,
    ValidateSignup:      nil, // Uses default validator
    EmailSender:         &core.ConsoleEmailSender{},
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

## Setting Up Routes

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

## Helper Functions

OneAuth provides helper functions to create callbacks from stores:

### NewCreateUserFunc

```go
createUser := localauth.NewCreateUserFunc(userStore, identityStore, channelStore)
user, err := createUser(&core.Credentials{
    Username: "johndoe",
    Email:    &email,
    Password: "password123",
})
```

### NewCredentialsValidator

```go
validateCreds := localauth.NewCredentialsValidator(identityStore, channelStore, userStore)
user, err := validateCreds("john@example.com", "password123", "email")
```

### NewVerifyEmailFunc

```go
verifyEmail := localauth.NewVerifyEmailFunc(identityStore, tokenStore)
err := verifyEmail(tokenString)
```

### NewUpdatePasswordFunc

```go
updatePassword := localauth.NewUpdatePasswordFunc(identityStore, channelStore)
err := updatePassword("john@example.com", "newpassword456")
```

## Next Steps

- [API_AUTH.md](API_AUTH.md) — JWT-based API authentication for mobile apps, SPAs, and services
- [BROWSER_AUTH.md](BROWSER_AUTH.md) — OAuth integration, session management, channel linking
- [STORES.md](STORES.md) — Store interfaces and persistent implementations (GORM, GAE)
- [GRPC.md](GRPC.md) — gRPC authentication interceptors
- [TESTING.md](TESTING.md) — Testing, security, and troubleshooting
