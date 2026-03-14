# Testing, Security & Troubleshooting

## Testing

OneAuth handlers can be tested without a running HTTP server using `httptest`:

```go
func TestSignup(t *testing.T) {
    // Setup
    tmpDir, _ := os.MkdirTemp("", "test-*")
    defer os.RemoveAll(tmpDir)

    userStore := fs.NewFSUserStore(tmpDir)
    identityStore := fs.NewFSIdentityStore(tmpDir)
    channelStore := fs.NewFSChannelStore(tmpDir)

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

### Test File Reference

- `local_test.go`, `auth_flows_test.go` — complete browser auth patterns
- `api_auth_test.go` — API authentication with JWT, refresh tokens, and API keys
- `custom_claims_test.go` — custom claims injection and multi-tenant JWT validation
- `keystore_test.go` — KeyStore interface and InMemoryKeyStore usage
- `grpc/context_test.go`, `grpc/interceptor_test.go` — gRPC patterns

## Security Considerations

### Password Storage

OneAuth uses bcrypt with default cost for password hashing. Passwords are never stored in plain text.

### Token Security

- Verification tokens: 32 bytes, hex-encoded (64 characters)
- Default expiry: 24 hours for email verification, 1 hour for password reset
- Tokens are single-use and deleted after consumption
- Expired tokens are automatically rejected

### Rate Limiting

Implement rate limiting at the HTTP handler level:

```go
rateLimiter := ratelimit.New(10, time.Minute) // 10 requests per minute

mux.Handle("/auth/login", rateLimiter.Wrap(localAuth))
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

For production with larger user bases, implement database-backed stores. See [STORES.md](STORES.md) for GORM and GAE implementations.
