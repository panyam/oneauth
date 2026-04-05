# Client SDK

The `client/` package provides a Go SDK for CLI tools and programmatic clients consuming oneauth-protected APIs. It handles login, token storage, automatic token refresh, and authenticated HTTP requests.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        AuthClient                           │
│  - Login / Logout                                           │
│  - GetToken() with automatic refresh                        │
│  - HTTPClient() returns authenticated *http.Client          │
└──────────────────────────┬──────────────────────────────────┘
                           │
         ┌─────────────────┼──────────────────────┐
         │                 │                      │
         ▼                 ▼                      ▼
┌────────────────┐  ┌──────────────┐   ┌─────────────────┐
│CredentialStore │  │refreshTranspt│   │  AuthTransport  │
│  (interface)   │  │ (401 retry + │   │  (static Bearer │
│                │  │  pre-expiry  │   │   header)       │
│                │  │  refresh)    │   │                 │
└────────┬───────┘  └──────────────┘   └─────────────────┘
         │
         ▼
┌──────────────────┐
│ client/stores/fs │
│  JSON file       │
│ ~/.config/<app>  │
└──────────────────┘
```

## Quick Start

```go
import (
    "github.com/panyam/oneauth/client"
    "github.com/panyam/oneauth/client/stores/fs"
)

// 1. Create a credential store
store, err := fs.NewFSCredentialStore("", "myapp")
// Stores credentials at ~/.config/myapp/credentials.json

// 2. Create an auth client
authClient := client.NewAuthClient("https://api.example.com", store)

// 3. Login
cred, err := authClient.Login("user@example.com", "password", "read write")

// 4. Use the authenticated HTTP client
resp, err := authClient.HTTPClient().Get("https://api.example.com/resource")
// Authorization: Bearer <token> is added automatically
// On 401, token is refreshed and request retried
```

## AuthClient

The main entry point for the client SDK.

### Constructor

```go
func NewAuthClient(serverURL string, store CredentialStore, opts ...ClientOption) *AuthClient
```

The server URL is normalized to `scheme://host` (path is stripped). Default token endpoint is `/auth/cli/token`.

### Options

```go
// Custom token endpoint
client.NewAuthClient(url, store, client.WithTokenEndpoint("/oauth/token"))

// Custom HTTP client (inherits timeout, TLS settings)
client.NewAuthClient(url, store, client.WithHTTPClient(&http.Client{
    Timeout: 30 * time.Second,
}))

// Custom transport
client.NewAuthClient(url, store, client.WithTransport(customTransport))
```

### Methods

#### Login

```go
cred, err := authClient.Login("user@example.com", "password", "read write")
```

Sends a `grant_type=password` request to the token endpoint. Stores the credential and persists to disk.

#### Client Credentials (Machine-to-Machine)

```go
cred, err := authClient.ClientCredentialsToken("billing-svc", "secret", []string{"billing:read"})
```

Sends a `grant_type=client_credentials` request. No refresh token — machine clients re-authenticate when the token expires. Stores the credential for subsequent API calls via `HTTPClient()`.

#### AS Metadata Discovery (RFC 8414 / OIDC Discovery)

```go
meta, err := client.DiscoverAS("https://auth.example.com")
// meta.TokenEndpoint, meta.JWKSURI, meta.IntrospectionEndpoint, etc.
```

Fetches OAuth AS metadata from well-known endpoints. Tries RFC 8414 (`/.well-known/oauth-authorization-server`) first, falls back to OIDC Discovery (`/.well-known/openid-configuration`). Supports path-based issuers (e.g., Keycloak realms).

Use `WithHTTPClientForDiscovery(client)` to customize the HTTP client (TLS, timeouts).

#### Browser Login (OAuth Authorization Code + PKCE)

```go
cred, err := authClient.LoginWithBrowser(client.BrowserLoginConfig{
    ClientID: "my-cli-app",
    Scopes:   []string{"openid", "read", "write"},
})
```

Opens the user's default browser to the authorization server's login page. After the user authenticates (password, SSO, MFA — whatever the AS supports), the browser redirects to a temporary loopback server that catches the authorization code. The code is exchanged for tokens via PKCE.

This is the same pattern used by `gh auth login`, `gcloud auth login`, and `kubectl` with OIDC. Endpoints are auto-discovered via `DiscoverAS()`, or can be set explicitly via `AuthorizationEndpoint` and `TokenEndpoint` in the config.

#### Logout

```go
err := authClient.Logout()
```

Removes the stored credential for this server.

#### GetToken

```go
token, err := authClient.GetToken()
```

Returns the current access token. If the token expires within 5 minutes and a refresh token is available, it proactively refreshes before returning.

#### IsLoggedIn

```go
if authClient.IsLoggedIn() {
    // Has a valid, non-expired credential
}
```

#### HTTPClient

```go
httpClient := authClient.HTTPClient()
resp, err := httpClient.Get("https://api.example.com/resource")
```

Returns an `*http.Client` wired with `refreshTransport` that:
1. Adds `Authorization: Bearer <token>` to every request
2. Proactively refreshes tokens expiring within 5 minutes
3. On 401 response: refreshes the token and retries the request once

## Credential Storage

### ServerCredential

```go
type ServerCredential struct {
    AccessToken  string    `json:"access_token"`
    RefreshToken string    `json:"refresh_token,omitempty"`
    TokenType    string    `json:"token_type,omitempty"`
    UserID       string    `json:"user_id,omitempty"`
    UserEmail    string    `json:"user_email,omitempty"`
    Scope        string    `json:"scope,omitempty"`
    ExpiresAt    time.Time `json:"expires_at"`
    CreatedAt    time.Time `json:"created_at"`
}
```

Helper methods:
- `IsExpired() bool` — true if token has expired
- `IsExpiringSoon(within time.Duration) bool` — true if expiring within the given duration
- `HasRefreshToken() bool` — true if refresh token is present

### CredentialStore Interface

```go
type CredentialStore interface {
    GetCredential(serverURL string) (*ServerCredential, error)
    SetCredential(serverURL string, cred *ServerCredential) error
    RemoveCredential(serverURL string) error
    ListServers() ([]string, error)
    Save() error
}
```

### FSCredentialStore

File-based implementation that persists credentials as JSON.

```go
import "github.com/panyam/oneauth/client/stores/fs"

// Default path: ~/.config/myapp/credentials.json
store, err := fs.NewFSCredentialStore("", "myapp")

// Custom path
store, err := fs.NewFSCredentialStore("/path/to/credentials.json", "")
```

File format:
```json
{
  "servers": {
    "https://api.example.com": {
      "access_token": "eyJhbGci...",
      "refresh_token": "a1b2c3...",
      "expires_at": "2026-03-15T10:45:00Z",
      "user_id": "user-123",
      "scope": "read write"
    }
  }
}
```

Security: credentials file is written with `0600` permissions (owner-only), directory with `0700`.

## Token Refresh Flow

```
User makes request via HTTPClient()
  │
  ▼
refreshTransport.RoundTrip()
  │
  ├─ GetToken() checks if token expires within 5 min
  │   └─ If yes + has refresh token → refresh proactively
  │
  ├─ Adds Authorization: Bearer <token> header
  │
  ├─ Sends request
  │
  └─ If 401 received + has refresh token:
      └─ Refresh token, retry request once with new token
```

The refresh uses a `grant_type=refresh_token` request to the token endpoint. The base transport is used for refresh requests to avoid infinite loops.

## AuthTransport (Static Token)

For simpler cases where you have a static token and don't need refresh:

```go
import "github.com/panyam/oneauth/client"

transport := client.NewAuthTransport("my-static-token")
httpClient := &http.Client{Transport: transport}

resp, err := httpClient.Get("https://api.example.com/resource")
// Authorization: Bearer my-static-token
```

## Complete Example: CLI Tool

```go
package main

import (
    "fmt"
    "os"

    "github.com/panyam/oneauth/client"
    "github.com/panyam/oneauth/client/stores/fs"
)

func main() {
    store, _ := fs.NewFSCredentialStore("", "mycli")
    auth := client.NewAuthClient("https://api.example.com", store)

    switch os.Args[1] {
    case "login":
        cred, err := auth.Login(os.Args[2], os.Args[3], "read write")
        if err != nil {
            fmt.Fprintf(os.Stderr, "Login failed: %v\n", err)
            os.Exit(1)
        }
        fmt.Printf("Logged in as %s\n", cred.UserEmail)

    case "whoami":
        if !auth.IsLoggedIn() {
            fmt.Println("Not logged in")
            os.Exit(1)
        }
        cred, _ := auth.GetCredential()
        fmt.Printf("User: %s (%s)\n", cred.UserID, cred.UserEmail)

    case "fetch":
        resp, err := auth.HTTPClient().Get(os.Args[2])
        if err != nil {
            fmt.Fprintf(os.Stderr, "Request failed: %v\n", err)
            os.Exit(1)
        }
        defer resp.Body.Close()
        // ... handle response

    case "logout":
        auth.Logout()
        fmt.Println("Logged out")
    }
}
```

## Thread Safety

Both `AuthClient` and `FSCredentialStore` are protected by `sync.Mutex`. Safe for concurrent use from multiple goroutines.
