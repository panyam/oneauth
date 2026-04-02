# Stores

OneAuth uses interface-based storage with three built-in implementations: file-based (FS), GORM (SQL databases), and Google App Engine Datastore (GAE).

> **Sub-module note:** `stores/gorm` and `stores/gae` are separate Go modules (each has its own `go.mod`) to keep heavy dependencies (GORM/drivers, GCP SDK) out of the core module. Store backends import `github.com/panyam/oneauth/core` for entity types and `github.com/panyam/oneauth/keys` for key types — not the root `oneauth` package.

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

### UsernameStore (Optional)

Manages username uniqueness and username-based login. Only needed if your app requires unique usernames or login with username.

```go
type UsernameStore interface {
    ReserveUsername(username string, userID string) error
    GetUserByUsername(username string) (userID string, err error)
    ReleaseUsername(username string) error
    ChangeUsername(oldUsername, newUsername, userID string) error
}
```

**Why separate from IdentityStore?** Username is a display handle, not a contact method. It has different validation rules, changes more frequently, and enables O(1) lookup for username-based login.

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

## Store Implementations

### File-Based (FS)

Suitable for development, small applications (< 1000 users), and prototypes.

**Security:** FS stores use a `safeName()` sanitizer on all key/file names to prevent path traversal attacks. Directories are created with permissions `0700` and files with `0600`.

```go
import "github.com/panyam/oneauth/stores/fs"

storagePath := "/path/to/storage"
userStore := fs.NewFSUserStore(storagePath)
identityStore := fs.NewFSIdentityStore(storagePath)
channelStore := fs.NewFSChannelStore(storagePath)
tokenStore := fs.NewFSTokenStore(storagePath)
usernameStore := fs.NewFSUsernameStore(storagePath)
refreshTokenStore := fs.NewFSRefreshTokenStore(storagePath)
apiKeyStore := fs.NewFSAPIKeyStore(storagePath)
```

### GORM (SQL Databases)

For production use with PostgreSQL, MySQL, SQLite, etc.

```go
import "github.com/panyam/oneauth/stores/gorm"

usernameStore := gorm.NewUsernameStore(db)
```

### GAE (Google App Engine Datastore)

For applications running on Google App Engine.

```go
import "github.com/panyam/oneauth/stores/gae"

usernameStore := gae.NewUsernameStore(datastoreClient, namespace)
```

## Custom Store Implementation

Implement the store interfaces for your database:

```go
type PostgresUserStore struct {
    db *sql.DB
}

func (s *PostgresUserStore) CreateUser(userId string, isActive bool, profile map[string]any) (core.User, error) {
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

### Caching

Implement caching in your store implementations for better performance:

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

## KeyLookup & KeyStorage

For multi-tenant JWT validation, OneAuth provides key management interfaces built around the `KeyRecord` type.

### KeyRecord

```go
type KeyRecord struct {
    ClientID  string // app/tenant identifier
    Key       any    // []byte (HS256), *rsa.PublicKey (RS256), *ecdsa.PublicKey (ES256), or PEM bytes
    Algorithm string // "HS256", "RS256", "ES256"
}
```

### KeyLookup (Read-Only)

```go
type KeyLookup interface {
    GetKey(clientID string) (*KeyRecord, error)      // lookup by client ID
    GetKeyByKid(kid string) (*KeyRecord, error)      // lookup by key ID (RFC 7638 thumbprint)
}
```

### KeyStorage (Read + Write)

Extends `KeyLookup` with write operations for host registration and key management:

```go
type KeyStorage interface {
    KeyLookup
    PutKey(rec *KeyRecord) error
    DeleteKey(clientID string) error
    ListKeyIDs() ([]string, error)
}
```

### InMemoryKeyStore

For development and testing:

```go
keyStore := keys.NewInMemoryKeyStore()
keyStore.PutKey(&keys.KeyRecord{ClientID: "host-alpha", Key: []byte("alpha-secret-key"), Algorithm: "HS256"})
keyStore.PutKey(&keys.KeyRecord{ClientID: "host-beta",  Key: []byte("beta-secret-key"),  Algorithm: "HS256"})
```

### Persistent KeyStore Implementations

#### FS KeyStore

File-based persistent KeyStore for single-node deployments:

```go
import "github.com/panyam/oneauth/stores/fs"

keyStore := fs.NewFSKeyStore(storagePath)
```

#### GORM KeyStore

SQL-backed KeyStore for production use:

```go
import "github.com/panyam/oneauth/stores/gorm"

keyStore := gorm.NewKeyStore(db)
```

#### GAE KeyStore

Google App Engine Datastore-backed KeyStore:

```go
import "github.com/panyam/oneauth/stores/gae"

keyStore := gae.NewKeyStore(datastoreClient, namespace)
```

### keystoretest Shared Test Suite

The `keystoretest` package provides a reusable test suite that any `KeyStorage` implementation can run to verify correctness:

```go
import "github.com/panyam/oneauth/keystoretest"

func TestMyKeyStore(t *testing.T) {
    store := NewMyKeyStore(...)
    keystoretest.RunKeyStoreTests(t, store)
}
```

All three built-in KeyStore implementations (FS, GORM, GAE) use this shared test suite. When implementing a custom KeyStorage, run these tests to verify compatibility.

For how KeyLookup/KeyStorage is used in multi-tenant JWT validation, see [API_AUTH.md](API_AUTH.md#multi-tenant-jwt-validation-keystore).
