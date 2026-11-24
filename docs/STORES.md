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

### ChannelAdmin (Optional)

A `ChannelStore` looks channels up one at a time. An app whose operator creates and removes local accounts by hand also needs to list them and delete one. The fs, gorm and gae stores implement `accounts.ChannelAdmin` for that. A custom store may not, so check with a type assertion:

```go
if admin, ok := channelStore.(accounts.ChannelAdmin); ok {
    all, _ := admin.ListChannels(ctx, &accounts.ListChannelsRequest{Provider: "local"}) // Credentials is nil
    res, _ := admin.DeleteChannel(ctx, &accounts.DeleteChannelRequest{Provider: "local", IdentityKey: "username:alice"})
    log.Printf("%d local accounts, deleted alice: %v", len(all.Channels), res.Deleted)
}
```

A listing leaves `Credentials` out, so password hashes and provider tokens stay in the store. An empty `Provider` lists every channel. Deleting a channel that doesn't exist returns `Deleted: false` and no error. `localauth.HashPassword` and `localauth.CheckPassword` hash and check a local channel's `password_hash` the way the bundled validators do. `CheckPassword` with an empty hash runs a dummy comparison, so a missing account takes as long to refuse as a wrong password. The shared contract suite is `channeltest.RunAdmin`.

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
appStore := fs.NewFSAppStore(storagePath) // RFC 7591 / 7592 client registrations (issue 166)
```

The `FSAppStore` writes one JSON file per registration under `{storagePath}/apps/{client_id}.json`, with atomic writes (temp file + rename), `safeName` path-traversal defense, and lazy directory creation. Corrupt files surface as parse errors from `GetApp` (so operators can detect data integrity issues) but are silently skipped by `ListApps` (so admin tooling stays usable when one file is hand-edited badly).

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

## AppRegistrationStore

Persists app registration metadata for `AppRegistrar` and the DCR handler. Registrations are the source of truth for which `client_id`s exist and their RFC 7591/7592 metadata; without persistence, revoked apps come back on restart.

```go
type AppRegistrationStore interface {
    SaveApp(app *AppRegistration) error
    GetApp(clientID string) (*AppRegistration, error)
    ListApps() ([]*AppRegistration, error)
    DeleteApp(clientID string) error
}
```

`AppRegistrar` keeps an in-memory cache hydrated from the store on construction; reads hit the cache, writes go through `SaveRegistration` which writes the store first and updates the cache.

### Implementations

| Backend | Status | Use case |
|---------|--------|----------|
| `admin.InMemoryAppStore` | Available | Tests, dev (registrations lost on restart) |
| `stores/fs.FSAppStore` | Available (issue 166) | Single-node, dev-friendly persistence |
| `stores/gorm.GORMAppStore` | Available (issue 167) | Production, multi-node (Postgres / MySQL / SQLite) |

Construct with `admin.NewAppRegistrar(keyStore, auth)` for the default in-memory store, or `admin.NewAppRegistrarWithStore(keyStore, auth, store)` to plug in a persistent backend. The `cmd/oneauth-server` reference deployment exposes the choice via `app_store.type` (`memory` | `fs` | `gorm`) — see config schema below.

```yaml
app_store:
  type: gorm  # memory | fs | gorm
  fs:
    path: ${DATA_DIR}/apps
  gorm:
    driver: postgres
    dsn: ${DATABASE_URL}
```

When the `app_store.gorm` config matches the `keystore.gorm` config (same driver + DSN), `cmd/oneauth-server` reuses the same connection pool. They open separate pools otherwise. The shared `appstoretest` contract suite runs against in-memory SQLite by default and against PostgreSQL when `ONEAUTH_TEST_PGDB` is set.

### appstoretest Shared Test Suite

The `appstoretest` package mirrors `keystoretest`: any `AppRegistrationStore` implementation can run the contract tests to verify correctness.

```go
import "github.com/panyam/oneauth/appstoretest"

func TestMyAppStore(t *testing.T) {
    appstoretest.RunAll(t, func(t *testing.T) admin.AppRegistrationStore {
        return NewMyAppStore(...)
    })
}
```

The suite covers Save/Get/List/Delete contracts, overwrite, persistence (read-after-write), and a full-fields round-trip (catches serialization bugs in slice-typed columns like `RedirectURIs` and `GrantTypes`).

## Authorization codes, pushed requests, device authorizations and user tokens

Four single-use or fast-changing records share one shape: every backend runs a shared contract suite, and every persistent backend needs an atomic check-and-mark so a code, a pushed `request_uri` or a refreshed token is spent once across racing requests.

| Store | Memory | FS | GORM | GAE | Contract suite |
|---|---|---|---|---|---|
| `core.AuthorizationCodeStore` (RFC 6749 §4.1) | `core` | `FSAuthorizationCodeStore` | `AuthorizationCodeStore` | `GAEAuthorizationCodeStore` | `authcodetest.RunAll` |
| `core.PushedAuthorizationRequestStore` (RFC 9126) | `core` | `FSPushedAuthorizationRequestStore` | `PushedAuthorizationRequestStore` | `GAEPushedAuthorizationRequestStore` | `partest.RunAll` |
| `outbound.UserTokenStore` | `outbound` | `FSUserTokenStore` | `UserTokenStore` | `GAEUserTokenStore` | `usertokentest.RunAll` |
| `core.DeviceAuthorizationStore` (RFC 8628) | `core` | `FSDeviceAuthorizationStore` | `DeviceAuthStore` | `GAEDeviceAuthStore` | `deviceauthtest.RunAll` |

- **Atomic within one process only** for memory and FS (a mutex). Replicas need GORM (a conditional `UPDATE` or a transaction) or GAE (a Datastore transaction).
- **Codes, request URIs and device codes are hashed at rest.** FS, GORM and GAE key each record by `core.AtRestKey(value)`, a SHA-256 digest, and leave the plaintext out of the stored record, so a copy of the store can't redeem a code or poll for a device's tokens. Records written before hashing keep working across an upgrade (issues 382, 473). A device lookup by user code returns `DeviceCode` empty.
- **The reference server** picks the code and pushed-request backend with `code_flow.store.type` (`memory`, `fs`, `gorm`, `gae`); PAR always uses the code store's backend.

## Consent grants

`core.ConsentStore` keeps one grant per (subject, client_id), so `/authorize` can skip the consent screen for a request an earlier approval covers, including an OIDC `prompt=none` request. A save replaces the stored grant, and the caller merges scopes. The store returns an expired grant and leaves the decision to `ConsentGrant.Covers`.

| Store | Memory | FS | GORM | GAE | Contract suite |
|---|---|---|---|---|---|
| `core.ConsentStore` (OIDC Core §3.1.2.1) | `core` | `FSConsentStore` | `ConsentStore` | `GAEConsentStore` | `consenttest.RunAll` |

FS names each file by a SHA-256 of subject and client_id, and GAE names each entity the same way, so any characters in either ID are safe. GORM keys the `consents` table on (subject, client_id) and saves with one upsert statement.
