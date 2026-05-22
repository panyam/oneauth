---
package: gae
purpose: Google Cloud Datastore implementations of the oneauth store interfaces (keys, users, identities, channels, tokens, API keys, usernames), with multi-tenancy via Datastore namespaces.
last_rebuilt: ca8a742623b748f06d2564dce90465d1eeb10c6d
depends_on:
  - folder: core
    entities: [User, Identity, Channel, UserStore, IdentityStore, ChannelStore, TokenStore, RefreshTokenStore, APIKeyStore, UsernameStore, TokenType, AuthToken, RefreshToken, APIKey, AuthorizationDetail, GenerateSecureToken, GenerateAPIKeyID, GenerateAPIKeySecret, TokenExpiryRefreshToken, ErrAPIKeyNotFound, ErrTokenRevoked, ErrTokenExpired, ErrTokenNotFound, ErrTokenReused]
  - folder: keys
    entities: [KeyStorage, KidStorage, KeyRecord, ErrKidNotFound, ErrKeyNotFound, ErrAlgorithmMismatch]
  - folder: utils
    entities: [ComputeKid]
entities:
  - name: GAEKeyStore
    kind: struct
    role: keys.KeyStorage backed by Datastore, mapping client_id -> per-client signing key under kind SigningKey.
    why: Key name is the ClientID (one key per client); kid lookup is a separate indexed query because Datastore can't key on two attributes at once.
  - name: SigningKeyEntity
    kind: struct
    role: Datastore row for a per-client signing key (key_bytes, algorithm, kid).
    why: key_bytes is noindex (secret material, never queried); only kid is indexed since GetKeyByKid runs a filter query against it.
  - name: GAEKidStore
    kind: struct
    role: keys.KidStorage backed by Datastore (kind KidKey), holding kid -> key grace entries for key-rotation overlap.
    why: Datastore key name is the kid itself, making GetKeyByKid a direct point-get; GetKey(clientID) is intentionally unsupported because this store is kid-indexed, not client-indexed.
  - name: KidKeyEntity
    kind: struct
    role: Datastore row for a grace-period kid entry (key_bytes, algorithm, client_id, expires_at).
    why: expires_at is noindex on purpose — CleanExpired scans and filters in Go because the needed "not-zero AND less-than" predicate isn't expressible as a single native Datastore filter.
  - name: UserStore
    kind: struct
    role: core.UserStore over kind User; create/get/save user with JSON-encoded profile.
    why: SaveUser re-reads the existing row to preserve CreatedAt (read-modify-write without a transaction) and defaults IsActive=true unless the concrete value is a *GAEUser.
  - name: GAEUser
    kind: struct
    role: core.User implementation returned by UserStore (Id + Profile accessors).
    why: Type-asserted in SaveUser as the only way to recover the IsActive flag, since the core.User interface doesn't expose active state.
  - name: IdentityStore
    kind: struct
    role: core.IdentityStore over kind Identity; key is "type:value".
    why: SetUserForIdentity and MarkIdentityVerified run in transactions and bump Version, giving optimistic-concurrency metadata that the plain Get/Put paths skip.
  - name: ChannelStore
    kind: struct
    role: core.ChannelStore over kind Channel; key is "provider:identityKey", stores JSON credentials/profile.
    why: SaveChannel reads-then-writes to preserve CreatedAt and monotonically increment Version (1 on first write), unlike the unconditioned UserStore.SaveUser.
  - name: TokenStore
    kind: struct
    role: core.TokenStore over kind AuthToken for verification/reset tokens; key is the secret token string.
    why: GetToken self-cleans — an expired token is deleted on read and reported as "expired", so reads double as lazy GC.
  - name: RefreshTokenStore
    kind: struct
    role: core.RefreshTokenStore over kind RefreshToken; key is the SHA-256 hash of the token, supports rotation/families.
    why: Stores only the token hash (raw token never persisted); RotateRefreshToken detects reuse of an already-revoked token and revokes the whole family outside the transaction (family revocation can't run inside the failing tx).
  - name: APIKeyStore
    kind: struct
    role: core.APIKeyStore over kind APIKey; key is the keyID, secret stored as a bcrypt hash.
    why: Full key format is "oa_<keyid>_secret"; ValidateAPIKey reconstructs keyID from the first two underscore-segments and bcrypt-compares the third, so the secret is never stored in plaintext or recoverable.
  - name: UsernameStore
    kind: struct
    role: core.UsernameStore over kind Username; key is the lowercased username, original case preserved in a field.
    why: All mutations are transactional to keep username reservation race-free; ChangeUsername short-circuits case-only renames (same normalized key) vs. a real delete-old/reserve-new atomic swap.
  - name: WithContext
    kind: method (on every store)
    role: Returns a shallow copy of the store carrying a caller-supplied context.Context.
    why: Stores stash ctx as a field (set to context.Background() at construction) rather than taking ctx per-call — a deliberate stopgap noted as the planned ctx-as-parameter migration (issues 110/175).
---

The package provides Datastore-backed implementations of the oneauth store
interfaces for Google App Engine / GCP deployments. All entities live as
top-level Datastore kinds (no ancestor hierarchy); multi-tenancy is achieved
purely through Datastore namespaces, set per store at construction and stamped
onto every key via the shared `namespacedKey` helper.

Two cross-cutting conventions recur across every store:

- **ctx-on-the-struct.** Each store holds `client`, `namespace`, and a `ctx`
  field initialized to `context.Background()`, with a `WithContext` copy
  constructor. This is a known interim shape pending the gRPC-style
  ctx-as-first-parameter migration (issues 110/175); the `kidstore.go` comment
  is the canonical note on it.
- **JSON-in-noindex-blobs.** Structured fields (profiles, credentials, scopes,
  device info, RFC 9396 authorization_details) are JSON-marshalled into
  `noindex` byte fields. Only fields that back a query filter (user_id, type,
  family, revoked, kid, identity_key, expires_at) are indexed.

Security-relevant choices: refresh tokens are persisted only as SHA-256 hashes
and API-key secrets only as bcrypt hashes; listings blank out hashes and token
values before returning. Refresh-token rotation implements reuse detection with
family-wide revocation, performed outside the aborted transaction.

The `build !wasm` tag on every file excludes this backend from WASM builds
(the Datastore client is not WASM-compatible). `GAEUser` is the only exported
concrete model living in `stores.go`; the `*Entity` structs in `models.go` are
the on-disk Datastore representations and are converted to/from `core` types at
the store boundary.
