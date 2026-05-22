---
package: gorm
purpose: GORM/SQL-backed implementations of the oneauth store interfaces (users, identities, channels, tokens, API keys, usernames, signing keys, kid grace store, app registrations) usable against any GORM-supported driver.
last_rebuilt: ca8a742623b748f06d2564dce90465d1eeb10c6d
entities:
  - name: AutoMigrate
    kind: func
    role: Single entry point that auto-migrates all ten oneauth tables in one call.
    why: Centralizes schema creation so callers can't forget a table; every store's New* doc tells callers to run this first.
  - name: JSONMap
    kind: type
    role: map[string]any with driver.Valuer/Scanner that JSON-encodes into a jsonb column.
    why: Scan returns nil (not an error) on a non-[]byte value — tolerates drivers/columns that hand back already-decoded or unexpected types rather than failing the read.
  - name: StringSlice
    kind: type
    role: []string Valuer/Scanner for storing slices as JSON.
    why: Same defensive non-[]byte tolerance as JSONMap; nil slices store as SQL NULL rather than "[]".
  - name: AuthorizationDetailsJSON
    kind: type
    role: []core.AuthorizationDetail Valuer/Scanner for RFC 9396 details as jsonb.
    why: Keeps the rich-authorization payload as a structured column on refresh tokens without a join table or DB-specific JSON ops.
  - name: UserModel
    kind: struct
    role: GORM row for users; carries a Version column for optimistic concurrency.
    why: Profile is jsonb so arbitrary app claims ride along without schema changes.
  - name: IdentityModel
    kind: struct
    role: Email/phone identity keyed by composite (Type, Value), linked to a user.
    why: Composite primary key enforces one row per identity globally; UserID indexed (not FK) to keep the store backend-agnostic.
  - name: ChannelModel
    kind: struct
    role: Per-provider auth channel keyed by (Provider, IdentityKey) with credentials/profile blobs.
    why: ExpiresAt is indexed to support channel-auth expiry sweeps; IdentityKey sized 320 to fit max email length.
  - name: AuthTokenModel
    kind: struct
    role: Short-lived verification/password-reset token row keyed by the token string.
    why: No Version/Revoked — these are single-use and physically deleted, unlike refresh tokens.
  - name: RefreshTokenModel
    kind: struct
    role: Long-lived refresh token row; stores only TokenHash, with Token gorm:"-" (memory only).
    why: Raw token is never persisted (hash-at-rest); Family + Generation columns implement RFC reuse-detection / rotation lineage.
  - name: APIKeyModel
    kind: struct
    role: Long-lived programmatic API key row storing a bcrypt KeyHash, never the secret.
    why: ExpiresAt is a *time.Time so "no expiry" is NULL rather than a zero date that some dialects mangle.
  - name: UsernameModel
    kind: struct
    role: Username→userID mapping keyed by NormalizedUsername with a case-preserved Username column.
    why: Lowercased key gives case-insensitive uniqueness while preserving display case; Version drives optimistic locking.
  - name: SigningKeyModel
    kind: struct
    role: Per-client signing key row; Kid carries a unique index.
    why: Unique Kid index lets GetKeyByKid resolve a key without scanning, and prevents two clients sharing a kid.
  - name: KidKeyModel
    kind: struct
    role: kid→key grace-window row for key rotation, with nullable ExpiresAt.
    why: ExpiresAt is *time.Time so never-expiring entries are NULL, dodging the 0001-01-01 zero-date that some SQL dialects emit.
  - name: AppRegistrationModel
    kind: struct
    role: OAuth client/app registration row covering RFC 7591/7592 metadata and RFC 9396 detail types.
    why: Slice fields use gorm:"serializer:json" (not jsonb type tags) so the same model works on SQLite/MySQL/Postgres without DB-specific JSON quirks; persists RegistrationAccessToken so DCR management survives restart.
  - name: GORMUser
    kind: struct
    role: Thin adapter wrapping UserModel to satisfy core.User.
    why: Keeps the persistence model out of the public interface; exposes only Id()/Profile().
  - name: UserStore
    kind: struct
    role: core.UserStore impl (CreateUser, GetUserById, SaveUser).
    why: Maps gorm.ErrRecordNotFound to a descriptive error so callers don't depend on the GORM sentinel.
  - name: IdentityStore
    kind: struct
    role: core.IdentityStore impl with createIfMissing get-or-create.
    why: GetIdentity returns a bool "created" flag so callers can branch on first-sight without a second round trip.
  - name: ChannelStore
    kind: struct
    role: core.ChannelStore impl (get-or-create, save, list by identity).
    why: Initializes empty JSONMaps on create so downstream code never dereferences nil maps.
  - name: TokenStore
    kind: struct
    role: core.TokenStore impl for verification/reset tokens.
    why: GetToken self-deletes expired tokens on read (lazy GC) rather than relying on a background sweeper.
  - name: RefreshTokenStore
    kind: struct
    role: core.RefreshTokenStore impl with rotation, family/user revocation, cleanup.
    why: RotateRefreshToken runs inside a transaction and rejects an already-revoked token with ErrTokenReused — the reuse-detection trigger; rotation preserves Family but bumps Generation.
  - name: APIKeyStore
    kind: struct
    role: core.APIKeyStore impl with bcrypt validation.
    why: ValidateAPIKey hand-parses the "oa_<keyid>_<secret>" triple and bcrypt-compares, returning ErrAPIKeyNotFound on bad secret to avoid leaking whether the key id existed.
  - name: UsernameStore
    kind: struct
    role: core.UsernameStore impl using optimistic concurrency (version-checked WHERE).
    why: Cross-username changes delete-then-create and on a lost create-race best-effort re-create the old row — there is no enclosing transaction, so the window is documented rather than locked.
  - name: KeyStore
    kind: struct
    role: keys.KeyStorage impl for per-client signing keys, plus backward-compat alias methods.
    why: PutKey only accepts []byte keys (ErrAlgorithmMismatch otherwise) and auto-computes Kid via utils.ComputeKid when blank; legacy aliases (RegisterKey/GetVerifyKey/...) kept so older callers don't break.
  - name: KidStore
    kind: struct
    role: keys.KidStorage impl for the rotation grace window (Add/Remove/GetKeyByKid/CleanExpired).
    why: GetKey(clientID) deliberately always returns ErrKeyNotFound because this store is kid-indexed only; expired entries are filtered at read time AND physically removed by CleanExpired, mirroring the in-memory store.
  - name: AppStore
    kind: struct
    role: admin.AppRegistrationStore impl (production, multi-node, shared DB source of truth).
    why: Mirrors InMemoryAppStore semantics exactly (errClientIDRequired message, ErrAppNotFound) so the shared appstoretest contract suite passes uniformly across backends.
depends_on:
  - folder: core
    entities: [User, Identity, Channel, AuthToken, RefreshToken, APIKey, TokenType, AuthorizationDetail, UserStore, IdentityStore, ChannelStore, TokenStore, RefreshTokenStore, APIKeyStore, UsernameStore, GenerateSecureToken, GenerateAPIKeyID, GenerateAPIKeySecret, TokenExpiryRefreshToken, ErrTokenNotFound, ErrTokenExpired, ErrTokenRevoked, ErrTokenReused, ErrAPIKeyNotFound]
  - folder: keys
    entities: [KeyRecord, KeyStorage, KidStorage, ErrKeyNotFound, ErrKidNotFound, ErrAlgorithmMismatch]
  - folder: admin
    entities: [AppRegistration, AppRegistrationStore, ErrAppNotFound]
  - folder: utils
    entities: [ComputeKid]
---

These types are pure SQL-backed adapters: every store struct holds a `*gorm.DB` and
translates between a `core`/`keys`/`admin` interface type and a local `*Model` row.
The split between exported `*Model` structs and the conversion helpers
(`ToX`/`XToModel`, `appRegistrationToModel`/`modelToAppRegistration`) keeps GORM tags
and column sizing out of the domain types while letting GORM auto-migrate the schema.

Two cross-cutting conventions recur and are the real design content here. First,
secrets are never stored in the clear: refresh tokens persist only a SHA-256
`TokenHash` (the raw `Token` is `gorm:"-"`, memory-only), and API keys persist a
bcrypt hash with the secret discarded after creation. Second, the package is written
to behave identically across SQLite/MySQL/Postgres — hence `*time.Time` for
optional expiries (NULL beats a zero date), `serializer:json` on `AppRegistrationModel`
slices instead of dialect-specific `jsonb`, and `Scan` implementations that tolerate
non-`[]byte` input rather than erroring.

Concurrency is handled two ways depending on the table. `RefreshTokenStore.RotateRefreshToken`
uses a real DB transaction for atomic revoke-old + create-new with reuse detection.
`UsernameStore` instead uses version-checked optimistic concurrency and, for the
cross-username rename path, an unprotected delete-then-create with best-effort rollback —
a known, documented race window rather than a transaction.
