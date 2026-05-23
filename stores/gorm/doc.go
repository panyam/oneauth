//go:build !wasm
// +build !wasm

// Package gorm provides GORM/SQL-backed implementations of every oneauth
// store interface.
//
// The package supplies persistent stores for users, identities, channels,
// verification/reset tokens, refresh tokens, API keys, usernames, signing
// keys, kid grace keys, and app registrations — runnable on any
// GORM-supported driver (SQLite, MySQL, Postgres, ...). Each store owns its
// own *gorm.DB plus a GORM model whose ToX/XToModel helpers bridge to the
// transport-agnostic core/keys/admin types. AutoMigrate creates all ten
// tables in one call and MUST run before any store is used. Slice and map
// fields are JSON-encoded into single columns (via JSONMap, StringSlice,
// AuthorizationDetailsJSON, or the gorm serializer tag) to stay portable
// across drivers without DB-specific JSONB handling. Error and not-found
// semantics deliberately match the in-memory reference stores so the shared
// contract test suites pass uniformly across backends.
//
// ENTITIES
//
// AutoMigrate — runs db.AutoMigrate for all ten oneauth GORM models in one
// call. Single migration entrypoint; callers MUST run it (or equivalent)
// before any store is used.
//
// JSONMap — map[string]any with driver.Valuer/Scanner that JSON-encodes into
// a single column. Custom Value/Scan so jsonb columns round-trip portably;
// Scan silently no-ops on non-[]byte input.
//
// StringSlice — []string with Valuer/Scanner that JSON-encodes into one
// column. Avoids a join table for scope lists; portable across
// SQLite/MySQL/Postgres.
//
// AuthorizationDetailsJSON — []core.AuthorizationDetail with Valuer/Scanner
// for RFC 9396 details as jsonb. Stores rich authorization details inline on
// the refresh token row.
//
// UserModel — GORM model for the users table (ID, IsActive, Profile,
// Version). Profile uses JSONMap; Version present for future optimistic
// locking.
//
// IdentityModel — GORM model for identities, keyed by (Type, Value)
// composite primary key. ToIdentity/IdentityToModel bridge to core.Identity;
// composite PK enforces one row per type+value.
//
// ChannelModel — GORM model for auth channels, keyed by (Provider,
// IdentityKey). Credentials and Profile are JSONMap; ExpiresAt tracks
// channel-auth expiry.
//
// AuthTokenModel — GORM model for verification/reset tokens, keyed by raw
// Token. Token is the primary key in plaintext — these are short-lived
// single-use tokens, unlike refresh tokens.
//
// RefreshTokenModel — GORM model for refresh tokens, keyed by TokenHash;
// Token field is gorm-ignored. Only the SHA-256 hash is persisted; raw Token
// (gorm:"-") lives in memory only.
//
// APIKeyModel — GORM model for API keys, keyed by KeyID, storing a bcrypt
// KeyHash. Secret is never stored; only the bcrypt hash, validated at
// lookup time.
//
// UsernameModel — GORM model mapping NormalizedUsername (PK) to UserID with
// a Version column. Lowercase normalized PK gives case-insensitive
// uniqueness; Version drives optimistic concurrency.
//
// GORMUser — core.User adapter wrapping a *UserModel. Exposes Id()/Profile()
// without leaking the GORM model to callers.
//
// UserStore — core.UserStore impl (CreateUser, GetUserById, SaveUser).
// GetUserById maps gorm.ErrRecordNotFound to a descriptive error.
//
// IdentityStore — core.IdentityStore impl with get-or-create, verify, and
// user-reassign. GetIdentity optionally inserts a placeholder (empty UserID)
// row when createIfMissing.
//
// ChannelStore — core.ChannelStore impl with get-or-create by (provider,
// identityKey). Initializes empty JSONMaps on creation to avoid nil-map
// writes.
//
// TokenStore — core.TokenStore impl for verification/reset tokens. GetToken
// lazily deletes the row when expired, returning "token expired".
//
// RefreshTokenStore — core.RefreshTokenStore impl with rotation, family/user
// revoke, cleanup. Hashes tokens with SHA-256; RotateRefreshToken runs
// inside a transaction with reuse detection.
//
// APIKeyStore — core.APIKeyStore impl issuing oa_<keyid>_<secret> keys with
// bcrypt validation. ValidateAPIKey hand-parses the three-part key and
// bcrypt-compares; never returns the hash to callers.
//
// UsernameStore — core.UsernameStore impl with optimistic-concurrency
// reserve/change/release. Uses WHERE version=? guards and RowsAffected==0
// to detect concurrent edits; best-effort rollback in ChangeUsername.
//
// SigningKeyModel — GORM model for per-client signing keys, keyed by
// ClientID with a unique Kid index. Kid computed via utils.ComputeKid when
// absent.
//
// KeyStore — keys.KeyStorage impl (PutKey, GetKey, GetKeyByKid, ListKeyIDs)
// plus legacy aliases. Backward-compat aliases (RegisterKey/GetVerifyKey/
// etc.) delegate to the canonical methods.
//
// KidKeyModel — GORM model for kid->key grace entries, keyed by Kid with
// nullable ExpiresAt. ExpiresAt is *time.Time so nil means "never expires",
// dodging SQL 0001-01-01 zero-date quirks.
//
// KidStore — keys.KidStorage impl (Add upsert, Remove, GetKeyByKid,
// CleanExpired). GetKey always returns ErrKeyNotFound (kid-indexed only);
// reads filter expired entries to match in-memory semantics.
//
// AppRegistrationModel — GORM model for app/client registrations
// (RFC 7591/7592 + RFC 9396 fields). Slice fields use gorm:"serializer:json"
// to avoid DB-specific JSONB quirks; persists RFC 7592 management
// credentials across restarts.
//
// AppStore — admin.AppRegistrationStore impl (SaveApp, GetApp, ListApps,
// DeleteApp). Error semantics (ErrAppNotFound, ClientID-required) mirror
// InMemoryAppStore so the shared contract suite passes uniformly.
//
// FLOWS
//
// See [diagrams.md](diagrams.md) for sequence diagrams of: refresh-token
// rotation (transactional with reuse detection) and username change
// (cross-record optimistic concurrency with best-effort rollback).
package gorm
