//go:build !wasm
// +build !wasm

// Package gorm provides GORM-based implementations of oneauth store interfaces.
//
// <!-- design:start -->
// Package gorm supplies GORM/SQL-backed implementations of every oneauth store
// interface — users, identities, channels, verification/reset tokens, refresh
// tokens, API keys, usernames, signing keys, kid grace keys, and app
// registrations — runnable on any GORM-supported driver. Each store owns its
// own *gorm.DB and a GORM model whose ToX/XToModel helpers bridge to the
// transport-agnostic core/keys/admin types; AutoMigrate creates all ten tables
// in one call and MUST run before any store is used. Slice and map fields are
// JSON-encoded into single columns (via JSONMap, StringSlice,
// AuthorizationDetailsJSON, or the gorm serializer tag) to stay portable across
// SQLite, MySQL, and Postgres without DB-specific JSONB handling. Error and
// not-found semantics deliberately match the in-memory reference stores so the
// shared contract test suites pass uniformly across backends.
//
// # ENTITIES
//
// AutoMigrate — runs db.AutoMigrate for all ten oneauth models in one call;
// the single migration entrypoint callers invoke before use.
//
// JSONMap — map[string]any with driver Valuer/Scanner that JSON-encodes into
// one column; Scan silently no-ops on non-[]byte input.
//
// StringSlice — []string with Valuer/Scanner; avoids a join table for scope
// lists.
//
// AuthorizationDetailsJSON — []core.AuthorizationDetail Valuer/Scanner storing
// RFC 9396 details inline as jsonb.
//
// UserModel — users table model (ID, IsActive, Profile, Version); Profile is a
// JSONMap.
//
// IdentityModel — identities model with a (Type, Value) composite primary key;
// ToIdentity/IdentityToModel bridge to core.Identity.
//
// ChannelModel — auth-channel model keyed by (Provider, IdentityKey) with
// JSONMap Credentials/Profile and an ExpiresAt.
//
// AuthTokenModel — verification/reset token model keyed by the raw Token (these
// are short-lived single-use tokens, unlike refresh tokens).
//
// RefreshTokenModel — refresh-token model keyed by SHA-256 TokenHash; the raw
// Token field is gorm-ignored and lives in memory only.
//
// APIKeyModel — API-key model keyed by KeyID storing a bcrypt KeyHash; the
// secret is never persisted.
//
// UsernameModel — NormalizedUsername (lowercase PK) to UserID mapping with a
// Version column for optimistic concurrency.
//
// GORMUser — core.User adapter over a *UserModel exposing Id()/Profile().
//
// UserStore — core.UserStore impl (CreateUser, GetUserById, SaveUser).
//
// IdentityStore — core.IdentityStore impl with optional get-or-create (inserts
// a placeholder empty-UserID row), verify, and user-reassign.
//
// ChannelStore — core.ChannelStore impl with get-or-create by
// (provider, identityKey), initializing empty JSONMaps on creation.
//
// TokenStore — core.TokenStore impl; GetToken lazily deletes expired rows.
//
// RefreshTokenStore — core.RefreshTokenStore impl with SHA-256 hashing,
// transactional rotation with reuse detection, and family/user revoke.
//
// APIKeyStore — core.APIKeyStore impl issuing oa_<keyid>_<secret> keys,
// validating via bcrypt and never returning the hash.
//
// UsernameStore — core.UsernameStore impl using WHERE version=? guards and
// RowsAffected==0 checks for optimistic-concurrency reserve/change/release.
//
// SigningKeyModel — per-client signing-key model keyed by ClientID with a
// unique Kid index.
//
// KeyStore — keys.KeyStorage impl (PutKey, GetKey, GetKeyByKid, ListKeyIDs)
// plus backward-compatible aliases that delegate to the canonical methods.
//
// KidKeyModel — kid->key grace-entry model keyed by Kid with a nullable
// ExpiresAt (nil means never expires).
//
// KidStore — keys.KidStorage impl (Add upsert, Remove, GetKeyByKid,
// CleanExpired); GetKey always returns ErrKeyNotFound since it is kid-indexed.
//
// AppRegistrationModel — app/client registration model carrying RFC 7591/7592
// metadata and RFC 9396 detail types, with slice fields serialized as JSON.
//
// AppStore — admin.AppRegistrationStore impl (SaveApp, GetApp, ListApps,
// DeleteApp) whose error semantics mirror InMemoryAppStore.
//
// # FLOWS
//
// See diagrams.md for the transactional refresh-token rotation flow and the
// cross-record username-change optimistic-concurrency flow.
// <!-- design:end -->
//
// It supports any database that GORM supports (PostgreSQL, MySQL, SQLite, etc.)
// and is suitable for production deployments requiring relational database storage.
//
// # Database Schema
//
// The package auto-migrates the following tables:
//   - users: User accounts
//   - identities: Email/phone identities linked to users
//   - channels: Authentication channels (local, google, github, etc.)
//   - auth_tokens: Verification and password reset tokens
//   - refresh_tokens: Long-lived refresh tokens for API access
//   - api_keys: Long-lived API keys for programmatic access
//
// # Usage
//
//	db, _ := gorm.Open(postgres.Open(dsn), &gorm.Config{})
//	userStore := gormstore.NewUserStore(db)
//	refreshTokenStore := gormstore.NewRefreshTokenStore(db)
//	apiKeyStore := gormstore.NewAPIKeyStore(db)
package gorm
