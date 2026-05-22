//go:build !wasm
// +build !wasm

// Package gae provides Google Cloud Datastore implementations of oneauth store interfaces.
//
// <!-- design:start -->
// Package gae supplies Google Cloud Datastore-backed implementations of
// oneauth's KeyStorage and KidStorage (keys/) plus the core user, identity,
// channel, auth-token, refresh-token, API-key, and username store
// interfaces, with all kinds isolated per tenant via Datastore namespaces.
// Each store holds a *datastore.Client, a namespace, and a context; the ctx
// lives on the struct (a pre-issue-110/175 pattern) and WithContext returns a
// copy to override it per call. The package owns Datastore entity shapes and
// the marshalling between them and core types; it does not own the auth logic
// or the interfaces themselves. Notable: large blobs (profiles, credentials,
// scopes, key bytes) are stored as noindex JSON, refresh tokens and API key
// secrets are persisted only as hashes, and reservation/rotation operations
// run inside Datastore transactions for atomicity.
//
// # ENTITIES
//
// GAEKeyStore — keys.KeyStorage over Datastore; per-client signing keys keyed
// by ClientID, with kid indexed so GetKeyByKid can reverse-lookup.
//
// NewKeyStore — constructs a GAEKeyStore for a namespace with a background ctx.
//
// SigningKeyEntity — Datastore entity for a signing key; KeyBytes noindex, kid
// indexed.
//
// GAEKidStore — keys.KidStorage over Datastore; kid grace entries keyed by the
// kid itself, so GetKey (client-indexed) always returns ErrKeyNotFound.
//
// NewKidStore — constructs a GAEKidStore; compile-time asserts KidStorage.
//
// KidKeyEntity — Datastore entity for a kid grace entry; ExpiresAt noindex
// because CleanExpired scans and filters in Go (Datastore can't combine
// not-zero and less-than filters), which is fine for small kid stores.
//
// UserStore — core.UserStore; user accounts with JSON profile blobs. SaveUser
// reads-before-writes to preserve CreatedAt.
//
// GAEUser — core.User impl; SaveUser type-asserts to recover the active flag,
// else defaults active=true.
//
// IdentityStore — core.IdentityStore; identities keyed by "type:value".
// SetUserForIdentity and MarkIdentityVerified bump Version atomically in a txn.
//
// ChannelStore — core.ChannelStore; channels keyed by "provider:identityKey".
// SaveChannel preserves CreatedAt and monotonically increments Version.
//
// TokenStore — core.TokenStore; verification/reset tokens keyed by the token
// string. GetToken self-deletes expired tokens before erroring.
//
// RefreshTokenStore — core.RefreshTokenStore; tokens keyed by SHA-256 hash
// (never the raw value), with rotation, family revocation, and cleanup.
//
// APIKeyStore — core.APIKeyStore; bcrypt-hashed keys keyed by KeyID.
// ValidateAPIKey parses the "oa_keyid_secret" format; hashes are stripped from
// listings.
//
// UsernameStore — core.UsernameStore; case-insensitive username->userID
// reservations keyed by lowercased username, with txn-guarded uniqueness.
//
// # FLOWS
//
// See diagrams.md for the refresh-token rotation and reuse-detection flow.
// <!-- design:end -->
//
// It is designed for deployment on Google Cloud Platform and supports multi-tenancy
// through Datastore namespaces.
//
// # Datastore Kinds
//
// The package uses the following Datastore kinds:
//   - User: User accounts with profile data
//   - Identity: Email/phone identities linked to users
//   - Channel: Authentication channels (local, google, github, etc.)
//   - AuthToken: Verification and password reset tokens
//   - RefreshToken: Long-lived refresh tokens for API access
//   - APIKey: Long-lived API keys for programmatic access
//
// # Namespacing
//
// All stores support Datastore namespaces for multi-tenant applications.
// Pass a namespace when creating stores to isolate data between tenants:
//
//	userStore := gae.NewUserStore(client, "tenant-123")
//	tokenStore := gae.NewRefreshTokenStore(client, "tenant-123")
//
// # Usage
//
//	client, _ := datastore.NewClient(ctx, projectID)
//	userStore := gae.NewUserStore(client, "")  // default namespace
//	refreshTokenStore := gae.NewRefreshTokenStore(client, "")
//	apiKeyStore := gae.NewAPIKeyStore(client, "")
package gae
