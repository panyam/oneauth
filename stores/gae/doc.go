//go:build !wasm
// +build !wasm

// Package gae supplies Google Cloud Datastore-backed implementations of
// oneauth's KeyStorage and KidStorage (keys/) plus the core user,
// identity, channel, auth-token, refresh-token, API-key, and username
// store interfaces, with all kinds isolated per tenant via Datastore
// namespaces.
//
// Each store holds a *datastore.Client, a namespace, and a context; the
// ctx lives on the struct (a pre-issue-110/175 pattern) and WithContext
// returns a copy to override it per call. The package owns the
// Datastore entity shapes and the marshalling between them and core
// types; it does not own the auth logic or the interfaces themselves.
// Notable: large blobs (profiles, credentials, scopes, key bytes) are
// stored as noindex JSON, refresh tokens and API key secrets are
// persisted only as hashes, and reservation/rotation operations run
// inside Datastore transactions for atomicity.
//
// ENTITIES
//
// GAEKeyStore — keys.KeyStorage over Datastore for per-client signing
// keys. Keyed by ClientID with kid indexed so GetKeyByKid can
// reverse-lookup.
//
// NewKeyStore — constructs a GAEKeyStore for a namespace with a
// background ctx. ctx lives on the struct (pre-issue-110/175 pattern);
// use WithContext to scope per call.
//
// SigningKeyEntity — Datastore entity for a per-client signing key.
// KeyBytes is noindex; kid is indexed to support reverse-lookup
// queries.
//
// GAEKidStore — keys.KidStorage over Datastore for kid→key grace
// entries. Keyed by the kid itself, so GetKey (client-indexed) always
// returns ErrKeyNotFound here.
//
// NewKidStore — constructs a GAEKidStore for a namespace with a
// background ctx. A var _ assertion guarantees keys.KidStorage
// conformance at build time.
//
// KidKeyEntity — Datastore entity for a kid grace entry. ExpiresAt is
// noindex; CleanExpired scans and filters in Go because Datastore
// can't combine not-zero and less-than filters, which is fine for
// small kid stores.
//
// UserStore — core.UserStore over Datastore for user accounts with
// JSON profile blobs. SaveUser reads-before-writes to preserve
// CreatedAt across updates.
//
// GAEUser — core.User implementation carrying ID, active flag, and
// profile map. SaveUser type-asserts to *GAEUser to recover the active
// flag; defaults to active=true otherwise.
//
// IdentityStore — core.IdentityStore; identities keyed by
// "type:value". SetUserForIdentity and MarkIdentityVerified bump
// Version atomically inside a transaction.
//
// ChannelStore — core.ChannelStore; auth channels keyed by
// "provider:identityKey". SaveChannel preserves CreatedAt and
// monotonically increments Version.
//
// TokenStore — core.TokenStore; verification/reset tokens keyed by
// the token string. GetToken self-deletes expired tokens before
// erroring.
//
// RefreshTokenStore — core.RefreshTokenStore; refresh tokens keyed by
// SHA-256 hash. Supports rotation, family revocation on reuse, and
// cleanup; raw tokens never land in Datastore.
//
// APIKeyStore — core.APIKeyStore; bcrypt-hashed API keys keyed by
// KeyID. ValidateAPIKey parses the "oa_keyid_secret" format; hashes
// are stripped from listings.
//
// UsernameStore — core.UsernameStore; case-insensitive
// username->userID reservations. Lowercased keys with txn-guarded
// uniqueness; ChangeUsername atomically swaps old and new entries.
//
// UserEntity — Datastore entity for a user; profile stored as noindex
// JSON. Mirrors core.User with versioning and timestamps for
// Datastore persistence.
//
// IdentityEntity — Datastore entity for an identity (type:value ->
// userID). ToIdentity and IdentityToEntity bridge to core.Identity.
//
// ChannelEntity — Datastore entity for an auth channel
// (provider:identityKey). Credentials and profile stored as noindex
// JSON; tracks expiry and version.
//
// AuthTokenEntity — Datastore entity for verification/reset tokens.
// Key name is the token itself; ToAuthToken/AuthTokenToEntity bridge
// to core.AuthToken.
//
// RefreshTokenEntity — Datastore entity for a refresh token keyed by
// hash. Carries family, generation, scopes, authorization_details,
// and revocation metadata.
//
// APIKeyEntity — Datastore entity for an API key keyed by KeyID.
// Stores bcrypt hash plus scopes (JSON noindex) and optional expiry
// flagged by HasExpiry.
//
// UsernameEntity — Datastore entity mapping lowercased username ->
// userID. Original-case username preserved alongside the normalized
// key.
//
// KindSigningKey — Datastore kind name for signing keys. Shared
// between entity definitions and query construction.
//
// KindKidKey — Datastore kind name for kid grace entries. Shared
// between entity definitions and query construction.
//
// KindUser — Datastore kind name for users. One of seven core kind
// constants declared in stores.go.
//
// KindIdentity — Datastore kind name for identities. One of seven
// core kind constants.
//
// KindChannel — Datastore kind name for channels. One of seven core
// kind constants.
//
// KindAuthToken — Datastore kind name for auth tokens. One of seven
// core kind constants.
//
// KindRefreshToken — Datastore kind name for refresh tokens. One of
// seven core kind constants.
//
// KindAPIKey — Datastore kind name for API keys. One of seven core
// kind constants.
//
// KindUsername — Datastore kind name for username reservations. One
// of seven core kind constants.
//
// FLOWS
//
// See [diagrams.md](diagrams.md) for sequence diagrams of:
// refresh-token rotation with reuse detection.
package gae
