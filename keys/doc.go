// Package keys owns signing-key storage, lookup, encryption-at-rest,
// kid-based rotation with grace periods, and JWKS publication/consumption
// for OneAuth.
//
// <!-- design:start -->
// The keys package centralizes everything about JWT signing-key material:
// where keys live, how they are looked up (by clientID or by kid), how HMAC
// secrets are encrypted at rest, how rotated keys are kept alive during a
// grace period, and how public keys are published and consumed over JWKS. It
// deliberately keeps two contracts separate — KeyLookup (read-only) and the
// write extensions KeyStorage and KidStorage — so read-only sources such as a
// remote JWKS endpoint can plug in without implementing write methods, and so
// decorators operate on one KeyRecord value instead of forwarding many
// per-field accessors. Concrete persistent backends (FS, GORM, GAE) live in
// stores/ and implement these interfaces; this package ships the in-memory
// implementations and the cross-cutting decorators.
//
// # ENTITIES
//
// KeyRecord — single value type carrying ClientID, Key, Algorithm, and Kid for
// every key operation, replacing scattered per-field accessors.
//
// KeyLookup — read-only interface: GetKey(clientID) and GetKeyByKid(kid).
//
// KeyStorage — KeyLookup plus PutKey/DeleteKey/ListKeyIDs; the clientID-keyed
// write contract for persistent backends and the encryption decorator.
//
// KidStorage — KeyLookup plus Add/Remove/CleanExpired; keyed by kid, so
// GetKey(clientID) always returns ErrKeyNotFound. Lets retired keys persist
// across restarts in backends rather than only in process memory.
//
// InMemoryKeyStore — thread-safe in-memory KeyStorage maintaining a
// kid->clientID secondary index so GetKeyByKid stays O(1) and consistent on
// overwrite and delete.
//
// EncryptedKeyStorage — KeyStorage decorator that AES-256-GCM encrypts HMAC
// (HS256/384/512) secrets at rest while asymmetric keys pass through. It
// computes the kid from plaintext before encryption so kid lookups still work,
// and falls back to returning ciphertext-as-plaintext when decryption fails to
// tolerate pre-encryption data during migration.
//
// NewEncryptedKeyStorage — builds the decorator from a 64-hex-char (32-byte)
// master key, deriving the AES key via HKDF-SHA256 with a fixed info string.
//
// JWKSHandler — HTTP handler serving /.well-known/jwks.json from a KeyStore
// plus an optional KidStore for grace-period keys. Publishes only asymmetric
// keys (HS256 secrets are never exposed) and supports ETag / If-None-Match /
// Cache-Control conditional caching.
//
// JWKSKeyStore — read-only KeyLookup that fetches and caches public keys from a
// remote JWKS URL with background refresh. Cache misses trigger an on-demand
// refresh (rate-limited by MinRefreshGap) before returning ErrKeyNotFound;
// GetSigningKey always errors since only public keys are available.
//
// NewJWKSKeyStore — constructs a JWKSKeyStore with functional options
// (WithHTTPClient, WithRefreshInterval, WithMinRefreshGap); Start() performs
// the initial fetch and launches background refresh. Defaults: RefreshInterval
// 1h, MinRefreshGap 5s.
//
// KidStore — in-memory KidStorage holding kid->key mappings including
// time-expiring grace-period entries, so a rotated-out key keeps validating
// tokens until its grace period lapses.
//
// CompositeKeyLookup — tries multiple KeyLookups in order and returns the first
// hit, combining a KeyStorage's current key with a KidStore's grace entries
// behind one lookup.
//
// # FLOWS
//
// See [diagrams.md](diagrams.md) for sequence diagrams of: key rotation with a
// grace-period KidStore, and JWKS publication merging current keys with
// grace-period keys.
// <!-- design:end -->
package keys
