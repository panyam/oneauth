// Package keys owns signing-key storage, kid-based lookup, encryption
// at rest, grace-period rotation, and JWKS publication and consumption
// for OneAuth.
//
// The package centralizes every concern about JWT signing-key material:
// where keys live, how they are looked up by clientID or by kid, how
// HMAC secrets are encrypted on disk, how rotated keys keep validating
// already-issued tokens during a grace period, and how public keys are
// served and consumed over JWKS. It deliberately splits two contracts —
// the read-only KeyLookup and the write extensions KeyStorage and
// KidStorage — so a remote JWKS endpoint can plug in without write
// methods and so decorators operate on one KeyRecord value rather than
// forwarding many per-field accessors. Concrete persistent backends
// (FS, GORM, GAE) live under stores/ and implement these interfaces;
// this package ships the in-memory implementations and the
// cross-cutting decorators.
//
// ENTITIES
//
// KeyRecord — single value type carrying ClientID, Key, Algorithm, and
// Kid. Replaces scattered per-field accessors so decorators forward one
// value, not many getters.
//
// KeyLookup — read-only contract with GetKey(clientID) and
// GetKeyByKid(kid). Lets read-only sources like a remote JWKS plug in
// without implementing writes.
//
// KeyStorage — KeyLookup plus PutKey, DeleteKey, and ListKeyIDs.
// ClientID-keyed write contract for persistent backends and the
// encryption decorator.
//
// KidStorage — KeyLookup plus Add, Remove, and CleanExpired, keyed by
// kid. Lets retired grace-period keys persist across restarts in
// backends, not just process memory.
//
// InMemoryKeyStore — thread-safe in-memory KeyStorage with a kid to
// clientID secondary index. Keeps GetKeyByKid O(1) and consistent
// across overwrite and delete; default for tests and small deployments.
//
// NewInMemoryKeyStore — constructor for an empty InMemoryKeyStore.
// Standard entry point for callers wiring an in-memory keystore.
//
// EncryptedKeyStorage — KeyStorage decorator that AES-256-GCM encrypts
// HMAC secrets at rest while asymmetric keys pass through. Computes kid
// from plaintext before encryption so kid lookups still work; falls
// back to plaintext when decryption fails for pre-encryption migration.
//
// NewEncryptedKeyStorage — builds the decorator from a 64-hex-character
// master key. Derives the AES key via HKDF-SHA256 with a fixed info
// string so the on-disk key is never the master key directly.
//
// JWKSHandler — HTTP handler serving /.well-known/jwks.json from a
// KeyStore plus an optional KidStore. Publishes only asymmetric keys
// (HMAC secrets never leak) and supports ETag, If-None-Match, and
// Cache-Control conditional caching.
//
// JWKSKeyStore — read-only KeyLookup that fetches and caches public
// keys from a remote JWKS URL with background refresh. Cache misses
// trigger an on-demand refresh rate-limited by MinRefreshGap;
// GetSigningKey always errors since only public keys are available.
//
// NewJWKSKeyStore — constructor accepting functional options for the
// JWKS client. Defaults RefreshInterval to 1h and MinRefreshGap to 5s;
// Start performs the initial fetch and launches the refresher.
//
// JWKSOption — functional option for JWKSKeyStore configuration.
// WithHTTPClient, WithRefreshInterval, and WithMinRefreshGap follow the
// standard functional-options pattern.
//
// KidStore — in-memory KidStorage holding kid to key mappings including
// time-expiring grace entries. A rotated-out key keeps validating
// tokens until its grace period lapses, then CleanExpired drops it.
//
// NewKidStore — constructor for an empty KidStore. Standard entry point
// when grace-period rotation is wired in process memory.
//
// CompositeKeyLookup — tries multiple KeyLookups in order and returns
// the first hit. Combines a KeyStorage's current key with a KidStore's
// grace entries behind one read-side interface.
//
// ErrKeyNotFound — sentinel error for a missing clientID lookup. Stable
// signal for callers and middleware that must branch on absence rather
// than format errors.
//
// ErrAlgorithmMismatch — sentinel error when a key's algorithm does not
// match the expected JWT alg. Lets validation reject token-alg
// substitution attacks distinctly from key-missing errors.
//
// ErrKidNotFound — sentinel error for an unknown or expired kid.
// Distinguishes grace-period expiry from a genuinely missing client
// registration.
//
// FLOWS
//
// See [diagrams.md](diagrams.md) for sequence diagrams of: key rotation
// with a grace-period KidStore, and JWKS publication merging current
// keys with grace-period keys.
package keys
