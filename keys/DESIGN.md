---
package: keys
purpose: JWT signing-key management — storage interfaces, in-memory and encrypted backends, kid-indexed grace-period retention for rotation, and JWKS endpoint serving/fetching.
last_rebuilt: ca8a742623b748f06d2564dce90465d1eeb10c6d
entities:
  - name: KeyRecord
    kind: struct
    role: The single value type all key operations exchange (ClientID, Key, Algorithm, Kid).
    why: Deliberately collapses what used to be separate field accessors into one record so decorators/backends implement ~5 methods instead of forwarding many getters.
  - name: KeyLookup
    kind: interface
    role: Read-only key lookup by clientID (GetKey) or kid (GetKeyByKid).
    why: The minimal contract every store satisfies, including read-only ones like JWKSKeyStore — kept separate from write ops so read-only backends aren't forced to stub writes.
  - name: KeyStorage
    kind: interface
    role: KeyLookup plus write ops (PutKey, DeleteKey, ListKeyIDs); implemented by persistent clientID-keyed backends.
    why: Splitting writes from KeyLookup is the decomposition that lets EncryptedKeyStorage wrap and JWKSKeyStore opt out cleanly.
  - name: KidStorage
    kind: interface
    role: KeyLookup plus kid-keyed grace-period ops (Add/Remove/CleanExpired) for retired keys.
    why: Exists so retired keys survive process restarts via stores/ backends; keyed by kid not clientID, so GetKey(clientID) is always ErrKeyNotFound by design.
  - name: InMemoryKeyStore
    kind: struct
    role: Thread-safe in-memory KeyStorage for tests and single-process use, with a kid→clientID secondary index.
    why: Maintains kidIndex alongside the primary map so GetKeyByKid is O(1); index entries must be deleted in lockstep on Put/Delete or stale kids would resolve.
  - name: EncryptedKeyStorage
    kind: struct
    role: KeyStorage decorator encrypting HMAC secrets at rest with AES-256-GCM; asymmetric keys pass through.
    why: Computes kid from plaintext BEFORE encryption so kid lookups still work on encrypted bytes; decrypt failure falls back to returning plaintext to allow zero-downtime migration of pre-encryption data.
  - name: NewEncryptedKeyStorage
    kind: function
    role: Constructs the decorator, deriving the AEAD key from a 64-hex-char master key via HKDF-SHA256.
    why: HKDF with a fixed info string ("oneauth-keystore-encryption-v1") domain-separates the derived key; the 64-hex (32-byte) length check fails loudly rather than silently truncating.
  - name: KidStore
    kind: struct
    role: In-memory KidStorage holding kid→key mappings including grace-period entries during rotation.
    why: Lets the old key keep validating tokens until its ExpiresAt while PutKey installs the new current key; zero ExpiresAt means never-expires.
  - name: CompositeKeyLookup
    kind: struct
    role: Chains multiple KeyLookups, returning the first hit.
    why: The seam that unions a KeyStorage's current key with a KidStore's grace-period keys without either knowing about the other.
  - name: JWKSHandler
    kind: struct
    role: HTTP handler serving /.well-known/jwks.json from a KeyStorage (plus optional KidStore for grace-period keys).
    why: Only asymmetric keys are emitted — HS256 secrets are never exposed (that would leak the symmetric signing secret); adds ETag/If-None-Match + Cache-Control for cheap conditional refresh.
  - name: JWKSKeyStore
    kind: struct
    role: Read-only KeyLookup that fetches/caches public keys from a remote JWKS URL with background refresh.
    why: GetSigningKey always errors and GetKey(clientID) returns ErrKeyNotFound — JWKS carries no client_id mapping, so only kid lookup is meaningful; MinRefreshGap prevents refresh stampede on cache misses.
  - name: JWKSOption
    kind: type
    role: Functional option (WithHTTPClient / WithRefreshInterval / WithMinRefreshGap) for JWKSKeyStore.
    why: Keeps the constructor stable while letting callers tune client, refresh cadence, and stampede guard.
depends_on:
  - folder: utils
    entities: [ComputeKid, DecodeVerifyKey, IsAsymmetricAlg, JWK, JWKSet, JWKToPublicKey, PublicKeyToJWK]
---

The `keys` package is the JWT signing-key layer. Its central abstraction is `KeyRecord`, a flat value type that every operation passes around, so decorators and backends implement a handful of record-oriented methods rather than a sprawl of per-field accessors. The interface trio is split by concern: `KeyLookup` (read-only, satisfied by everything), `KeyStorage` (clientID-keyed read+write, for persistent backends), and `KidStorage` (kid-keyed grace-period retention).

**Key storage.** `InMemoryKeyStore` is the reference `KeyStorage` for tests and single-process deployments. It keeps a `kidIndex` (kid→clientID) so kid lookups stay O(1); the index must be kept in lockstep with the primary map on every Put/Delete or stale kids would resolve to wrong keys. The numerous `RegisterKey`/`GetVerifyKey`/`GetSigningKey`/`GetExpectedAlg`/`ListKeys`/`GetCurrentKid` methods on both `InMemoryKeyStore` and `EncryptedKeyStorage` are backward-compat shims over the new record API, kept during the migration off the old `KeyStore`/`WritableKeyStore` interfaces.

**EncryptedKeyStorage.** A decorator that encrypts only HMAC (HS256/384/512) secrets at rest with AES-256-GCM; asymmetric public keys pass through untouched. Two non-obvious behaviors: (1) the kid is computed from *plaintext* key material before encryption, so kid-based lookups work even though the stored bytes are ciphertext; (2) decryption failure logs and returns the bytes as plaintext, a deliberate fallback so a store containing pre-encryption rows can be read during migration. The master key is run through HKDF-SHA256 (with a fixed info string for domain separation) to derive the AEAD key, and the constructor rejects anything other than 64 hex chars.

**KidStore (rotation/grace period).** `KidStore` is an in-memory `KidStorage` keyed by kid. During rotation you `Add` the outgoing key with an `ExpiresAt` grace window, then `PutKey` the new current key into the `KeyStorage`; the old key keeps validating tokens until it expires. Zero `ExpiresAt` means no expiry. `CompositeKeyLookup` chains a `KeyStorage` (current keys) with a `KidStore` (grace-period keys) so validation can resolve either. Persistent `KidStorage` backends live in `stores/{fs,gorm,gae}`, outside this package.

**JWKS.** `JWKSHandler` serves the public key set, optionally merging grace-period asymmetric keys directly from a `KidStore`'s internal records. Gotcha: **JWKS only ever exposes asymmetric keys — HS256 secrets are correctly omitted**, since publishing a symmetric signing secret would hand out the ability to forge tokens. It marshals once, derives an ETag from the body's SHA-256, and honors `If-None-Match`. `JWKSKeyStore` is the consumer side: a read-only store that fetches a remote JWKS and refreshes in the background. It only supports kid lookup (`GetKey` by clientID returns `ErrKeyNotFound`, `GetSigningKey` always errors) because JWKS carries no client_id→key mapping, and a returned `KeyRecord` has an empty `ClientID` so callers can skip cross-app checks. `MinRefreshGap` guards against refresh stampedes when many lookups miss the cache at once.
