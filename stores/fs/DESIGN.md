---
package: fs
purpose: Filesystem-backed (one-JSON-file-per-record) implementations of OneAuth's core store interfaces, intended for single-process dev/test deployments.
last_rebuilt: ca8a742623b748f06d2564dce90465d1eeb10c6d
entities:
  - name: safeName
    kind: function
    role: Sanitizes user-supplied identifiers before they become path components.
    why: Single chokepoint for path-traversal defense — every store routes filenames through it, so the guard against "..", null bytes, absolute paths, and separator chars lives in exactly one place.
  - name: writeAtomicFile
    kind: function
    role: Writes data via temp-file-then-rename, chmod 0600.
    why: Rename is atomic on POSIX, so a crash mid-write leaves either the old or new file intact, never a half-written one; centralizes the durability/permission contract for all stores.
  - name: FSKeyStore
    kind: struct
    role: keys.KeyStorage backed by one file per clientID under signing_keys/.
    why: GetKeyBykid/ListKeyIDs scan the whole dir because the layout is clientID-indexed only — no secondary kid index, accepted as fine for the small key counts a dev store holds.
  - name: fsKeyEntry
    kind: struct
    role: On-disk JSON shape for a signing key (clientID, key bytes, alg, kid).
    why: Decouples the persisted format from keys.KeyRecord so the wire/struct type can evolve without rewriting files; kid is omitempty for back-compat with pre-rotation records.
  - name: FSKidStore
    kind: struct
    role: keys.KidStorage backed by one file per kid under kid_keys/, carrying a grace-period expiry.
    why: Separate from FSKeyStore because rotation needs kid-indexed lookup with TTL semantics; GetKey(clientID) deliberately returns ErrKeyNotFound to match the in-memory KidStore (it is not a clientID lookup).
  - name: fsKidEntry
    kind: struct
    role: On-disk JSON for a retired/grace key, keyed by kid with an ExpiresAt.
    why: Zero-value ExpiresAt means "never expires" — mirrors keys.kidRecord.isExpired so FS and in-memory backends agree on the never-expiry sentinel.
  - name: isExpired
    kind: function
    role: Reports whether a grace expiry has passed, treating zero time as never.
    why: Intentionally duplicates the in-memory store's rule so expired-kid filtering is identical across backends.
  - name: FSUserStore / FSUser
    kind: struct
    role: core.UserStore persisting users as JSON under users/; FSUser is the core.User impl.
    why: SaveUser tolerates foreign core.User impls by reconstructing an FSUser and best-effort recovering created_at from the profile map — avoids hard-coupling to its own concrete type.
  - name: FSAppStore
    kind: struct
    role: admin.AppRegistrationStore persisting each registration as apps/{client_id}.json.
    why: File-per-record so concurrent ops don't serialize on one mutex; explicitly a single-process store — multi-process needs real transactions (GORMAppStore, #167).
  - name: FSAPIKeyStore
    kind: struct
    role: core API key store; creates, bcrypt-hashes, validates, revokes keys under api_keys/.
    why: Full key (keyID_secret) is returned only at creation; only the bcrypt hash is persisted, and listings null out KeyHash so secrets never leak through admin paths.
  - name: FSRefreshTokenStore
    kind: struct
    role: core refresh-token store with rotation, family revocation, and theft detection.
    why: Filenames are SHA-256 of the token (not the token itself) so the raw secret never appears on disk; rotating an already-revoked token returns ErrTokenReused to flag a reuse attack.
  - name: FSTokenStore
    kind: struct
    role: core store for short-lived verification/reset tokens under tokens/.
    why: GetToken self-heals by auto-deleting an expired token on read, so expired entries don't accumulate without a separate sweeper.
  - name: FSChannelStore
    kind: struct
    role: core.Channel store keyed by provider+identityKey under channels/.
    why: GetChannel has a create-if-missing path and SaveChannel auto-bumps Version, baking optimistic-versioning bookkeeping into the persistence layer.
  - name: FSIdentityStore
    kind: struct
    role: core.Identity store keyed by type+value under identities/.
    why: Uses core.IdentityKey + filepath.Base for filenames rather than safeName — the only store not on the shared guard, relying on IdentityKey's own shape plus Base() to block traversal.
  - name: FSUsernameStore / FSUsername
    kind: struct
    role: username-uniqueness + login-lookup store, filenamed by normalized (lowercase) username.
    why: Normalized lowercase filename enforces case-insensitive uniqueness via the filesystem itself; ChangeUsername is not cross-file atomic and best-effort restores the old name on failure — flagged as last-write-wins, use a DB store under contention.
depends_on:
  - folder: core
    entities: [APIKey, AuthToken, Channel, ErrAPIKeyNotFound, ErrTokenExpired, ErrTokenNotFound, ErrTokenReused, ErrTokenRevoked, GenerateAPIKeyID, GenerateAPIKeySecret, GenerateSecureToken, Identity, IdentityKey, RefreshToken, TokenExpiryRefreshToken, TokenType, User]
  - folder: keys
    entities: [ErrAlgorithmMismatch, ErrKeyNotFound, ErrKidNotFound, KeyRecord, KeyStorage, KidStorage]
  - folder: admin
    entities: [AppRegistration, AppRegistrationStore, ErrAppNotFound]
  - folder: utils
    entities: [ComputeKid]
---

These files are the filesystem reference backend for OneAuth's storage-agnostic store
interfaces (`keys.KeyStorage`, `keys.KidStorage`, `core.UserStore`/`APIKey`/`RefreshToken`/
`AuthToken`/`Channel`/`Identity` stores, `admin.AppRegistrationStore`, and the username
store). Every store follows the same shape: one JSON file per record under a typed
subdirectory of `StoragePath`, atomic writes through `writeAtomicFile`, and path-traversal
defense through `safeName` (with `FSIdentityStore` the lone exception, using
`core.IdentityKey` + `filepath.Base`).

The unifying design stance is **single-process, file-per-record**: in-process concurrency
is mediated by `sync.RWMutex` where present, and cross-process or high-contention safety is
explicitly out of scope — the godoc repeatedly points at GORM/database backends for that.
List/scan operations (`ListApps`, `ListKeyIDs`, `GetKeyByKid`, `GetUserTokens`, etc.) walk
the whole directory and skip unparseable files rather than failing, trading strict integrity
for partial-recovery resilience; `FSAppStore.GetApp` is the deliberate counter-example,
surfacing a corrupt-file parse error instead of masking it as "not found". Secret-bearing
stores never persist raw secrets: API keys store only bcrypt hashes and refresh tokens are
filed under their SHA-256 hash.
