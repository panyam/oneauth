// Package fs provides filesystem-backed (one JSON file per record)
// implementations of OneAuth's key, kid, app, user, username, identity,
// channel, token, refresh-token, and API-key stores for single-process
// dev and small deployments.
//
// Every store in this package shares one shape. Each record is a JSON
// file under {StoragePath}/{kind}/, written atomically via
// writeAtomicFile (temp file in the same directory, os.Rename, chmod
// 0600) so a crash mid-write leaves either the old or the new file but
// never a half-written one. User-supplied identifiers go through
// safeName before becoming path components — it rejects empty names,
// null bytes, absolute paths and embedded "..", and folds /, \, : into
// underscores; it is the single point of defense against path traversal
// for the whole package. Directories are created lazily on first write,
// and reverse-lookup or list operations scan the relevant directory and
// skip unreadable or corrupt files rather than failing the whole call.
// Backends that need real cross-process transactions should use a
// database-backed store (e.g. GORM); the FS stores assume a single
// writer process and mediate in-process concurrency with sync.RWMutex
// (or, for the older user/identity/channel/token stores, atomic writes
// alone).
//
// ENTITIES
//
// safeName — single point of defense sanitizing user-supplied
// identifiers before use in filesystem paths. Rejects empty/null-byte/
// absolute/.. inputs and folds /, \, : into underscores so callers
// cannot escape the storage directory.
//
// writeAtomicFile — writes data atomically via tempfile in the same
// directory, os.Rename, then chmod 0600. A crash mid-write leaves
// either the old or the new file, never a half-written one.
//
// FSKeyStore — keys.KeyStorage impl with one signing-key JSON file per
// clientID under signing_keys/. Keys must be []byte (else
// ErrAlgorithmMismatch); GetKeyByKid scans all files because the
// layout is clientID-indexed. Also exposes backward-compatible
// aliases (RegisterKey, GetVerifyKey, GetSigningKey, GetExpectedAlg,
// ListKeys, GetCurrentKid).
//
// NewFSKeyStore — constructor for FSKeyStore. The signing_keys/
// directory is created lazily on first PutKey, not at construction.
//
// fsKeyEntry — on-disk JSON shape for a signing key (ClientID, Key,
// Algorithm, Kid). Decouples the persisted layout from the
// keys.KeyRecord domain type.
//
// FSKidStore — keys.KidStorage impl with one kid-indexed JSON file
// per kid under kid_keys/. Each entry carries a grace-period
// ExpiresAt (zero = never); expired entries are filtered on read and
// purged by CleanExpired. Remove is idempotent.
//
// NewFSKidStore — constructor for FSKidStore. GetKey(clientID) on a
// KidStorage always returns ErrKeyNotFound by design, matching the
// in-memory KidStore.
//
// fsKidEntry — on-disk JSON shape for a kid->key grace entry with
// ExpiresAt. Mirrors fsKeyEntry but keyed by kid and carries the
// rotation grace-period TTL.
//
// isExpired — helper matching keys.kidRecord.isExpired; zero time
// means never expires. Centralizes the grace-period predicate so
// on-read filtering and CleanExpired agree.
//
// FSAppStore — admin.AppRegistrationStore impl with one
// AppRegistration JSON file per client_id under apps/. GetApp
// distinguishes a corrupt file (parse error) from an absent
// registration (ErrAppNotFound); ListApps silently skips corrupt
// files so one hand-corrupted file cannot lock out admin tooling.
//
// NewFSAppStore — constructor for FSAppStore. Single-process only;
// multi-process deployments need a backend with real transaction
// semantics (e.g. GORMAppStore).
//
// FSUserStore — core.UserStore impl with one user JSON file per
// userId under users/. SaveUser converts foreign core.User
// implementations into FSUser, best-effort preserving created_at
// from the profile map.
//
// NewFSUserStore — constructor for FSUserStore. No mutex; relies on
// writeAtomicFile plus the single-process assumption.
//
// FSUser — persisted user record (UserId, IsActive, UserProfile
// map, CreatedAt, UpdatedAt) implementing core.User. Open profile
// map keeps the persisted shape extensible without schema migration.
//
// FSUsernameStore — UsernameStore impl enforcing uniqueness via one
// file per normalized (lowercase) username under usernames/.
// Optimistic Version field plus atomic file writes; ChangeUsername
// is best-effort restore on failure (not atomic across files).
//
// NewFSUsernameStore — constructor for FSUsernameStore. Concurrent
// same-name reservations resolve last-write-wins.
//
// FSUsername — persisted username record carrying both
// NormalizedUsername (used as filename/key) and original-case
// Username plus Version. Lets lookups be case-insensitive while
// display preserves original case; Version enables optimistic
// concurrency.
//
// FSIdentityStore — IdentityStore impl with one identity JSON file
// per type+value key under identities/. createIfMissing seeds an
// unassigned (empty UserID, unverified) identity; reverse lookups
// like GetUserIdentities scan the directory.
//
// NewFSIdentityStore — constructor for FSIdentityStore. Uses
// filepath.Base on the composed identity key for path safety
// (rather than safeName).
//
// FSChannelStore — ChannelStore impl with one channel JSON file per
// provider+identityKey under channels/. SaveChannel auto-bumps
// Version and CreatedAt/UpdatedAt; reverse lookup by identityKey
// scans the directory.
//
// NewFSChannelStore — constructor for FSChannelStore. createIfMissing
// seeds empty credentials/profile maps.
//
// FSTokenStore — verification/reset token store with one AuthToken
// JSON file per token value under tokens/. GetToken auto-deletes
// and rejects expired tokens; DeleteUserTokens scans the directory
// filtering by userID and type.
//
// NewFSTokenStore — constructor for FSTokenStore. Filename is the
// (safeName-sanitized) token itself, so the secret appears on disk
// in the path — acceptable for short-lived single-use tokens.
//
// FSRefreshTokenStore — RefreshToken store with rotation and
// family-based theft detection, one file per token under
// refresh_tokens/. Filename is the SHA256 hash of the token (not
// the raw value) so the secret never appears in a path;
// RotateRefreshToken revokes the old token and mints a successor in
// the same family, returning ErrTokenReused when an already-revoked
// token is replayed.
//
// NewFSRefreshTokenStore — constructor for FSRefreshTokenStore. Uses
// RWMutex plus getTokenUnsafe/forEachToken internals so multi-token
// sweeps hold a single lock.
//
// FSAPIKeyStore — APIKey store with one file per keyID under
// api_keys/ and bcrypt-hashed secrets. CreateAPIKey returns the
// full "oa_keyid_secret" once; ValidateAPIKey parses the triple and
// bcrypt-compares; listings clear KeyHash before returning.
//
// NewFSAPIKeyStore — constructor for FSAPIKeyStore. Only the bcrypt
// hash of the secret is persisted; the raw secret leaves the store
// exactly once at creation.
//
// FLOWS
//
// See [diagrams.md](diagrams.md) for sequence diagrams of: atomic
// write, refresh-token rotation with theft detection, API-key
// validation, and username change with best-effort restore.
package fs
