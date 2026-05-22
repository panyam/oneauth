// Package fs provides filesystem-backed (JSON-file-per-record) implementations
// of OneAuth's KeyStore, KidStore, AppRegistrationStore, User/Username/Identity/
// Channel/Token/RefreshToken/APIKey store interfaces, intended for single-process
// dev and small deployments.
//
// <!-- design:start -->
// Every store in this package shares one shape: each record is a JSON file under
// {StoragePath}/{kind}/, written atomically (temp file + rename + chmod 0600 via
// writeAtomicFile) so a crash mid-write leaves either the old or the new file but
// never a half-written one. User-supplied identifiers are run through safeName,
// the single point of defense against path traversal: it rejects empty names,
// null bytes, absolute paths, and embedded "..", and folds /, \, : into
// underscores. Backends that need real cross-process transaction semantics should
// use a database-backed store instead (e.g. GORM); the FS stores assume a single
// writer process and mediate in-process concurrency with sync.RWMutex (or, for
// the older user/identity/channel/token stores, atomic writes alone). Directories
// are created lazily on first write, and reverse-lookup and list operations scan
// the relevant directory, skipping unreadable or corrupt files rather than failing
// the whole call.
//
// # ENTITIES
//
// FSKeyStore — keys.KeyStorage impl; one signing-key JSON file per clientID under
// signing_keys/. Keys must be []byte (else ErrAlgorithmMismatch); GetKeyByKid
// scans all files because the layout is clientID-indexed. Also exposes
// backward-compatible aliases (RegisterKey, GetVerifyKey, GetSigningKey,
// GetExpectedAlg, ListKeys, GetCurrentKid). NewFSKeyStore constructs it.
//
// FSKidStore — keys.KidStorage impl; one kid-indexed JSON file per kid under
// kid_keys/, each carrying a grace-period expires_at (zero = never). Mirrors
// FSKeyStore but is kid-keyed, so GetKey(clientID) always returns ErrKeyNotFound
// by design (matching the in-memory KidStore). Expired entries are filtered on
// read and purged by CleanExpired; Remove is idempotent. NewFSKidStore constructs
// it.
//
// FSAppStore — admin.AppRegistrationStore impl; one AppRegistration JSON file per
// client_id under apps/. GetApp distinguishes a corrupt file (parse error) from an
// absent registration (ErrAppNotFound), while ListApps silently skips corrupt
// files so one hand-corrupted file cannot lock out admin tooling. Single-process
// only. NewFSAppStore constructs it.
//
// FSUserStore — core UserStore impl; one user JSON file per userId under users/.
// SaveUser converts foreign core.User implementations into FSUser, best-effort
// preserving created_at from the profile map. FSUser is the persisted record
// (id, active flag, open profile map, timestamps). NewFSUserStore constructs it.
//
// FSUsernameStore — UsernameStore impl enforcing username uniqueness via one file
// per normalized (lowercase) username under usernames/. FSUsername stores both the
// normalized name (used as filename/key) and the original case for display, plus a
// Version for optimistic concurrency. ChangeUsername is not atomic across files and
// best-effort restores the old name on failure; concurrent same-name reservations
// resolve last-write-wins. NewFSUsernameStore constructs it.
//
// FSIdentityStore — IdentityStore impl; one identity JSON file per type+value key
// under identities/. createIfMissing seeds an unassigned (empty UserID,
// unverified) identity. Reverse lookups such as GetUserIdentities scan the
// directory. NewFSIdentityStore constructs it.
//
// FSChannelStore — ChannelStore impl; one channel JSON file per provider+identityKey
// under channels/. SaveChannel auto-bumps Version and CreatedAt/UpdatedAt;
// createIfMissing seeds empty credentials/profile maps; lookup by identityKey scans
// the directory. NewFSChannelStore constructs it.
//
// FSTokenStore — verification/reset token store; one AuthToken JSON file per token
// value under tokens/, with the (sanitized) token as the filename. GetToken
// auto-deletes and rejects expired tokens; DeleteUserTokens scans the directory
// filtering by userID and type. NewFSTokenStore constructs it.
//
// FSRefreshTokenStore — RefreshToken store with rotation and family-based theft
// detection; one file per token under refresh_tokens/. The filename is the SHA256
// hash of the token, not the raw value, so the secret never appears in a path.
// RotateRefreshToken revokes the old token and mints a successor in the same
// family, returning ErrTokenReused when an already-revoked token is replayed.
// NewFSRefreshTokenStore constructs it.
//
// FSAPIKeyStore — APIKey store; one file per keyID under api_keys/ with the secret
// stored only as a bcrypt hash. CreateAPIKey returns the full "oa_keyid_secret"
// once; ValidateAPIKey parses that triple and bcrypt-compares; listings clear
// KeyHash before returning. NewFSAPIKeyStore constructs it.
// <!-- design:end -->
package fs
