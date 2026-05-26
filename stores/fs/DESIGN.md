# fs

Filesystem-backed implementations of every oneauth store interface — `UserStore`, `IdentityStore`, `ChannelStore`, `VerificationTokenStore`, `RefreshTokenStore`, `APIKeyStore`, `UsernameStore`, `AppRegistrationStore`, `KeyStorage`, `KidStorage`. The shape is uniform across the package: a `StoragePath` root, one fixed subdirectory per store (`users/`, `identities/`, `channels/`, `tokens/`, `refresh_tokens/`, `api_keys/`, `usernames/`, `apps/`, `signing_keys/`, `kid_keys/`), and one JSON file per record under that subdirectory. Two helpers carry the package: [`safeName`](utils.go) is the single point of defense against path traversal — every caller-supplied identifier routes through it before becoming a filename — and [`writeAtomicFile`](utils.go) does temp-file + `os.Rename` with `0600` perms so readers never observe a half-written file. Intra-process concurrency is handled by per-store `sync.RWMutex` where mutation chains exist (`FSAppStore`, `FSKeyStore`, `FSKidStore`, `FSRefreshTokenStore`, `FSAPIKeyStore`); the simpler stores rely on atomic-rename semantics alone. Intended for dev and single-node deployments — production multi-process workloads should use the GORM backend (#167).

## Contents

- [Entities](#entities)
- [Flows](#flows)
  - [Atomic write](#atomic-write)
  - [Refresh token rotation with reuse detection](#refresh-token-rotation-with-reuse-detection)
  - [Key rotation against KidStorage](#key-rotation-against-kidstorage)
  - [API key creation and validation](#api-key-creation-and-validation)
  - [Username change across files](#username-change-across-files)
- [Gotchas](#gotchas)

## Entities

| Entity | Kind | Role | Why |
|---|---|---|---|
| `safeName` | function | Sanitizes user input for path use; rejects traversal, null bytes, absolute paths. | Single CWE-22 defense point shared across every store. |
| `writeAtomicFile` | function | Temp-file write + `os.Rename` to target with `0600` perms. | Crash-safety: readers see old or new contents, never partial. |
| `FSUser` | struct | JSON record implementing `accounts.User` (Id, Profile, timestamps). | On-disk shape decoupled from the interface. |
| `FSUserStore` | struct | `accounts.UserStore` as one file per user under `users/`. | Simplest mapping; `safeName` makes any userId safe. |
| `FSUserStore.CreateUser` | method | Builds FSUser, stamps timestamps, persists via `SaveUser`. | Single-call constructor + persistence. |
| `FSUserStore.GetUserById` | method | Reads `users/{safeID}.json`; missing surfaces as typed error. | Distinguishes missing vs unreadable. |
| `FSUserStore.SaveUser` | method | Marshals any `accounts.User` into FSUser shape and atomically writes. | Accepts users created elsewhere without losing fields. |
| `FSIdentityStore` | struct | `accounts.IdentityStore` as one file per `(type, value)` under `identities/`. | One OS read per provider login lookup. |
| `FSIdentityStore.GetIdentity` | method | Loads or upsert-creates an identity; createIfMissing seeds unverified/unlinked. | Federated bootstrap before user linking. |
| `FSIdentityStore.SaveIdentity` | method | Atomic write under `identities/{key}.json`. | Centralizes the marshal + atomic-write step. |
| `FSIdentityStore.SetUserForIdentity` | method | Loads, bumps Version, sets UserID, saves. | Account-linking after the user account exists. |
| `FSIdentityStore.MarkIdentityVerified` | method | Loads, sets Verified=true, bumps Version, saves. | Email/phone verification handoff. |
| `FSIdentityStore.GetUserIdentities` | method | Full dir scan filtered by UserID. | Linked-accounts list; O(N) acceptable at dev scale. |
| `FSChannelStore` | struct | `accounts.ChannelStore` as one file per `(provider, identityKey)` under `channels/`. | Channel credentials isolated from primary identity records. |
| `FSChannelStore.GetChannel` | method | Loads or upsert-creates with empty credentials/profile maps. | Federated flow needs a writable channel for refresh tokens. |
| `FSChannelStore.SaveChannel` | method | Bumps Version (or seeds), updates timestamps, atomic write. | Optimistic-concurrency hook even without CAS. |
| `FSChannelStore.GetChannelsByIdentity` | method | Full dir scan filtered by IdentityKey. | Profile UI lists every provider for one identity. |
| `FSTokenStore` | struct | `localauth.VerificationTokenStore` for email-verify / password-reset under `tokens/`. | Short-lived tokens with auto-cleanup on expired read. |
| `FSTokenStore.CreateToken` | method | Generates secure token, builds VerificationToken, atomic write. | Single call for signup / forgot-password link minting. |
| `FSTokenStore.GetToken` | method | Reads token JSON; if `IsExpired()` deletes and returns "expired". | Self-cleaning read path avoids a separate sweeper. |
| `FSTokenStore.DeleteToken` | method | Idempotent removal; absent file is not an error. | Called on successful use and on expiry. |
| `FSTokenStore.DeleteUserTokens` | method | Full dir scan; removes every token matching userID + type. | "Forgot password again" invalidates the previous link. |
| `FSRefreshTokenStore` | struct | `core.RefreshTokenStore` keyed by `sha256(token)` under `refresh_tokens/`; RWMutex-guarded. | Hashed filename means the raw token never appears in fs metadata. |
| `FSRefreshTokenStore.CreateRefreshToken` | method | Mints token + family ID, generation=1, saves under hashed filename. | Roots a family for rotation-chain theft detection. |
| `FSRefreshTokenStore.RotateRefreshToken` | method | Loads old; if already revoked returns `ErrTokenReused`; else revokes old and mints new in same family with generation+1. | RFC 6749 §10.4 rotation with reuse detection — the interesting flow. |
| `FSRefreshTokenStore.RevokeRefreshToken` | method | Marks one token revoked + stamps `RevokedAt`; idempotent. | Direct revocation endpoint backing. |
| `FSRefreshTokenStore.RevokeUserTokens` | method | `forEachToken` sweep; revokes every non-revoked token for user. | Logout-everywhere / takeover recovery. |
| `FSRefreshTokenStore.RevokeTokenFamily` | method | `forEachToken` sweep; revokes every non-revoked token in family. | Once reuse is detected, kill the whole chain. |
| `FSRefreshTokenStore.GetUserTokens` | method | Lists active tokens for user; clears raw `Token` before returning. | Admin/profile listing must never leak bearer material. |
| `FSRefreshTokenStore.CleanupExpiredTokens` | method | Removes expired tokens and revoked tokens older than 24h. | Bounds disk growth with a 24h audit grace. |
| `FSRefreshTokenStore.forEachToken` | method | Iterates dir, parses each, calls visitor; skips unreadable/unparseable. | Shared traversal kernel for revoke/list/cleanup. |
| `FSAPIKeyStore` | struct | `core.APIKeyStore` as one file per keyID under `api_keys/`; bcrypt-hashes secret; RWMutex-guarded. | Long-lived keys need hash-at-rest separate from short-lived refresh tokens. |
| `FSAPIKeyStore.CreateAPIKey` | method | Generates keyID + secret, bcrypts secret, persists, returns `oa_keyid_secret` once. | One-time secret reveal; only the bcrypt hash survives on disk. |
| `FSAPIKeyStore.ValidateAPIKey` | method | Parses `oa_keyid_secret`, loads record, checks revoked/expired/bcrypt. | Per-request validation; returns metadata so caller can derive scopes. |
| `FSAPIKeyStore.RevokeAPIKey` | method | Marks key revoked + stamps `RevokedAt`; idempotent. | User-initiated key rotation. |
| `FSAPIKeyStore.ListUserAPIKeys` | method | Full dir scan; returns user's keys with `KeyHash` zeroed. | Never expose the bcrypt hash even though it's not the secret. |
| `FSAPIKeyStore.UpdateAPIKeyLastUsed` | method | Re-saves the record with `LastUsedAt=now`. | Hot path on every API call — full file rewrite is the cost. |
| `FSUsername` | struct | JSON record: normalized form + original case + UserID + Version. | Case-insensitive lookup with case-preserving display. |
| `FSUsernameStore` | struct | Username uniqueness store as one file per normalized name under `usernames/`. | Uniqueness enforced by filesystem — filename collision = taken. |
| `FSUsernameStore.ReserveUsername` | method | If owned by same user updates case; else if exists errors "taken"; else creates. | Best-effort uniqueness; last-write-wins on a true race. |
| `FSUsernameStore.GetUserByUsername` | method | Reads `usernames/{lowercase}.json`, returns UserID. | Username-login lookup from CredentialsValidatorWithUsername. |
| `FSUsernameStore.ReleaseUsername` | method | Removes the file; idempotent on absent. | Account deletion / admin moderation. |
| `FSUsernameStore.ChangeUsername` | method | Same normalized → update case; different → verify ownership, check new is free, delete old + write new, attempt old-restore on failure. | Cross-file move; explicitly not atomic — documented as such. |
| `FSAppStore` | struct | `admin.AppRegistrationStore` as one file per client_id under `apps/`; RWMutex-guarded. | DCR-registered OAuth clients; file-per-record avoids serializing the catalog. |
| `FSAppStore.SaveApp` | method | Rejects empty ClientID, marshals, atomic write under `apps/{safeID}.json`. | Used by both DCR creation and updates. |
| `FSAppStore.GetApp` | method | Missing → `admin.ErrAppNotFound`; corrupt JSON → parse error (deliberately not ErrAppNotFound). | Callers must distinguish absent vs unreadable. |
| `FSAppStore.ListApps` | method | Reads dir, skips dirs/non-.json/corrupt, returns parsed list. | Partial recovery beats total failure for admin tooling. |
| `FSAppStore.DeleteApp` | method | Stats then `os.Remove`; missing → `ErrAppNotFound`. | Matches `InMemoryAppStore` semantics. |
| `fsKeyEntry` | struct | On-disk JSON for a signing key — ClientID, raw bytes, algorithm, optional kid. | Decouples wire format from `keys.KeyRecord` (interface-typed Key). |
| `FSKeyStore` | struct | `keys.KeyStorage` as one file per client_id under `signing_keys/`; RWMutex-guarded. | HMAC secrets / per-client signing keys; by-kid lookup is a directory scan. |
| `FSKeyStore.PutKey` | method | Auto-computes kid if absent, atomic write under `signing_keys/{safeID}.json`. | Ensures every persisted key has a kid even if caller didn't supply one. |
| `FSKeyStore.GetKey` | method | Reads file by clientID; missing → `ErrKeyNotFound`. | Hot validation path. |
| `FSKeyStore.GetKeyByKid` | method | Linear scan matching `entry.Kid`; not-found → `ErrKidNotFound`. | JWKS lookup path; O(N) acceptable at target scale. |
| `FSKeyStore.DeleteKey` | method | Stats then `os.Remove`; missing → `ErrKeyNotFound`. | Client deletion; pairs with FSKidStore for grace. |
| `FSKeyStore.ListKeyIDs` | method | Directory scan returning every entry's ClientID. | Admin enumeration. |
| `FSKeyStore.RegisterKey` / `GetVerifyKey` / `GetSigningKey` / `GetExpectedAlg` / `ListKeys` / `GetCurrentKid` | method | Backward-compat shims around `PutKey`/`GetKey`/`ListKeyIDs`. | Pre-KeyRecord callers still compile. |
| `fsKidEntry` | struct | On-disk JSON for a kid→key grace entry — adds `ExpiresAt` (zero = never) over fsKeyEntry. | Encodes rotation grace window with the key bytes. |
| `FSKidStore` | struct | `keys.KidStorage` as one file per kid under `kid_keys/`; RWMutex-guarded. | Retired keys with a TTL for rotation-grace verification. |
| `FSKidStore.Add` | method | Writes `kid_keys/{safeKid}.json` with key, alg, clientID, expiresAt. | Called during rotation to park the previous signing key. |
| `FSKidStore.Remove` | method | Idempotent file removal. | Force-evict a kid out of grace. |
| `FSKidStore.GetKey` | method | Always returns `ErrKeyNotFound`. | KidStorage is kid-indexed; matches in-memory contract. |
| `FSKidStore.GetKeyByKid` | method | Reads `kid_keys/{safeKid}.json`; expired → `ErrKidNotFound`. | Hot verify path during rotation grace. |
| `FSKidStore.CleanExpired` | method | Sweeps dir, deletes entries past `ExpiresAt`. | Called by a separate rotation maintenance job. |
| `isExpired` | function | Returns false for zero time (never-expires sentinel). | Centralizes the "zero = never" rule for lookup and cleanup. |

## Flows

### Atomic write

The crash-safety primitive every mutator uses. Temp file in the *same* directory (so the rename is on one filesystem), close, rename, chmod.

```mermaid
sequenceDiagram
    participant Store as FSXxxStore
    participant FS as Filesystem

    Store->>FS: os.CreateTemp(dir, ".tmp-*")
    FS-->>Store: tmpFile, tmpPath
    Store->>FS: tmpFile.Write(data)
    Store->>FS: tmpFile.Close()
    Note over Store,FS: At this point the temp file is fully on disk;<br/>target path still holds the old bytes (if any).
    Store->>FS: os.Rename(tmpPath, path)
    Note over Store,FS: Atomic on POSIX — reader sees old or new, never partial.
    Store->>FS: os.Chmod(path, 0600)
    Store->>Store: return nil
```

### Refresh token rotation with reuse detection

The headline flow of `FSRefreshTokenStore` — sender-constrained rotation with theft detection rooted in the family ID. Note the entire operation is under a single write lock so the old-token revoke and new-token mint cannot interleave with a second rotation of the same token.

```mermaid
sequenceDiagram
    participant Client
    participant RT as FSRefreshTokenStore
    participant FS as refresh_tokens/

    Client->>RT: RotateRefreshToken(oldToken)
    RT->>RT: mu.Lock()
    RT->>FS: ReadFile(sha256(oldToken).json)
    alt File missing
        FS-->>RT: ErrTokenNotFound
        RT-->>Client: ErrTokenNotFound
    else Revoked = true
        Note over RT: Reuse of a revoked token = theft.<br/>Caller is expected to call<br/>RevokeTokenFamily(old.Family).
        RT-->>Client: ErrTokenReused
    else IsExpired
        RT-->>Client: ErrTokenExpired
    else Valid
        RT->>RT: old.Revoked = true; old.RevokedAt = now
        RT->>FS: writeAtomicFile(sha256(oldToken).json)
        RT->>RT: mint newToken; build RefreshToken with old.Family,<br/>generation = old.Generation + 1
        RT->>FS: writeAtomicFile(sha256(newToken).json)
        RT-->>Client: newRefreshToken
    end
    RT->>RT: mu.Unlock()
```

### Key rotation against KidStorage

How `FSKeyStore` and `FSKidStore` cooperate during key rotation. The previous key is parked in `FSKidStore` with a TTL so any token already in flight under the old kid can still verify; meanwhile the new key takes over as the current signer.

```mermaid
sequenceDiagram
    participant Admin
    participant KS as FSKeyStore (signing_keys/)
    participant Kid as FSKidStore (kid_keys/)
    participant Verifier as JWT verify path

    Admin->>KS: GetKey(clientID)
    KS-->>Admin: oldKeyRecord {Key, Alg, Kid}
    Admin->>Kid: Add(oldKid, oldKey, alg, clientID, now+graceTTL)
    Kid->>Kid: writeAtomicFile(kid_keys/{oldKid}.json)
    Admin->>KS: PutKey({clientID, newKey, alg, newKid})
    KS->>KS: writeAtomicFile(signing_keys/{clientID}.json)
    Note over KS,Kid: From here on, new tokens sign with newKid;<br/>old tokens still verify until oldKid expires.

    par Verify new-kid token
        Verifier->>KS: GetKeyByKid(newKid)
        KS-->>Verifier: newKeyRecord
    and Verify old-kid token (grace)
        Verifier->>Kid: GetKeyByKid(oldKid)
        alt before ExpiresAt
            Kid-->>Verifier: oldKeyRecord
        else after ExpiresAt
            Kid-->>Verifier: ErrKidNotFound
        end
    end

    Note over Kid: Later: CleanExpired() removes the parked entry.
```

### API key creation and validation

`FSAPIKeyStore` splits the wire-format `oa_keyid_secret` into a public ID (used as filename) and a bcrypt-hashed secret (compared on every request).

```mermaid
sequenceDiagram
    participant User
    participant AK as FSAPIKeyStore
    participant FS as api_keys/

    Note over User,AK: --- Creation (one-time secret reveal) ---
    User->>AK: CreateAPIKey(userID, name, scopes, expiresAt)
    AK->>AK: keyID = "oa_" + random; secret = random
    AK->>AK: keyHash = bcrypt(secret)
    AK->>FS: writeAtomicFile(api_keys/{keyID}.json, {KeyHash, ...})
    AK-->>User: fullKey = keyID + "_" + secret  (only chance to capture)

    Note over User,AK: --- Validation on every request ---
    User->>AK: ValidateAPIKey("oa_xxx_secret")
    AK->>AK: parts = SplitN(fullKey, "_", 3); keyID = parts[0]+"_"+parts[1]
    AK->>FS: ReadFile(api_keys/{keyID}.json)
    alt Missing
        FS-->>AK: ErrAPIKeyNotFound
    else Revoked
        AK-->>User: ErrTokenRevoked
    else Expired
        AK-->>User: ErrTokenExpired
    else
        AK->>AK: bcrypt.CompareHashAndPassword(KeyHash, secret)
        alt mismatch
            AK-->>User: ErrAPIKeyNotFound  (constant-time-ish failure)
        else match
            AK-->>User: apiKey record
        end
    end
```

### Username change across files

The one explicitly-non-atomic flow in the package. Two files must move in opposite directions; the implementation does best-effort restore on partial failure, and the comments call this out as a reason to migrate to a DB backend under contention.

```mermaid
sequenceDiagram
    participant User
    participant US as FSUsernameStore
    participant FS as usernames/

    User->>US: ChangeUsername(old, new, userID)
    alt normalize(old) == normalize(new)
        US->>FS: read usernames/{normalized}.json
        US->>US: verify UserID matches; update Username (case); bump Version
        US->>FS: writeAtomicFile(...) — done
    else different normalized form
        US->>FS: read usernames/{oldNormalized}.json
        Note over US: verify exists + owned by userID
        US->>FS: read usernames/{newNormalized}.json
        alt new already exists
            US-->>User: error "new username already taken"
        else new is free
            US->>FS: os.Remove(usernames/{oldNormalized}.json)
            US->>FS: writeAtomicFile(usernames/{newNormalized}.json)
            alt new write failed
                Note over US,FS: BEST-EFFORT restore — no rollback log
                US->>FS: writeAtomicFile(usernames/{oldNormalized}.json)
                US-->>User: error "failed to create new username"
            else success
                US-->>User: nil
            end
        end
    end
```

## Gotchas

- **`safeName` is the only path-traversal defense — and it lives in [`utils.go`](utils.go).** Every store that takes caller-supplied identifiers (`FSUserStore`, `FSChannelStore`, `FSTokenStore`, `FSAPIKeyStore`, `FSUsernameStore`, `FSAppStore`, `FSKeyStore`, `FSKidStore`) routes those identifiers through it before any `filepath.Join`. `FSIdentityStore` is an outlier — it uses `filepath.Base(accounts.IdentityKey(...))` directly, relying on the upstream `IdentityKey` to produce a safe form. If you add a new store, route input through `safeName`; if you change `safeName`, the security suite in [`security_test.go`](security_test.go) must still pass. `FSRefreshTokenStore` sidesteps the problem entirely by using `sha256(token)` as the filename.

- **Atomic-rename requires same-filesystem temp file.** `writeAtomicFile` uses `os.CreateTemp(dir, ...)` with `dir = filepath.Dir(path)`, which is critical: a cross-filesystem rename degrades to a copy-and-delete (not atomic) on Linux. If you ever change the temp dir to something like `os.TempDir()`, the crash-safety guarantee collapses silently.

- **No cross-process locking.** The `sync.RWMutex` in `FSAppStore`, `FSKeyStore`, `FSKidStore`, `FSRefreshTokenStore`, `FSAPIKeyStore` only serializes *intra-process* access. Two oneauth processes pointing at the same directory will race on writes — last-writer-wins, and a concurrent `RotateRefreshToken` from two processes can mint two new tokens that both look "valid" until one is used. Multi-process deployments belong on the GORM backend (#167). The mutex-less stores (`FSUserStore`, `FSIdentityStore`, `FSChannelStore`, `FSTokenStore`, `FSUsernameStore`) are *additionally* exposed to intra-process races on read-modify-write sequences like `SetUserForIdentity`.

- **NFS is unsafe.** `os.Rename` on NFS is not guaranteed atomic across clients, and file locking semantics differ from local POSIX. The same goes for SMB/CIFS. This backend is documented for "single-node deployments" deliberately — running it on a shared volume mounted by multiple machines breaks every safety claim in [`utils.go`](utils.go).

- **List operations are O(N) directory scans.** `FSKeyStore.GetKeyByKid`, `FSIdentityStore.GetUserIdentities`, `FSChannelStore.GetChannelsByIdentity`, `FSRefreshTokenStore.GetUserTokens` / `RevokeUserTokens` / `RevokeTokenFamily` / `CleanupExpiredTokens`, `FSAPIKeyStore.ListUserAPIKeys`, `FSTokenStore.DeleteUserTokens`, `FSAppStore.ListApps`, `FSKidStore.CleanExpired` all read every file in their directory on every call. The package targets dev / small deployments where the file count stays in the hundreds; beyond that, the linear scans on `RevokeUserTokens` (called on every "logout everywhere") and `GetKeyByKid` (called on every JWT verify) will dominate latency. There is no secondary index — that's the next backend's job.

- **Username uniqueness is best-effort, not atomic.** `FSUsernameStore.ReserveUsername` does a read-then-write with no inter-step locking. Two concurrent reservations of the same username can both observe "not found" and both successfully write the same file via atomic rename — last-writer-wins. `ChangeUsername` is worse: a true cross-file move with explicit best-effort restore documented in the source. Under contention, use a DB backend.

- **`FSTokenStore.GetToken` deletes during read.** Reading an expired verification token *deletes* the file as a side effect. This is convenient at dev scale (no separate GC needed for the common case) but means a buggy caller that swallows the `"token expired"` error will silently destroy state. Tests that mock time around tokens must remember the GC happens on the *first* read after expiry.

- **`FSAppStore` distinguishes corrupt from missing — others don't.** Only `FSAppStore.GetApp` deliberately surfaces JSON parse errors as a separate condition from `ErrAppNotFound`, with `TestFSAppStore_CorruptFile_GetReturnsError` enforcing that contract. The other stores will return parse errors directly from `json.Unmarshal` (so callers comparing against typed errors via `errors.Is(err, ErrXxxNotFound)` will see `false` on a corrupt file) but they don't have that behavior documented as a guarantee. If you add corrupt-file tests for other stores, expect that distinction to need explicit handling.

- **`FSRefreshTokenStore` filename is `sha256(token)` — and that's load-bearing.** It means (a) the raw token never appears in `ls`, `stat`, or backup metadata, and (b) `safeName` is unnecessary because hex chars are filesystem-safe by construction. Do not "simplify" this to `safeName(token)` — you'd leak the secret into directory listings and into any error message that includes the path.

- **API key wire format is `oa_keyid_secret` — three parts, not two.** `FSAPIKeyStore.ValidateAPIKey` does `SplitN(fullKey, "_", 3)` and expects `parts[0] == "oa"`. The "keyID" stored on disk is itself `oa_<random>` (so `parts[0]+"_"+parts[1]`). If a future change moves the prefix or adds another segment, this parser breaks silently — it just returns `ErrAPIKeyNotFound` for everything.

- **`FSAPIKeyStore.UpdateAPIKeyLastUsed` rewrites the whole file on every request.** Every authenticated API call goes through `ValidateAPIKey` → and if the caller updates last-used, that's a JSON marshal + temp-file write + rename + chmod per request. This is fine at dev scale, prohibitive at production scale. Skip the update on hot paths or buffer it.

- **`FSKidStore.GetKey(clientID)` always returns `ErrKeyNotFound` — by contract.** It's the same trap as the in-memory KidStore: `KidStorage` is kid-indexed only, not clientID-indexed, so anyone using `FSKidStore` as a generic `keys.KeyStorage` will see every clientID lookup fail. Pair it with `FSKeyStore` (or a composite store) for clientID-keyed lookups.

- **Schema migrations are manual.** Every record is a JSON document; adding a field is fine (default-zero on read), removing or renaming a field requires either a migration script or accepting that old files stop parsing — at which point `FSAppStore.GetApp` will report it, the other stores will silently drop the record from list operations (per the "skip corrupt" pattern in `ListApps` and `forEachToken`).

## Depends on

- [`accounts/`](../../accounts/DESIGN.md) — `User`, `UserStore`, `Identity`, `IdentityStore`, `IdentityKey`, `Channel`, `ChannelStore`
- [`admin/`](../../admin/DESIGN.md) — `AppRegistration`, `AppRegistrationStore`, `ErrAppNotFound`
- [`core/`](../../core/DESIGN.md) — `APIKey`, `APIKeyStore`, `RefreshToken`, `RefreshTokenStore`, `GenerateSecureToken`, `GenerateAPIKeyID`, `GenerateAPIKeySecret`, `TokenExpiryRefreshToken`, `ErrAPIKeyNotFound`, `ErrTokenNotFound`, `ErrTokenExpired`, `ErrTokenRevoked`, `ErrTokenReused`
- [`keys/`](../../keys/DESIGN.md) — `KeyStorage`, `KidStorage`, `KeyRecord`, `ErrKeyNotFound`, `ErrKidNotFound`, `ErrAlgorithmMismatch`
- [`localauth/`](../../localauth/DESIGN.md) — `VerificationTokenStore`, `VerificationToken`, `VerificationType`
- [`utils/`](../../utils/DESIGN.md) — `ComputeKid`
