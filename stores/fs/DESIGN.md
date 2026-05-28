# fs

Filesystem-backed implementations of every oneauth store interface — `UserStore`, `IdentityStore`, `ChannelStore`, `UsernameStore`, `VerificationTokenStore`, `RefreshTokenStore`, `APIKeyStore`, `AppRegistrationStore`, `KeyStorage`, `KidStorage`. The shape is uniform across the package: a `StoragePath` root, one fixed subdirectory per store (`users/`, `identities/`, `channels/`, `usernames/`, `tokens/`, `refresh_tokens/`, `api_keys/`, `apps/`, `signing_keys/`, `kid_keys/`), and one JSON file per record under that subdirectory. Every method follows the post-#204 gRPC-shape convention `(ctx, *XRequest) → (*XResponse, error)`. Two helpers carry the package: [`safeName`](utils.go) is the single point of defense against path traversal — every caller-supplied identifier routes through it before becoming a filename — and [`writeAtomicFile`](utils.go) does temp-file + `os.Rename` with `0600` perms so readers never observe a half-written file. Intra-process concurrency is handled by per-store `sync.RWMutex` where mutation chains exist (`FSAppStore`, `FSKeyStore`, `FSKidStore`, `FSRefreshTokenStore`, `FSAPIKeyStore`); the simpler stores rely on atomic-rename semantics alone. Intended for dev and single-node deployments — production multi-process workloads should use the GORM backend (#167).

## Contents

- [Entities](#entities)
- [Flows](#flows)
  - [Atomic write](#atomic-write)
  - [Refresh token rotation with reuse detection](#refresh-token-rotation-with-reuse-detection)
- [Gotchas](#gotchas)

## Entities

| Entity | Kind | Role | Why |
|---|---|---|---|
| `safeName` | function | Sanitizes user input for path use; rejects traversal, null bytes, absolute paths. | Single CWE-22 defense point shared across every store. |
| `writeAtomicFile` | function | Temp-file write + `os.Rename` to target with `0600` perms. | Crash-safety: readers see old or new contents, never partial. |
| `isExpired` | function | Returns false for zero time (never-expires sentinel). | Centralizes the "zero = never" rule used in `FSKidStore` lookup and cleanup. |
| `FSUser` | struct | JSON record implementing `accounts.User` (Id, Profile, timestamps). | On-disk shape decoupled from the interface so profile maps round-trip cleanly. |
| `FSUserStore` | struct | `accounts.UserStore` as one file per user under `users/`. | Simplest mapping; `safeName` makes any userId safe. |
| `FSIdentityStore` | struct | `accounts.IdentityStore` as one file per `(type, value)` under `identities/`. | One OS read per provider login lookup; `GetIdentity` upsert-creates on `CreateIfMissing` for federated bootstrap. |
| `FSChannelStore` | struct | `accounts.ChannelStore` as one file per `(provider, identityKey)` under `channels/`. | Channel credentials (OAuth refresh tokens, etc.) isolated from primary identity records. |
| `FSUsername` | struct | JSON record: normalized form + original case + UserID + Version. | Case-insensitive lookup with case-preserving display. |
| `FSUsernameStore` | struct | `accounts.UsernameStore` as one file per normalized name under `usernames/`. | Uniqueness enforced by filesystem — filename collision = taken. `ChangeUsername` is the one explicitly non-atomic flow in the package. |
| `FSTokenStore` | struct | `localauth.VerificationTokenStore` for email-verify / password-reset under `tokens/`. | Short-lived tokens with auto-cleanup on expired read — no separate sweeper needed for the common case. |
| `FSRefreshTokenStore` | struct | `core.RefreshTokenStore` keyed by `sha256(token)` under `refresh_tokens/`; RWMutex-guarded. | Hashed filename means the raw token never appears in filesystem metadata. Rotation revokes-old + mints-new atomically under a single write lock for RFC 6749 §10.4 reuse detection. |
| `FSAPIKeyStore` | struct | `core.APIKeyStore` as one file per keyID under `api_keys/`; bcrypt-hashes secret; RWMutex-guarded. | Long-lived keys need hash-at-rest separate from short-lived refresh tokens. Wire format `oa_keyid_secret` is split on validate. |
| `FSAppStore` | struct | `admin.AppRegistrationStore` as one file per client_id under `apps/`; RWMutex-guarded. | DCR-registered OAuth clients; file-per-record avoids serializing the catalog. Distinguishes corrupt JSON from missing — see gotchas. |
| `fsKeyEntry` | struct | On-disk JSON for a signing key — ClientID, raw bytes, algorithm, optional kid. | Decouples wire format from `keys.KeyRecord` (interface-typed `Key`). |
| `FSKeyStore` | struct | `keys.KeyStorage` as one file per client_id under `signing_keys/`; RWMutex-guarded. | HMAC secrets / per-client signing keys; the by-kid lookup is necessarily a directory scan since filenames are keyed by clientID. |
| `fsKidEntry` | struct | On-disk JSON for a kid→key grace entry — adds `ExpiresAt` (zero = never) over `fsKeyEntry`. | Encodes the rotation grace window with the key bytes. |
| `FSKidStore` | struct | `keys.KidStorage` as one file per kid under `kid_keys/`; RWMutex-guarded. | Retired keys with a TTL for rotation-grace verification. `GetKey(clientID)` is hard-coded to `ErrKeyNotFound` — KidStorage is kid-indexed only. |

## Flows

### Atomic write

The crash-safety primitive every mutator in the package uses. The design rationale for the whole file-per-record approach lives here: a `read file → unmarshal → return` read path is trivial; the *write* path is what makes file-per-record viable as a real store. Temp file in the *same* directory (so the rename is on one filesystem), close, rename, chmod.

```mermaid
sequenceDiagram
    participant Store as FSXxxStore
    participant FS as Filesystem

    Store->>FS: os.CreateTemp(dir, ".tmp-*")
    FS-->>Store: tmpFile, tmpPath
    Store->>FS: tmpFile.Write(data)
    Store->>FS: tmpFile.Close()
    Note over Store,FS: Temp file is fully on disk;<br/>target path still holds the old bytes (if any).
    Store->>FS: os.Rename(tmpPath, path)
    Note over Store,FS: Atomic on POSIX — reader sees old or new, never partial.<br/>NFS / SMB break this guarantee — see gotchas.
    Store->>FS: os.Chmod(path, 0600)
    Store->>Store: return nil
```

### Refresh token rotation with reuse detection

The one read-modify-write chain in the package that *has* to be lock-serialized, and the reason `FSRefreshTokenStore` carries an `sync.RWMutex`. RFC 6749 §10.4 rotation with sender-constrained replay detection: revoking the old token and minting the new one happen under a single write lock so a second concurrent `RotateRefreshToken` on the same token sees the revocation and returns `ErrTokenReused` (the theft signal). The filename is `sha256(token)` — a deliberate choice over `safeName(token)` because hex is filesystem-safe by construction *and* the raw bearer never appears in `ls`, `stat`, or backup metadata.

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
        Note over RT: Reuse of a revoked token = theft.<br/>Caller is expected to follow up with<br/>RevokeTokenFamily(old.Family).
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

## Gotchas

- **`safeName` is the only path-traversal defense — and it lives in [`utils.go`](utils.go).** Every store that takes caller-supplied identifiers (`FSUserStore`, `FSChannelStore`, `FSTokenStore`, `FSAPIKeyStore`, `FSUsernameStore`, `FSAppStore`, `FSKeyStore`, `FSKidStore`) routes those identifiers through it before any `filepath.Join`. `FSIdentityStore` is an outlier — it uses `filepath.Base(accounts.IdentityKey(...))` directly, relying on the upstream `IdentityKey` to produce a safe form. If you add a new store, route input through `safeName`; if you change `safeName`, the security suite in [`security_test.go`](security_test.go) must still pass. `FSRefreshTokenStore` sidesteps the problem entirely by using `sha256(token)` as the filename.

- **Atomic-rename requires same-filesystem temp file.** `writeAtomicFile` uses `os.CreateTemp(dir, ...)` with `dir = filepath.Dir(path)`, which is critical: a cross-filesystem rename degrades to a copy-and-delete (not atomic) on Linux. If you ever change the temp dir to something like `os.TempDir()`, the crash-safety guarantee collapses silently.

- **No cross-process locking.** The `sync.RWMutex` in `FSAppStore`, `FSKeyStore`, `FSKidStore`, `FSRefreshTokenStore`, `FSAPIKeyStore` only serializes *intra-process* access. Two oneauth processes pointing at the same directory will race on writes — last-writer-wins, and a concurrent `RotateRefreshToken` from two processes can mint two new tokens that both look "valid" until one is used. Multi-process deployments belong on the GORM backend (#167). The mutex-less stores (`FSUserStore`, `FSIdentityStore`, `FSChannelStore`, `FSTokenStore`, `FSUsernameStore`) are *additionally* exposed to intra-process races on read-modify-write sequences like `SetUserForIdentity`.

- **NFS is unsafe.** `os.Rename` on NFS is not guaranteed atomic across clients, and file locking semantics differ from local POSIX. The same goes for SMB/CIFS. This backend is documented for "single-node deployments" deliberately — running it on a shared volume mounted by multiple machines breaks every safety claim in [`utils.go`](utils.go).

- **Corrupt-file recovery semantics differ by store.** `FSAppStore.GetApp` deliberately surfaces JSON parse errors as a separate condition from `admin.ErrAppNotFound` — callers must distinguish "registration absent (safe to recreate)" from "registration unreadable (operator intervention)". `FSAppStore.ListApps`, `FSRefreshTokenStore.forEachToken`, and `FSKidStore.CleanExpired` take the opposite stance: they *skip* corrupt files silently so one bad record doesn't lock out admin tooling. Single-record `Get*` paths on the other stores will return the raw `json.Unmarshal` error — callers comparing against typed errors via `errors.Is(err, ErrXxxNotFound)` will see `false` on a corrupt file, but that behavior isn't documented as a contract.

- **List operations are O(N) directory scans.** `FSKeyStore.GetKeyByKid`, `FSIdentityStore.GetUserIdentities`, `FSChannelStore.GetChannelsByIdentity`, `FSRefreshTokenStore.GetSubjectTokens` / `RevokeSubjectTokens` / `RevokeTokenFamily` / `CleanupExpiredTokens`, `FSAPIKeyStore.ListSubjectAPIKeys`, `FSTokenStore.DeleteSubjectTokens`, `FSAppStore.ListApps`, `FSKidStore.CleanExpired` all read every file in their directory on every call. The package targets dev / small deployments where the file count stays in the hundreds; beyond that, the linear scans on `RevokeSubjectTokens` (called on every "logout everywhere") and `GetKeyByKid` (called on every JWT verify) will dominate latency. There is no secondary index — that's the next backend's job.

- **Username uniqueness is best-effort, not atomic.** `FSUsernameStore.ReserveUsername` does a read-then-write with no inter-step locking. Two concurrent reservations of the same username can both observe "not found" and both successfully write the same file via atomic rename — last-writer-wins. `ChangeUsername` is worse: a true cross-file move (delete old, write new) with explicit best-effort restore on partial failure, and no rollback log. Under contention, use a DB backend.

- **`FSTokenStore.GetToken` deletes during read.** Reading an expired verification token *deletes* the file as a side effect. This is convenient at dev scale (no separate GC needed for the common case) but means a buggy caller that swallows the `"token expired"` error will silently destroy state. Tests that mock time around tokens must remember the GC happens on the *first* read after expiry.

- **`FSRefreshTokenStore` filename is `sha256(token)` — and that's load-bearing.** It means (a) the raw token never appears in `ls`, `stat`, or backup metadata, and (b) `safeName` is unnecessary because hex chars are filesystem-safe by construction. Do not "simplify" this to `safeName(token)` — you'd leak the secret into directory listings and into any error message that includes the path.

- **API key wire format is `oa_keyid_secret` — three parts, not two.** `FSAPIKeyStore.ValidateAPIKey` does `SplitN(fullKey, "_", 3)` and expects `parts[0] == "oa"`. The "keyID" stored on disk is itself `oa_<random>` (so `parts[0]+"_"+parts[1]`). If a future change moves the prefix or adds another segment, this parser breaks silently — it just returns `ErrAPIKeyNotFound` for everything.

- **`FSAPIKeyStore.UpdateAPIKeyLastUsed` rewrites the whole file on every request.** Every authenticated API call goes through `ValidateAPIKey` → and if the caller updates last-used, that's a JSON marshal + temp-file write + rename + chmod per request. This is fine at dev scale, prohibitive at production scale. Skip the update on hot paths or buffer it.

- **`FSKidStore.GetKey(clientID)` always returns `ErrKeyNotFound` — by contract.** It's the same trap as the in-memory KidStore: `KidStorage` is kid-indexed only, not clientID-indexed, so anyone using `FSKidStore` as a generic `keys.KeyStorage` will see every clientID lookup fail. Pair it with `FSKeyStore` (or a composite store) for clientID-keyed lookups.

- **Schema migrations are manual.** Every record is a JSON document; adding a field is fine (default-zero on read), removing or renaming a field requires either a migration script or accepting that old files stop parsing — at which point `FSAppStore.GetApp` will surface the error, the other stores will silently drop the record from list operations (per the "skip corrupt" pattern in `ListApps` and `forEachToken`).

## Depends on

- [`accounts/`](../../accounts/DESIGN.md) — `User`, `UserStore`, `Identity`, `IdentityStore`, `IdentityKey`, `Channel`, `ChannelStore`, `UsernameStore`
- [`admin/`](../../admin/DESIGN.md) — `AppRegistration`, `AppRegistrationStore`, `ErrAppNotFound`
- [`core/`](../../core/DESIGN.md) — `APIKey`, `APIKeyStore`, `RefreshToken`, `RefreshTokenStore`, `GenerateSecureToken`, `GenerateAPIKeyID`, `GenerateAPIKeySecret`, `TokenExpiryRefreshToken`, `ErrAPIKeyNotFound`, `ErrTokenNotFound`, `ErrTokenExpired`, `ErrTokenRevoked`, `ErrTokenReused`
- [`keys/`](../../keys/DESIGN.md) — `KeyStorage`, `KidStorage`, `KeyRecord`, `ErrKeyNotFound`, `ErrKidNotFound`, `ErrAlgorithmMismatch`
- [`localauth/`](../../localauth/DESIGN.md) — `VerificationTokenStore`, `VerificationToken`, `VerificationType`
- [`utils/`](../../utils/DESIGN.md) — `ComputeKid`
