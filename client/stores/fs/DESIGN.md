# fs

Filesystem-backed implementation of the oneauth client's `CredentialStore`. Holds an in-memory `map[string]*ServerCredential` keyed by normalized `scheme://host`, guarded by a `sync.RWMutex`, and persists it on explicit `Save` to a single JSON file at `~/.config/<appName>/credentials.json` (or a caller-supplied path) with directory perms `0700` and file perms `0600`. Designed as the default credential backend for CLIs and desktop apps that need OAuth tokens to survive across runs without dragging in a database.

## Contents

- [Entities](#entities)
- [Gotchas](#gotchas)
- [Depends on](#depends-on)

## Entities

| Entity | Kind | Role | Why |
|---|---|---|---|
| `FSCredentialStore` | struct | In-memory map of normalized-URL to `ServerCredential`, guarded by a `RWMutex` and backed by a JSON file. | Mutations stay in memory until `Save`, so callers control when secrets touch disk. |
| `credentialFile` | struct | On-disk JSON envelope wrapping the servers map under a `"servers"` key. | Single top-level object leaves room for schema/version fields without breaking older readers. |
| `NewFSCredentialStore` | func | Constructor that defaults the path to `~/.config/<appName>/credentials.json` and eagerly loads any existing file. | First-run callers want an empty-but-usable store rather than a "file not found" error. |
| `normalizeURL` | func | Collapses a server URL to `scheme://host`, defaulting missing scheme to `https`. | Tokens are per-issuer, not per-endpoint; path/query variants must dedup onto one entry. |
| `FSCredentialStore.GetCredential` | method | Lookup by normalized URL; returns `(nil, nil)` on miss. | Errors are reserved for URL parsing; missing-credential is a normal state, not a failure. |
| `FSCredentialStore.SetCredential` | method | Stores a credential under its normalized key and marks the store dirty. | Defers disk write to `Save` so many updates batch into one file rewrite. |
| `FSCredentialStore.RemoveCredential` | method | Deletes a credential by normalized key and marks the store dirty. | Mirrors `Set`'s batching model so removals also wait for `Save`. |
| `FSCredentialStore.ListServers` | method | Returns all normalized server URL keys. | Exposes the canonical `scheme://host` form callers can pass back into `Get`/`Remove`. |
| `FSCredentialStore.Save` | method | Writes the map to disk as indented JSON when dirty, creating dir `0700` and file `0600`. | Restricted perms because contents are bearer tokens; no-op when unchanged to avoid needless fsync. |
| `FSCredentialStore.Path` | method | Returns the resolved path to the credentials file. | After default-path resolution, callers (and logs) need to know where the file actually landed. |

## Gotchas

- **`Save` is the only persistence trigger.** `SetCredential` and `RemoveCredential` flip a `modified` flag but never touch disk; a caller that forgets to invoke `Save` on shutdown loses every mutation. The `modified` flag also short-circuits `Save` to a no-op, so an externally edited file will not be rewritten unless an in-process mutation has happened first.
- **URL normalization is lossy and intentional.** `normalizeURL` discards path, query, and userinfo — only `scheme://host` (with `https` defaulted) survives as the key. `http://localhost:8080/v1` and `http://localhost:8080/v2` therefore share one credential entry, which is the intended dedup behavior but surprising if you expected path-scoped tokens.
- **`GetCredential` signals "missing" as `(nil, nil)`.** The error return is reserved for URL-parsing failures; a successful lookup that finds nothing returns no error. Callers that only check `err` will silently treat an unauthenticated server as authenticated with a nil credential.
- **Malformed files abort construction.** A corrupt `credentials.json` makes `NewFSCredentialStore` return an error rather than starting fresh, so a single bad file can lock a user out of their CLI until they delete it manually. Only `os.IsNotExist` is tolerated.
- **Whole-file rewrite, no atomic swap, single-writer by design.** Every `Save` serializes and overwrites the entire file with `os.WriteFile` — there is no per-key partial write, no temp-file-and-rename, and no file lock, so a crash mid-write can truncate the file and two processes pointing at the same path will clobber each other.
- **Default-path discovery silently falls back.** If `os.UserConfigDir` fails, the constructor falls back to `~/.config` via `os.UserHomeDir`. On platforms where the user config dir differs (notably macOS, where it is `~/Library/Application Support`), the actual location can differ from what tests or docs assume — `Path()` is the source of truth.

## Depends on

- [`client/`](../../DESIGN.md) — `ServerCredential`: FSCredentialStore implements `client.CredentialStore` and stores `client.ServerCredential` values keyed by normalized server URL.
