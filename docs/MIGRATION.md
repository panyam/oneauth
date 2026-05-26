# Migration Guide

## v0.1.2 → v0.1.3 — Subject vocab (phase 1: token-bearing types)

The principal field on token-bearing types renames from `UserID` to `Subject` to match RFC 7519 / RFC 8693 vocabulary. Affects `core.RefreshToken`, `core.APIKey`, `localauth.VerificationToken`, and the storage interface methods on `RefreshTokenStore`, `APIKeyStore`, and `VerificationTokenStore`.

### Code changes (consumers)

Search-and-replace on your consumer:

```
.UserID                         →  .Subject     (only on RefreshToken / APIKey / VerificationToken instances)
GetUserTokens(                  →  GetSubjectTokens(
RevokeUserTokens(               →  RevokeSubjectTokens(
ListUserAPIKeys(                →  ListSubjectAPIKeys(
DeleteUserTokens(               →  DeleteSubjectTokens(
```

`accounts.Identity.UserID`, `accounts.Username.UserID`, `UserStore`, and the `httpauth` public surface all stay unchanged.

### Stored data migration

#### GORM (Postgres / MySQL / SQLite)

```sql
ALTER TABLE refresh_tokens RENAME COLUMN user_id TO subject;
ALTER TABLE api_keys       RENAME COLUMN user_id TO subject;
ALTER TABLE auth_tokens    RENAME COLUMN user_id TO subject;
-- indexes on user_id are auto-renamed by Postgres/MySQL. On SQLite,
-- drop and recreate the index after the rename.
```

#### Filesystem store

`stores/fs` persists JSON files with a `user_id` field on three token kinds:
`refresh_tokens/*.json`, `api_keys/*.json`, `tokens/*.json`. Rewrite the
field name in place, or **reset the store** (re-issue all tokens / API
keys; users re-verify email).

```bash
# In each affected directory:
for f in refresh_tokens api_keys tokens; do
  find "$f" -name '*.json' -exec sed -i.bak 's/"user_id":/"subject":/g' {} \;
done
```

#### GAE / Datastore

`subject` becomes the new Datastore property name on
`RefreshToken`, `APIKey`, and `AuthToken` kinds. Either run a Datastore
update job to copy `user_id` → `subject` and drop `user_id`, or reset
those kinds. Active filter queries on those kinds also need updating
(they used `FilterField("user_id", ...)` — the library now filters by
`subject`).

If you have no production data on these stores (dev / staging), the
simplest path is to delete those kinds and let the library recreate
them with the new property.

### Easier alternative

If you have no production data persisted yet, just reset the three
token stores and re-issue everything on next login. No SQL needed.

---

# Migration Guide: Sub-Module Split (v0.0.x → v0.0.40)

## What Changed

OneAuth is now split into multiple Go modules. The core module (`github.com/panyam/oneauth`) is lightweight (~6 deps). Heavy backends are separate sub-modules that you import only if you need them.

## Who Is Affected

- **Apps that import `stores/gorm`** — add `github.com/panyam/oneauth/stores/gorm` to your `go.mod`
- **Apps that import `stores/gae`** — add `github.com/panyam/oneauth/stores/gae`
- **Apps that import `saml`** — add `github.com/panyam/oneauth/saml`
- **Apps that import `grpc`** — add `github.com/panyam/oneauth/grpc`
- **Apps that import `oauth2`** — add `github.com/panyam/oneauth/oauth2`
- **Apps that only use `core`, `keys`, `apiauth`, `localauth`, `httpauth`, `admin`, `stores/fs`** — no changes needed

## Migration Steps

### 1. Update go.mod

**Before (single module):**
```
require github.com/panyam/oneauth v0.0.38
```

**After (add sub-modules you use):**
```
require (
    github.com/panyam/oneauth            v0.0.40
    github.com/panyam/oneauth/stores/gorm v0.0.40  // only if you use GORM stores
)
```

### 2. Update imports (if you haven't already)

The subpackage reorganization (v0.0.39) moved types from the root package to subpackages. If you're still on v0.0.38, update imports per the table in CLAUDE.md.

### 3. Run go mod tidy

```bash
go mod tidy
```

## Module Map

| Module | What | Heavy Deps |
|--------|------|-----------|
| `github.com/panyam/oneauth` | Core: types, keys, apiauth, localauth, httpauth, admin, stores/fs | None (jwt, scs, x/crypto, x/oauth2) |
| `.../stores/gorm` | GORM SQL stores | gorm.io/gorm, postgres/sqlite drivers |
| `.../stores/gae` | Google Datastore stores | cloud.google.com/go/datastore + GCP SDK |
| `.../saml` | SAML SP | crewjam/saml, XML libs |
| `.../grpc` | gRPC interceptors | google.golang.org/grpc, protobuf |
| `.../oauth2` | OAuth2 provider clients | golang.org/x/oauth2/google |

## Common Scenarios

### "I just want JWT validation for my API"
```
require github.com/panyam/oneauth v0.0.40

import (
    "github.com/panyam/oneauth/apiauth"
    "github.com/panyam/oneauth/keys"
)
```
**Deps pulled:** jwt/v5, x/crypto. That's it.

### "I want JWT + GORM persistence"
```
require (
    github.com/panyam/oneauth            v0.0.40
    github.com/panyam/oneauth/stores/gorm v0.0.40
)
```

### "I want the full server (everything)"
```
require (
    github.com/panyam/oneauth            v0.0.40
    github.com/panyam/oneauth/stores/gorm v0.0.40
    github.com/panyam/oneauth/stores/gae  v0.0.40
    github.com/panyam/oneauth/saml        v0.0.40
    github.com/panyam/oneauth/grpc        v0.0.40
    github.com/panyam/oneauth/oauth2      v0.0.40
)
```
