# Migration Guide: Sub-Module Split (v0.0.x → v0.1.0)

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
    github.com/panyam/oneauth            v0.1.0
    github.com/panyam/oneauth/stores/gorm v0.1.0  // only if you use GORM stores
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
require github.com/panyam/oneauth v0.1.0

import (
    "github.com/panyam/oneauth/apiauth"
    "github.com/panyam/oneauth/keys"
)
```
**Deps pulled:** jwt/v5, x/crypto. That's it.

### "I want JWT + GORM persistence"
```
require (
    github.com/panyam/oneauth            v0.1.0
    github.com/panyam/oneauth/stores/gorm v0.1.0
)
```

### "I want the full server (everything)"
```
require (
    github.com/panyam/oneauth            v0.1.0
    github.com/panyam/oneauth/stores/gorm v0.1.0
    github.com/panyam/oneauth/stores/gae  v0.1.0
    github.com/panyam/oneauth/saml        v0.1.0
    github.com/panyam/oneauth/grpc        v0.1.0
    github.com/panyam/oneauth/oauth2      v0.1.0
)
```
