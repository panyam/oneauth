# Migration Guide

## Next release — `APIAuth` retired (#298)

The legacy `apiauth.APIAuth` god struct is removed. The new wire-up is `apiauth.NewOneAuth` plus the per-concern HTTP factory methods on the returned `*OneAuth`.

### Code changes (consumers)

Before:

```go
apiAuth := &apiauth.APIAuth{
    JWTSecretKey:           secret,
    JWTIssuer:              issuer,
    JWTAudience:            audience,
    RefreshTokenStore:      refreshStore,
    ValidateCredentials:    validateCreds,
    GetSubjectScopes:       getScopes,
    Blacklist:              blacklist,
    ClientKeyStore:         keyStore,
    ClientAuthenticator:    customAuthenticator, // optional
    AcceptedAudiences:      []string{"https://as/api/token"},
    TrustedAssertionIssuers: trustedIssuers,
    DeviceAuthStore:        deviceStore,
    AuthorizationCodeStore: codeStore,
    AppStore:               appStore,
    TracerProvider:         tp,
    TokenHooks:             tokenHooks,
    CustomClaimsFunc:       customClaims,
    // JWTSigningAlg / JWTSigningKey / JWTVerifyKey for asymmetric setups
}

mux.HandleFunc("POST /api/token", apiAuth.ServeHTTP)
mux.HandleFunc("POST /api/logout", apiAuth.HandleLogout)
mux.HandleFunc("POST /api/logout-all", apiAuth.HandleLogoutAll)
mux.HandleFunc("GET /api/sessions", apiAuth.HandleListSessions)
mux.HandleFunc("GET /api/keys", apiAuth.HandleAPIKeys)
mux.HandleFunc("DELETE /api/keys/", apiAuth.HandleRevokeAPIKey)
mux.Handle("POST /oauth/introspect", apiauth.NewIntrospectionHandler(apiAuth, keyStore))
mux.Handle("POST /oauth/revoke", apiauth.NewRevocationHandler(apiAuth, keyStore))
```

After:

```go
oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
    KeyStore:                keyStore,    // was ClientKeyStore — KeyStorage implements KeyLookup
    SigningKey:              []byte(secret), // for asymmetric: pass the private key directly
    SigningAlg:              "HS256",        // was JWTSigningAlg
    VerifyKey:               nil,            // asymmetric: public key for the validator (omit for HS256)
    Issuer:                  issuer,         // was JWTIssuer
    Audience:                audience,       // was JWTAudience
    RefreshStore:            refreshStore,   // was RefreshTokenStore
    ValidateCredentials:     validateCreds,
    GetSubjectScopes:        getScopes,
    Blacklist:               blacklist,
    Authenticator:           customAuthenticator,
    AcceptedAudiences:       []string{"https://as/api/token"},
    TrustedAssertionIssuers: trustedIssuers,
    DeviceAuthStore:         deviceStore,
    AuthorizationCodeStore:  codeStore,
    AppStore:                appStore,
    TracerProvider:          tp,
    Hooks:                   apiauth.Hooks{Token: tokenHooks}, // was top-level TokenHooks
    CustomClaims:            customClaims,                     // was CustomClaimsFunc
})

tokenEndpoint := apiauth.NewTokenEndpointHandler(oa)
sessions := oa.SessionsHTTPHandler()
apiKeys := oa.APIKeysHTTPHandler(apiKeyStore, getScopes)

mux.Handle("POST /api/token", tokenEndpoint)
mux.HandleFunc("POST /api/logout", sessions.HandleLogout)
mux.HandleFunc("POST /api/logout-all", sessions.HandleLogoutAll)
mux.HandleFunc("GET /api/sessions", sessions.HandleListSessions)
mux.HandleFunc("GET /api/keys", apiKeys.HandleAPIKeys)
mux.HandleFunc("DELETE /api/keys/", apiKeys.HandleRevokeAPIKey)
mux.Handle("POST /oauth/introspect", oa.IntrospectionHTTPHandler())
mux.Handle("POST /oauth/revoke", oa.RevocationHTTPHandler())
```

Field-by-field mapping for the swap:

```
APIAuth.JWTSecretKey         →  OneAuthConfig.SigningKey ([]byte) + .SigningAlg "HS256"
APIAuth.JWTSigningKey        →  OneAuthConfig.SigningKey (private key) + .SigningAlg
APIAuth.JWTVerifyKey         →  OneAuthConfig.VerifyKey (public key)
APIAuth.JWTSigningAlg        →  OneAuthConfig.SigningAlg
APIAuth.JWTIssuer            →  OneAuthConfig.Issuer
APIAuth.JWTAudience          →  OneAuthConfig.Audience
APIAuth.RefreshTokenStore    →  OneAuthConfig.RefreshStore
APIAuth.ClientKeyStore       →  OneAuthConfig.KeyStore   (KeyStorage implements KeyLookup)
APIAuth.ClientAuthenticator  →  OneAuthConfig.Authenticator
APIAuth.CustomClaimsFunc     →  OneAuthConfig.CustomClaims
APIAuth.TokenHooks           →  OneAuthConfig.Hooks.Token
APIAuth.OnLoginSuccess (deprecated field) → OneAuthConfig.Hooks.Auth.OnLoginSuccess (signature drops *http.Request)
APIAuth.OnLoginFailure (deprecated field) → OneAuthConfig.Hooks.Auth.OnLoginFailure (signature drops *http.Request)
APIAuth.ServeHTTP            →  apiauth.NewTokenEndpointHandler(oa)
APIAuth.HandleLogout / HandleLogoutAll / HandleListSessions → oa.SessionsHTTPHandler()
APIAuth.HandleAPIKeys / HandleRevokeAPIKey                  → oa.APIKeysHTTPHandler(apiKeyStore, getScopes)
APIAuth.ApproveDeviceAuthorization / DenyDeviceAuthorization → call core.DeviceAuthorizationStore.Approve... / Deny... directly
apiauth.NewIntrospectionHandler(apiAuth, ks)                → oa.IntrospectionHTTPHandler()
apiauth.NewRevocationHandler(apiAuth, ks)                   → oa.RevocationHTTPHandler()
DeviceFlowMountConfig.APIAuth  → DeviceFlowMountConfig.OneAuth
AuthorizeMountConfig.APIAuth   → AuthorizeMountConfig.OneAuth
```

### Test fixtures

Tests that constructed `&apiauth.APIAuth{...}` for assertions on issued tokens should construct a `*OneAuth` and either keep references to the relevant handlers or use a small fixture struct that bundles them. See `apiauth/test_helpers_test.go` for a working example.

### Behavioral notes

- `Hooks.Auth.OnLoginSuccess` / `OnLoginFailure` no longer carry `*http.Request` — wrap with HTTP middleware if you need IP / user-agent details.
- `TokenEndpointHandler.handleClientCredentials` calls `Issuer.CreateAccessToken` directly with the already-authenticated `client_id`. The legacy code path delegated to `Issuer.ClientCredentials`, which re-validated the secret — fine for `client_secret_basic` / `client_secret_post` but it broke `private_key_jwt`. The new shape is uniformly correct across all four token-endpoint auth methods.
- BCL hooks (`Hooks.Token.OnSubjectRevoked` / `OnTokenRevoked`) are snapshotted by `NewOneAuth`. Configure them in `OneAuthConfig.Hooks` before calling the constructor; do not mutate `oa.Hooks.Token` afterwards — `TokenRevoker` and `SessionsHandler` will not see the change.

## v0.1.3 → v0.1.4 — Subject vocab (phase 2: consumers, helpers, transports)

Completes the rename started in v0.1.3. Go API surfaces that handle the *principal-of-a-token* concept move from **UserID** to **Subject**. Account-model types (`accounts.User`, `accounts.Identity.UserID`, etc.) remain untouched.

### Code changes (consumers)

Search-and-replace on your consumer:

```
core.GetUserIDFromContext         →  core.GetSubjectFromContext
core.SetUserIDInContext           →  core.SetSubjectInContext
core.DefaultUserParamName         →  core.DefaultSubjectParamName
core.GetUserScopesFunc            →  core.GetSubjectScopesFunc
core.DefaultGetUserScopes         →  core.DefaultGetSubjectScopes
apiauth.GetUserIDFromAPIContext   →  apiauth.GetSubjectFromAPIContext
APIAuth.GetUserScopes             →  GetSubjectScopes
JWTIssuerConfig.GetUserScopes     →  GetSubjectScopes
OneAuthConfig.GetUserScopes       →  GetSubjectScopes
PasswordGrantResponse.UserID      →  .Subject
TokenInfo.UserID                  →  .Subject
Middleware.UserParamName          →  SubjectParamName
Middleware.GetLoggedInUserId(     →  Middleware.GetLoggedInSubject(
OneAuth.SetLoggedInUserID(        →  OneAuth.SetLoggedInSubject(
grpc.UserIDFromContext            →  grpc.SubjectFromContext
grpc.UserIDFromContextWithConfig  →  grpc.SubjectFromContextWithConfig
grpc.UserIDToOutgoingContext      →  grpc.SubjectToOutgoingContext
grpc.DefaultMetadataKeyUserID     →  grpc.DefaultMetadataKeySubject
grpc.Config.MetadataKeyUserID     →  grpc.Config.MetadataKeySubject
```

### Session invalidation (no code action needed)

The session-cookie key flipped from `loggedInUserId` to `loggedInSubject`. Cookies issued by ≤ v0.1.3 are not recognised — users re-login on next visit. No SQL or session-store migration needed.

### gRPC fleet upgrade

The metadata header changed from `x-user-id` to `x-subject`. Upgrade gRPC clients and servers together. `SwitchUserTo*` and `x-switch-user` are unchanged (impersonation is human-user-scoped).

---

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
