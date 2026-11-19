# outbound/ — Credentials for calling third-party APIs

The app calling someone else's API, as itself or for one of its users. Each source is an `oauth2.TokenSource`. Design and threat notes: [docs/OUTBOUND_CREDENTIALS.md](../docs/OUTBOUND_CREDENTIALS.md) (issue #467).

## Contents
- **installation.go** — `GitHubAppInstallation`: signs the App JWT (RS256, 9-minute life), trades it for an installation token, caches it until 5 minutes before expiry, one fetch for concurrent callers. `ParseRSAPrivateKeyPEM` reads GitHub's PKCS#1 keys. `GitHubAPIError` carries GitHub's message only.
- **usertoken.go** — `UserTokens` (per provider: `Save`, `Delete`, `TokenSource`) and `StoredUserToken`: sealed with `keys.Sealer`, refreshed and written back with compare-and-swap, waits `RaceWait` for another replica's refresh before `ErrReconnect`.
- **usertoken_store.go** — `UserTokenStore` interface (gRPC shape, CAS on `Version`), `ErrUserTokenNotFound`, `ErrVersionConflict`, `MemoryUserTokenStore`. FS backend: `stores/fs.FSUserTokenStore`. Contract suite: `usertokentest.RunAll`.
- **secretref.go** — `SecretRef` (`env:NAME`, `file:/abs/path`); a bare value is refused. Package doc.
- **static.go** — `Static`: a fixed secret from a `SecretRef`, read on every call.
- **githubtest/** — fake GitHub: checks App JWTs, issues installation tokens and single-use-refresh user tokens, and serves `/user` and `/installation/repositories` for live tokens.

## Dependencies
`keys/` (Sealer), `utils/` (RSA key size), `golang.org/x/oauth2`, `golang-jwt/v5`.
