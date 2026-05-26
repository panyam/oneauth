# accounts/ — Federated End-User Account Model

The data shape shared by both username/password (localauth) and provider-mediated
(federatedauth) authentication flows. This package owns the principal types
and store interfaces — it does NOT own any HTTP handlers.

## Contents
- **user.go** — `User` interface, `BasicUser` struct, `Identity`, `Channel`, `IdentityKey()`, `HandleUserFunc`, `CreateUserFunc`, `DetectUsernameType`, `LinkedChannels`
- **stores.go** — `UserStore`, `IdentityStore`, `ChannelStore`, `UsernameStore`
- **errors.go** — `AuthError`, `AuthErrorHandler`, `ErrCode*` constants, `NewAuthError`, `CredentialsValidator` (function type)

## Who uses this
- [`localauth/`](../localauth/SUMMARY.md) — wires `Channel.Provider="local"` for username/password
- [`federatedauth/`](../federatedauth/SUMMARY.md) — wires `Channel.Provider="google"/"github"/"saml"`
- [`stores/fs/`, `stores/gorm/`, `stores/gae/`](../stores/) — backend implementations
- [`apiauth/`](../apiauth/SUMMARY.md) — for the password-grant `CredentialsValidator`
- [`httpauth/`](../httpauth/SUMMARY.md) — no direct dependency; takes `userID string` only

## Dependencies
Standard library + `golang.org/x/oauth2` (for `HandleUserFunc`'s `*oauth2.Token` parameter).
