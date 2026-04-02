# core/ — Foundation Types

Foundation types and interfaces for the OneAuth authentication framework. Every other OneAuth package imports core.

## Contents
- **user.go** — `User` interface, `BasicUser`, `Identity`, `Channel`, `IdentityKey()`, `HandleUserFunc`
- **stores.go** — Store interfaces: `UserStore`, `IdentityStore`, `ChannelStore`, `RefreshTokenStore`, `APIKeyStore`, `UsernameStore`
- **tokens.go** — `TokenType`, `AuthToken`, `RefreshToken`, `APIKey`, `TokenPair`, `TokenRequest`, `TokenError`, `TokenStore`, error vars, expiry constants
- **credentials.go** — `SignupPolicy`, `AuthError`, `Credentials`, validator function types, `DetectUsernameType()`, preset policies
- **scopes.go** — Scope constants (`ScopeRead`, etc.), `GetUserScopesFunc`, `ParseScopes`, `JoinScopes`, `IntersectScopes`
- **email.go** — `SendEmail` interface, `ConsoleEmailSender`
- **context.go** — `GetUserIDFromContext()`, `SetUserIDInContext()`, `DefaultUserParamName`

## Recent Additions
- **ratelimiter.go** — `RateLimiter` interface and `InMemoryRateLimiter` (token-bucket, used by `localauth` and formerly by `apiauth` before being moved here)
- **lockout.go** — `AccountLockout` struct for tracking failed login attempts and temporary account lockouts

## Dependencies
Standard library + `golang.org/x/oauth2` (for `HandleUserFunc`'s `*oauth2.Token` parameter).
