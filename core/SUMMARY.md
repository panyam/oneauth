# core/ — Foundation Types

Foundation types and interfaces for the OneAuth authentication framework. Every other OneAuth package imports core.

## Contents
- **user.go** — `User` interface, `BasicUser`, `Identity`, `Channel`, `IdentityKey()`, `HandleUserFunc`
- **stores.go** — Store interfaces: `UserStore`, `IdentityStore`, `ChannelStore`, `RefreshTokenStore`, `APIKeyStore`, `UsernameStore`
- **tokens.go** — `TokenType`, `AuthToken`, `RefreshToken`, `APIKey`, `TokenPair`, `TokenRequest`, `TokenError`, `TokenStore`, error vars, expiry constants
- **credentials.go** — `SignupPolicy`, `AuthError`, `Credentials`, validator function types, `DetectUsernameType()`, preset policies
- **scopes.go** — Scope constants (`ScopeRead`, etc.), `GetUserScopesFunc`, `ParseScopes`, `JoinScopes`, `IntersectScopes`, `UnionScopes`
- **email.go** — `SendEmail` interface, `ConsoleEmailSender`
- **context.go** — `GetUserIDFromContext()`, `SetUserIDInContext()`, `DefaultUserParamName`

## Recent Additions
- **blacklist.go** — `TokenBlacklist` interface and `InMemoryBlacklist` for jti-based JWT revocation
- **ratelimiter.go** — `RateLimiter` interface and `InMemoryRateLimiter` (token-bucket)
- **lockout.go** — `AccountLockout` struct for tracking failed login attempts and temporary account lockouts

## Dependencies
Standard library + `golang.org/x/oauth2` (for `HandleUserFunc`'s `*oauth2.Token` parameter).
