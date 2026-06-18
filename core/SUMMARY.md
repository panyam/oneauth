# core/ — Transport-Level Foundation Types

Transport-level types and interfaces used across the OneAuth packages. After the
account-model extraction this package no longer owns user/identity/channel
concepts — those live in [`accounts/`](../accounts/SUMMARY.md) (data shape)
and [`localauth/`](../localauth/SUMMARY.md) (username/password) and
[`federatedauth/`](../federatedauth/SUMMARY.md) (OAuth/SAML callbacks).

## Contents
- **stores.go** — Store interfaces: `RefreshTokenStore`, `APIKeyStore`
- **tokens.go** — `RefreshToken`, `APIKey`, `TokenPair`, `TokenRequest`, `TokenError`, error vars, expiry constants, `GenerateSecureToken`, `GenerateAPIKeyID`, `GenerateAPIKeySecret`
- **scopes.go** — Scope constants (`ScopeRead`, etc.), `GetUserScopesFunc`, `ParseScopes`, `JoinScopes`, `IntersectScopes`, `UnionScopes`
- **context.go** — `GetUserIDFromContext()`, `SetUserIDInContext()`, `DefaultUserParamName`
- **authorization_details.go** — `AuthorizationDetail` struct (RFC 9396), custom JSON marshal/unmarshal with extension flattening, `ValidateAll()`, `FilterByType()`, `ErrInvalidAuthorizationDetails`
- **blacklist.go** — `TokenBlacklist` interface and `InMemoryBlacklist` for jti-based JWT revocation
- **ratelimiter.go** — `RateLimiter` interface and `InMemoryRateLimiter` (token-bucket); also `AccountLockout` for tracking failed login attempts and temporary account lockouts
- **device_authorization.go** — `DeviceAuthorization`, `DeviceAuthorizationStore` interface + `InMemoryDeviceAuthorizationStore`, `UpperUserCode` normalization helper (RFC 8628)
- **authorization_code.go** — `AuthorizationCode`, `AuthorizationCodeStore` interface + `InMemoryAuthorizationCodeStore`, `ErrAuthorizationCodeNotFound` sentinel (RFC 6749 §4.1)

## What moved out (and where)
- `User`, `BasicUser`, `Identity`, `Channel`, `IdentityKey`, `HandleUserFunc`, `UserStore`, `IdentityStore`, `ChannelStore`, `UsernameStore`, `AuthError`, `AuthErrorHandler`, `ErrCode*`, `DetectUsernameType`, `CredentialsValidator`, `LinkedChannels` → [`accounts/`](../accounts/SUMMARY.md)
- `Credentials`, `CreateUserFunc`, `SignupPolicy`, `SignupValidator`, `DefaultSignupValidator`, `Policy*` presets, `SendEmail`, `ConsoleEmailSender`, `AuthToken`/`TokenStore`/`TokenType`/email-verify+password-reset consts (renamed `Verification*`) → [`localauth/`](../localauth/SUMMARY.md)
- `SaveUserAndRedirect`, `HandleLinkOAuthCallback`, `AuthUserStore`, `EnsureAuthUserConfig`, `NewEnsureAuthUserFunc` (provider-driven user creation orchestration) → [`federatedauth/`](../federatedauth/SUMMARY.md)

## Dependencies
Standard library only.
