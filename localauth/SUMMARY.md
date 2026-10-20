# localauth/ — Local Username/Password Authentication

Local (form-based) authentication: signup, login, email verification, password reset, credential linking, and channel-aware user creation.

## Contents
- **local.go** — `LocalAuth` struct (login, email verify, forgot/reset password, credential linking handler)
- **Password reset (issue 88)** — tokens are stored as `HashVerificationToken` (SHA-256), consumed via `DeleteToken`→`Deleted` before the password changes, checked against the signup password policy, and followed by `AfterPasswordReset` (`NewRevokeSessionsOnReset` revokes the account's refresh tokens).
- **oidc_claims.go** — `ProfileClaims(users, identities)`: an OIDC `UserClaimsFunc` mapping the local profile to `preferred_username`, `email`/`email_verified`, `phone_number`/`phone_number_verified`, gated by scope (#339). Login and signup pass `user_id` to `HandleUser` so a session names the user by the same ID tokens use
- **signup.go** — `HandleSignup`, form parsing, policy-based validation
- **helpers.go** — `NewCreateUserFunc`, `NewCredentialsValidator`, `NewVerifyEmailFunc`, `NewUpdatePasswordFunc`, `NewEnsureAuthUserFunc`, `LinkLocalCredentials`, `EnsureAuthUserConfig`

## Recent Additions
- **LocalAuth.RateLimiter** — optional `core.RateLimiter` field for per-IP/per-user login rate limiting
- **TrustedProxies + signup / forgot-password limits (issue 88)** — `LocalAuth.TrustedProxies` decides whether X-Forwarded-For is believed; `RateLimiter` also covers signup (per address) and forgot-password (per address and per email).
- **LocalAuth.Lockout** — optional `core.AccountLockout` field for locking accounts after repeated failed attempts
- **Timing oracle fix** — login always performs a bcrypt compare (even for non-existent users) to prevent user enumeration via response timing

## Dependencies
`core/` for all foundation types.

- **Signup enumeration (issue 408):** with `RequireEmailVerification`, a taken email gets the same answer as a fresh one and the owner is mailed through the optional `AccountExistsEmailSender`; the verification response no longer carries `user_id`.
