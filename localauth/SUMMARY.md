# localauth/ — Local Username/Password Authentication

Local (form-based) authentication: signup, login, email verification, password reset, credential linking, and channel-aware user creation.

## Contents
- **local.go** — `LocalAuth` struct (login, email verify, forgot/reset password, credential linking handler)
- **signup.go** — `HandleSignup`, form parsing, policy-based validation
- **helpers.go** — `NewCreateUserFunc`, `NewCredentialsValidator`, `NewVerifyEmailFunc`, `NewUpdatePasswordFunc`, `NewEnsureAuthUserFunc`, `LinkLocalCredentials`, `EnsureAuthUserConfig`

## Dependencies
`core/` for all foundation types.
