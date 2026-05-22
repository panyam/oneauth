---
package: localauth
purpose: Form-based local username/password authentication — signup, login, email verification, password reset, and channel-aware/incremental credential linking — built on top of core store interfaces.
last_rebuilt: ca8a742623b748f06d2564dce90465d1eeb10c6d
entities:
  - name: LocalAuth
    kind: struct
    role: Central config-and-handler object holding all wiring (callbacks, stores, URLs, policy, rate limiter, lockout) and exposing the HTTP handlers for login/signup/verify/reset/link.
    why: Deliberately a flat bag of optional fields rather than a constructor — every capability (email verification, token store, lockout, username uniqueness) is opt-in by leaving a field nil, so apps wire only what they use.
  - name: VerifyEmailFunc
    kind: type (func)
    role: Callback `func(token string) error` invoked to mark an email verified given a verification token.
    why: Indirection so LocalAuth never touches the identity/token stores directly — the app supplies the function (typically via NewVerifyEmailFunc), keeping the handler store-agnostic.
  - name: UpdatePasswordFunc
    kind: type (func)
    role: Callback `func(email, newPassword string) error` invoked during password reset to persist a new password.
    why: Same decoupling rationale as VerifyEmailFunc; also lets the supplied impl create a local channel on the fly for OAuth-only users (see NewUpdatePasswordFunc).
  - name: LocalAuth.ServeHTTP
    kind: method
    role: Login handler — parses credentials, applies rate limit + lockout, validates, and on success calls HandleUser.
    why: Rate-limit and lockout checks run BEFORE credential validation specifically to prevent a timing bypass that would let attackers probe past the limiter.
  - name: LocalAuth.HandleSignup
    kind: method
    role: Registration handler — parses form, validates against policy, enforces username uniqueness, creates user, optionally sends verification email, then auto-logs-in unless verification is required.
    why: Username reservation and verification-email failures are logged but never fail the signup (user already created) — avoids leaving a half-created account; auto-login is suppressed only when RequireEmailVerification AND an EmailSender exist.
  - name: LocalAuth.HandleVerifyEmail
    kind: method
    role: Verifies an email via the `?token=` query param using the VerifyEmail callback.
    why: Returns JSON success rather than redirecting — rendering/redirect is left to the app layer.
  - name: LocalAuth.HandleForgotPassword / HandleForgotPasswordForm
    kind: method
    role: Issues a password-reset token and emails a reset link (POST); GET renders a form or redirects.
    why: Always returns generic success even when the email/token creation fails — deliberate to avoid revealing whether an email is registered (account enumeration defense).
  - name: LocalAuth.HandleResetPassword / HandleResetPasswordForm
    kind: method
    role: Validates a reset token, enforces min length, updates the password, and deletes the token (one-time use).
    why: GET form embeds the token via html/template HTMLEscapeString to prevent reflected XSS (G705); token deletion failure is only warned, not fatal.
  - name: LinkCredentialsConfig
    kind: struct
    role: Dependency bundle (UserStore, IdentityStore, ChannelStore, optional UsernameStore) for the HandleLinkCredentials handler.
    why: Separate from EnsureAuthUserConfig at the type level but structurally identical — kept distinct so the link-credentials handler's surface reads independently (it converts via EnsureAuthUserConfig() internally).
  - name: GetLoggedInUserFunc
    kind: type (func)
    role: App-supplied `func(r) (userID, error)` that extracts the current user from session/JWT.
    why: localauth has no opinion on session handling, so incremental-auth linking requires the app to bridge its own auth state in.
  - name: LocalAuth.HandleLinkCredentials
    kind: method
    role: Protected handler that adds local (password) auth to an existing OAuth-only user.
    why: Maps the "already exists" error to 409 Conflict via string matching on the error message — a string-sniff coupling between this handler and LinkLocalCredentials' error text (a gotcha if either side changes wording).
  - name: NewCreateUserFunc
    kind: constructor (func)
    role: Builds a core.CreateUserFunc from the three stores — creates User + Identity (verified=false) + local Channel with a bcrypt password hash.
    why: Signup-created identities are unverified by design (email not yet proven); requires email or phone, errors otherwise.
  - name: NewCredentialsValidator
    kind: constructor (func)
    role: Builds a core.CredentialsValidator that looks up the local channel by email/phone identity and bcrypt-compares the password.
    why: On user-not-found it still runs bcrypt against dummyBcryptHash to keep response time constant (CWE-208 timing oracle / enumeration defense); username-type login is explicitly unsupported here.
  - name: NewCredentialsValidatorWithUsername
    kind: constructor (func)
    role: Variant validator that additionally resolves a username via UsernameStore to the user's email identity before password check; falls back to email/phone lookup.
    why: Separate constructor rather than a flag because username login needs an extra store (UsernameStore) and an indirection through the user's email identity; notably it does NOT include the dummy-bcrypt timing defense the email-only validator has.
  - name: NewVerifyEmailFunc
    kind: constructor (func)
    role: Builds a VerifyEmailFunc that checks token type, marks the email identity verified, and deletes the token.
    why: Enforces one-time-use by deleting the token; type-check guards against a reset token being replayed as a verification token.
  - name: NewUpdatePasswordFunc
    kind: constructor (func)
    role: Builds an UpdatePasswordFunc that re-hashes and stores the password, creating a local channel if none exists.
    why: Auto-creates the local channel so an OAuth-only user can establish a password purely via the reset flow (incremental auth without a separate link step).
  - name: EnsureAuthUserConfig
    kind: struct
    role: Dependency bundle for NewEnsureAuthUserFunc and the linking helpers.
    why: Single shared config type lets OAuth user-creation and local credential linking share the same channel-linking machinery.
  - name: NewEnsureAuthUserFunc
    kind: constructor (func)
    role: Builds the AuthUserStore.EnsureAuthUser logic — given email, either links a new channel to an existing user or creates a fresh user+identity+channel.
    why: Email is the linking key across providers (local/google/github point to one user); OAuth-sourced identities are created verified (authtype=="oauth"), local ones are not — trust follows the provider.
  - name: LinkLocalCredentials
    kind: func
    role: Adds a local password channel to an existing user after verifying the email belongs to that user, reserving username, and updating profile["channels"].
    why: Rejects if a local channel already exists (no silent overwrite); username reservation and profile update failures are warned-not-fatal since the credential channel is the source of truth.
  - name: generateSecureUserId
    kind: func
    role: Generates a 16-byte hex user ID via crypto/rand.
    why: Crypto-random (not sequential/UUID-lib) so IDs are unguessable and the package carries no extra ID dependency.
  - name: getClientIP
    kind: func
    role: Extracts client IP from X-Forwarded-For / X-Real-IP / RemoteAddr for rate-limit keying.
    why: Trusts proxy headers first — correct behind a trusted reverse proxy, but a spoofing vector if exposed directly (deployment gotcha).
depends_on:
  - folder: core
    entities: [AccountLockout, AuthError, AuthErrorHandler, BasicUser, Channel, ChannelStore, CreateUserFunc, Credentials, CredentialsValidator, DefaultSignupPolicy, DefaultSignupValidator, DetectUsernameType, ErrCodeEmailExists, ErrCodeInvalidCreds, ErrCodeInvalidEmail, ErrCodeInvalidPhone, ErrCodeInvalidUsername, ErrCodeMissingField, ErrCodeUsernameTaken, ErrCodeWeakPassword, HandleUserFunc, Identity, IdentityKey, IdentityStore, NewAuthError, RateLimiter, SendEmail, SignupPolicy, SignupValidator, TokenExpiryEmailVerification, TokenExpiryPasswordReset, TokenStore, TokenTypeEmailVerification, TokenTypePasswordReset, User, UsernameStore, UserStore]
---

# localauth

Local, form-based authentication for OneAuth. The package is a thin HTTP layer over the `core` store interfaces; it owns no storage itself and instead receives behavior through callback fields on `LocalAuth` (`ValidateCredentials`, `CreateUser`, `VerifyEmail`, `UpdatePassword`, `HandleUser`). The `New*Func` constructors in `helpers.go` are the canonical implementations of those callbacks, wired from `UserStore` / `IdentityStore` / `ChannelStore` / `TokenStore` / `UsernameStore`.

Three flows live here:

- **Signup** (`signup.go`): parse → validate (policy-based via `SignupPolicy`, or the deprecated `ValidateSignup` legacy validator) → uniqueness check → create user → optional verification email → auto-login or "verify your email". Created identities start unverified.
- **Login** (`local.go` `ServeHTTP`): rate-limit/lockout gates first, then credential validation, then `HandleUser`. The validator and lockout cooperate to defend against brute force and (via the dummy-bcrypt trick) user enumeration.
- **Password reset / email verification** (`local.go` + `helpers.go`): token-store backed, one-time-use tokens, generic responses on the forgot-password path to avoid leaking which emails exist.

A fourth concern, **channel linking / incremental auth**, threads through `helpers.go` (`NewEnsureAuthUserFunc`, `LinkLocalCredentials`) and `local.go` (`HandleLinkCredentials`): a single user may have multiple provider channels (local, google, github) keyed off a shared email identity, with the linked set tracked in `profile["channels"]`.

Two non-obvious asymmetries worth flagging: (1) only the email/phone validator carries the constant-time dummy-bcrypt enumeration defense — `NewCredentialsValidatorWithUsername` does not; (2) `HandleLinkCredentials` detects the conflict case by substring-matching the error string returned from `LinkLocalCredentials`, a brittle coupling between the two.
