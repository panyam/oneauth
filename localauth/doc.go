// Package localauth provides HTTP handlers and store-backed callbacks for
// local username/password authentication — signup, login, email verification,
// password reset, and linking local credentials onto existing OAuth users.
//
// The package centers on LocalAuth, a configuration-as-struct type whose
// optional fields decide which features are live: a nil TokenStore disables
// password reset, a nil EmailSender disables verification emails, and so on,
// rather than failing at construction. Its methods are thin HTTP handlers
// (ServeHTTP for login, HandleSignup, HandleVerifyEmail, the forgot/reset
// password pair, and HandleLinkCredentials) that parse forms (url-encoded,
// multipart, or JSON), enforce policy, and delegate persistence to callback
// functions. Those callbacks (VerifyEmailFunc, UpdatePasswordFunc,
// core.CredentialsValidator, core.CreateUserFunc) are built from the New*Func
// constructors, which close over the User/Identity/Channel stores so the
// handlers stay store-agnostic. The data model is channel-aware: a User has
// one Identity per email/phone, and multiple Channels (local, google, github)
// keyed by the same identity, with profile["channels"] tracking linked
// providers. Passwords are bcrypt-hashed; missing-user login runs bcrypt
// against a dummy hash to defeat a CWE-208 timing oracle; forgot-password
// always reports success to prevent account enumeration; reset forms embed
// tokens via html/template escaping to prevent XSS.
//
// ENTITIES
//
// LocalAuth — config-as-struct holding validators, stores, email sender,
// policy, and error handlers; drives all handler behavior via which fields
// are set.
//
// LocalAuth.ServeHTTP — login handler; parses credentials, applies rate
// limiting and account lockout (both before validation, keyed by
// IP:username), validates, and fires HandleUser on success.
//
// LocalAuth.HandleSignup — registration handler; validates against policy or
// legacy validator, enforces username uniqueness, creates the user,
// optionally emails a verification link, and auto-logs-in unless
// verification is both required and configured.
//
// LocalAuth.HandleVerifyEmail — verifies an email-verification token from
// the ?token query param via the VerifyEmail callback.
//
// LocalAuth.HandleForgotPasswordForm — GET handler; redirects to
// ForgotPasswordURL or renders a built-in HTML form.
//
// LocalAuth.HandleForgotPassword — POST handler; mints a reset token and
// emails the link, always returning success to avoid revealing whether the
// email exists.
//
// LocalAuth.HandleResetPasswordForm — GET handler; redirects to
// ResetPasswordURL or renders a built-in form with the token
// html/template-escaped (G705).
//
// LocalAuth.HandleResetPassword — POST handler; validates token and type,
// enforces an inline 8-char minimum, updates the password, and deletes the
// one-time token.
//
// LocalAuth.HandleLinkCredentials — returns a protected-route handler that
// adds a local password (and optional username) to a logged-in OAuth-only
// user; needs a caller-supplied GetLoggedInUserFunc and maps "already exist"
// to 409 Conflict.
//
// VerifyEmailFunc — func(token) error callback for email verification;
// built by NewVerifyEmailFunc.
//
// UpdatePasswordFunc — func(email, newPassword) error callback; built by
// NewUpdatePasswordFunc.
//
// GetLoggedInUserFunc — app-supplied func(r) (userID, error) resolving the
// current session user; localauth has no session model of its own.
//
// LinkCredentialsConfig — store bundle for HandleLinkCredentials, converted
// internally to EnsureAuthUserConfig.
//
// EnsureAuthUserConfig — User/Identity/Channel (plus optional Username)
// store bundle shared by the ensure-user and linking helpers.
//
// NewCreateUserFunc — builds core.CreateUserFunc creating User + unverified
// Identity + local Channel with a bcrypt hash; rejects if the identity
// already exists.
//
// NewCredentialsValidator — builds an email/phone login validator; runs
// bcrypt against a dummy hash on missing user (CWE-208) and does not
// support username login.
//
// NewCredentialsValidatorWithUsername — adds username login (resolved via
// UsernameStore to the email identity) with fallback to email/phone; lacks
// the dummy-hash defense.
//
// NewVerifyEmailFunc — builds a VerifyEmailFunc that checks token type,
// marks the email identity verified, and deletes the token (deletion
// failure is non-fatal).
//
// NewUpdatePasswordFunc — builds an UpdatePasswordFunc that rehashes and
// stores the new password, auto-creating a local channel for OAuth-only
// users.
//
// NewEnsureAuthUserFunc — builds the AuthUserStore.EnsureAuthUser logic;
// links a new channel to an email-matched existing user or creates
// user/identity/channel afresh (OAuth identities verified, local
// unverified).
//
// LinkLocalCredentials — adds a local password channel to an existing user,
// reserves the username, and appends "local" to profile["channels"];
// verifies email ownership and rejects if a local channel already exists.
//
// FLOWS
//
// See diagrams.md for sequence diagrams of: signup (with optional email
// verification), login (with rate-limit and account lockout), password
// reset (forgot then reset), and channel linking via NewEnsureAuthUserFunc.
package localauth
