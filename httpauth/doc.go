// Package httpauth provides session-based HTTP auth glue plus standalone
// middleware for CSRF, security headers, and request body limits.
//
// This package is the HTTP-facing layer of OneAuth. OneAuth is the top-level
// coordinator: it owns a ServeMux, an scs session manager, JWT minting and
// verification, and the login/logout cookie lifecycle, mounting OAuth
// provider handlers under prefixes and acting as the callback sink that
// turns a verified identity into session and JWT cookies. Around that core
// sit four independent, composable net/http middlewares — request user
// resolution, CSRF protection, request body limits, and security headers —
// each usable on its own. The package does not implement OAuth providers
// or token issuance itself; it wires stores (UserStore + IdentityStore +
// ChannelStore) and a pluggable token verifier together. Note the JWT
// secret defaults to a hardcoded value when neither the field nor
// ONEAUTH_JWT_SECRET_KEY is set, which is fine for tests but unsafe in
// production.
//
// ENTITIES
//
// OneAuth — top-level session-auth coordinator owning the mux, scs session
// manager, JWT minting/verification, and login/logout cookie lifecycle.
//
// AuthUserStore — composite store (UserStore + IdentityStore +
// ChannelStore) whose EnsureAuthUser is the OAuth/local user-creation
// entry point.
//
// New — constructs a OneAuth for the given app name and applies defaults.
//
// OneAuth.EnsureDefaults — idempotently fills app name, session timeout,
// JWT issuer/secret, cookie name, and wires verifyJWT as the default
// token verifier.
//
// OneAuth.Handler — returns the configured ServeMux after lazy route
// setup.
//
// OneAuth.AddAuth — mounts a provider handler under a prefix with subtree
// matching plus a 308 redirect from the bare prefix (308 preserves POST).
//
// OneAuth.SaveUserAndRedirect — OAuth callback sink: ensures the user,
// sets login cookies, and redirects to the single-use oauthCallbackURL.
//
// OneAuth.HandleLinkOAuthCallback — links an OAuth provider to an
// existing local user only after the OAuth email matches the account
// email.
//
// OneAuth.StartLinkOAuth — stashes the user ID under linkingUserID in
// session to flag a later callback as a linking flow.
//
// OneAuth.GetLinkingUserID — pops (reads and clears) the linkingUserID
// value.
//
// LinkOAuthConfig — bundles the three stores needed by the link callback.
//
// Middleware — request-scoped user resolver reading the user ID from
// context, session, or Authorization header/cookie via a pluggable
// VerifyToken.
//
// Middleware.EnsureReasonableDefaults — backfills param/header names.
//
// Middleware.GetLoggedInUserId — resolves the user ID across context,
// session, and bearer tokens/cookies, truncating tokens in logs.
//
// Middleware.ExtractUser — loads the user ID into context without
// enforcing presence (anonymous-friendly).
//
// Middleware.EnsureUser — requires a logged-in user, redirecting (302) to
// login when GetRedirURL is set, else returning 401.
//
// CSRFMiddleware — double-submit-cookie CSRF protector; cookie is
// intentionally non-HttpOnly so JS can echo it, and bearer requests are
// exempt by default.
//
// CSRFMiddleware.Protect — issues a token cookie on safe methods and
// validates a matching token (constant-time compare) on unsafe methods.
//
// CSRFToken — extracts the CSRF token from request context (empty if
// inactive).
//
// CSRFTemplateField — renders an HTML-escaped hidden input carrying the
// token.
//
// LimitBody — middleware rejecting oversized bodies with 413 and wrapping
// the body in MaxBytesReader to cover chunked transfers (CWE-400).
//
// LimitBodyReader — in-handler helper wrapping the body with
// MaxBytesReader.
//
// IsBodyTooLargeError — detects a MaxBytesReader limit-exceeded error.
//
// DefaultMaxBodySize — default 1MB body size cap.
//
// SecurityHeaders — middleware applying the default OWASP header set.
//
// SecurityHeadersConfig — per-header config where "" (or 0 for HSTS)
// disables an individual header.
//
// DefaultSecurityHeadersConfig — returns the secure-by-default header
// set.
//
// SecurityHeadersWithConfig — middleware applying a caller-supplied
// header set.
//
// FLOWS
//
// See diagrams.md for sequence diagrams of: OAuth login callback
// lifecycle (SaveUserAndRedirect), EnsureUser request gate, and CSRF
// double-submit validation (Protect).
package httpauth
