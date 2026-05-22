// Package core provides the foundation types and interfaces for the OneAuth
// authentication framework. Every other OneAuth package imports core.
//
// <!-- design:start -->
// core owns OneAuth's foundation layer: the unified account data model
// (User/Identity/Channel), the composed store interfaces every backend
// implements, token and scope value types, RFC 9396 authorization details, and
// a set of pluggable, in-memory security primitives (blacklist, rate limiter,
// account lockout). It deliberately owns no transport, no storage backend, and
// no business policy — those are supplied by sibling packages and app-provided
// callbacks. The notable shape is decomposition: stores are split by concern
// (UserStore, IdentityStore, ChannelStore, RefreshTokenStore, APIKeyStore,
// UsernameStore, TokenStore) rather than one god interface, and the account
// model layers Channels (auth providers) onto Identities (contacts) onto a
// single User, so one account can carry many login methods.
//
// # ENTITIES
//
// User — Account abstraction exposing only Id() and Profile(); an interface so
// backends supply their own row type. BasicUser is the trivial default.
//
// Identity — A verifiable contact (email/phone) owned by one user, carrying a
// Version for optimistic locking. Verification state lives here, per-contact.
//
// Channel — An auth provider (local/google/github) keyed by IdentityKey,
// holding per-provider credentials. ExpiresAt + IsExpired drive re-auth.
//
// IdentityKey — Builds the canonical "type:value" key linking channels to
// identities, the single source of truth for that format.
//
// HandleUserFunc — Post-auth callback (token + userInfo + http writer) where
// apps issue sessions; the seam that keeps core transport-agnostic.
//
// UserStore / IdentityStore / ChannelStore — Composed CRUD/get-or-create
// interfaces for the account model. GetIdentity/GetChannel fold lookup and
// provisioning into one call via a createIfMissing flag.
//
// RefreshTokenStore — Refresh-token lifecycle with rotation and family-based
// theft detection: RotateRefreshToken returns ErrTokenReused on an
// already-revoked token, signaling theft and prompting family revocation.
//
// APIKeyStore — API-key lifecycle. The full key (id_secret) is returned only
// at creation; only the bcrypt hash is stored, so the secret is unrecoverable.
//
// UsernameStore — Optional username uniqueness and atomic rename; optional
// because the unified model keys on identities, not usernames.
//
// TokenStore — Storage for short-lived verification/reset AuthTokens, kept
// distinct from refresh tokens (different lifetimes, no rotation/family).
//
// AuthToken — Verification or reset token; IsValid checks both type and expiry
// to block cross-purpose reuse.
//
// RefreshToken — Long-lived API token carrying Family/Generation, scopes, and
// RFC 9396 details, enabling rotation-with-theft-detection across a lineage.
//
// APIKey — Long-lived programmatic key (public KeyID + bcrypt KeyHash) with
// optional expiry; nil ExpiresAt means never-expires.
//
// TokenPair / TokenRequest / TokenError — OAuth token-endpoint wire types.
// TokenRequest is a union over all grants; Assertion (resource-owner, jwt-bearer)
// and ClientAssertion (client auth) are deliberately separate fields. TokenPair
// carries IssuedTokenType for RFC 8693 token-exchange only.
//
// TokenType + GenerateSecureToken / GenerateAPIKeyID / GenerateAPIKeySecret —
// Token kind enum and centralized crypto/rand generators; the "oa_" key prefix
// keeps keys identifiable in logs.
//
// AuthorizationDetail — A single RFC 9396 authorization_details object. Custom
// JSON marshalling flattens the Extra extension map to the top level and rejects
// extension keys that collide with reserved common fields. Validate requires a
// non-empty Type (the only mandatory field); FilterByType selects by type.
//
// SignupPolicy — Declarative signup requirements with getter methods that supply
// safe fallbacks so a zero-value never yields an invalid regex or zero length.
// Presets: DefaultSignupPolicy, PolicyUsernameRequired, PolicyEmailOnly, and the
// OAuth-friendly all-optional PolicyFlexible.
//
// Credentials — Signup/login input; Email and Phone are pointers so "absent" is
// distinguishable from empty string.
//
// AuthError / AuthErrorHandler — Structured error with Code/Message/Field for
// per-field form rendering; the handler returns false to fall back to core's
// default JSON response.
//
// SignupValidator / CredentialsValidator / CreateUserFunc / GetUserScopesFunc /
// DetectUsernameType — Function-typed seams keeping validation, user creation,
// and scope policy in the app while core owns the flow. DetectUsernameType lets
// one login field accept email/phone/username.
//
// scope helpers — Parse/Join/Intersect/Union/Contains/Validate/Equal over scope
// slices. IntersectScopes restricts (requested vs allowed); UnionScopes merges —
// documented as complements.
//
// TokenBlacklist / InMemoryBlacklist — Revoked-jti tracking until natural
// expiry; pluggable (memory single-node, Redis distributed) with self-expiring
// entries that bound growth.
//
// RateLimiter / InMemoryRateLimiter — Per-key Allow() gate; the in-memory
// token-bucket refills lazily on each call, avoiding a background ticker.
//
// AccountLockout — Per-key consecutive-failure counter that locks after
// MaxAttempts for LockDuration; lockouts self-expire on read, so no sweeper.
//
// SendEmail / ConsoleEmailSender — App-provided email transport seam with a
// console dev stand-in.
//
// GetUserIDFromContext / SetUserIDInContext — Request-context user-ID helpers
// using a private key type to avoid cross-package context-key collisions.
//
// # FLOWS
//
// See [diagrams.md](diagrams.md) for sequence diagrams of: local signup,
// refresh-token rotation with theft detection.
// <!-- design:end -->
//
// The core package contains:
//   - User, Identity, and Channel types (the data model)
//   - Store interfaces (UserStore, IdentityStore, ChannelStore, etc.)
//   - Token types and token store interface
//   - Credentials, signup policies, and validation types
//   - Scope constants and helpers
//   - Email sender interface
//   - Request context helpers (GetUserIDFromContext, SetUserIDInContext)
package core
