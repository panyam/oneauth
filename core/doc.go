// Package core provides the foundation types, store interfaces, and pluggable
// security primitives shared by every OneAuth package.
//
// core owns OneAuth's foundation layer: the unified account data model
// (User/Identity/Channel), the composed store interfaces every backend
// implements, token and scope value types, RFC 9396 authorization details,
// and a set of pluggable in-memory security primitives (blacklist, rate
// limiter, account lockout). It deliberately owns no transport, no storage
// backend, and no business policy — those are supplied by sibling packages
// and app-provided callbacks. The notable shape is decomposition: stores
// are split by concern (UserStore, IdentityStore, ChannelStore,
// RefreshTokenStore, APIKeyStore, UsernameStore, TokenStore) rather than
// one god interface, and the account model layers Channels (auth providers)
// onto Identities (contacts) onto a single User, so one account can carry
// many login methods.
//
// ENTITIES
//
// User — Account abstraction exposing only Id() and Profile(); an interface
// so backends supply their own row type. BasicUser is the trivial default.
//
// BasicUser — Trivial in-memory User implementation; the default for
// callers and tests that have no backing store row.
//
// Identity — A verifiable contact (email/phone) owned by one user, carrying
// a Version for optimistic locking. Verification state lives here,
// per-contact.
//
// Channel — An auth provider (local/google/github) keyed by IdentityKey,
// holding per-provider credentials. ExpiresAt and IsExpired drive re-auth.
//
// IdentityKey — Builds the canonical "type:value" key linking channels to
// identities; the single source of truth for that format.
//
// HandleUserFunc — Post-auth callback (token plus userInfo plus http
// writer) where apps issue sessions; the seam that keeps core
// transport-agnostic.
//
// UserStore — CRUD plus get-or-create for User rows. Decomposed by concern
// so backends do not implement a god interface.
//
// IdentityStore — Manage Identity rows with verification and
// user-association. GetIdentity folds lookup and provisioning into one call
// via a createIfMissing flag.
//
// ChannelStore — Manage Channel rows keyed by provider plus identity key.
// Mirrors IdentityStore's get-or-create shape for consistency.
//
// RefreshTokenStore — Refresh-token lifecycle with rotation and family-based
// theft detection: RotateRefreshToken returns ErrTokenReused on an
// already-revoked token, signaling theft and prompting family revocation.
//
// APIKeyStore — API-key lifecycle. The full key (id_secret) is returned
// only at creation; only the bcrypt hash is stored, so the secret is
// unrecoverable.
//
// UsernameStore — Optional username uniqueness and atomic rename; optional
// because the unified model keys on identities, not usernames.
//
// TokenStore — Storage for short-lived verification and reset AuthTokens,
// kept distinct from refresh tokens (different lifetimes, no
// rotation/family).
//
// AuthToken — Verification or reset token; IsValid checks both type and
// expiry to block cross-purpose reuse.
//
// TokenType — Enum of token kinds (email_verification, password_reset,
// refresh); one typed namespace so AuthToken.IsValid can compare safely.
//
// RefreshToken — Long-lived API token carrying Family, Generation, scopes,
// and RFC 9396 details, enabling rotation-with-theft-detection across a
// lineage.
//
// APIKey — Long-lived programmatic key (public KeyID plus bcrypt KeyHash)
// with optional expiry; nil ExpiresAt means never-expires.
//
// TokenPair — OAuth token-endpoint success response payload. Carries
// IssuedTokenType for RFC 8693 token-exchange responses only.
//
// TokenRequest — OAuth token-endpoint request payload, a union over grant
// types. Keeps Assertion (resource-owner, jwt-bearer) and ClientAssertion
// (client authentication) deliberately separate.
//
// TokenError — OAuth 2.0 wire-format error envelope (error,
// error_description) so every transport emits identically.
//
// GenerateSecureToken — Crypto-random 32-byte hex token generator;
// centralizes randomness so callers cannot roll weak tokens.
//
// GenerateAPIKeyID — Generates a key ID prefixed with "oa_"; the prefix
// keeps API keys identifiable in logs and grep.
//
// GenerateAPIKeySecret — Generates the secret half of an API key; pairs
// with GenerateAPIKeyID and is what gets bcrypted.
//
// AuthorizationDetail — A single RFC 9396 authorization_details object.
// Custom JSON marshalling flattens the Extra extension map to the top level
// and rejects extension keys that collide with reserved common fields.
//
// AuthorizationDetail.Validate — Requires a non-empty Type (the only
// mandatory RFC 9396 field).
//
// ValidateAll — Validates a slice of AuthorizationDetail; convenience over
// per-item Validate when handling a request list.
//
// FilterByType — Selects details by Type so callers can route subsets to
// different policy handlers.
//
// ErrInvalidAuthorizationDetails — Sentinel error for malformed
// authorization_details per RFC 9396 section 5.2.
//
// SignupPolicy — Declarative signup requirements with getter methods that
// supply safe fallbacks so a zero-value never yields an invalid regex or
// zero length. Presets: DefaultSignupPolicy, PolicyUsernameRequired,
// PolicyEmailOnly, and the OAuth-friendly all-optional PolicyFlexible.
//
// Credentials — Signup/login input; Email and Phone are pointers so absent
// is distinguishable from empty string.
//
// AuthError — Structured error with Code, Message, Field for per-field
// form rendering and machine-readable codes.
//
// AuthErrorHandler — Pluggable error renderer; returns true if it wrote
// the response, false to fall back to core's default JSON.
//
// SignupValidator / CredentialsValidator / CreateUserFunc — Function-typed
// seams keeping validation and user creation in the app while core owns
// the flow.
//
// DefaultSignupValidator — Sensible default signup validation (length,
// format, email/phone presence) most apps can use unmodified.
//
// DetectUsernameType — Heuristically classifies a login field as email,
// phone, or username so one input can accept all three.
//
// GetUserScopesFunc — Callback that returns the allowed scopes for a user;
// scope policy stays app-defined (roles, groups, plan).
//
// DefaultGetUserScopes — Returns a default callback granting
// read/write/profile/offline to all users for callers without their own.
//
// ParseScopes / JoinScopes — Round-trip the OAuth space-separated scope
// wire format, deduplicated.
//
// IntersectScopes / UnionScopes — Restrict (requested vs allowed) and
// merge (existing plus new), documented as complements.
//
// ContainsScope / ContainsAllScopes — Membership and all-of checks at
// handler boundaries for protected endpoints.
//
// ValidateRequestedScopes — Splits requested scopes into valid/invalid
// against an allowed set, driving standards-compliant invalid_scope
// responses.
//
// ScopesEqual — Order-independent scope-slice equality so callers do not
// have to normalise.
//
// TokenBlacklist — Revoked-jti tracking until natural expiry; pluggable
// (memory single-node, Redis distributed) with the same shape.
//
// InMemoryBlacklist — Thread-safe in-memory TokenBlacklist with
// CleanupExpired sweeper; bounded growth via self-expiring entries.
//
// RateLimiter — Per-key Allow() gate that decouples rate policy from the
// limiter implementation.
//
// InMemoryRateLimiter — Token-bucket RateLimiter; refills lazily on each
// call, avoiding a background ticker, with CleanupStale to drop abandoned
// keys.
//
// AccountLockout — Per-key consecutive-failure counter that locks after
// MaxAttempts for LockDuration; lockouts self-expire on read, so no
// sweeper.
//
// SendEmail — App-provided email transport seam for verification and
// password-reset emails; keeps SMTP/SES wiring out of core.
//
// ConsoleEmailSender — Development SendEmail implementation that logs to
// stdout so apps can boot end-to-end without an SMTP backend.
//
// GetUserIDFromContext / SetUserIDInContext — Request-context user-ID
// helpers using a private key type to avoid cross-package context-key
// collisions. DefaultUserParamName documents the key string.
//
// FLOWS
//
// See [diagrams.md](diagrams.md) for sequence diagrams of: local signup,
// refresh-token rotation with theft detection.
package core
