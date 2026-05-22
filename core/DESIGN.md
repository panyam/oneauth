---
package: core
purpose: Foundation data model, store interfaces, token/scope/credential types, and RFC 9396 authorization details that every other OneAuth package imports.
last_rebuilt: ca8a742623b748f06d2564dce90465d1eeb10c6d
entities:
  - name: User
    kind: interface
    role: Minimal contract for a unified user account — Id() plus an open Profile() map.
    why: Deliberately tiny so any app's user type can satisfy it; profile is an untyped map to stay storage- and app-agnostic.
  - name: BasicUser
    kind: struct
    role: Stock User implementation backed by an ID string and a profile map.
    why: Lets callers and tests use core without writing their own User type.
  - name: Identity
    kind: struct
    role: A verifiable contact method (email/phone) owned by a user, with a Version field.
    why: Identity (the contact) is split from Channel (the auth mechanism) so one user can verify a contact once yet authenticate it through many providers; Version exists for optimistic locking across backends.
  - name: Channel
    kind: struct
    role: An authentication mechanism/provider binding (local, google, github) keyed by IdentityKey, holding credentials and provider profile.
    why: Separating Channel from Identity is the core multi-provider model; ExpiresAt drives re-auth and IsExpired() treats zero-time as never-expiring.
  - name: IdentityKey
    kind: function
    role: Builds the canonical "type:value" key (e.g. "email:john@x.com") joining identities to channels.
    why: Single source of truth for the key format so every store and channel agrees; avoids ad-hoc string concatenation drift.
  - name: HandleUserFunc
    kind: type (func)
    role: Post-authentication callback fired after OAuth or local login with token, userinfo, and the HTTP req/resp.
    why: The only reason core depends on golang.org/x/oauth2; lets apps own the post-login redirect/session decision instead of the library.
  - name: UserStore
    kind: interface
    role: CRUD for user accounts (create, get-by-id, upsert).
    why: Composed-not-god — kept separate from identity/channel stores so a backend implements only what it needs.
  - name: IdentityStore
    kind: interface
    role: Manages contact identities, their user association, and verification state.
    why: get-or-create flags (createIfMissing) plus explicit SetUserForIdentity keep account-linking logic in the store layer, not scattered in callers.
  - name: ChannelStore
    kind: interface
    role: Manages auth channels/providers keyed by identity.
    why: Mirrors IdentityStore's get-or-create shape; lets one identity fan out to multiple provider channels.
  - name: RefreshTokenStore
    kind: interface
    role: Lifecycle of refresh tokens including rotation, family revocation, and per-user revocation.
    why: RotateRefreshToken returning ErrTokenReused encodes refresh-token-theft detection (reuse of a rotated token revokes the whole family) into the interface contract.
  - name: APIKeyStore
    kind: interface
    role: Lifecycle of long-lived API keys for programmatic access.
    why: CreateAPIKey returns the full key only once (keyID + "_" + secret); the store keeps only a hash, so the plaintext secret is never recoverable.
  - name: UsernameStore
    kind: interface
    role: Optional username-uniqueness reservations with atomic change.
    why: Split out as optional because username-based login is app-specific; ChangeUsername is atomic to avoid a window where a username is unowned or double-claimed.
  - name: TokenType
    kind: type (string)
    role: Enum of short-lived auth-token kinds (email verification, password reset, refresh).
    why: Distinguishes AuthToken purposes so IsValid can reject a reset token used for verification.
  - name: AuthToken
    kind: struct
    role: A short-lived verification/reset token with type, user, email, and expiry.
    why: Separate from RefreshToken/APIKey because its lifecycle is single-use and email-bound, not session-bound.
  - name: TokenStore
    kind: interface
    role: CRUD for AuthToken values (verification/reset tokens).
    why: Distinct from RefreshTokenStore — these are ephemeral, single-purpose tokens, not OAuth credentials.
  - name: RefreshToken
    kind: struct
    role: Long-lived API refresh token carrying Family/Generation for rotation and AuthorizationDetails (RFC 9396).
    why: Family + Generation make theft detection possible; carrying AuthorizationDetails lets fine-grained authz survive token rotation.
  - name: APIKey
    kind: struct
    role: Long-lived programmatic key storing a bcrypt KeyHash and optional expiry.
    why: ExpiresAt is a pointer so nil means "never expires" — distinguishing unset from a zero time matters for IsExpired.
  - name: TokenPair
    kind: struct
    role: OAuth token-endpoint success response (access/refresh/scope + RFC 9396 + RFC 8693 IssuedTokenType).
    why: IssuedTokenType is present only for token-exchange responses; the json omitempty tags keep the response RFC-clean for other grants.
  - name: TokenRequest
    kind: struct
    role: Union request shape for every token-endpoint grant (password, refresh, client_credentials, jwt-bearer, token-exchange).
    why: Crucially separates Assertion (resource-owner, RFC 7523 jwt-bearer grant) from ClientAssertion (client auth, private_key_jwt/client_secret_jwt) — conflating them is a classic security bug.
  - name: TokenError
    kind: struct
    role: OAuth 2.0 compliant error response (error + error_description).
    why: Matches RFC 6749 wire format so handlers can serialize errors directly.
  - name: GenerateSecureToken / GenerateAPIKeyID / GenerateAPIKeySecret
    kind: function
    role: crypto/rand-backed generators for opaque tokens and API key parts.
    why: Centralized so all opaque secrets use crypto/rand (never math/rand) and the "oa_" key prefix is consistent.
  - name: SignupPolicy
    kind: struct
    role: Configurable signup requirements (which fields required, uniqueness enforcement, password/username rules).
    why: Zero-value-safe via GetUsernamePattern/GetMinPasswordLength fallbacks; presets (PolicyFlexible etc.) encode OAuth-friendly vs strict tradeoffs so apps don't reinvent them.
  - name: AuthError
    kind: struct
    role: Structured auth error carrying machine Code, human Message, and offending Field.
    why: Field + Code let UIs attach errors to the right form input and localize, rather than parsing a flat string.
  - name: AuthErrorHandler
    kind: type (func)
    role: App hook to render/redirect on auth errors; returns true if it handled the response.
    why: The bool return is the contract — false falls back to core's default JSON, letting apps override only the cases they care about.
  - name: Credentials
    kind: struct
    role: Signup/login input (username/email/phone/password) with Email and Phone as pointers.
    why: Email/Phone are *string so "absent" is distinguishable from "empty", which the validators rely on (at least one of email/phone required).
  - name: SignupValidator / CredentialsValidator / CreateUserFunc
    kind: type (func)
    role: Pluggable function types for validating signup, validating login, and constructing users.
    why: Function-type seams keep core policy-free; apps inject behavior instead of subclassing.
  - name: DetectUsernameType
    kind: function
    role: Heuristically classifies a login identifier as email, phone, or username.
    why: Enables one login field accepting any identifier; "@" → email, leading +/digit → phone is a deliberate cheap heuristic, not full validation.
  - name: AuthorizationDetail
    kind: struct
    role: One RFC 9396 authorization_details object — typed common fields plus an Extra map for API-specific extensions.
    why: Custom Marshal/Unmarshal flatten Extra into the top-level JSON (spec requires flat, not nested), and reject extension keys colliding with the six reserved common-field names.
  - name: ValidateAll / FilterByType
    kind: function
    role: Validate a slice of details (type required) and select details by type.
    why: ValidateAll is nil/empty-safe so callers needn't guard; FilterByType lets consumers route per authorization-type without re-parsing.
  - name: TokenBlacklist
    kind: interface
    role: jti-based revocation of JWT access tokens with auto-expiry.
    why: Pluggable (in-memory vs Redis) so single-node and distributed deployments share one revocation contract (RFC 7519 jti).
  - name: InMemoryBlacklist
    kind: struct
    role: Thread-safe map-backed TokenBlacklist for single-process use.
    why: Entries keyed by jti→expiry self-expire on read (IsRevoked treats expired as not-revoked); CleanupExpired must be called periodically or the map grows unbounded.
  - name: RateLimiter
    kind: interface
    role: Allow(key) gate for operations like login attempts.
    why: One-method interface keeps the abstraction trivial to back with Redis or any other limiter.
  - name: InMemoryRateLimiter
    kind: struct
    role: Token-bucket rate limiter with per-key buckets, configurable rate and burst.
    why: CleanupStale exists because abandoned keys (e.g. one-off IPs) would otherwise leak buckets forever.
  - name: AccountLockout
    kind: struct
    role: Tracks consecutive auth failures per key and temporarily locks after a threshold.
    why: Complements RateLimiter (distinct concern: failure-driven lockout vs request-rate); lockouts self-expire on IsLocked check after LockDuration.
  - name: SendEmail
    kind: interface
    role: App-provided email sender for verification and password-reset links.
    why: Keeps core transport-free; apps wire in real providers.
  - name: ConsoleEmailSender
    kind: struct
    role: Dev-only SendEmail that logs links to stdout.
    why: Lets examples and tests run the full reset/verify flow without an SMTP dependency.
  - name: GetUserIDFromContext / SetUserIDInContext
    kind: function
    role: Read/write the logged-in user ID on a request context.
    why: Uses an unexported userParamNameKey type to avoid context-key collisions with other packages — the standard Go safe-context-key idiom.
  - name: Scope helpers (ParseScopes, JoinScopes, IntersectScopes, UnionScopes, ContainsScope, ContainsAllScopes, ValidateRequestedScopes, ScopesEqual)
    kind: function
    role: Set operations on space-separated OAuth scope strings.
    why: IntersectScopes (restrict requested-against-allowed) and UnionScopes (merge, sorted+deduped) are deliberate complements; centralizing dedup/whitespace handling prevents subtle scope-grant bugs across packages.
  - name: GetUserScopesFunc
    kind: type (func)
    role: App callback returning the scopes a user is allowed to hold.
    why: Scope authority is app-specific (roles/groups/profile), so core only defines the seam plus a permissive DefaultGetUserScopes.
depends_on: []
---

# core — Foundation Package

`core` is the dependency root: every other OneAuth package imports it and it imports nothing from siblings. Its only non-stdlib dependency is `golang.org/x/oauth2`, pulled in solely for the `*oauth2.Token` parameter of `HandleUserFunc`.

Four design threads run through the package:

1. **The Identity/Channel/User split.** A `User` is the account; an `Identity` is a verifiable contact (email/phone); a `Channel` is a way to authenticate (local password, google, github). One identity can be reached through many channels, joined by the canonical `IdentityKey` ("type:value"). The store interfaces (`UserStore`, `IdentityStore`, `ChannelStore`, plus `RefreshTokenStore`, `APIKeyStore`, `UsernameStore`) are decomposed by concern rather than fused into one god store — each backend implements only the interfaces it supports.

2. **Tokens and credentials as data, not behavior.** Token structs (`AuthToken`, `RefreshToken`, `APIKey`, `TokenPair`, `TokenRequest`) carry RFC-shaped JSON tags and small `IsExpired`/`IsValid` helpers but no I/O. The security-relevant invariants are encoded into the store contracts: refresh-token theft detection lives in `RotateRefreshToken`'s `ErrTokenReused` and the `Family`/`Generation` fields; API-key secrets are returned once and stored only as hashes. `TokenRequest` is a careful union over all five supported grants, and its comments draw the load-bearing distinction between subject `Assertion` (RFC 7523 jwt-bearer, authenticates the resource owner) and `ClientAssertion` (RFC 7521/7523 client auth methods).

3. **RFC 9396 authorization details.** `AuthorizationDetail` is the one non-trivial serialization concern here: the spec mandates a *flat* JSON object mixing reserved common fields with arbitrary API-specific extensions, so the type hand-rolls `MarshalJSON`/`UnmarshalJSON` to flatten the `Extra` map into the top level and reject extension keys that collide with the six reserved names (`commonFields`). It threads through `RefreshToken`, `TokenPair`, and `TokenRequest`.

4. **Pluggable security primitives with in-memory defaults.** `TokenBlacklist`, `RateLimiter`, and `AccountLockout` each pair a small interface/struct with a thread-safe in-memory implementation suitable for single-node use and swappable for Redis in distributed deployments. All three accumulate entries and expose explicit cleanup (`CleanupExpired`, `CleanupStale`, or self-expiry on read) — callers must invoke periodic cleanup or accept unbounded map growth.

Note: `SUMMARY.md` references a `lockout.go`, but `AccountLockout` actually lives in `ratelimiter.go` alongside the rate limiter — there is no separate `lockout.go` file.
