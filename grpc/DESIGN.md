---
package: grpc
purpose: Propagates an authenticated user ID across the HTTP-to-gRPC boundary via gRPC metadata, with server-side interceptors that enforce (or optionally relax) authentication per method.
last_rebuilt: ca8a742623b748f06d2564dce90465d1eeb10c6d
entities:
  - name: Config
    kind: struct
    role: Holds the metadata key names and the switch-user toggle used to read/write auth identity.
    why: Keys are configurable rather than hardcoded so the package can coexist with other systems' metadata conventions; EnableSwitchAuth is deliberately a separate gate because user impersonation is a dev/test-only footgun.
  - name: InterceptorConfig
    kind: struct
    role: Embeds *Config and adds RequireAuth plus a PublicMethods allowlist to drive interceptor enforcement.
    why: Embedding *Config keeps a single source of truth for key names; PublicMethods is a per-full-method allowlist so health/reflection endpoints can stay open without disabling auth globally.
  - name: DefaultConfig
    kind: func
    role: Returns a Config with the x-user-id / x-switch-user defaults and switch auth off.
    why: Switch auth defaults to false so impersonation is never silently available — it must be an explicit opt-in.
  - name: EnsureDefaults
    kind: method
    role: Backfills empty key fields on a Config with their default values.
    why: Lets callers construct a partial Config (e.g. only overriding one key) without nil/empty-string keys reaching the metadata lookups; called defensively on every entry path.
  - name: UserIDFromContext
    kind: func
    role: Extracts the authenticated user ID from incoming gRPC metadata, empty if none.
    why: Returning "" rather than an error/bool keeps call sites terse; authentication enforcement is the interceptor's job, not the reader's.
  - name: UserIDFromContextWithConfig
    kind: func
    role: Config-aware variant of UserIDFromContext that honors custom keys and the switch-user override.
    why: Switch-user is checked before the real user ID so an enabled impersonation header wins — the ordering is the whole point of the feature.
  - name: UserIDToOutgoingContext
    kind: func
    role: Appends the user ID to outgoing client-side metadata under the default key.
    why: This is the HTTP-edge-to-gRPC handoff; the HTTP layer authenticates, then stamps the identity here so downstream services trust the metadata rather than re-authenticating.
  - name: UserIDToOutgoingContextWithKey
    kind: func
    role: Custom-key variant of UserIDToOutgoingContext.
    why: Uses AppendToOutgoingContext (not Set) to avoid clobbering unrelated metadata already on the context.
  - name: SwitchUserToOutgoingContext
    kind: func
    role: Stamps a switch-user (impersonation) header onto outgoing metadata.
    why: Only effective if the server has EnableSwitchAuth on — the client side can always send it, but trust lives entirely server-side, preventing accidental prod impersonation.
  - name: SwitchUserToOutgoingContextWithKey
    kind: func
    role: Custom-key variant of SwitchUserToOutgoingContext.
    why: Same append-not-overwrite contract as the user-ID writers for metadata safety.
  - name: IsAuthenticated
    kind: func
    role: Convenience predicate, true when a user ID is present in context.
    why: Sugar over the empty-string contract of UserIDFromContext so handler code reads as intent rather than string comparison.
  - name: UnaryAuthInterceptor
    kind: func
    role: Builds a gRPC unary server interceptor that extracts the user and rejects unauthenticated calls unless the method is public.
    why: Enforcement is method-scoped (RequireAuth AND not in PublicMethods) so a single interceptor serves mixed open/protected services; nil config falls back to require-auth-everywhere — fail-closed by default.
  - name: StreamAuthInterceptor
    kind: func
    role: Stream-server counterpart to UnaryAuthInterceptor.
    why: Mirrors the unary path so streaming RPCs get identical fail-closed enforcement; pulls ctx off the ServerStream because streams don't receive ctx directly.
  - name: NewPublicMethodsConfig
    kind: func
    role: Builds a require-auth InterceptorConfig pre-seeded with the given public method names.
    why: The common shape — auth on, with a short exemption list — packaged so callers don't hand-build the map.
  - name: OptionalAuthConfig
    kind: func
    role: Builds an InterceptorConfig that never rejects, leaving auth advisory.
    why: For services that want identity-when-present but no hard gate; keeps the "read returns empty" semantics intact without a 401-equivalent.
  - name: extractUserID
    kind: func
    role: Internal metadata reader used by both interceptors.
    why: Duplicates the switch-then-real ordering of UserIDFromContextWithConfig but against the interceptor's embedded Config, keeping the interceptors self-contained.
depends_on: []
---

## gRPC auth interceptor + context helpers

This package is a thin trust-propagation layer, not an authenticator. The decision it
encodes is that authentication happens once at the HTTP edge, and the resulting user ID
travels into the gRPC mesh as plain metadata. Two symmetric halves implement this:

- **Client/edge side** (`*ToOutgoingContext*`) stamps identity onto outgoing metadata using
  `AppendToOutgoingContext`, never overwriting existing metadata.
- **Server side** (`UnaryAuthInterceptor` / `StreamAuthInterceptor`) reads incoming metadata
  and decides whether to admit the call.

Enforcement is fail-closed: a nil interceptor config means require-auth for every method, and
only methods explicitly listed in `PublicMethods` (keyed by full `/package.Service/Method`
name) are exempted. `OptionalAuthConfig` is the deliberate escape hatch for advisory-only auth.

The switch-user (impersonation) path is gated by `EnableSwitchAuth`, which defaults to off.
Importantly, trust is server-side only: a client may always *send* a switch-user header, but it
is honored solely when the receiving server has opted in — so impersonation cannot leak into an
environment that didn't ask for it. When enabled, the switch-user value is checked *before* the
real user ID, so it wins.
