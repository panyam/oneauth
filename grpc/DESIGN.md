# grpc

A small standalone sub-module of helpers for using OneAuth identity inside gRPC services. It standardizes how the authenticated user ID rides across the wire as gRPC metadata (default key `x-user-id`), provides outgoing helpers for clients/gateways to attach that header, and ships unary + stream server interceptors that enforce per-method auth with a `PublicMethods` bypass set and an opt-in switch-user impersonation header for dev/testing.

The package deliberately does not verify identity — it trusts the metadata header. Cryptographic verification (JWT, introspection) happens upstream in an HTTP gateway, and this layer propagates the already-authenticated subject into gRPC handlers.

## Contents

- [Entities](#entities)
- [Flows](#flows)
  - [Incoming unary request: enforce per-method auth](#incoming-unary-request-enforce-per-method-auth)
  - [Outgoing client call: attach identity and optional impersonation](#outgoing-client-call-attach-identity-and-optional-impersonation)
- [Gotchas](#gotchas)
- [Depends on](#depends-on)

## Entities

| Entity | Kind | Role | Why |
|---|---|---|---|
| `DefaultMetadataKeyUserID` | const | Default metadata key (`x-user-id`) carrying the authenticated user ID. | gRPC normalizes metadata keys to lowercase, so the constant is lowercase too. |
| `DefaultMetadataKeySwitchUser` | const | Default metadata key (`x-switch-user`) for impersonating another user. | Honored only when `EnableSwitchAuth` is set; meant for dev/testing. |
| `Config` | struct | Metadata-key names plus the `EnableSwitchAuth` toggle. | Keys are customizable so callers can avoid collisions with other application metadata. |
| `DefaultConfig` | func | Returns a `Config` with default keys and switch-auth disabled. | Safe default - impersonation is off unless explicitly opted into. |
| `Config.EnsureDefaults` | method | Fills empty key fields with their default values in place. | Accept a partially populated `Config` without nil/empty-key bugs. |
| `UserIDFromContext` | func | Extracts the user ID from incoming gRPC metadata using defaults. | Returns `""` rather than erroring so callers decide how to treat anonymous requests. |
| `UserIDFromContextWithConfig` | func | Same extraction, caller-supplied `Config` (nil falls back to default). | Switch-user key is checked before the real user ID when `EnableSwitchAuth` is on. |
| `UserIDToOutgoingContext` | func | Appends the user ID to outgoing metadata under the default key. | Used by HTTP gateways/clients to forward identity into downstream gRPC calls. |
| `UserIDToOutgoingContextWithKey` | func | Same as above but with a custom metadata key. | Mirrors the configurable key on the extraction side. |
| `SwitchUserToOutgoingContext` | func | Appends a switch-user impersonation header (default key) to outgoing metadata. | No effect unless the server has `EnableSwitchAuth` set - clients cannot self-grant. |
| `SwitchUserToOutgoingContextWithKey` | func | Switch-user append with a custom key. | Pairs with the custom-key extraction path. |
| `IsAuthenticated` | func | Reports whether the context carries a non-empty user ID (default config). | Convenience predicate over `UserIDFromContext`. |
| `IsAuthenticatedWithConfig` | func | Authentication predicate with an explicit `Config`. | Lets switch-user-aware callers test presence consistently with extraction. |
| `InterceptorConfig` | struct | Embeds `Config` and adds `RequireAuth` plus a `PublicMethods` bypass set. | `PublicMethods` keys are full `/pkg.Service/Method` names matched against `info.FullMethod`. |
| `DefaultInterceptorConfig` | func | Returns a config that requires auth on every method with no public bypass. | Secure-by-default posture for new servers. |
| `NewPublicMethodsConfig` | func | Builds a require-auth config seeded with the given unauthenticated methods. | Common case - most servers expose a few health/login methods without auth. |
| `OptionalAuthConfig` | func | Returns a config that lets unauthenticated requests through. | For services that read identity opportunistically but never reject. |
| `UnaryAuthInterceptor` | func | Unary server interceptor that extracts identity and enforces auth per method. | Only rejects with `Unauthenticated` when `RequireAuth` is set and method is not public; does not inject identity into the context - downstream code calls `UserIDFromContext`. |
| `StreamAuthInterceptor` | func | Stream-side counterpart enforcing the same per-method rules on stream open. | Checks `ss.Context()` once at open; per-message identity is unchanged. |
| `extractUserID` | func | Internal helper used by both interceptors to read the user ID from metadata. | Single source of truth for switch-user precedence and key lookup. |

## Flows

### Incoming unary request: enforce per-method auth

```mermaid
sequenceDiagram
    participant Client
    participant Server as gRPC server
    participant Interceptor as UnaryAuthInterceptor
    participant Handler as RPC handler

    Client->>Server: Unary RPC + metadata (x-user-id, optional x-switch-user)
    Server->>Interceptor: invoke(ctx, req, info)
    Interceptor->>Interceptor: extractUserID(ctx, config)
    alt EnableSwitchAuth and x-switch-user non-empty
        Interceptor->>Interceptor: use x-switch-user value
    else
        Interceptor->>Interceptor: use x-user-id value (or "")
    end
    alt RequireAuth and method not in PublicMethods and userID == ""
        Interceptor-->>Client: status.Error(Unauthenticated)
    else
        Interceptor->>Handler: handler(ctx, req)
        Handler-->>Interceptor: response
        Interceptor-->>Client: response
    end
```

The stream interceptor follows the same shape, except it reads `ss.Context()` once when the stream opens and never re-checks per message.

### Outgoing client call: attach identity and optional impersonation

```mermaid
sequenceDiagram
    participant Caller as HTTP gateway / client
    participant Helpers as grpc package helpers
    participant Server as Downstream gRPC server

    Caller->>Helpers: UserIDToOutgoingContext(ctx, userID)
    Helpers-->>Caller: ctx with x-user-id appended
    opt Impersonation (dev only)
        Caller->>Helpers: SwitchUserToOutgoingContext(ctx, targetID)
        Helpers-->>Caller: ctx with x-switch-user appended
    end
    Caller->>Server: gRPC call with outgoing metadata
    Note over Server: UserIDFromContext picks switch-user first if EnableSwitchAuth=true
```

## Gotchas

- **Interceptor does not inject the user ID into the context.** `UnaryAuthInterceptor` and `StreamAuthInterceptor` only read the metadata to decide whether to reject the call; they pass the original `ctx` straight through to the handler. Downstream code must call `UserIDFromContext(ctx)` itself — there is no separate context-value key set by this package, so a `ctx.Value(...)` lookup will not find the user ID.
- **Switch-user is server-controlled, not client-controlled.** `SwitchUserToOutgoingContext` always appends the header, but the server ignores it unless `Config.EnableSwitchAuth` is `true`. Treat this as a dev/testing affordance only — leaving `EnableSwitchAuth` off in production is the entire security model around impersonation.
- **Empty `x-switch-user` falls back to `x-user-id`.** When switch-auth is enabled, an empty switch header is treated as "no override" and the real user ID is used instead (covered by `TestUserIDFromContext_SwitchUserEmpty`). Sending an empty switch header is therefore safe but pointless.
- **`PublicMethods` keys must match `info.FullMethod` exactly.** That means the leading slash and the full `/package.Service/Method` form (e.g. `/pkg.Svc/Method1`), not bare method names. A typo silently turns into "auth required" for that endpoint, which surfaces as an `Unauthenticated` error rather than a configuration warning.
- **Metadata keys are lowercase.** gRPC normalizes header keys, so the defaults are `x-user-id` and `x-switch-user`. If you supply custom keys via `Config`, keep them lowercase — otherwise the `md.Get(...)` lookup silently returns nothing.
- **Stream auth is checked once, at stream open.** `StreamAuthInterceptor` reads `ss.Context()` when the stream is established. Mid-stream identity changes are out of scope; there is no per-message re-check.
- **No identity verification happens here.** The interceptors trust whatever value arrives in the metadata header. Cryptographic verification (JWT / introspection) must have happened upstream — typically in an HTTP gateway — before the request reaches the gRPC layer. This sub-module is purely about propagating an already-authenticated identity.
- **Error mapping is fixed at `codes.Unauthenticated`.** Failed auth always produces `status.Error(codes.Unauthenticated, "authentication required")`. There is no hook to differentiate "missing identity" from "invalid identity" because invalid identity isn't a concept at this layer (see previous gotcha).
- **Standalone sub-module.** `grpc/go.mod` declares `github.com/panyam/oneauth/grpc` with only `google.golang.org/grpc` as a direct dependency — it deliberately does not depend on the rest of OneAuth, so it stays cheap to import from any gRPC service.

## Depends on

*(no sibling-folder dependencies)*
