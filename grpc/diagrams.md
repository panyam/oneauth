# grpc — Flows

### Interceptor auth enforcement and public-method bypass

How `UnaryAuthInterceptor` / `StreamAuthInterceptor` decide whether to admit a
call. The interceptor only enforces *presence* of an identity; it does not add
the identity to the context, so handlers still read it via `UserIDFromContext`.

```mermaid
flowchart TD
    A[Incoming RPC] --> B[extractUserID from incoming metadata]
    B --> C{EnableSwitchAuth?}
    C -- yes, switch key set --> D[userID = switch-user value]
    C -- no / unset --> E[userID = x-user-id value]
    D --> F{RequireAuth && method not in PublicMethods?}
    E --> F
    F -- no --> H[call handler]
    F -- yes --> G{userID empty?}
    G -- yes --> I[return codes.Unauthenticated]
    G -- no --> H[call handler]
```

### HTTP-to-gRPC context propagation

How an authenticated identity established at an HTTP edge reaches a downstream
gRPC handler. The client side appends metadata to the outgoing context; the
server side reads it back. Switch-user is honored only if the server enabled it.

```mermaid
sequenceDiagram
    participant HTTP as HTTP edge / gRPC client
    participant Out as Outgoing ctx (metadata)
    participant ICept as Server interceptor
    participant H as gRPC handler

    HTTP->>Out: UserIDToOutgoingContext(ctx, userID)
    HTTP->>Out: SwitchUserToOutgoingContext(ctx, target) [optional]
    Out->>ICept: RPC carries x-user-id / x-switch-user metadata
    ICept->>ICept: extractUserID + RequireAuth / PublicMethods check
    ICept->>H: handler(ctx, req)  (context unchanged)
    H->>H: UserIDFromContext(ctx) reads user ID
```
