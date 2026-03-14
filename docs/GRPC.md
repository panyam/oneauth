# gRPC Authentication

OneAuth provides gRPC authentication utilities in the `grpc` subpackage for propagating user identity from HTTP sessions to gRPC service calls.

## Installation

The gRPC package is included with OneAuth:

```go
import oagrpc "github.com/panyam/oneauth/grpc"
```

## Context Utilities

### Extracting User ID from Context

In your gRPC service implementations, extract the authenticated user:

```go
func (s *MyService) GetUserProfile(ctx context.Context, req *pb.GetUserProfileRequest) (*pb.UserProfile, error) {
    userID := oagrpc.UserIDFromContext(ctx)
    if userID == "" {
        return nil, status.Error(codes.Unauthenticated, "authentication required")
    }

    // Use userID to fetch profile...
    return profile, nil
}
```

### Injecting User ID into Outgoing Context

When making gRPC calls from an HTTP handler (e.g., in a gRPC-gateway):

```go
func (h *Handler) handleRequest(w http.ResponseWriter, r *http.Request) {
    // Get user from session/token
    userID := h.authMiddleware.GetLoggedInUserId(r)

    // Add to outgoing gRPC context
    ctx := oagrpc.UserIDToOutgoingContext(r.Context(), userID)

    // Make gRPC call
    resp, err := h.grpcClient.SomeMethod(ctx, req)
}
```

### Using with gRPC-Gateway

With grpc-gateway's `runtime.ServeMux`, inject user ID via metadata:

```go
gwmux := runtime.NewServeMux(
    runtime.WithMetadata(func(ctx context.Context, r *http.Request) metadata.MD {
        userID := authMiddleware.GetLoggedInUserId(r)
        if userID != "" {
            return metadata.Pairs(oagrpc.DefaultMetadataKeyUserID, userID)
        }
        return metadata.Pairs()
    }),
)
```

## Auth Interceptors

### Basic Usage

Add authentication enforcement to your gRPC server:

```go
import oagrpc "github.com/panyam/oneauth/grpc"

server := grpc.NewServer(
    grpc.UnaryInterceptor(oagrpc.UnaryAuthInterceptor(nil)),
    grpc.StreamInterceptor(oagrpc.StreamAuthInterceptor(nil)),
)
```

With default config, all methods require authentication. Unauthenticated requests receive `codes.Unauthenticated`.

### Public Methods

Allow certain methods to be accessed without authentication:

```go
config := oagrpc.NewPublicMethodsConfig(
    "/myapp.v1.AuthService/Login",
    "/myapp.v1.AuthService/Register",
    "/myapp.v1.HealthService/Check",
)

server := grpc.NewServer(
    grpc.UnaryInterceptor(oagrpc.UnaryAuthInterceptor(config)),
    grpc.StreamInterceptor(oagrpc.StreamAuthInterceptor(config)),
)
```

### Optional Authentication

For services where authentication is optional (user ID available if authenticated, but not required):

```go
config := oagrpc.OptionalAuthConfig()

server := grpc.NewServer(
    grpc.UnaryInterceptor(oagrpc.UnaryAuthInterceptor(config)),
)
```

Your service can then check if the user is authenticated:

```go
func (s *MyService) GetContent(ctx context.Context, req *pb.GetContentRequest) (*pb.Content, error) {
    userID := oagrpc.UserIDFromContext(ctx)

    if userID != "" {
        // Personalized content for authenticated user
        return s.getPersonalizedContent(userID, req)
    }

    // Generic content for anonymous user
    return s.getPublicContent(req)
}
```

## Configuration

### Custom Metadata Keys

Use custom metadata keys if needed:

```go
config := &oagrpc.InterceptorConfig{
    Config: &oagrpc.Config{
        MetadataKeyUserID:     "x-custom-user-id",
        MetadataKeySwitchUser: "x-custom-switch-user",
    },
    RequireAuth: true,
    PublicMethods: make(map[string]bool),
}
```

### Switch User for Testing

Enable user switching for development/testing:

```go
config := &oagrpc.InterceptorConfig{
    Config: &oagrpc.Config{
        EnableSwitchAuth: true, // Only enable in dev/test!
    },
    RequireAuth: true,
    PublicMethods: make(map[string]bool),
}
```

When enabled, the `x-switch-user` metadata header overrides the actual user ID.

## Complete Integration Example

```go
package main

import (
    "context"
    "net"
    "net/http"

    "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
    oa "github.com/panyam/oneauth"
    oagrpc "github.com/panyam/oneauth/grpc"
    "google.golang.org/grpc"
    "google.golang.org/grpc/metadata"
)

func main() {
    // Setup oneauth for HTTP
    authMiddleware := &oa.Middleware{
        // ... configure ...
    }

    // Setup gRPC server with auth interceptors
    grpcServer := grpc.NewServer(
        grpc.UnaryInterceptor(oagrpc.UnaryAuthInterceptor(
            oagrpc.NewPublicMethodsConfig("/myapp.v1.Auth/Login"),
        )),
    )

    // Register services
    pb.RegisterMyServiceServer(grpcServer, &myServiceImpl{})

    // Start gRPC server
    lis, _ := net.Listen("tcp", ":9090")
    go grpcServer.Serve(lis)

    // Setup gRPC-gateway with user ID injection
    gwmux := runtime.NewServeMux(
        runtime.WithMetadata(func(ctx context.Context, r *http.Request) metadata.MD {
            userID := authMiddleware.GetLoggedInUserId(r)
            if userID != "" {
                return metadata.Pairs(oagrpc.DefaultMetadataKeyUserID, userID)
            }
            return metadata.Pairs()
        }),
    )

    // Register gateway handlers
    pb.RegisterMyServiceHandlerFromEndpoint(context.Background(), gwmux, ":9090", nil)

    // Start HTTP server
    http.ListenAndServe(":8080", authMiddleware.ExtractUser(gwmux))
}
```
