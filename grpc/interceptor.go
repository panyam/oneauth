package grpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// InterceptorConfig configures the auth interceptor behavior.
type InterceptorConfig struct {
	// Config holds the metadata key configuration.
	*Config

	// RequireAuth when true rejects unauthenticated requests.
	// When false, requests proceed but UserIDFromContext returns empty.
	RequireAuth bool

	// PublicMethods is a set of method names that don't require auth.
	// Only used when RequireAuth is true.
	// Keys should be full method names like "/package.Service/Method".
	PublicMethods map[string]bool
}

// DefaultInterceptorConfig returns a config that requires auth for all methods.
func DefaultInterceptorConfig() *InterceptorConfig {
	return &InterceptorConfig{
		Config:        DefaultConfig(),
		RequireAuth:   true,
		PublicMethods: make(map[string]bool),
	}
}

// NewPublicMethodsConfig creates a config with the specified public methods.
func NewPublicMethodsConfig(publicMethods ...string) *InterceptorConfig {
	config := &InterceptorConfig{
		Config:        DefaultConfig(),
		RequireAuth:   true,
		PublicMethods: make(map[string]bool),
	}
	for _, method := range publicMethods {
		config.PublicMethods[method] = true
	}
	return config
}

// OptionalAuthConfig returns a config that allows unauthenticated requests.
func OptionalAuthConfig() *InterceptorConfig {
	return &InterceptorConfig{
		Config:        DefaultConfig(),
		RequireAuth:   false,
		PublicMethods: make(map[string]bool),
	}
}

// UnaryAuthInterceptor returns a gRPC unary interceptor that processes auth metadata.
// It handles the switch-user header when EnableSwitchAuth is set in the config.
func UnaryAuthInterceptor(config *InterceptorConfig) grpc.UnaryServerInterceptor {
	if config == nil {
		config = DefaultInterceptorConfig()
	}
	if config.Config == nil {
		config.Config = DefaultConfig()
	}
	config.Config.EnsureDefaults()

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		userID := extractUserID(ctx, config)

		// Check if auth is required for this method
		if config.RequireAuth && !config.PublicMethods[info.FullMethod] {
			if userID == "" {
				return nil, status.Error(codes.Unauthenticated, "authentication required")
			}
		}

		return handler(ctx, req)
	}
}

// StreamAuthInterceptor returns a gRPC stream interceptor that processes auth metadata.
func StreamAuthInterceptor(config *InterceptorConfig) grpc.StreamServerInterceptor {
	if config == nil {
		config = DefaultInterceptorConfig()
	}
	if config.Config == nil {
		config.Config = DefaultConfig()
	}
	config.Config.EnsureDefaults()

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()
		userID := extractUserID(ctx, config)

		// Check if auth is required for this method
		if config.RequireAuth && !config.PublicMethods[info.FullMethod] {
			if userID == "" {
				return status.Error(codes.Unauthenticated, "authentication required")
			}
		}

		return handler(srv, ss)
	}
}

// extractUserID extracts the user ID from context using the interceptor config.
func extractUserID(ctx context.Context, config *InterceptorConfig) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	// Check for switch user first (only if enabled)
	if config.Config.EnableSwitchAuth {
		if values := md.Get(config.Config.MetadataKeySwitchUser); len(values) > 0 && values[0] != "" {
			return values[0]
		}
	}

	// Fall back to actual user ID
	if values := md.Get(config.Config.MetadataKeyUserID); len(values) > 0 {
		return values[0]
	}

	return ""
}
