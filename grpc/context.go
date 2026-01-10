// Package grpc provides authentication context utilities for passing
// user information between HTTP handlers and gRPC services via metadata.
package grpc

import (
	"context"

	"google.golang.org/grpc/metadata"
)

// Default metadata keys for authentication context.
// These can be customized via Config if needed.
const (
	// DefaultMetadataKeyUserID is the default gRPC metadata key for the authenticated user ID
	DefaultMetadataKeyUserID = "x-user-id"

	// DefaultMetadataKeySwitchUser is the default gRPC metadata key for switching to a different user (testing only)
	DefaultMetadataKeySwitchUser = "x-switch-user"
)

// Config holds the metadata key configuration for auth context.
type Config struct {
	// MetadataKeyUserID is the gRPC metadata key for the authenticated user ID.
	// Defaults to "x-user-id".
	MetadataKeyUserID string

	// MetadataKeySwitchUser is the gRPC metadata key for switching to a different user.
	// Only used when switch auth is enabled. Defaults to "x-switch-user".
	MetadataKeySwitchUser string

	// EnableSwitchAuth when true allows the X-Switch-User header to override the user ID.
	// Should only be enabled in development/testing environments.
	EnableSwitchAuth bool
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		MetadataKeyUserID:     DefaultMetadataKeyUserID,
		MetadataKeySwitchUser: DefaultMetadataKeySwitchUser,
		EnableSwitchAuth:      false,
	}
}

// EnsureDefaults fills in default values for any unset fields.
func (c *Config) EnsureDefaults() {
	if c.MetadataKeyUserID == "" {
		c.MetadataKeyUserID = DefaultMetadataKeyUserID
	}
	if c.MetadataKeySwitchUser == "" {
		c.MetadataKeySwitchUser = DefaultMetadataKeySwitchUser
	}
}

// UserIDFromContext extracts the authenticated user ID from the gRPC context metadata.
// Returns empty string if no user is authenticated.
func UserIDFromContext(ctx context.Context) string {
	return UserIDFromContextWithConfig(ctx, nil)
}

// UserIDFromContextWithConfig extracts the authenticated user ID using the specified config.
func UserIDFromContextWithConfig(ctx context.Context, config *Config) string {
	if config == nil {
		config = DefaultConfig()
	}
	config.EnsureDefaults()

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	// Check for switch user first (only if enabled)
	if config.EnableSwitchAuth {
		if values := md.Get(config.MetadataKeySwitchUser); len(values) > 0 && values[0] != "" {
			return values[0]
		}
	}

	// Get the actual user ID
	if values := md.Get(config.MetadataKeyUserID); len(values) > 0 {
		return values[0]
	}

	return ""
}

// UserIDToOutgoingContext adds the user ID to outgoing gRPC context metadata.
func UserIDToOutgoingContext(ctx context.Context, userID string) context.Context {
	return UserIDToOutgoingContextWithKey(ctx, userID, DefaultMetadataKeyUserID)
}

// UserIDToOutgoingContextWithKey adds the user ID to outgoing gRPC context metadata with a custom key.
func UserIDToOutgoingContextWithKey(ctx context.Context, userID string, key string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, key, userID)
}

// SwitchUserToOutgoingContext adds a switch-user header to outgoing gRPC context metadata.
// This is only effective when EnableSwitchAuth is set on the server.
func SwitchUserToOutgoingContext(ctx context.Context, switchToUserID string) context.Context {
	return SwitchUserToOutgoingContextWithKey(ctx, switchToUserID, DefaultMetadataKeySwitchUser)
}

// SwitchUserToOutgoingContextWithKey adds a switch-user header with a custom key.
func SwitchUserToOutgoingContextWithKey(ctx context.Context, switchToUserID string, key string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, key, switchToUserID)
}

// IsAuthenticated returns true if there is an authenticated user in the context.
func IsAuthenticated(ctx context.Context) bool {
	return UserIDFromContext(ctx) != ""
}

// IsAuthenticatedWithConfig returns true if there is an authenticated user using the specified config.
func IsAuthenticatedWithConfig(ctx context.Context, config *Config) bool {
	return UserIDFromContextWithConfig(ctx, config) != ""
}
