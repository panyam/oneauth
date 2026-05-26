package grpc

import (
	"context"

	"google.golang.org/grpc/metadata"
)

// Default metadata keys for authentication context.
// These can be customized via Config if needed.
const (
	// DefaultMetadataKeySubject is the default gRPC metadata key for the
	// authenticated subject (RFC 7519 `sub` — user ID for human-driven
	// flows, client_id for client_credentials).
	DefaultMetadataKeySubject = "x-subject"

	// DefaultMetadataKeySwitchUser is the default gRPC metadata key for
	// switching to a different user (testing/impersonation only — by
	// nature scoped to human users, hence retains "User" naming).
	DefaultMetadataKeySwitchUser = "x-switch-user"
)

// Config holds the metadata key configuration for auth context.
type Config struct {
	// MetadataKeySubject is the gRPC metadata key carrying the
	// authenticated subject. Defaults to "x-subject".
	MetadataKeySubject string

	// MetadataKeySwitchUser is the gRPC metadata key for impersonation.
	// Only used when switch auth is enabled. Defaults to "x-switch-user".
	MetadataKeySwitchUser string

	// EnableSwitchAuth when true allows the X-Switch-User header to
	// override the subject. Should only be enabled in development /
	// testing environments.
	EnableSwitchAuth bool
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		MetadataKeySubject:    DefaultMetadataKeySubject,
		MetadataKeySwitchUser: DefaultMetadataKeySwitchUser,
		EnableSwitchAuth:      false,
	}
}

// EnsureDefaults fills in default values for any unset fields.
func (c *Config) EnsureDefaults() {
	if c.MetadataKeySubject == "" {
		c.MetadataKeySubject = DefaultMetadataKeySubject
	}
	if c.MetadataKeySwitchUser == "" {
		c.MetadataKeySwitchUser = DefaultMetadataKeySwitchUser
	}
}

// SubjectFromContext extracts the authenticated subject from the gRPC
// context metadata. Returns empty string if no subject is present.
func SubjectFromContext(ctx context.Context) string {
	return SubjectFromContextWithConfig(ctx, nil)
}

// SubjectFromContextWithConfig extracts the authenticated subject using
// the specified config.
func SubjectFromContextWithConfig(ctx context.Context, config *Config) string {
	if config == nil {
		config = DefaultConfig()
	}
	config.EnsureDefaults()

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	// Check for switch user first (only if enabled) — impersonation is
	// human-user-scoped by nature, so this header keeps its name.
	if config.EnableSwitchAuth {
		if values := md.Get(config.MetadataKeySwitchUser); len(values) > 0 && values[0] != "" {
			return values[0]
		}
	}

	if values := md.Get(config.MetadataKeySubject); len(values) > 0 {
		return values[0]
	}

	return ""
}

// SubjectToOutgoingContext adds the subject to outgoing gRPC context
// metadata.
func SubjectToOutgoingContext(ctx context.Context, subject string) context.Context {
	return SubjectToOutgoingContextWithKey(ctx, subject, DefaultMetadataKeySubject)
}

// SubjectToOutgoingContextWithKey adds the subject to outgoing gRPC
// context metadata under a custom key.
func SubjectToOutgoingContextWithKey(ctx context.Context, subject string, key string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, key, subject)
}

// SwitchUserToOutgoingContext adds a switch-user header to outgoing
// gRPC context metadata. Only effective when EnableSwitchAuth is set
// on the server.
func SwitchUserToOutgoingContext(ctx context.Context, switchToUserID string) context.Context {
	return SwitchUserToOutgoingContextWithKey(ctx, switchToUserID, DefaultMetadataKeySwitchUser)
}

// SwitchUserToOutgoingContextWithKey adds a switch-user header with a
// custom key.
func SwitchUserToOutgoingContextWithKey(ctx context.Context, switchToUserID string, key string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, key, switchToUserID)
}

// IsAuthenticated returns true if there is an authenticated subject in
// the context.
func IsAuthenticated(ctx context.Context) bool {
	return SubjectFromContext(ctx) != ""
}

// IsAuthenticatedWithConfig returns true if there is an authenticated
// subject using the specified config.
func IsAuthenticatedWithConfig(ctx context.Context, config *Config) bool {
	return SubjectFromContextWithConfig(ctx, config) != ""
}
