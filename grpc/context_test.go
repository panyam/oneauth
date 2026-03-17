package grpc

// Tests for gRPC context helpers: user ID extraction, switch-user logic, outgoing metadata injection, and authentication checks.

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"
)

// TestDefaultConfig verifies that DefaultConfig returns a Config with expected default metadata keys and switch-auth disabled.
func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config.MetadataKeyUserID != DefaultMetadataKeyUserID {
		t.Errorf("expected MetadataKeyUserID %q, got %q", DefaultMetadataKeyUserID, config.MetadataKeyUserID)
	}
	if config.MetadataKeySwitchUser != DefaultMetadataKeySwitchUser {
		t.Errorf("expected MetadataKeySwitchUser %q, got %q", DefaultMetadataKeySwitchUser, config.MetadataKeySwitchUser)
	}
	if config.EnableSwitchAuth {
		t.Error("expected EnableSwitchAuth to be false by default")
	}
}

// TestEnsureDefaults verifies that EnsureDefaults fills in missing metadata keys on a zero-value Config.
func TestEnsureDefaults(t *testing.T) {
	config := &Config{}
	config.EnsureDefaults()
	if config.MetadataKeyUserID != DefaultMetadataKeyUserID {
		t.Errorf("expected MetadataKeyUserID %q, got %q", DefaultMetadataKeyUserID, config.MetadataKeyUserID)
	}
	if config.MetadataKeySwitchUser != DefaultMetadataKeySwitchUser {
		t.Errorf("expected MetadataKeySwitchUser %q, got %q", DefaultMetadataKeySwitchUser, config.MetadataKeySwitchUser)
	}
}

// TestUserIDFromContext_NoMetadata verifies that UserIDFromContext returns an empty string when no gRPC metadata is present.
func TestUserIDFromContext_NoMetadata(t *testing.T) {
	ctx := context.Background()
	userID := UserIDFromContext(ctx)
	if userID != "" {
		t.Errorf("expected empty user ID, got %q", userID)
	}
}

// TestUserIDFromContext_WithUserID verifies that UserIDFromContext extracts the user ID from incoming gRPC metadata.
func TestUserIDFromContext_WithUserID(t *testing.T) {
	md := metadata.Pairs(DefaultMetadataKeyUserID, "user123")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	userID := UserIDFromContext(ctx)
	if userID != "user123" {
		t.Errorf("expected user ID %q, got %q", "user123", userID)
	}
}

// TestUserIDFromContext_SwitchUserDisabled verifies that the switch-user header is ignored when switch-auth is disabled.
func TestUserIDFromContext_SwitchUserDisabled(t *testing.T) {
	md := metadata.Pairs(
		DefaultMetadataKeyUserID, "user123",
		DefaultMetadataKeySwitchUser, "switched456",
	)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	// With default config (switch auth disabled), should return actual user ID
	userID := UserIDFromContext(ctx)
	if userID != "user123" {
		t.Errorf("expected user ID %q (switch auth disabled), got %q", "user123", userID)
	}
}

// TestUserIDFromContext_SwitchUserEnabled verifies that the switch-user header overrides the real user ID when switch-auth is enabled.
func TestUserIDFromContext_SwitchUserEnabled(t *testing.T) {
	md := metadata.Pairs(
		DefaultMetadataKeyUserID, "user123",
		DefaultMetadataKeySwitchUser, "switched456",
	)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	config := &Config{EnableSwitchAuth: true}
	userID := UserIDFromContextWithConfig(ctx, config)
	if userID != "switched456" {
		t.Errorf("expected switched user ID %q, got %q", "switched456", userID)
	}
}

// TestUserIDFromContext_SwitchUserEmpty verifies that an empty switch-user header falls back to the actual user ID.
func TestUserIDFromContext_SwitchUserEmpty(t *testing.T) {
	md := metadata.Pairs(
		DefaultMetadataKeyUserID, "user123",
		DefaultMetadataKeySwitchUser, "",
	)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	config := &Config{EnableSwitchAuth: true}
	userID := UserIDFromContextWithConfig(ctx, config)
	// Should fall back to actual user when switch user is empty
	if userID != "user123" {
		t.Errorf("expected user ID %q (empty switch user), got %q", "user123", userID)
	}
}

// TestUserIDToOutgoingContext verifies that UserIDToOutgoingContext attaches the user ID to outgoing gRPC metadata.
func TestUserIDToOutgoingContext(t *testing.T) {
	ctx := context.Background()
	ctx = UserIDToOutgoingContext(ctx, "user789")

	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("expected outgoing metadata")
	}

	values := md.Get(DefaultMetadataKeyUserID)
	if len(values) != 1 || values[0] != "user789" {
		t.Errorf("expected user ID %q in outgoing context, got %v", "user789", values)
	}
}

// TestUserIDToOutgoingContextWithKey verifies that a custom metadata key can be used for the user ID in outgoing context.
func TestUserIDToOutgoingContextWithKey(t *testing.T) {
	ctx := context.Background()
	ctx = UserIDToOutgoingContextWithKey(ctx, "user789", "custom-user-key")

	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("expected outgoing metadata")
	}

	values := md.Get("custom-user-key")
	if len(values) != 1 || values[0] != "user789" {
		t.Errorf("expected user ID %q with custom key, got %v", "user789", values)
	}
}

// TestSwitchUserToOutgoingContext verifies that SwitchUserToOutgoingContext attaches the switch-user ID to outgoing metadata.
func TestSwitchUserToOutgoingContext(t *testing.T) {
	ctx := context.Background()
	ctx = SwitchUserToOutgoingContext(ctx, "switched123")

	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("expected outgoing metadata")
	}

	values := md.Get(DefaultMetadataKeySwitchUser)
	if len(values) != 1 || values[0] != "switched123" {
		t.Errorf("expected switch user ID %q, got %v", "switched123", values)
	}
}

// TestIsAuthenticated verifies that IsAuthenticated returns true only when a user ID is present in the context.
func TestIsAuthenticated(t *testing.T) {
	// No user
	ctx := context.Background()
	if IsAuthenticated(ctx) {
		t.Error("expected not authenticated with empty context")
	}

	// With user
	md := metadata.Pairs(DefaultMetadataKeyUserID, "user123")
	ctx = metadata.NewIncomingContext(context.Background(), md)
	if !IsAuthenticated(ctx) {
		t.Error("expected authenticated with user in context")
	}
}

// TestIsAuthenticatedWithConfig verifies that switch-user metadata counts as authenticated only when switch-auth is enabled.
func TestIsAuthenticatedWithConfig(t *testing.T) {
	md := metadata.Pairs(DefaultMetadataKeySwitchUser, "switched123")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	// Without switch auth enabled
	if IsAuthenticatedWithConfig(ctx, nil) {
		t.Error("expected not authenticated when switch auth disabled")
	}

	// With switch auth enabled
	config := &Config{EnableSwitchAuth: true}
	if !IsAuthenticatedWithConfig(ctx, config) {
		t.Error("expected authenticated when switch auth enabled")
	}
}

// TestCustomMetadataKeys verifies that UserIDFromContextWithConfig reads from custom metadata key names.
func TestCustomMetadataKeys(t *testing.T) {
	config := &Config{
		MetadataKeyUserID:     "x-custom-user",
		MetadataKeySwitchUser: "x-custom-switch",
	}

	md := metadata.Pairs("x-custom-user", "customuser123")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	userID := UserIDFromContextWithConfig(ctx, config)
	if userID != "customuser123" {
		t.Errorf("expected user ID %q with custom key, got %q", "customuser123", userID)
	}
}
