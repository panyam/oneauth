package grpc

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"
)

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

func TestUserIDFromContext_NoMetadata(t *testing.T) {
	ctx := context.Background()
	userID := UserIDFromContext(ctx)
	if userID != "" {
		t.Errorf("expected empty user ID, got %q", userID)
	}
}

func TestUserIDFromContext_WithUserID(t *testing.T) {
	md := metadata.Pairs(DefaultMetadataKeyUserID, "user123")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	userID := UserIDFromContext(ctx)
	if userID != "user123" {
		t.Errorf("expected user ID %q, got %q", "user123", userID)
	}
}

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
