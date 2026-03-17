package grpc

// Tests for gRPC auth interceptors: unary and stream authentication enforcement, public method bypass, and optional auth modes.

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TestDefaultInterceptorConfig verifies that the default interceptor config requires auth and initializes its fields.
func TestDefaultInterceptorConfig(t *testing.T) {
	config := DefaultInterceptorConfig()
	if !config.RequireAuth {
		t.Error("expected RequireAuth to be true by default")
	}
	if config.PublicMethods == nil {
		t.Error("expected PublicMethods to be initialized")
	}
	if config.Config == nil {
		t.Error("expected Config to be initialized")
	}
}

// TestNewPublicMethodsConfig verifies that NewPublicMethodsConfig marks the specified methods as public while requiring auth for others.
func TestNewPublicMethodsConfig(t *testing.T) {
	config := NewPublicMethodsConfig("/pkg.Svc/Method1", "/pkg.Svc/Method2")
	if !config.RequireAuth {
		t.Error("expected RequireAuth to be true")
	}
	if !config.PublicMethods["/pkg.Svc/Method1"] {
		t.Error("expected Method1 to be public")
	}
	if !config.PublicMethods["/pkg.Svc/Method2"] {
		t.Error("expected Method2 to be public")
	}
	if config.PublicMethods["/pkg.Svc/Method3"] {
		t.Error("expected Method3 to not be public")
	}
}

// TestOptionalAuthConfig verifies that OptionalAuthConfig creates a config with RequireAuth set to false.
func TestOptionalAuthConfig(t *testing.T) {
	config := OptionalAuthConfig()
	if config.RequireAuth {
		t.Error("expected RequireAuth to be false")
	}
}

// TestUnaryAuthInterceptor_RequireAuth_NoUser verifies that unauthenticated unary requests are rejected with codes.Unauthenticated.
func TestUnaryAuthInterceptor_RequireAuth_NoUser(t *testing.T) {
	interceptor := UnaryAuthInterceptor(nil)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/pkg.Svc/Method"}

	_, err := interceptor(ctx, nil, info, func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Error("handler should not be called")
		return nil, nil
	})

	if err == nil {
		t.Fatal("expected error for unauthenticated request")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected grpc status error, got %v", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated code, got %v", st.Code())
	}
}

// TestUnaryAuthInterceptor_RequireAuth_WithUser verifies that authenticated unary requests pass through to the handler.
func TestUnaryAuthInterceptor_RequireAuth_WithUser(t *testing.T) {
	interceptor := UnaryAuthInterceptor(nil)

	md := metadata.Pairs(DefaultMetadataKeyUserID, "user123")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/pkg.Svc/Method"}

	handlerCalled := false
	_, err := interceptor(ctx, nil, info, func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "result", nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !handlerCalled {
		t.Error("handler should have been called")
	}
}

// TestUnaryAuthInterceptor_PublicMethod verifies that public methods bypass authentication checks.
func TestUnaryAuthInterceptor_PublicMethod(t *testing.T) {
	config := NewPublicMethodsConfig("/pkg.Svc/PublicMethod")
	interceptor := UnaryAuthInterceptor(config)

	ctx := context.Background() // No user
	info := &grpc.UnaryServerInfo{FullMethod: "/pkg.Svc/PublicMethod"}

	handlerCalled := false
	_, err := interceptor(ctx, nil, info, func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "result", nil
	})

	if err != nil {
		t.Fatalf("unexpected error for public method: %v", err)
	}
	if !handlerCalled {
		t.Error("handler should have been called for public method")
	}
}

// TestUnaryAuthInterceptor_OptionalAuth verifies that optional auth mode allows unauthenticated requests through.
func TestUnaryAuthInterceptor_OptionalAuth(t *testing.T) {
	config := OptionalAuthConfig()
	interceptor := UnaryAuthInterceptor(config)

	ctx := context.Background() // No user
	info := &grpc.UnaryServerInfo{FullMethod: "/pkg.Svc/Method"}

	handlerCalled := false
	_, err := interceptor(ctx, nil, info, func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "result", nil
	})

	if err != nil {
		t.Fatalf("unexpected error with optional auth: %v", err)
	}
	if !handlerCalled {
		t.Error("handler should have been called with optional auth")
	}
}

// TestUnaryAuthInterceptor_SwitchUser verifies that the interceptor accepts switch-user metadata when switch-auth is enabled.
func TestUnaryAuthInterceptor_SwitchUser(t *testing.T) {
	config := DefaultInterceptorConfig()
	config.Config.EnableSwitchAuth = true
	interceptor := UnaryAuthInterceptor(config)

	md := metadata.Pairs(DefaultMetadataKeySwitchUser, "switched456")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/pkg.Svc/Method"}

	handlerCalled := false
	_, err := interceptor(ctx, nil, info, func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "result", nil
	})

	if err != nil {
		t.Fatalf("unexpected error with switch user: %v", err)
	}
	if !handlerCalled {
		t.Error("handler should have been called with switch user")
	}
}

// mockServerStream implements grpc.ServerStream for testing
type mockServerStream struct {
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context         { return m.ctx }
func (m *mockServerStream) SetHeader(metadata.MD) error      { return nil }
func (m *mockServerStream) SendHeader(metadata.MD) error     { return nil }
func (m *mockServerStream) SetTrailer(metadata.MD)           {}
func (m *mockServerStream) SendMsg(interface{}) error        { return nil }
func (m *mockServerStream) RecvMsg(interface{}) error        { return nil }

// TestStreamAuthInterceptor_RequireAuth_NoUser verifies that unauthenticated streaming requests are rejected with codes.Unauthenticated.
func TestStreamAuthInterceptor_RequireAuth_NoUser(t *testing.T) {
	interceptor := StreamAuthInterceptor(nil)

	stream := &mockServerStream{ctx: context.Background()}
	info := &grpc.StreamServerInfo{FullMethod: "/pkg.Svc/StreamMethod"}

	err := interceptor(nil, stream, info, func(srv interface{}, ss grpc.ServerStream) error {
		t.Error("handler should not be called")
		return nil
	})

	if err == nil {
		t.Fatal("expected error for unauthenticated stream")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected grpc status error, got %v", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated code, got %v", st.Code())
	}
}

// TestStreamAuthInterceptor_RequireAuth_WithUser verifies that authenticated streaming requests pass through to the handler.
func TestStreamAuthInterceptor_RequireAuth_WithUser(t *testing.T) {
	interceptor := StreamAuthInterceptor(nil)

	md := metadata.Pairs(DefaultMetadataKeyUserID, "user123")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	stream := &mockServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{FullMethod: "/pkg.Svc/StreamMethod"}

	handlerCalled := false
	err := interceptor(nil, stream, info, func(srv interface{}, ss grpc.ServerStream) error {
		handlerCalled = true
		return nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !handlerCalled {
		t.Error("handler should have been called")
	}
}

// TestStreamAuthInterceptor_PublicMethod verifies that public streaming methods bypass authentication checks.
func TestStreamAuthInterceptor_PublicMethod(t *testing.T) {
	config := NewPublicMethodsConfig("/pkg.Svc/PublicStream")
	interceptor := StreamAuthInterceptor(config)

	stream := &mockServerStream{ctx: context.Background()}
	info := &grpc.StreamServerInfo{FullMethod: "/pkg.Svc/PublicStream"}

	handlerCalled := false
	err := interceptor(nil, stream, info, func(srv interface{}, ss grpc.ServerStream) error {
		handlerCalled = true
		return nil
	})

	if err != nil {
		t.Fatalf("unexpected error for public stream: %v", err)
	}
	if !handlerCalled {
		t.Error("handler should have been called for public stream")
	}
}
