package apiauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/localauth"
	"github.com/panyam/oneauth/stores/fs"
)

const tracingValidTraceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

func newTracingRecorder(t *testing.T) (*tracetest.SpanRecorder, *sdktrace.TracerProvider) {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	return rec, tp
}

func findTracingSpan(spans []sdktrace.ReadOnlySpan, name string) sdktrace.ReadOnlySpan {
	for _, s := range spans {
		if s.Name() == name {
			return s
		}
	}
	return nil
}

func tracingAttr(span sdktrace.ReadOnlySpan, key string) (attribute.Value, bool) {
	for _, kv := range span.Attributes() {
		if string(kv.Key) == key {
			return kv.Value, true
		}
	}
	return attribute.Value{}, false
}

func setupAPIAuthWithTracer(t *testing.T, tp trace.TracerProvider) (*apiauth.APIAuth, string) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "oneauth-trace-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	userStore := fs.NewFSUserStore(tmpDir)
	identityStore := fs.NewFSIdentityStore(tmpDir)
	channelStore := fs.NewFSChannelStore(tmpDir)
	refreshStore := fs.NewFSRefreshTokenStore(tmpDir)

	email := "trace@example.com"
	create := localauth.NewCreateUserFunc(userStore, identityStore, channelStore)
	_, err = create(&localauth.Credentials{Username: "traceuser", Email: &email, Password: "password123"})
	require.NoError(t, err)

	return &apiauth.APIAuth{
		RefreshTokenStore:   refreshStore,
		JWTSecretKey:        "trace-secret",
		JWTIssuer:           "oneauth-trace-test",
		ValidateCredentials: localauth.NewCredentialsValidator(identityStore, channelStore, userStore),
		GetSubjectScopes: func(userID string) ([]string, error) {
			return []string{core.ScopeRead}, nil
		},
		TracerProvider: tp,
	}, email
}

func TestServeHTTP_EmitsTokenIssueSpan_WithGrantTypeAttribute(t *testing.T) {
	rec, tp := newTracingRecorder(t)
	apiAuth, email := setupAPIAuthWithTracer(t, tp)

	body, _ := json.Marshal(map[string]string{
		"grant_type": "password",
		"username":   email,
		"password":   "password123",
	})
	req := httptest.NewRequest(http.MethodPost, "/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	apiAuth.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	span := findTracingSpan(rec.Ended(), "oneauth.token.issue")
	require.NotNil(t, span, "expected oneauth.token.issue span")
	assert.Equal(t, trace.SpanKindServer, span.SpanKind())

	grant, ok := tracingAttr(span, "oauth.grant_type")
	require.True(t, ok)
	assert.Equal(t, "password", grant.AsString())
}

func TestServeHTTP_PropagatesInboundTraceparent(t *testing.T) {
	rec, tp := newTracingRecorder(t)
	apiAuth, email := setupAPIAuthWithTracer(t, tp)

	body, _ := json.Marshal(map[string]string{
		"grant_type": "password",
		"username":   email,
		"password":   "password123",
	})
	req := httptest.NewRequest(http.MethodPost, "/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("traceparent", tracingValidTraceparent)

	apiAuth.ServeHTTP(httptest.NewRecorder(), req)

	span := findTracingSpan(rec.Ended(), "oneauth.token.issue")
	require.NotNil(t, span)
	assert.Equal(t, "0af7651916cd43dd8448eb211c80319c", span.SpanContext().TraceID().String())
}

func TestRevocationHandler_EmitsRevokeSpan(t *testing.T) {
	rec, tp := newTracingRecorder(t)

	handler := &apiauth.RevocationHandler{
		Revoker:        apiauth.NewTokenRevoker(apiauth.TokenRevokerConfig{}),
		Authenticator:  apiauth.NewClientAuthenticator(nil),
		TracerProvider: tp,
	}

	form := url.Values{"token": {"opaque-token"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("traceparent", tracingValidTraceparent)
	req.SetBasicAuth("client-x", "secret-y")

	handler.ServeHTTP(httptest.NewRecorder(), req)

	span := findTracingSpan(rec.Ended(), "oneauth.revoke")
	require.NotNil(t, span, "expected oneauth.revoke span")
	assert.Equal(t, "0af7651916cd43dd8448eb211c80319c", span.SpanContext().TraceID().String())
}

func TestIntrospectionClient_InjectsTraceparentOnOutbound(t *testing.T) {
	_, tp := newTracingRecorder(t)

	var seenTraceparent string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenTraceparent = r.Header.Get("traceparent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":false}`))
	}))
	t.Cleanup(upstream.Close)

	v := &apiauth.IntrospectionValidator{
		IntrospectionURL: upstream.URL,
		ClientID:         "rs",
		ClientSecret:     "sekret",
		TracerProvider:   tp,
	}

	ctx, parent := tp.Tracer("test").Start(context.Background(), "caller")
	_, err := v.ValidateWithContext(ctx, "any-token")
	parent.End()
	require.NoError(t, err)

	require.NotEmpty(t, seenTraceparent, "introspection client must inject a traceparent")
	assert.Contains(t, seenTraceparent, parent.SpanContext().TraceID().String())
}

func TestServeHTTP_NilTracerProviderEmitsNoSpan(t *testing.T) {
	rec, _ := newTracingRecorder(t)

	apiAuth, email := setupAPIAuthWithTracer(t, nil)

	body, _ := json.Marshal(map[string]string{
		"grant_type": "password",
		"username":   email,
		"password":   "password123",
	})
	req := httptest.NewRequest(http.MethodPost, "/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	apiAuth.ServeHTTP(httptest.NewRecorder(), req)

	for _, s := range rec.Ended() {
		if strings.HasPrefix(s.Name(), "oneauth.") {
			t.Fatalf("nil TracerProvider must not emit spans, found %q", s.Name())
		}
	}
}
