package keys

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/panyam/oneauth/utils"
)

const validTraceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

func newRecorder(t *testing.T) (*tracetest.SpanRecorder, *sdktrace.TracerProvider) {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	return rec, tp
}

func findSpan(spans []sdktrace.ReadOnlySpan, name string) sdktrace.ReadOnlySpan {
	for _, s := range spans {
		if s.Name() == name {
			return s
		}
	}
	return nil
}

func attrValue(span sdktrace.ReadOnlySpan, key string) (attribute.Value, bool) {
	for _, kv := range span.Attributes() {
		if string(kv.Key) == key {
			return kv.Value, true
		}
	}
	return attribute.Value{}, false
}

func TestJWKSHandler_EmitsServeSpan_WithKeysReturnedAttr(t *testing.T) {
	rec, tp := newRecorder(t)

	ks := NewInMemoryKeyStore()
	_, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	_, err := ks.PutKey(context.Background(), &PutKeyRequest{
		Record: &KeyRecord{ClientID: "app_rsa", Key: pubPEM, Algorithm: "RS256"},
	})
	require.NoError(t, err)

	handler := &JWKSHandler{KeyStore: ks, TracerProvider: tp}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	span := findSpan(rec.Ended(), "oneauth.jwks.serve")
	require.NotNil(t, span, "expected oneauth.jwks.serve span")
	assert.Equal(t, trace.SpanKindServer, span.SpanKind())

	keysReturned, ok := attrValue(span, "jwks.keys_returned")
	require.True(t, ok, "expected jwks.keys_returned attribute")
	assert.Equal(t, int64(1), keysReturned.AsInt64())
}

func TestJWKSHandler_PropagatesIncomingTraceparent(t *testing.T) {
	rec, tp := newRecorder(t)

	ks := NewInMemoryKeyStore()
	handler := &JWKSHandler{KeyStore: ks, TracerProvider: tp}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	req.Header.Set("traceparent", validTraceparent)

	handler.ServeHTTP(httptest.NewRecorder(), req)

	span := findSpan(rec.Ended(), "oneauth.jwks.serve")
	require.NotNil(t, span)
	assert.Equal(t, "0af7651916cd43dd8448eb211c80319c", span.SpanContext().TraceID().String(),
		"server span must inherit the inbound trace ID")
	assert.True(t, span.Parent().IsRemote(),
		"server span parent must be marked remote")
}

func TestJWKSHandler_NilTracerProviderEmitsNoSpan(t *testing.T) {
	rec, _ := newRecorder(t)

	ks := NewInMemoryKeyStore()
	handler := &JWKSHandler{KeyStore: ks}

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	for _, s := range rec.Ended() {
		if s.Name() == "oneauth.jwks.serve" {
			t.Fatalf("nil TracerProvider must not emit spans, found %q", s.Name())
		}
	}
}

func TestJWKSKeyStore_RefreshInjectsTraceparent_AndEmitsRefreshSpan(t *testing.T) {
	rec, tp := newRecorder(t)

	// Build a JWKS-serving test server that records the inbound traceparent.
	_, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	pubKey, err := utils.DecodeVerifyKey(pubPEM, "RS256")
	require.NoError(t, err)
	kid, err := utils.ComputeKid(pubKey, "RS256")
	require.NoError(t, err)
	jwk, err := utils.PublicKeyToJWK(kid, "RS256", pubKey)
	require.NoError(t, err)

	var seenTraceparent string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenTraceparent = r.Header.Get("traceparent")
		_ = json.NewEncoder(w).Encode(utils.JWKSet{Keys: []utils.JWK{jwk}})
	}))
	t.Cleanup(upstream.Close)

	store := NewJWKSKeyStore(upstream.URL, WithTracerProvider(tp))
	require.NoError(t, store.Start())
	t.Cleanup(store.Stop)

	// Reset gap so a follow-up refresh under a known span context will fire.
	store.MinRefreshGap = 0

	// Start a synthetic caller span so the refresh inherits a real trace.
	ctx, callerSpan := tp.Tracer("test-caller").Start(context.Background(), "caller-span")
	require.NoError(t, store.refreshCtx(ctx))
	callerSpan.End()

	require.NotEmpty(t, seenTraceparent, "outbound refresh must inject a traceparent header")
	assert.Contains(t, seenTraceparent, callerSpan.SpanContext().TraceID().String(),
		"injected traceparent should carry the caller's trace ID")

	span := findSpan(rec.Ended(), "oneauth.jwks.refresh")
	require.NotNil(t, span, "expected oneauth.jwks.refresh span")
	assert.Equal(t, trace.SpanKindClient, span.SpanKind())
}

func TestJWKSKeyStore_GetKeyByKid_EmitsKeyLookupSpan(t *testing.T) {
	rec, tp := newRecorder(t)

	_, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	pubKey, _ := utils.DecodeVerifyKey(pubPEM, "RS256")
	kid, _ := utils.ComputeKid(pubKey, "RS256")
	jwk, _ := utils.PublicKeyToJWK(kid, "RS256", pubKey)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(utils.JWKSet{Keys: []utils.JWK{jwk}})
	}))
	t.Cleanup(upstream.Close)

	store := NewJWKSKeyStore(upstream.URL, WithTracerProvider(tp))
	require.NoError(t, store.Start())
	t.Cleanup(store.Stop)

	resp, err := store.GetKeyByKid(context.Background(), &GetKeyByKidRequest{Kid: kid})
	require.NoError(t, err)
	require.NotNil(t, resp)

	span := findSpan(rec.Ended(), "oneauth.jwks.key_lookup")
	require.NotNil(t, span, "expected oneauth.jwks.key_lookup span")

	kidAttr, ok := attrValue(span, "jwks.kid")
	require.True(t, ok)
	assert.Equal(t, kid, kidAttr.AsString())

	cacheHit, ok := attrValue(span, "jwks.cache_hit")
	require.True(t, ok)
	assert.True(t, cacheHit.AsBool(), "warm cache → cache_hit=true")
}
