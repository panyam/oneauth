package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/panyam/oneauth/client"
)

func TestDiscoverASWithContext_InjectsTraceparentOnOutbound(t *testing.T) {
	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	var seenTraceparent string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenTraceparent = r.Header.Get("traceparent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"` + upstreamSelfURL(r) + `","token_endpoint":"` + upstreamSelfURL(r) + `/token"}`))
	}))
	t.Cleanup(upstream.Close)

	ctx, span := tp.Tracer("test").Start(context.Background(), "caller-span")
	defer span.End()

	meta, err := client.DiscoverASWithContext(ctx, upstream.URL)
	require.NoError(t, err)
	require.NotNil(t, meta)

	require.NotEmpty(t, seenTraceparent, "discovery must inject a traceparent")
	assert.Contains(t, seenTraceparent, span.SpanContext().TraceID().String())
}

func TestDiscoverAS_NoActiveSpan_NoTraceparentHeader(t *testing.T) {
	var seenTraceparent string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenTraceparent = r.Header.Get("traceparent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"` + upstreamSelfURL(r) + `","token_endpoint":"` + upstreamSelfURL(r) + `/token"}`))
	}))
	t.Cleanup(upstream.Close)

	_, err := client.DiscoverAS(upstream.URL)
	require.NoError(t, err)
	assert.Empty(t, seenTraceparent, "no active span → no traceparent header")
}

func upstreamSelfURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}
