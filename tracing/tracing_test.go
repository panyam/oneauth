package tracing_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/panyam/oneauth/tracing"
)

// validTraceparent is a W3C Trace Context header that the propagator
// will happily extract — version 00, all-zeros except the trace ID,
// sample-flag set.
const validTraceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

func TestExtract_RoundTripFromUpstreamHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	r.Header.Set("traceparent", validTraceparent)

	ctx := tracing.Extract(r)

	sc := trace.SpanContextFromContext(ctx)
	require.True(t, sc.IsValid(), "expected a valid SpanContext after Extract")
	assert.Equal(t, "0af7651916cd43dd8448eb211c80319c", sc.TraceID().String())
	assert.Equal(t, "b7ad6b7169203331", sc.SpanID().String())
	assert.True(t, sc.IsSampled())
	assert.True(t, sc.IsRemote(), "extracted span context must be marked remote")
}

func TestExtract_MissingHeaderProducesPlainContext(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)

	ctx := tracing.Extract(r)

	assert.False(t, trace.SpanContextFromContext(ctx).IsValid(),
		"no traceparent header → no valid SpanContext")
}

func TestExtract_MalformedHeaderIsDropped(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	r.Header.Set("traceparent", "not-a-real-traceparent")

	ctx := tracing.Extract(r)

	assert.False(t, trace.SpanContextFromContext(ctx).IsValid(),
		"W3C §3.2.2.5: malformed traceparent MUST NOT be forwarded")
}

func TestExtract_NilRequestReturnsBackground(t *testing.T) {
	ctx := tracing.Extract(nil)
	assert.Equal(t, context.Background(), ctx)
}

func TestInject_WritesTraceparentFromActiveSpan(t *testing.T) {
	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	ctx, span := tp.Tracer("test").Start(context.Background(), "test-span")
	defer span.End()

	r := httptest.NewRequest(http.MethodPost, "https://example.com/token", nil)
	tracing.Inject(ctx, r)

	got := r.Header.Get("traceparent")
	require.NotEmpty(t, got, "Inject should write traceparent when ctx carries an active span")
	assert.Contains(t, got, span.SpanContext().TraceID().String(),
		"injected traceparent should carry the span's trace ID")
}

func TestInject_NoActiveSpanWritesNothing(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "https://example.com/token", nil)
	tracing.Inject(context.Background(), r)

	assert.Empty(t, r.Header.Get("traceparent"),
		"no active span → no header (propagator skips invalid span contexts)")
}

func TestInject_NilRequestIsNoop(t *testing.T) {
	assert.NotPanics(t, func() {
		tracing.Inject(context.Background(), nil)
	})
}

func TestTracer_NilProviderReturnsNoopThatDoesNotRecord(t *testing.T) {
	tr := tracing.Tracer(nil, "test")
	require.NotNil(t, tr)

	_, span := tr.Start(context.Background(), "noop-span")
	defer span.End()

	assert.False(t, span.SpanContext().IsValid(),
		"noop tracer span has no SpanContext")
	assert.False(t, span.IsRecording(),
		"noop tracer span must not be recording")
}

func TestTracer_RealProviderEmitsRecordableSpan(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	tr := tracing.Tracer(tp, tracing.InstrumentationName)
	_, span := tr.Start(context.Background(), "real-span")
	span.End()

	ended := recorder.Ended()
	require.Len(t, ended, 1)
	assert.Equal(t, "real-span", ended[0].Name())
	assert.Equal(t, tracing.InstrumentationName, ended[0].InstrumentationScope().Name)
}

func TestExtractThenInject_PropagatesParentToOutbound(t *testing.T) {
	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	inbound := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	inbound.Header.Set("traceparent", validTraceparent)
	ctx := tracing.Extract(inbound)

	ctx, span := tp.Tracer("server").Start(ctx, "server-span")
	defer span.End()

	outbound := httptest.NewRequest(http.MethodGet, "https://upstream.example.com/keys", nil)
	tracing.Inject(ctx, outbound)

	got := outbound.Header.Get("traceparent")
	require.NotEmpty(t, got)
	assert.Contains(t, got, "0af7651916cd43dd8448eb211c80319c",
		"outbound traceparent should reuse the incoming trace ID")
}
