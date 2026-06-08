// Package tracing wires oneauth's HTTP-handling code into OpenTelemetry
// trace context propagation (W3C Trace Context, https://www.w3.org/TR/trace-context/).
//
// The package is intentionally small: a propagator-bound Extract / Inject
// pair for the `traceparent` (and `tracestate`) headers, plus a Tracer
// helper that returns a no-op tracer when the caller hasn't wired a
// TracerProvider. oneauth's server and client code calls into these
// helpers without paying any allocation when tracing is disabled.
package tracing

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// InstrumentationName is the value passed to TracerProvider.Tracer when
// constructing a Tracer for code inside this module. Consumers reading
// emitted spans can rely on `instrumentation.scope.name = "github.com/panyam/oneauth"`
// to identify oneauth-emitted spans.
const InstrumentationName = "github.com/panyam/oneauth"

// propagator is the package-wide W3C Trace Context propagator. The W3C
// spec is the lingua franca of cross-process tracing; we deliberately
// do not enable Baggage here because oneauth does not carry
// application-level baggage and adding it later is a backwards-compatible
// change. Stateless and concurrency-safe.
var propagator propagation.TextMapPropagator = propagation.TraceContext{}

// Extract pulls W3C trace context out of the request headers and returns
// a context carrying the remote SpanContext. When the request has no
// `traceparent` header, or the header is malformed, the returned context
// is `r.Context()` unchanged — per W3C §3.2.2.5 ("MUST NOT forward")
// the malformed value is dropped silently rather than propagated.
//
// Callers that go on to start a span will get a span rooted under the
// upstream caller's trace when extraction succeeded, and a fresh local
// root when it did not.
func Extract(r *http.Request) context.Context {
	if r == nil {
		return context.Background()
	}
	return propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
}

// Inject writes W3C trace context from ctx onto the outgoing request's
// headers. When ctx carries no active span (or only a no-op span), no
// headers are written — callers do not need to guard the call.
//
// Use immediately before sending: any header mutation after Inject and
// before client.Do(r) risks dropping the traceparent.
func Inject(ctx context.Context, r *http.Request) {
	if r == nil {
		return
	}
	propagator.Inject(ctx, propagation.HeaderCarrier(r.Header))
}

// Tracer returns a trace.Tracer suitable for emitting oneauth spans.
//
// When tp is nil the returned tracer is the OTel no-op tracer: every
// span operation is a cheap allocation-free no-op, no SpanProcessor or
// Exporter is consulted, and no parent-extraction work is wasted. This
// keeps oneauth's hot path (handlers, validators) free when callers
// have not opted into tracing.
//
// The returned tracer is safe for concurrent use.
func Tracer(tp trace.TracerProvider, name string) trace.Tracer {
	if tp == nil {
		return tracenoop.NewTracerProvider().Tracer(name)
	}
	return tp.Tracer(name)
}
