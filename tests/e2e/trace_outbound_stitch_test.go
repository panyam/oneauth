package e2e_test

// End-to-end outbound trace stitching: a resource server's JWKSKeyStore
// fetches keys from an AS's JWKSHandler. With two separate TracerProviders
// (one per "process"), assert the inbound traceparent the AS sees carries
// the RS-side trace ID — proving the W3C wire stitches the two halves of
// the trace together. This is the literal acceptance trace in issue 254.
//
//   caller-span (RS)
//   └─ oneauth.jwks.key_lookup (RS)
//      └─ oneauth.jwks.refresh (RS, outbound HTTP)
//         └─ oneauth.jwks.serve (AS, parented via inbound traceparent)

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

func TestE2E_OutboundJWKSFetch_StitchesAcrossProcesses(t *testing.T) {
	// Two independent TPs simulate two oneauth processes wired to
	// separate observability backends.
	asRec := tracetest.NewSpanRecorder()
	asTP := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(asRec))
	t.Cleanup(func() { _ = asTP.Shutdown(context.Background()) })

	rsRec := tracetest.NewSpanRecorder()
	rsTP := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rsRec))
	t.Cleanup(func() { _ = rsTP.Shutdown(context.Background()) })

	// AS: a single registered RSA key + JWKSHandler with asTP wired.
	asKeyStore := keys.NewInMemoryKeyStore()
	_, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	pubKey, err := utils.DecodeVerifyKey(pubPEM, "RS256")
	require.NoError(t, err)
	expectedKid, err := utils.ComputeKid(pubKey, "RS256")
	require.NoError(t, err)
	_, err = asKeyStore.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID:  "as-app",
		Key:       pubPEM,
		Algorithm: "RS256",
		Kid:       expectedKid,
	}})
	require.NoError(t, err)

	asMux := http.NewServeMux()
	asMux.Handle("GET /.well-known/jwks.json", &keys.JWKSHandler{KeyStore: asKeyStore, TracerProvider: asTP})
	asServer := httptest.NewServer(asMux)
	t.Cleanup(asServer.Close)

	// RS: a JWKSKeyStore consuming the AS's JWKS, with rsTP wired.
	// Intentionally do NOT call Start() — the initial Start-triggered
	// refresh would be a trace root (no caller in scope) and pollute
	// the recorder. Letting GetKeyByKid drive the first refresh keeps
	// every emitted span under the caller's trace.
	rsKeyStore := keys.NewJWKSKeyStore(asServer.URL+"/.well-known/jwks.json", keys.WithTracerProvider(rsTP))

	// Synthetic caller — would be the RS's inbound handler span in real life.
	ctx, callerSpan := rsTP.Tracer("rs-caller").Start(context.Background(), "caller-span")

	// Lookup an unknown kid to force the refresh path.
	_, err = rsKeyStore.GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: "unknown-kid-forces-refresh"})
	require.Error(t, err, "unknown kid should miss after refresh")
	callerSpan.End()

	rsTraceID := callerSpan.SpanContext().TraceID().String()

	// RS side: key_lookup + refresh under the caller trace.
	rsSpans := rsRec.Ended()
	kl := findSpan(rsSpans, "oneauth.jwks.key_lookup")
	require.NotNil(t, kl, "expected oneauth.jwks.key_lookup on RS side")
	assert.Equal(t, rsTraceID, kl.SpanContext().TraceID().String(),
		"key_lookup must inherit the caller's trace")

	refresh := findSpan(rsSpans, "oneauth.jwks.refresh")
	require.NotNil(t, refresh, "expected oneauth.jwks.refresh on RS side")
	assert.Equal(t, rsTraceID, refresh.SpanContext().TraceID().String(),
		"refresh must inherit the caller's trace")

	// AS side: jwks.serve parented under the RS's trace via the W3C wire.
	asSpans := asRec.Ended()
	serve := findSpan(asSpans, "oneauth.jwks.serve")
	require.NotNil(t, serve, "expected oneauth.jwks.serve on AS side")
	assert.Equal(t, rsTraceID, serve.SpanContext().TraceID().String(),
		"AS jwks.serve must inherit the RS's trace ID — this is the W3C-wire stitch")
	assert.True(t, serve.Parent().IsRemote(),
		"AS jwks.serve parent must be marked remote (extracted from inbound traceparent)")
}
