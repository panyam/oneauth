# tracing/

W3C Trace Context propagation for oneauth's HTTP-handling code (SEP-414 / #254).

| Symbol | What |
|---|---|
| `Extract(r *http.Request) context.Context` | Read `traceparent` (+ `tracestate`) from inbound headers; malformed values are dropped per W3C §3.2.2.5. |
| `Inject(ctx context.Context, r *http.Request)` | Write the active span's `traceparent` onto an outbound request. No-op if ctx has no active span. |
| `Tracer(tp trace.TracerProvider, name string) trace.Tracer` | Returns the OTel no-op tracer when `tp == nil` — zero allocation cost on the disabled path. |
| `InstrumentationName` | `"github.com/panyam/oneauth"` — the value emitted as `instrumentation.scope.name` on every oneauth-emitted span. |

## Why this lives at the repo root

`tracing/` is dep-free of every other oneauth package so `keys/`, `apiauth/`, and `client/` can import it without cycles. It depends only on `go.opentelemetry.io/otel/{trace,propagation}` (the API surfaces, plus the W3C `TraceContext` propagator) — no SDK.

## Wiring (typical issuer)

```go
import "go.opentelemetry.io/otel/sdk/trace" // your tracer provider

tp := trace.NewTracerProvider( /* exporter, sampler, … */ )

apiAuth := &apiauth.APIAuth{ /* … */, TracerProvider: tp }
jwksH   := &keys.JWKSHandler{ /* … */, TracerProvider: tp }
introH  := apiauth.NewIntrospectionHandler(apiAuth, clientKeyStore) // inherits tp
revokeH := apiauth.NewRevocationHandler(apiAuth, clientKeyStore)     // inherits tp
```

Resource servers wire the same TP onto `APIMiddleware` and any `IntrospectionValidator` they use; the client SDK (`client/`) only needs a TP at the caller — the SDK pulls `traceparent` from the supplied ctx.

## Span names

| Span | Emitter |
|---|---|
| `oneauth.token.issue` | `APIAuth.ServeHTTP` (`/token`) |
| `oneauth.introspect` | `IntrospectionHandler.ServeHTTP` (`/oauth/introspect`) |
| `oneauth.revoke` | `RevocationHandler.ServeHTTP` (`/oauth/revoke`) |
| `oneauth.jwks.serve` | `JWKSHandler.ServeHTTP` (`/.well-known/jwks.json`) |
| `oneauth.jwks.key_lookup` | `JWKSKeyStore.GetKeyByKid` |
| `oneauth.jwks.refresh` | `JWKSKeyStore.refreshCtx` — outbound HTTP fetch |
| `oneauth.signature_verify` | `jwtValidator.ValidateToken` |
| `oneauth.introspection_client.request` | `IntrospectionValidator.ValidateWithContext` |
