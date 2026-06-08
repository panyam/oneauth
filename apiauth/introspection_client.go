package apiauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/panyam/oneauth/tracing"
)

// IntrospectionValidator validates tokens by calling a remote introspection
// endpoint (RFC 7662), as an alternative to local JWT validation via JWKS.
//
// Use this when:
//   - The resource server can't access the KeyStore or JWKS endpoint
//   - Centralized blacklist checking is needed
//   - Opaque (non-JWT) tokens need validation
//
// The validator authenticates to the introspection endpoint using client
// credentials (client_secret_basic).
//
// Optional response caching reduces load on the auth server. Cache entries
// expire after CacheTTL (default: no cache).
//
// See: https://www.rfc-editor.org/rfc/rfc7662
type IntrospectionValidator struct {
	// IntrospectionURL is the auth server's introspection endpoint.
	// Required.
	IntrospectionURL string

	// ClientID and ClientSecret authenticate this resource server to the
	// introspection endpoint via HTTP Basic auth (client_secret_basic).
	// Required.
	ClientID     string
	ClientSecret string

	// HTTPClient is used for introspection requests. If nil, uses
	// http.DefaultClient.
	HTTPClient *http.Client

	// CacheTTL enables response caching. If > 0, introspection responses
	// are cached for this duration. A revoked token may remain "active"
	// in the cache for up to CacheTTL after revocation.
	// Default: 0 (no caching).
	CacheTTL time.Duration

	// TracerProvider opts the introspection client into SEP-414
	// tracing. When set, ValidateWithContext emits an
	// `oneauth.introspection_client.request` span around the outbound
	// HTTP call AND injects a W3C `traceparent` header so the
	// upstream introspection endpoint can stitch its `oneauth.introspect`
	// span into the same trace. Nil keeps the path on the no-op fast
	// path with no allocation cost.
	TracerProvider trace.TracerProvider

	// cache stores introspection results keyed by token hash.
	mu    sync.RWMutex
	cache map[string]*cacheEntry
}

type cacheEntry struct {
	result *IntrospectionResult
	expiry time.Time
}

// IntrospectionResult holds the parsed introspection response.
type IntrospectionResult struct {
	Active    bool   `json:"active"`
	Sub       string `json:"sub,omitempty"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Jti       string `json:"jti,omitempty"`
	Aud       any    `json:"aud,omitempty"`
}

// Validate is the context-free convenience form of ValidateWithContext.
// SEP-414 trace propagation requires a context — callers that have one
// (any path serving an HTTP request) should prefer ValidateWithContext
// so the outbound introspection call inherits the inbound trace.
func (v *IntrospectionValidator) Validate(token string) (*IntrospectionResult, error) {
	return v.ValidateWithContext(context.Background(), token)
}

// ValidateWithContext calls the introspection endpoint to check if a
// token is active. Returns the introspection result with parsed claims,
// or an error if the introspection request itself failed (network error,
// auth failure, etc.).
//
// An inactive token is NOT an error — it returns IntrospectionResult{Active: false}.
// Only transport/auth failures return errors.
//
// When TracerProvider is set, the call emits an
// `oneauth.introspection_client.request` span and injects a W3C
// `traceparent` on the outbound HTTP request so the upstream
// /oauth/introspect endpoint can stitch its own span into the trace.
func (v *IntrospectionValidator) ValidateWithContext(ctx context.Context, token string) (*IntrospectionResult, error) {
	// Check cache first
	if v.CacheTTL > 0 {
		if cached := v.getCached(token); cached != nil {
			return cached, nil
		}
	}

	ctx, span := tracing.Tracer(v.TracerProvider, tracing.InstrumentationName).
		Start(ctx, "oneauth.introspection_client.request", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()
	span.SetAttributes(attribute.String("http.url", v.IntrospectionURL))

	client := v.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	// POST to introspection endpoint with Basic auth
	data := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.IntrospectionURL,
		strings.NewReader(data.Encode()))
	if err != nil {
		span.SetStatus(codes.Error, "build request failed")
		span.RecordError(err)
		return nil, fmt.Errorf("introspection request build failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(v.ClientID, v.ClientSecret)
	tracing.Inject(ctx, req)

	resp, err := client.Do(req)
	if err != nil {
		span.SetStatus(codes.Error, "request failed")
		span.RecordError(err)
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	span.SetAttributes(attribute.Int("http.response.status_code", resp.StatusCode))
	if resp.StatusCode == http.StatusUnauthorized {
		span.SetStatus(codes.Error, "auth failed")
		return nil, fmt.Errorf("introspection auth failed: invalid client credentials")
	}
	if resp.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "non-200 response")
		return nil, fmt.Errorf("introspection returned status %d", resp.StatusCode)
	}

	var result IntrospectionResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		span.SetStatus(codes.Error, "decode failed")
		span.RecordError(err)
		return nil, fmt.Errorf("introspection response decode failed: %w", err)
	}

	// Cache the result
	if v.CacheTTL > 0 {
		v.putCached(token, &result)
	}

	return &result, nil
}

// ValidateForMiddleware is the context-free convenience form of
// ValidateForMiddlewareWithContext. Prefer the context-bearing variant
// from any HTTP-serving path so SEP-414 trace propagation works.
func (v *IntrospectionValidator) ValidateForMiddleware(token string) (userID string, scopes []string, authType string, customClaims map[string]any, err error) {
	return v.ValidateForMiddlewareWithContext(context.Background(), token)
}

// ValidateForMiddlewareWithContext validates a token via the introspection
// endpoint and returns the fields APIMiddleware.validateRequest needs:
// userID, scopes, authType, customClaims. Returns an error if the token
// is inactive or introspection fails. ctx is forwarded into the outbound
// HTTP call so trace context propagates to the upstream introspection
// server (see ValidateWithContext).
func (v *IntrospectionValidator) ValidateForMiddlewareWithContext(ctx context.Context, token string) (userID string, scopes []string, authType string, customClaims map[string]any, err error) {
	result, err := v.ValidateWithContext(ctx, token)
	if err != nil {
		return "", nil, "", nil, err
	}
	if !result.Active {
		return "", nil, "", nil, fmt.Errorf("token is not active")
	}

	// Parse scopes
	if result.Scope != "" {
		scopes = strings.Split(result.Scope, " ")
	}

	// Build custom claims map
	customClaims = make(map[string]any)
	if result.ClientID != "" {
		customClaims["client_id"] = result.ClientID
	}
	if result.Iss != "" {
		customClaims["iss"] = result.Iss
	}
	if result.Jti != "" {
		customClaims["jti"] = result.Jti
	}
	if result.Aud != nil {
		customClaims["aud"] = result.Aud
	}

	return result.Sub, scopes, "introspection", customClaims, nil
}

// getCached returns a cached result if it exists and hasn't expired.
func (v *IntrospectionValidator) getCached(token string) *IntrospectionResult {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.cache == nil {
		return nil
	}
	entry, ok := v.cache[token]
	if !ok || time.Now().After(entry.expiry) {
		return nil
	}
	return entry.result
}

// putCached stores an introspection result in the cache.
func (v *IntrospectionValidator) putCached(token string, result *IntrospectionResult) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.cache == nil {
		v.cache = make(map[string]*cacheEntry)
	}
	v.cache[token] = &cacheEntry{
		result: result,
		expiry: time.Now().Add(v.CacheTTL),
	}
}
