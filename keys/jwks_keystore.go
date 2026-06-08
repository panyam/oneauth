package keys

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/panyam/oneauth/tracing"
	"github.com/panyam/oneauth/utils"
)

// JWKSKeyStore implements KeyLookup (read-only) by fetching public keys from a remote JWKS endpoint.
// It caches keys locally and refreshes them periodically.
type JWKSKeyStore struct {
	JWKSURL         string
	HTTPClient      *http.Client
	RefreshInterval time.Duration // default: 1 hour
	MinRefreshGap   time.Duration // default: 5 seconds

	// TracerProvider opts the keystore into SEP-414 tracing. When set:
	//   - GetKeyByKid emits an `oneauth.jwks.key_lookup` span (attributes:
	//     `jwks.kid`, `jwks.cache_hit`).
	//   - refresh() emits an `oneauth.jwks.refresh` span and injects a
	//     W3C `traceparent` header on the outbound JWKS HTTP fetch so the
	//     upstream JWKS endpoint can stitch its own work into the trace.
	// Nil keeps every span on the no-op fast path. Configured via
	// WithTracerProvider.
	TracerProvider trace.TracerProvider

	mu        sync.RWMutex
	keys      map[string]*cachedKey
	lastFetch time.Time
	stopCh    chan struct{}
}

type cachedKey struct {
	PublicKey crypto.PublicKey
	Algorithm string
	Kid       string // the kid from JWKS (thumbprint)
}

// JWKSOption configures a JWKSKeyStore.
type JWKSOption func(*JWKSKeyStore)

// WithHTTPClient sets the HTTP client for JWKS fetching.
func WithHTTPClient(c *http.Client) JWKSOption {
	return func(s *JWKSKeyStore) { s.HTTPClient = c }
}

// WithRefreshInterval sets how often keys are refreshed in the background.
func WithRefreshInterval(d time.Duration) JWKSOption {
	return func(s *JWKSKeyStore) { s.RefreshInterval = d }
}

// WithMinRefreshGap sets the minimum time between refreshes (prevents stampede).
func WithMinRefreshGap(d time.Duration) JWKSOption {
	return func(s *JWKSKeyStore) { s.MinRefreshGap = d }
}

// WithTracerProvider opts the keystore into SEP-414 tracing — spans on
// the GetKeyByKid hot path and outbound traceparent injection on the
// JWKS refresh request. Nil (the default) keeps tracing off and the
// no-op path zero-cost. See JWKSKeyStore.TracerProvider for the full
// contract.
func WithTracerProvider(tp trace.TracerProvider) JWKSOption {
	return func(s *JWKSKeyStore) { s.TracerProvider = tp }
}

// NewJWKSKeyStore creates a new JWKSKeyStore. Call Start() to begin fetching keys.
func NewJWKSKeyStore(jwksURL string, opts ...JWKSOption) *JWKSKeyStore {
	s := &JWKSKeyStore{
		JWKSURL:         jwksURL,
		RefreshInterval: 1 * time.Hour,
		MinRefreshGap:   5 * time.Second,
		keys:            make(map[string]*cachedKey),
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.HTTPClient == nil {
		s.HTTPClient = http.DefaultClient
	}
	return s
}

// Start performs the initial JWKS fetch and starts background refresh.
func (s *JWKSKeyStore) Start() error {
	if err := s.refresh(); err != nil {
		return fmt.Errorf("jwks: initial fetch failed: %w", err)
	}
	s.stopCh = make(chan struct{})
	go s.backgroundRefresh()
	return nil
}

// Stop stops the background refresh goroutine.
func (s *JWKSKeyStore) Stop() {
	if s.stopCh != nil {
		close(s.stopCh)
	}
}

func (s *JWKSKeyStore) backgroundRefresh() {
	ticker := time.NewTicker(s.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := s.refresh(); err != nil {
				log.Printf("jwks: background refresh failed: %v", err)
			}
		case <-s.stopCh:
			return
		}
	}
}

// refresh runs a JWKS refresh without inheriting a caller context. Used
// by Start() (no caller in scope) and backgroundRefresh() (ticker-driven,
// no caller). Spans emitted from this path are trace roots — that's
// correct, since there is no upstream span to parent under.
func (s *JWKSKeyStore) refresh() error {
	return s.refreshCtx(context.Background())
}

// refreshCtx runs a JWKS refresh under the given context. Called from
// GetKeyByKid on cache miss so the resulting `oneauth.jwks.refresh` span
// nests under the caller's `oneauth.jwks.key_lookup` span. The W3C
// `traceparent` header on the outbound HTTP request is sourced from
// ctx, so an OTel-aware JWKS upstream can stitch its `oneauth.jwks.serve`
// span into the same trace.
func (s *JWKSKeyStore) refreshCtx(ctx context.Context) error {
	s.mu.RLock()
	lastFetch := s.lastFetch
	s.mu.RUnlock()

	if time.Since(lastFetch) < s.MinRefreshGap {
		return nil
	}

	ctx, span := tracing.Tracer(s.TracerProvider, tracing.InstrumentationName).
		Start(ctx, "oneauth.jwks.refresh", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()
	span.SetAttributes(attribute.String("jwks.url", s.JWKSURL))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.JWKSURL, nil)
	if err != nil {
		span.SetStatus(codes.Error, "build request failed")
		span.RecordError(err)
		return fmt.Errorf("build request failed: %w", err)
	}
	tracing.Inject(ctx, req)

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		span.SetStatus(codes.Error, "fetch failed")
		span.RecordError(err)
		return fmt.Errorf("fetch failed: %w", err)
	}
	defer resp.Body.Close()

	span.SetAttributes(attribute.Int("http.response.status_code", resp.StatusCode))
	if resp.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "unexpected status")
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var jwkSet utils.JWKSet
	if err := json.NewDecoder(resp.Body).Decode(&jwkSet); err != nil {
		span.SetStatus(codes.Error, "decode failed")
		span.RecordError(err)
		return fmt.Errorf("decode failed: %w", err)
	}

	newKeys := make(map[string]*cachedKey, len(jwkSet.Keys))
	for _, jwk := range jwkSet.Keys {
		pub, alg, err := utils.JWKToPublicKey(jwk)
		if err != nil {
			log.Printf("jwks: skipping key %s: %v", jwk.Kid, err)
			continue
		}
		newKeys[jwk.Kid] = &cachedKey{PublicKey: pub, Algorithm: alg, Kid: jwk.Kid}
	}

	s.mu.Lock()
	s.keys = newKeys
	s.lastFetch = time.Now()
	s.mu.Unlock()

	span.SetAttributes(attribute.Int("jwks.keys_loaded", len(newKeys)))
	return nil
}

// GetKey returns ErrKeyNotFound — JWKSKeyStore only supports kid-based lookup.
// JWKS doesn't carry clientID→key mappings; use GetKeyByKid instead.
func (s *JWKSKeyStore) GetKey(ctx context.Context, req *GetKeyRequest) (*GetKeyResponse, error) {
	return nil, ErrKeyNotFound
}

// GetKeyByKid returns the key record for the given kid.
// ClientID is empty since JWKS doesn't carry client_id metadata —
// the middleware skips the cross-app check in this case.
func (s *JWKSKeyStore) GetKeyByKid(ctx context.Context, req *GetKeyByKidRequest) (*GetKeyByKidResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetKeyByKid: req is required")
	}
	ctx, span := tracing.Tracer(s.TracerProvider, tracing.InstrumentationName).
		Start(ctx, "oneauth.jwks.key_lookup")
	defer span.End()
	span.SetAttributes(attribute.String("jwks.kid", req.Kid))

	s.mu.RLock()
	entry, ok := s.keys[req.Kid]
	s.mu.RUnlock()
	if ok {
		span.SetAttributes(attribute.Bool("jwks.cache_hit", true))
		return &GetKeyByKidResponse{Record: &KeyRecord{Key: entry.PublicKey, Algorithm: entry.Algorithm, Kid: req.Kid}}, nil
	}
	span.SetAttributes(attribute.Bool("jwks.cache_hit", false))

	// Cache miss — try refreshing under the caller's context so the
	// refresh span nests under this key_lookup span and the outbound
	// JWKS fetch carries the same trace.
	s.refreshCtx(ctx)

	s.mu.RLock()
	entry, ok = s.keys[req.Kid]
	s.mu.RUnlock()
	if ok {
		return &GetKeyByKidResponse{Record: &KeyRecord{Key: entry.PublicKey, Algorithm: entry.Algorithm, Kid: req.Kid}}, nil
	}
	span.SetStatus(codes.Error, "kid not found")
	return nil, ErrKidNotFound
}
