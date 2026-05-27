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

	"github.com/panyam/oneauth/utils"
)

// JWKSKeyStore implements KeyLookup (read-only) by fetching public keys from a remote JWKS endpoint.
// It caches keys locally and refreshes them periodically.
type JWKSKeyStore struct {
	JWKSURL         string
	HTTPClient      *http.Client
	RefreshInterval time.Duration // default: 1 hour
	MinRefreshGap   time.Duration // default: 5 seconds

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

func (s *JWKSKeyStore) refresh() error {
	s.mu.RLock()
	lastFetch := s.lastFetch
	s.mu.RUnlock()

	if time.Since(lastFetch) < s.MinRefreshGap {
		return nil
	}

	resp, err := s.HTTPClient.Get(s.JWKSURL)
	if err != nil {
		return fmt.Errorf("fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var jwkSet utils.JWKSet
	if err := json.NewDecoder(resp.Body).Decode(&jwkSet); err != nil {
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
	s.mu.RLock()
	entry, ok := s.keys[req.Kid]
	s.mu.RUnlock()
	if ok {
		return &GetKeyByKidResponse{Record: &KeyRecord{Key: entry.PublicKey, Algorithm: entry.Algorithm, Kid: req.Kid}}, nil
	}

	// Cache miss — try refreshing
	s.refresh()

	s.mu.RLock()
	entry, ok = s.keys[req.Kid]
	s.mu.RUnlock()
	if ok {
		return &GetKeyByKidResponse{Record: &KeyRecord{Key: entry.PublicKey, Algorithm: entry.Algorithm, Kid: req.Kid}}, nil
	}
	return nil, ErrKidNotFound
}
