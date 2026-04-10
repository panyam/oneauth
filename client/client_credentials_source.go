package client

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/panyam/oneauth/core"
)

// tokenExpiryBuffer is subtracted from token expiry times to account for
// clock skew and network latency. Without this, tokens could expire between
// the freshness check and the server receiving the request.
const tokenExpiryBuffer = 30 * time.Second

// TokenSource provides OAuth2 access tokens. This interface matches
// mcpkit/core.TokenSource by structural typing — no cross-module import needed.
type TokenSource interface {
	Token() (string, error)
}

// ScopeAwareTokenSource extends TokenSource with scope step-up capability.
// When additional scopes are required, the cached token is invalidated and
// a new token is obtained with the merged scope set.
type ScopeAwareTokenSource interface {
	TokenSource
	TokenForScopes(scopes []string) (string, error)
}

// ClientCredentialsSource implements TokenSource for machine-to-machine auth
// using the OAuth 2.0 client_credentials grant (RFC 6749 §4.4).
//
// It caches the access token and automatically refreshes it when expired.
// TokenForScopes supports scope step-up by merging additional scopes and
// invalidating the cache.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
type ClientCredentialsSource struct {
	// TokenEndpoint is the authorization server's token URL.
	TokenEndpoint string

	// ClientID identifies this client to the authorization server.
	ClientID string

	// ClientSecret authenticates this client.
	ClientSecret string

	// Scopes to request.
	Scopes []string

	// Audience is the resource server's canonical URI (RFC 8707 resource indicator).
	Audience string

	// Refresher enables proactive token refresh before expiry. When nil or
	// Refresher.Buffer == 0, refresh is reactive — happens on the next
	// Token() call after expiry.
	//
	// Typical values: Buffer of 30s-60s for tokens with 5-15 minute lifetimes.
	// The goroutine starts lazily on the first Token() call and runs until
	// Close() is called on the source.
	Refresher *ProactiveRefresher

	mu     sync.Mutex
	client *AuthClient
	token  string
	expiry time.Time
}

// ProactiveRefresher configures and manages background token refresh before
// expiry. It bundles the refresh policy (Buffer) with the runtime state
// needed to coordinate the background goroutine lifecycle.
type ProactiveRefresher struct {
	// Buffer is how long before token expiry to refresh. Must be positive
	// to enable proactive refresh. A buffer of 30s means the refresh fires
	// 30 seconds before the token would have expired reactively.
	Buffer time.Duration

	// Runtime state — do not set these; managed internally.
	once   sync.Once
	stop   chan struct{}
	closed bool
}

// Token returns a cached access token if still valid, or fetches a new one
// via the client_credentials grant.
//
// If Refresher.Buffer > 0, the background refresh goroutine starts lazily
// on the first Token() call.
func (s *ClientCredentialsSource) Token() (string, error) {
	if s.Refresher != nil && s.Refresher.Buffer > 0 {
		s.Refresher.once.Do(func() {
			s.Refresher.stop = make(chan struct{})
			go s.backgroundRefresh()
		})
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != "" && time.Now().Add(tokenExpiryBuffer).Before(s.expiry) {
		return s.token, nil
	}

	return s.fetchTokenLocked()
}

// fetchTokenLocked performs a client_credentials token fetch.
// Caller must hold s.mu.
func (s *ClientCredentialsSource) fetchTokenLocked() (string, error) {
	if s.client == nil {
		s.client = NewAuthClient(s.TokenEndpoint, nil,
			WithASMetadata(&ASMetadata{TokenEndpoint: s.TokenEndpoint}))
	}

	cred, err := s.client.ClientCredentialsToken(s.ClientID, s.ClientSecret, s.Scopes)
	if err != nil {
		return "", fmt.Errorf("client credentials: %w", err)
	}

	s.token = cred.AccessToken
	s.expiry = cred.ExpiresAt
	return s.token, nil
}

// backgroundRefresh runs in a goroutine and refreshes the token before
// its expiry. It sleeps until (expiry - Refresher.Buffer), refreshes, and
// repeats. If the token is not yet fetched, it polls briefly.
//
// On refresh failure, it logs and retries after a short backoff — the
// next Token() call will trigger a reactive refresh if the current token
// has actually expired by then.
func (s *ClientCredentialsSource) backgroundRefresh() {
	// Minimum wait between iterations to prevent tight-loops when refresh
	// fails or when we're already past the refresh time.
	const minWait = 500 * time.Millisecond

	for {
		s.mu.Lock()
		expiry := s.expiry
		s.mu.Unlock()

		var wait time.Duration
		switch {
		case expiry.IsZero():
			// Token not yet fetched — poll briefly and re-check.
			wait = minWait
		default:
			refreshAt := expiry.Add(-s.Refresher.Buffer)
			wait = time.Until(refreshAt)
			if wait < minWait {
				wait = minWait
			}
		}

		select {
		case <-s.Refresher.stop:
			return
		case <-time.After(wait):
			if !expiry.IsZero() && time.Now().After(expiry.Add(-s.Refresher.Buffer)) {
				s.doBackgroundRefresh()
			}
		}
	}
}

// doBackgroundRefresh fetches a new token and updates the cache under lock.
// Failures are logged and swallowed — the next Token() call will retry
// reactively if the token is actually expired by then.
func (s *ClientCredentialsSource) doBackgroundRefresh() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.fetchTokenLocked(); err != nil {
		log.Printf("oneauth: proactive token refresh failed: %v (will retry reactively)", err)
	}
}

// Close stops the background refresh goroutine if one is running.
// Safe to call multiple times. Returns nil always (io.Closer compliance).
// After Close, subsequent Token() calls still work reactively.
func (s *ClientCredentialsSource) Close() error {
	if s.Refresher == nil {
		return nil
	}
	// Guard against double-close: the stop channel may not exist if
	// Token() was never called.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Refresher.closed {
		return nil
	}
	s.Refresher.closed = true
	if s.Refresher.stop != nil {
		close(s.Refresher.stop)
	}
	return nil
}

// TokenForScopes invalidates the cached token, merges the requested scopes
// with the existing scope set (using core.UnionScopes), and fetches a fresh
// token with the combined scopes.
func (s *ClientCredentialsSource) TokenForScopes(scopes []string) (string, error) {
	s.mu.Lock()
	s.token = ""
	s.expiry = time.Time{}
	s.Scopes = core.UnionScopes(s.Scopes, scopes)
	s.mu.Unlock()

	return s.Token()
}
