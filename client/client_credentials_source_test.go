package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tokenServer creates an httptest.Server that mimics an OAuth2 token endpoint
// at /token, returning access tokens with configurable expiry. The requestCount
// tracks how many token requests the server received.
func tokenServer(t *testing.T, expiry time.Duration, requestCount *atomic.Int32) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		n := requestCount.Add(1)
		// AuthClient sends form-encoded POST
		assert.Equal(t, "client_credentials", r.FormValue("grant_type"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": fmt.Sprintf("tok-%d", n),
			"token_type":   "Bearer",
			"expires_in":   int(expiry.Seconds()),
		})
	})
	return httptest.NewServer(mux)
}

// TestClientCredentialsSource_Token verifies that ClientCredentialsSource
// caches the access token and reuses it on subsequent calls, avoiding
// unnecessary round-trips to the token endpoint.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
func TestClientCredentialsSource_Token(t *testing.T) {
	var count atomic.Int32
	srv := tokenServer(t, 1*time.Hour, &count)
	defer srv.Close()

	src := &ClientCredentialsSource{
		TokenEndpoint: srv.URL + "/token",
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
	}

	// First call fetches a token
	tok1, err := src.Token()
	require.NoError(t, err)
	assert.NotEmpty(t, tok1)
	assert.Equal(t, int32(1), count.Load())

	// Second call should return cached token (no new request)
	tok2, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, tok1, tok2)
	assert.Equal(t, int32(1), count.Load())
}

// TestClientCredentialsSource_TokenExpired verifies that an expired cached
// token triggers a fresh token request to the authorization server.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
func TestClientCredentialsSource_TokenExpired(t *testing.T) {
	var count atomic.Int32
	srv := tokenServer(t, 1*time.Hour, &count)
	defer srv.Close()

	src := &ClientCredentialsSource{
		TokenEndpoint: srv.URL + "/token",
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
	}

	// Get initial token
	tok1, err := src.Token()
	require.NoError(t, err)

	// Simulate expiry by setting expiry in the past
	src.mu.Lock()
	src.expiry = time.Now().Add(-1 * time.Minute)
	src.mu.Unlock()

	// Next call should fetch a new token
	tok2, err := src.Token()
	require.NoError(t, err)
	assert.NotEqual(t, tok1, tok2)
	assert.Equal(t, int32(2), count.Load())
}

// TestClientCredentialsSource_TokenForScopes verifies that TokenForScopes
// invalidates the cached token, merges the new scopes with existing ones,
// and fetches a fresh token with the combined scope set.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-3.3
func TestClientCredentialsSource_TokenForScopes(t *testing.T) {
	var count atomic.Int32
	srv := tokenServer(t, 1*time.Hour, &count)
	defer srv.Close()

	src := &ClientCredentialsSource{
		TokenEndpoint: srv.URL + "/token",
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		Scopes:        []string{"read"},
	}

	// Get initial token
	_, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, int32(1), count.Load())

	// Request additional scopes — should invalidate cache and re-fetch
	tok, err := src.TokenForScopes([]string{"write", "read"})
	require.NoError(t, err)
	assert.NotEmpty(t, tok)
	assert.Equal(t, int32(2), count.Load())

	// Scopes should be merged (union) and sorted
	assert.Equal(t, []string{"read", "write"}, src.Scopes)
}

// TestClientCredentialsSource_ProactiveRefresh verifies that when Refresher
// is configured with a positive Buffer, a background goroutine refreshes
// the token before its natural expiry. This avoids latency spikes on the
// hot path for long-running M2M agents.
func TestClientCredentialsSource_ProactiveRefresh(t *testing.T) {
	var count atomic.Int32
	// Token expires in 2s, refresh 1s before expiry = refresh fires at ~1s
	// (minWait between iterations is 500ms, so this is comfortably above it)
	srv := tokenServer(t, 2*time.Second, &count)
	defer srv.Close()

	src := &ClientCredentialsSource{
		TokenEndpoint: srv.URL + "/token",
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		Refresher: &ProactiveRefresher{
			Buffer: 1 * time.Second,
		},
	}
	defer src.Close()

	// First Token() call fetches + starts background refresh
	_, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, int32(1), count.Load())

	// Wait long enough for at least one background refresh to fire
	// (first refresh at +1s, next at +2s)
	time.Sleep(1500 * time.Millisecond)

	// Count should have increased due to background refresh
	if got := count.Load(); got < 2 {
		t.Errorf("expected at least 2 token fetches (initial + background), got %d", got)
	}
}

// TestClientCredentialsSource_CloseStopsRefresher verifies that Close()
// stops the background refresh goroutine. After Close, no further token
// fetches should occur from the background goroutine.
func TestClientCredentialsSource_CloseStopsRefresher(t *testing.T) {
	var count atomic.Int32
	// Long-lived token so reactive path doesn't fire
	srv := tokenServer(t, 1*time.Hour, &count)
	defer srv.Close()

	src := &ClientCredentialsSource{
		TokenEndpoint: srv.URL + "/token",
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		Refresher: &ProactiveRefresher{
			Buffer: 30 * time.Second,
		},
	}

	// Start the refresher
	_, err := src.Token()
	require.NoError(t, err)

	// Close before any background refresh fires
	require.NoError(t, src.Close())

	// Capture count after close
	beforeClose := count.Load()

	// Wait long enough that background refresh would have fired if still running
	time.Sleep(1 * time.Second)

	// Count should not have increased
	afterWait := count.Load()
	if afterWait != beforeClose {
		t.Errorf("expected no fetches after Close, got %d -> %d", beforeClose, afterWait)
	}
}

// TestClientCredentialsSource_CloseIdempotent verifies that Close() can be
// called multiple times without panicking or returning an error.
func TestClientCredentialsSource_CloseIdempotent(t *testing.T) {
	var count atomic.Int32
	srv := tokenServer(t, 1*time.Hour, &count)
	defer srv.Close()

	src := &ClientCredentialsSource{
		TokenEndpoint: srv.URL + "/token",
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		Refresher: &ProactiveRefresher{
			Buffer: 30 * time.Second,
		},
	}

	_, err := src.Token()
	require.NoError(t, err)

	// Double close — should not panic
	require.NoError(t, src.Close())
	require.NoError(t, src.Close())
}

// TestClientCredentialsSource_TokenForScopesConcurrent verifies that
// concurrent calls to TokenForScopes from multiple goroutines correctly
// accumulate scopes via core.UnionScopes without losing any. The mutex
// on the source ensures serial execution of the update, so the final
// Scopes set should contain the union of all requested scopes (#138).
func TestClientCredentialsSource_TokenForScopesConcurrent(t *testing.T) {
	var count atomic.Int32
	srv := tokenServer(t, 1*time.Hour, &count)
	defer srv.Close()

	src := &ClientCredentialsSource{
		TokenEndpoint: srv.URL + "/token",
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		Scopes:        []string{"base"},
	}

	// Fetch initial token
	_, err := src.Token()
	require.NoError(t, err)

	// 5 goroutines each requesting different scopes
	var wg sync.WaitGroup
	scopeRequests := [][]string{
		{"read"},
		{"write"},
		{"admin"},
		{"delete"},
		{"audit"},
	}
	for _, scopes := range scopeRequests {
		wg.Add(1)
		go func(s []string) {
			defer wg.Done()
			_, err := src.TokenForScopes(s)
			if err != nil {
				t.Errorf("TokenForScopes(%v) failed: %v", s, err)
			}
		}(scopes)
	}
	wg.Wait()

	// All 5 scopes + initial "base" should be present in src.Scopes
	expected := []string{"admin", "audit", "base", "delete", "read", "write"}
	src.mu.Lock()
	got := src.Scopes
	src.mu.Unlock()
	assert.ElementsMatch(t, expected, got,
		"concurrent TokenForScopes should accumulate all scopes via union")
}

// TestClientCredentialsSource_TokenForScopesEmptySlice verifies that
// calling TokenForScopes with an empty slice does NOT clear the existing
// scope set (union with empty leaves current unchanged). This preserves
// accumulated scopes in the edge case where a caller passes nil or []
// defensively (#138).
func TestClientCredentialsSource_TokenForScopesEmptySlice(t *testing.T) {
	var count atomic.Int32
	srv := tokenServer(t, 1*time.Hour, &count)
	defer srv.Close()

	src := &ClientCredentialsSource{
		TokenEndpoint: srv.URL + "/token",
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		Scopes:        []string{"read", "write"},
	}

	// Establish scope set
	_, err := src.Token()
	require.NoError(t, err)

	// Call TokenForScopes with empty slice
	_, err = src.TokenForScopes([]string{})
	require.NoError(t, err)

	// Scopes should be unchanged
	src.mu.Lock()
	got := src.Scopes
	src.mu.Unlock()
	assert.ElementsMatch(t, []string{"read", "write"}, got,
		"empty slice should not clear existing scopes")
}

// TestClientCredentialsSource_TokenForScopesTriggersRefetch verifies that
// calling TokenForScopes invalidates the cached token and triggers a
// fresh fetch with the accumulated scopes (#138). Without cache
// invalidation, a step-up call could return the stale narrow-scope token.
func TestClientCredentialsSource_TokenForScopesTriggersRefetch(t *testing.T) {
	var count atomic.Int32
	srv := tokenServer(t, 1*time.Hour, &count)
	defer srv.Close()

	src := &ClientCredentialsSource{
		TokenEndpoint: srv.URL + "/token",
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		Scopes:        []string{"read"},
	}

	// Initial fetch
	tok1, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, int32(1), count.Load())

	// Another Token() call — should return cached
	tok2, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, tok1, tok2)
	assert.Equal(t, int32(1), count.Load())

	// TokenForScopes should invalidate cache and refetch
	tok3, err := src.TokenForScopes([]string{"write"})
	require.NoError(t, err)
	assert.Equal(t, int32(2), count.Load(), "TokenForScopes should trigger refetch")
	// The returned token should differ from the cached one (fresh fetch)
	assert.NotEqual(t, tok1, tok3)
}

// TestClientCredentialsSource_CloseWithoutRefresher verifies that Close()
// is safe to call when no Refresher is configured (reactive-only mode).
func TestClientCredentialsSource_CloseWithoutRefresher(t *testing.T) {
	var count atomic.Int32
	srv := tokenServer(t, 1*time.Hour, &count)
	defer srv.Close()

	src := &ClientCredentialsSource{
		TokenEndpoint: srv.URL + "/token",
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		// No Refresher
	}

	require.NoError(t, src.Close()) // should be no-op
}
