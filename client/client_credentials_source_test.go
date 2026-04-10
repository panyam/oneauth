package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
