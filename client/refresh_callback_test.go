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

// TestClientCredentialsSource_OnTokenFiresOnInitialFetch verifies that the
// OnToken callback fires after the very first Token() call. Persistence
// consumers need this: they want to save the first-obtained credential
// without maintaining a parallel code path for "initial" vs "refreshed"
// tokens.
func TestClientCredentialsSource_OnTokenFiresOnInitialFetch(t *testing.T) {
	var count atomic.Int32
	srv := tokenServer(t, 1*time.Hour, &count)
	defer srv.Close()

	var mu sync.Mutex
	var captured []*ServerCredential

	src := &ClientCredentialsSource{
		TokenEndpoint: srv.URL + "/token",
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		OnToken: func(cred *ServerCredential) {
			mu.Lock()
			defer mu.Unlock()
			captured = append(captured, cred)
		},
	}

	_, err := src.Token()
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, captured, 1, "OnToken should fire exactly once on initial fetch")
	assert.Equal(t, "tok-1", captured[0].AccessToken)
}

// TestClientCredentialsSource_OnTokenFiresOnReactiveRefresh verifies that
// the OnToken callback also fires when a cached-but-expired token is
// re-fetched via the reactive path (Token() after cache expiry).
func TestClientCredentialsSource_OnTokenFiresOnReactiveRefresh(t *testing.T) {
	var count atomic.Int32
	srv := tokenServer(t, 1*time.Hour, &count)
	defer srv.Close()

	var mu sync.Mutex
	var captured []*ServerCredential

	src := &ClientCredentialsSource{
		TokenEndpoint: srv.URL + "/token",
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		OnToken: func(cred *ServerCredential) {
			mu.Lock()
			defer mu.Unlock()
			captured = append(captured, cred)
		},
	}

	// Initial fetch (should fire callback).
	_, err := src.Token()
	require.NoError(t, err)

	// Expire the cache.
	src.mu.Lock()
	src.expiry = time.Now().Add(-1 * time.Minute)
	src.mu.Unlock()

	// Second fetch (should fire again).
	_, err = src.Token()
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, captured, 2, "OnToken should fire on both initial and reactive refresh")
	assert.Equal(t, "tok-1", captured[0].AccessToken)
	assert.Equal(t, "tok-2", captured[1].AccessToken)
}

// TestClientCredentialsSource_OnTokenFiresFromProactiveRefresher verifies
// that the OnToken callback fires from the background refresh goroutine
// when Refresher is configured. Persistence consumers with long-running
// M2M agents need this — otherwise proactive refreshes would update the
// in-memory token without updating the on-disk store.
//
// Documents the thread-safety contract: the callback MUST be safe to call
// from the background goroutine, not only from the caller's goroutine.
func TestClientCredentialsSource_OnTokenFiresFromProactiveRefresher(t *testing.T) {
	var count atomic.Int32
	// Short expiry + short buffer so a refresh fires well before test timeout.
	srv := tokenServer(t, 2*time.Second, &count)
	defer srv.Close()

	var mu sync.Mutex
	var captured []*ServerCredential

	src := &ClientCredentialsSource{
		TokenEndpoint: srv.URL + "/token",
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		Refresher:     &ProactiveRefresher{Buffer: 1 * time.Second},
		OnToken: func(cred *ServerCredential) {
			mu.Lock()
			defer mu.Unlock()
			captured = append(captured, cred)
		},
	}
	defer src.Close()

	_, err := src.Token()
	require.NoError(t, err)

	// Wait for at least one background refresh to fire.
	time.Sleep(1500 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(captured) < 2 {
		t.Fatalf("expected at least 2 OnToken invocations (initial + background refresh), got %d", len(captured))
	}
}

// TestClientCredentialsSource_OnTokenNilIsOptional verifies that a nil
// OnToken field is safe — the source behaves identically to a source
// with no callback configured. Guards against a regression where the
// refresh path panics on a nil callback.
func TestClientCredentialsSource_OnTokenNilIsOptional(t *testing.T) {
	var count atomic.Int32
	srv := tokenServer(t, 1*time.Hour, &count)
	defer srv.Close()

	src := &ClientCredentialsSource{
		TokenEndpoint: srv.URL + "/token",
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		// OnToken: intentionally left nil
	}

	tok, err := src.Token()
	require.NoError(t, err)
	assert.NotEmpty(t, tok)
}

// authClientRefreshServer serves /token with refresh_token grant support.
// It tracks each refresh request and issues a new access token per call,
// mirroring a real OAuth AS.
func authClientRefreshServer(t *testing.T, requestCount *atomic.Int32) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		n := requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  fmt.Sprintf("refreshed-%d", n),
			"refresh_token": fmt.Sprintf("new-refresh-%d", n),
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	})
	return httptest.NewServer(mux)
}

// TestAuthClient_OnTokenFiresOnRefresh verifies that AuthClient.OnToken
// fires after a successful refresh_token grant exchange (the browser-login
// refresh path). Without this, consumers using AuthClient for interactive
// OAuth flows have no hook to persist the refreshed credential outside
// of implementing a full CredentialStore.
func TestAuthClient_OnTokenFiresOnRefresh(t *testing.T) {
	var count atomic.Int32
	srv := authClientRefreshServer(t, &count)
	defer srv.Close()

	// Seed the store with an expiring credential that has a refresh token.
	store := newMockCredentialStore()
	initial := &ServerCredential{
		AccessToken:  "initial-access",
		RefreshToken: "initial-refresh",
		ExpiresAt:    time.Now().Add(-1 * time.Minute), // already expired
	}
	require.NoError(t, store.SetCredential(srv.URL, initial))

	var mu sync.Mutex
	var captured []*ServerCredential

	client := NewAuthClient(srv.URL, store,
		WithTokenEndpoint("/token"),
		WithASMetadata(&ASMetadata{TokenEndpoint: srv.URL + "/token"}))
	client.OnToken = func(cred *ServerCredential) {
		mu.Lock()
		defer mu.Unlock()
		captured = append(captured, cred)
	}

	// IsLoggedIn + explicit refresh path would trigger via GetValidAccessToken;
	// call refreshTokenLocked directly via the test entry point.
	client.mu.Lock()
	err := client.refreshTokenLocked(initial)
	client.mu.Unlock()
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, captured, 1, "OnToken should fire once after a successful refresh")
	assert.Equal(t, "refreshed-1", captured[0].AccessToken)
	assert.Equal(t, "new-refresh-1", captured[0].RefreshToken)
}

// TestAuthClient_OnTokenNilIsOptional mirrors the ClientCredentialsSource
// nil-safety check for AuthClient.
func TestAuthClient_OnTokenNilIsOptional(t *testing.T) {
	var count atomic.Int32
	srv := authClientRefreshServer(t, &count)
	defer srv.Close()

	store := newMockCredentialStore()
	initial := &ServerCredential{
		AccessToken:  "initial-access",
		RefreshToken: "initial-refresh",
		ExpiresAt:    time.Now().Add(-1 * time.Minute),
	}
	require.NoError(t, store.SetCredential(srv.URL, initial))

	client := NewAuthClient(srv.URL, store,
		WithTokenEndpoint("/token"),
		WithASMetadata(&ASMetadata{TokenEndpoint: srv.URL + "/token"}))
	// OnToken: intentionally left nil

	client.mu.Lock()
	err := client.refreshTokenLocked(initial)
	client.mu.Unlock()
	require.NoError(t, err)
}
