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
