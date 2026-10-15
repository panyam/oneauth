package client_test

// Nonces a server hands out outside a challenge, and the proof minted for
// the retry after a refresh.
//
// References:
//   - RFC 9449 §8.2 (https://www.rfc-editor.org/rfc/rfc9449#section-8.2) — new nonce in any response
//   - RFC 9449 §9 (https://www.rfc-editor.org/rfc/rfc9449#section-9)
//   - RFC 9449 §11.1 (https://www.rfc-editor.org/rfc/rfc9449#section-11.1) — a proof is single use
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/client"
)

func nonceIn(t *testing.T, r *http.Request) string {
	t.Helper()
	_, payload := claimsOf(t, r.Header.Get("DPoP"))
	nonce, _ := payload["nonce"].(string)
	return nonce
}

// §8.2: the AS may send a fresh nonce on a successful response, and the
// client uses it next time instead of waiting to be challenged.
func TestDPoPClient_UsesANonceFromASuccessfulTokenResponse(t *testing.T) {
	var seen []string
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, nonceIn(t, r))
		w.Header().Set("DPoP-Nonce", fmt.Sprintf("rotated-%d", len(seen)))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"granted","token_type":"DPoP","expires_in":900}`))
	}))
	defer as.Close()
	c := client.NewAuthClient(as.URL, nil,
		client.WithDPoPKey(newKey(t)),
		client.WithASMetadata(&client.ASMetadata{Issuer: "nonce-as", TokenEndpoint: as.URL + "/api/token"}))

	for range 3 {
		_, err := c.ClientCredentialsToken(dpopClientID, dpopClientSecret, []string{"read"})
		require.NoError(t, err)
	}

	assert.Equal(t, []string{"", "rotated-1", "rotated-2"}, seen)
}

// §9: the same at a resource server.
func TestDPoPClient_UsesANonceFromASuccessfulResourceResponse(t *testing.T) {
	var seen []string
	rs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, nonceIn(t, r))
		w.Header().Set("DPoP-Nonce", fmt.Sprintf("rs-%d", len(seen)))
	}))
	defer rs.Close()
	store := newMemStore()
	c := client.NewAuthClient(rs.URL, store, client.WithDPoPKey(newKey(t)))
	require.NoError(t, store.SetCredential(rs.URL, &client.ServerCredential{AccessToken: "bound", ExpiresAt: time.Now().Add(time.Hour)}))

	for range 2 {
		resp, err := c.HTTPClient().Get(rs.URL + "/data")
		require.NoError(t, err)
		resp.Body.Close()
	}

	assert.Equal(t, []string{"", "rs-1"}, seen)
}

// After a 401 the client refreshes and retries. The refresh itself carries a
// proof, since a bound refresh token is useless without one (§5), and the
// retry needs a new proof with a new jti and an ath for the new token;
// resending the first proof would be a replay.
func TestDPoPClient_RefreshThenRetryMintsAFreshProof(t *testing.T) {
	type sent struct{ token, jti, ath string }
	var calls []sent
	var refreshProof string
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/cli/token", func(w http.ResponseWriter, r *http.Request) {
		refreshProof = r.Header.Get("DPoP")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-token","refresh_token":"rt-2","token_type":"DPoP","expires_in":900}`))
	})
	mux.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		_, payload := claimsOf(t, r.Header.Get("DPoP"))
		jti, _ := payload["jti"].(string)
		ath, _ := payload["ath"].(string)
		token := r.Header.Get("Authorization")[len("DPoP "):]
		calls = append(calls, sent{token, jti, ath})
		if token != "new-token" {
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	store := newMemStore()
	c := client.NewAuthClient(srv.URL, store, client.WithDPoPKey(newKey(t)))
	require.NoError(t, store.SetCredential(srv.URL, &client.ServerCredential{
		AccessToken: "old-token", RefreshToken: "rt-1", ExpiresAt: time.Now().Add(time.Hour),
	}))

	resp, err := c.HTTPClient().Get(srv.URL + "/data")
	require.NoError(t, err)
	resp.Body.Close()

	require.NotEmpty(t, refreshProof, "the refresh request must carry a DPoP proof")
	require.Len(t, calls, 2)
	assert.Equal(t, "new-token", calls[1].token)
	assert.NotEqual(t, calls[0].jti, calls[1].jti, "the retry must not reuse the first proof")
	sum := sha256.Sum256([]byte("new-token"))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), calls[1].ath)
}
