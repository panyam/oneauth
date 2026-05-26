package client

// Wire-level tests for AuthClient.TokenExchange — the RFC 8693
// (`urn:ietf:params:oauth:grant-type:token-exchange`) primitive on the
// client SDK.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	tokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"
	tokenTypeIDJAG   = "urn:ietf:params:oauth:token-type:id-jag"
	tokenTypeJWT     = "urn:ietf:params:oauth:token-type:jwt"
)

// tokenExchangeServer accepts a token-exchange request and forwards the
// parsed form to `inspect` for assertions. Returns an issued token with
// the supplied `issuedType` so tests can assert the `issued_token_type`
// response field round-trips.
func tokenExchangeServer(t *testing.T, issuedType string, inspect func(*testing.T, *http.Request)) *httptest.Server {
	t.Helper()
	var count atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", r.FormValue("grant_type"))
		inspect(t, r)
		n := count.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      fmt.Sprintf("exchanged-tok-%d", n),
			"issued_token_type": issuedType,
			"token_type":        "Bearer",
			"expires_in":        300,
			"scope":             "read write",
		})
	})
	return httptest.NewServer(mux)
}

// TestTokenExchange_AllParameters verifies every optional parameter is
// emitted on the wire, repeated values like `audience` / `resource`
// appear multiple times, and `issued_token_type` round-trips on the
// response side.
func TestTokenExchange_AllParameters(t *testing.T) {
	srv := tokenExchangeServer(t, tokenTypeIDJAG, func(t *testing.T, r *http.Request) {
		assert.Equal(t, "outer-id-token", r.FormValue("subject_token"))
		assert.Equal(t, tokenTypeIDToken, r.FormValue("subject_token_type"))
		assert.Equal(t, "actor-token", r.FormValue("actor_token"))
		assert.Equal(t, tokenTypeJWT, r.FormValue("actor_token_type"))
		assert.Equal(t, tokenTypeIDJAG, r.FormValue("requested_token_type"))
		assert.Equal(t,
			[]string{"https://api.example.com", "https://files.example.com"},
			r.Form["audience"],
			"audience MUST be sent as repeated form values (RFC 8693 §2.1)",
		)
		assert.Equal(t,
			[]string{"https://api.example.com/v1", "https://files.example.com/v1"},
			r.Form["resource"],
			"resource MUST be sent as repeated form values (RFC 8707 §2)",
		)
		assert.Equal(t, "read write", r.FormValue("scope"), "scope MUST be a single space-delimited form value")
	})
	defer srv.Close()

	c := NewAuthClient(srv.URL, nil, WithASMetadata(&ASMetadata{TokenEndpoint: srv.URL + "/token"}))
	resp, err := c.TokenExchange(&TokenExchangeRequest{
		ClientID:           "demo",
		ClientSecret:       "shh",
		SubjectToken:       "outer-id-token",
		SubjectTokenType:   tokenTypeIDToken,
		ActorToken:         "actor-token",
		ActorTokenType:     tokenTypeJWT,
		RequestedTokenType: tokenTypeIDJAG,
		Audience:           []string{"https://api.example.com", "https://files.example.com"},
		Resource:           []string{"https://api.example.com/v1", "https://files.example.com/v1"},
		Scope:              []string{"read", "write"},
	})
	require.NoError(t, err)
	assert.Equal(t, "exchanged-tok-1", resp.AccessToken)
	assert.Equal(t, tokenTypeIDJAG, resp.IssuedTokenType, "issued_token_type MUST round-trip from the AS")
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, 300, resp.ExpiresIn)
	assert.Equal(t, []string{"read", "write"}, resp.Scope)
}

// TestTokenExchange_MinimalRequest verifies that when only the required
// fields are set, the optional parameters do NOT appear on the wire at
// all — even as empty values. Wrong-empty-but-present can cause some
// strict ASes to reject the request.
func TestTokenExchange_MinimalRequest(t *testing.T) {
	srv := tokenExchangeServer(t, tokenTypeJWT, func(t *testing.T, r *http.Request) {
		assert.Equal(t, "outer-token", r.FormValue("subject_token"))
		assert.Equal(t, tokenTypeIDToken, r.FormValue("subject_token_type"))

		for _, key := range []string{"actor_token", "actor_token_type", "requested_token_type", "audience", "resource", "scope"} {
			_, present := r.Form[key]
			assert.False(t, present, "optional form key %q MUST be omitted when unset", key)
		}
	})
	defer srv.Close()

	c := NewAuthClient(srv.URL, nil, WithASMetadata(&ASMetadata{TokenEndpoint: srv.URL + "/token"}))
	resp, err := c.TokenExchange(&TokenExchangeRequest{
		ClientID:         "demo",
		ClientSecret:     "shh",
		SubjectToken:     "outer-token",
		SubjectTokenType: tokenTypeIDToken,
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.AccessToken)
}
