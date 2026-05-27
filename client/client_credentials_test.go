package client

// Wire-level tests for AuthClient.ClientCredentials — the gRPC-shape
// primary entry point for the client_credentials grant (RFC 6749 §4.4)
// that ClientCredentialsToken and ClientCredentialsTokenWithAssertion
// now wrap.
//
// Focused on the additive parameters introduced alongside the request
// struct: RFC 8707 `resource` (multi-valued) and RFC 9396
// `authorization_details` (JSON-encoded form value).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/core"
)

// paramCaptureServer accepts a client_credentials token request and
// invokes `inspect` with the parsed form so a test can assert on
// individual form values (including multi-valued ones like `resource`).
func paramCaptureServer(t *testing.T, inspect func(*testing.T, *http.Request)) *httptest.Server {
	t.Helper()
	var count atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		inspect(t, r)
		n := count.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("tok-%d", n),
			"token_type":   "Bearer",
			"expires_in":   int((1 * time.Hour).Seconds()),
		})
	})
	return httptest.NewServer(mux)
}

// TestClientCredentials_ResourceParamSent — a request with multiple
// Resources MUST emit `resource` as multiple form values per RFC 8707
// §2. The OneAuth AS happens to consume only the first via FormValue
// today, but the wire shape is correct.
func TestClientCredentials_ResourceParamSent(t *testing.T) {
	srv := paramCaptureServer(t, func(t *testing.T, r *http.Request) {
		got := r.Form["resource"]
		assert.Equal(t, []string{"https://api.example.com", "https://files.example.com"}, got,
			"resource MUST be sent as repeated form values (RFC 8707 §2)")
	})
	defer srv.Close()

	c := NewAuthClient(srv.URL, nil, WithASMetadata(&ASMetadata{TokenEndpoint: srv.URL + "/token"}))
	cred, err := c.ClientCredentials(context.Background(), &ClientCredentialsRequest{
		ClientID:     "demo",
		ClientSecret: "shh",
		Resources:    []string{"https://api.example.com", "https://files.example.com"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, cred.AccessToken)
}

// TestClientCredentials_AuthorizationDetailsSent — RFC 9396 §6.1
// requires `authorization_details` to be sent as a JSON-encoded string
// in form params. The client MUST marshal the slice once and emit it
// under that single key.
func TestClientCredentials_AuthorizationDetailsSent(t *testing.T) {
	want := []core.AuthorizationDetail{
		{Type: "payment_initiation", Locations: []string{"https://bank.example.com"}, Actions: []string{"initiate"}},
	}

	srv := paramCaptureServer(t, func(t *testing.T, r *http.Request) {
		raw := r.FormValue("authorization_details")
		require.NotEmpty(t, raw, "authorization_details MUST be present")
		var got []core.AuthorizationDetail
		require.NoError(t, json.Unmarshal([]byte(raw), &got))
		assert.Equal(t, want, got, "authorization_details MUST round-trip through JSON form-encoding (RFC 9396 §6.1)")
	})
	defer srv.Close()

	c := NewAuthClient(srv.URL, nil, WithASMetadata(&ASMetadata{TokenEndpoint: srv.URL + "/token"}))
	cred, err := c.ClientCredentials(context.Background(), &ClientCredentialsRequest{
		ClientID:             "demo",
		ClientSecret:         "shh",
		AuthorizationDetails: want,
	})
	require.NoError(t, err)
	require.NotEmpty(t, cred.AccessToken)
}

// TestClientCredentialsSource_RFC8707AndRFC9396FlowThrough proves that
// the cached source forwards Resources and AuthorizationDetails to the
// underlying token request. Catches the regression class that motivated
// removing the previous (silently-no-op) Audience and
// AuthorizationDetails fields.
func TestClientCredentialsSource_RFC8707AndRFC9396FlowThrough(t *testing.T) {
	want := []core.AuthorizationDetail{{Type: "payment_initiation"}}
	srv := paramCaptureServer(t, func(t *testing.T, r *http.Request) {
		assert.Equal(t, []string{"https://api.example.com"}, r.Form["resource"], "source.Resources MUST flow through")
		raw := r.FormValue("authorization_details")
		var got []core.AuthorizationDetail
		require.NoError(t, json.Unmarshal([]byte(raw), &got))
		assert.Equal(t, want, got, "source.AuthorizationDetails MUST flow through")
	})
	defer srv.Close()

	src := &ClientCredentialsSource{
		TokenEndpoint:        srv.URL + "/token",
		ClientID:             "demo",
		ClientSecret:         "shh",
		Resources:            []string{"https://api.example.com"},
		AuthorizationDetails: want,
	}
	tok, err := src.Token()
	require.NoError(t, err)
	require.NotEmpty(t, tok)
}
