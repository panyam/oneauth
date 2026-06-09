package cmd

// Tests for `oneauth introspect <issuer>` against an in-memory AS that
// serves RFC 8414 metadata and RFC 7662 introspection responses.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// syntheticIntrospectAS extends syntheticAS-style infrastructure with an
// /introspect endpoint. Defined here (rather than threading flags into
// the shared fixture in token_test.go) so a future token-only assertion
// doesn't accidentally depend on introspection behavior.
type syntheticIntrospectAS struct {
	srv         *httptest.Server
	introspect  func(form map[string][]string, basicUser, basicPass string) (status int, body map[string]any)
	hitCount    atomic.Int32
	lastAuthHdr atomic.Value // string
}

func newSyntheticIntrospectAS(t *testing.T) *syntheticIntrospectAS {
	t.Helper()
	as := &syntheticIntrospectAS{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 as.srv.URL,
			"token_endpoint":         as.srv.URL + "/token",
			"introspection_endpoint": as.srv.URL + "/oauth/introspect",
		})
	})
	mux.HandleFunc("/oauth/introspect", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		as.hitCount.Add(1)
		user, pass, _ := r.BasicAuth()
		as.lastAuthHdr.Store(user + ":" + pass)
		status, body := http.StatusOK, map[string]any{"active": false}
		if as.introspect != nil {
			status, body = as.introspect(r.Form, user, pass)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	})
	as.srv = httptest.NewServer(mux)
	t.Cleanup(as.srv.Close)
	return as
}

func TestRunIntrospect_ActiveTokenJSON(t *testing.T) {
	as := newSyntheticIntrospectAS(t)
	as.introspect = func(form map[string][]string, user, pass string) (int, map[string]any) {
		assert.Equal(t, []string{"TOK"}, form["token"])
		return http.StatusOK, map[string]any{
			"active":    true,
			"sub":       "alice",
			"scope":     "read write",
			"client_id": "rs",
		}
	}
	ff := &introspectFlags{
		token:        "TOK",
		clientID:     "rs",
		clientSecret: "shh",
		format:       "json",
	}
	var stdout bytes.Buffer
	require.NoError(t, runIntrospect(context.Background(), &stdout, as.srv.URL, ff))

	var out map[string]any
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	assert.Equal(t, true, out["active"])
	assert.Equal(t, "alice", out["sub"])
	assert.Equal(t, "read write", out["scope"])
	assert.Equal(t, "rs:shh", as.lastAuthHdr.Load())
}

func TestRunIntrospect_InactiveActiveFormat(t *testing.T) {
	// --format active prints the bare bool — the predicate form for
	// `if [ "$(oneauth introspect ... --format active)" = "true" ]`.
	as := newSyntheticIntrospectAS(t)
	as.introspect = func(_ map[string][]string, _, _ string) (int, map[string]any) {
		return http.StatusOK, map[string]any{"active": false}
	}
	ff := &introspectFlags{
		token:        "TOK",
		clientID:     "rs",
		clientSecret: "shh",
		format:       "active",
	}
	var stdout bytes.Buffer
	require.NoError(t, runIntrospect(context.Background(), &stdout, as.srv.URL, ff))
	assert.Equal(t, "false\n", stdout.String())
}

func TestRunIntrospect_StdinToken(t *testing.T) {
	as := newSyntheticIntrospectAS(t)
	as.introspect = func(form map[string][]string, _, _ string) (int, map[string]any) {
		assert.Equal(t, []string{"stdin-token"}, form["token"])
		return http.StatusOK, map[string]any{"active": true}
	}
	stdin, restore := redirectStdin(t, "stdin-token\n")
	defer restore(stdin)

	ff := &introspectFlags{
		tokenStdin:   true,
		clientID:     "rs",
		clientSecret: "shh",
		format:       "json",
	}
	var stdout bytes.Buffer
	require.NoError(t, runIntrospect(context.Background(), &stdout, as.srv.URL, ff))
}

func TestRunIntrospect_MissingToken(t *testing.T) {
	as := newSyntheticIntrospectAS(t)
	ff := &introspectFlags{
		clientID:     "rs",
		clientSecret: "shh",
		format:       "json",
	}
	err := runIntrospect(context.Background(), new(bytes.Buffer), as.srv.URL, ff)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--token")
}

func TestRunIntrospect_NoIntrospectionEndpointAdvertised(t *testing.T) {
	// When AS metadata lacks introspection_endpoint, the CLI must fail
	// loudly rather than silently POSTing to an empty URL.
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":         srv.URL,
			"token_endpoint": srv.URL + "/token",
			// no introspection_endpoint
		})
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	ff := &introspectFlags{
		token:        "TOK",
		clientID:     "rs",
		clientSecret: "shh",
		format:       "json",
	}
	err := runIntrospect(context.Background(), new(bytes.Buffer), srv.URL, ff)
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "introspection_endpoint")
}
