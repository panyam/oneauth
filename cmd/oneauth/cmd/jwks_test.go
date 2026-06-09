package cmd

// Tests for `oneauth jwks <issuer>` against an in-memory AS that
// advertises a jwks_uri and serves an RFC 7517 JSON Web Key Set.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/panyam/oneauth/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type syntheticJWKSAS struct {
	srv *httptest.Server
	set utils.JWKSet
}

func newSyntheticJWKSAS(t *testing.T, set utils.JWKSet) *syntheticJWKSAS {
	t.Helper()
	as := &syntheticJWKSAS{set: set}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":         as.srv.URL,
			"token_endpoint": as.srv.URL + "/token",
			"jwks_uri":       as.srv.URL + "/.well-known/jwks.json",
		})
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(as.set)
	})
	as.srv = httptest.NewServer(mux)
	t.Cleanup(as.srv.Close)
	return as
}

func TestRunJWKS_HappyPath(t *testing.T) {
	as := newSyntheticJWKSAS(t, utils.JWKSet{Keys: []utils.JWK{
		{Kty: "RSA", Kid: "abc", Alg: "RS256", Use: "sig", N: "n", E: "AQAB"},
		{Kty: "EC", Kid: "def", Alg: "ES256", Use: "sig", Crv: "P-256", X: "x", Y: "y"},
	}})
	jf := &jwksFlags{format: "json"}
	var stdout bytes.Buffer
	require.NoError(t, runJWKS(context.Background(), &stdout, as.srv.URL, jf))

	var got utils.JWKSet
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &got))
	require.Len(t, got.Keys, 2)
	assert.Equal(t, "abc", got.Keys[0].Kid)
	assert.Equal(t, "def", got.Keys[1].Kid)
}

func TestRunJWKS_KidFilter(t *testing.T) {
	as := newSyntheticJWKSAS(t, utils.JWKSet{Keys: []utils.JWK{
		{Kty: "RSA", Kid: "abc", Alg: "RS256", Use: "sig"},
		{Kty: "RSA", Kid: "xyz", Alg: "RS256", Use: "sig"},
	}})
	jf := &jwksFlags{format: "json", kid: "xyz"}
	var stdout bytes.Buffer
	require.NoError(t, runJWKS(context.Background(), &stdout, as.srv.URL, jf))

	var got utils.JWKSet
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &got))
	require.Len(t, got.Keys, 1)
	assert.Equal(t, "xyz", got.Keys[0].Kid)
}

func TestRunJWKS_SigOnlyFilter(t *testing.T) {
	as := newSyntheticJWKSAS(t, utils.JWKSet{Keys: []utils.JWK{
		{Kty: "RSA", Kid: "abc", Alg: "RS256", Use: "sig"},
		{Kty: "RSA", Kid: "enc", Alg: "RS256", Use: "enc"},
	}})
	jf := &jwksFlags{format: "json", sigOnly: true}
	var stdout bytes.Buffer
	require.NoError(t, runJWKS(context.Background(), &stdout, as.srv.URL, jf))

	var got utils.JWKSet
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &got))
	require.Len(t, got.Keys, 1)
	assert.Equal(t, "abc", got.Keys[0].Kid)
}

func TestRunJWKS_TableFormat(t *testing.T) {
	as := newSyntheticJWKSAS(t, utils.JWKSet{Keys: []utils.JWK{
		{Kty: "RSA", Kid: "abc", Alg: "RS256", Use: "sig"},
	}})
	jf := &jwksFlags{format: "table"}
	var stdout bytes.Buffer
	require.NoError(t, runJWKS(context.Background(), &stdout, as.srv.URL, jf))
	out := stdout.String()
	assert.True(t, strings.HasPrefix(out, "ALG"), "table header expected: %s", out)
	assert.Contains(t, out, "RS256")
	assert.Contains(t, out, "abc")
}

func TestRunJWKS_NoJWKSURI(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":         srv.URL,
			"token_endpoint": srv.URL + "/token",
			// no jwks_uri
		})
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	jf := &jwksFlags{format: "json"}
	err := runJWKS(context.Background(), new(bytes.Buffer), srv.URL, jf)
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "jwks_uri")
}

func TestRunJWKS_Non2xxFromJWKSURI(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":         srv.URL,
			"token_endpoint": srv.URL + "/token",
			"jwks_uri":       srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	jf := &jwksFlags{format: "json"}
	err := runJWKS(context.Background(), new(bytes.Buffer), srv.URL, jf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}
