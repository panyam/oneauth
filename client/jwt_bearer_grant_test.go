package client

// Wire-level tests for AuthClient.JwtBearerGrant — the RFC 7523 §2.1
// (`urn:ietf:params:oauth:grant-type:jwt-bearer`) primitive on the
// client SDK. Distinct from the private_key_jwt CLIENT auth method,
// which authenticates the client itself; this grant exchanges an
// assertion for an access token.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jwtBearerGrantServer accepts a jwt-bearer grant request and forwards
// the parsed form to `inspect` so per-test assertions can check the
// wire shape (including client authentication negotiation).
func jwtBearerGrantServer(t *testing.T, inspect func(*testing.T, *http.Request)) *httptest.Server {
	t.Helper()
	var count atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:jwt-bearer", r.FormValue("grant_type"))
		inspect(t, r)
		n := count.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("bearer-tok-%d", n),
			"token_type":   "Bearer",
			"expires_in":   600,
			"scope":        "read",
		})
	})
	return httptest.NewServer(mux)
}

// TestJwtBearerGrant_Roundtrip confirms the basic wire shape — grant
// type and assertion form fields — and that a usable ServerCredential
// flows back to the caller.
func TestJwtBearerGrant_Roundtrip(t *testing.T) {
	srv := jwtBearerGrantServer(t, func(t *testing.T, r *http.Request) {
		assert.Equal(t, "signed-jwt-assertion", r.FormValue("assertion"))
		assert.Equal(t, "read", r.FormValue("scope"))
		assert.Equal(t, []string{"https://api.example.com"}, r.Form["resource"])
	})
	defer srv.Close()

	c := NewAuthClient(srv.URL, nil, WithASMetadata(&ASMetadata{TokenEndpoint: srv.URL + "/token"}))
	cred, err := c.JwtBearerGrant(context.Background(), &JwtBearerGrantRequest{
		ClientID:     "demo",
		ClientSecret: "shh",
		Assertion:    "signed-jwt-assertion",
		Scope:        []string{"read"},
		Resources:    []string{"https://api.example.com"},
	})
	require.NoError(t, err)
	assert.Equal(t, "bearer-tok-1", cred.AccessToken)
}

// TestJwtBearerGrant_ClientAuthBasic verifies that when AS metadata
// advertises client_secret_basic, the bearer-assertion request carries
// HTTP Basic client authentication AND the assertion form field.
func TestJwtBearerGrant_ClientAuthBasic(t *testing.T) {
	srv := jwtBearerGrantServer(t, func(t *testing.T, r *http.Request) {
		assert.Equal(t, "signed-jwt-assertion", r.FormValue("assertion"))
		user, pass, ok := r.BasicAuth()
		require.True(t, ok, "Authorization: Basic header MUST be present for client_secret_basic")
		assert.Equal(t, "demo", user)
		assert.Equal(t, "shh", pass)
	})
	defer srv.Close()

	c := NewAuthClient(srv.URL, nil, WithASMetadata(&ASMetadata{
		TokenEndpoint:            srv.URL + "/token",
		TokenEndpointAuthMethods: []string{"client_secret_basic"},
	}))
	cred, err := c.JwtBearerGrant(context.Background(), &JwtBearerGrantRequest{
		ClientID:     "demo",
		ClientSecret: "shh",
		Assertion:    "signed-jwt-assertion",
	})
	require.NoError(t, err)
	require.NotEmpty(t, cred.AccessToken)
}

// TestJwtBearerGrant_ClientAuthPrivateKeyJwt verifies the dual-JWT
// case: a `client_assertion` (private_key_jwt CLIENT auth) plus an
// `assertion` (RFC 7523 §2.1 grant payload) coexist in the same form
// without colliding.
func TestJwtBearerGrant_ClientAuthPrivateKeyJwt(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	srv := jwtBearerGrantServer(t, func(t *testing.T, r *http.Request) {
		assert.Equal(t, "signed-jwt-assertion", r.FormValue("assertion"), "the grant payload assertion")
		assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", r.FormValue("client_assertion_type"))
		clientAssertion := r.FormValue("client_assertion")
		require.NotEmpty(t, clientAssertion, "client_assertion (client_secret_jwt / private_key_jwt) MUST be present")
		require.NotEqual(t, "signed-jwt-assertion", clientAssertion, "client_assertion MUST differ from the grant assertion")
		parsed, _, perr := new(jwt.Parser).ParseUnverified(clientAssertion, jwt.MapClaims{})
		require.NoError(t, perr, "client_assertion MUST be a parseable JWT")
		claims, _ := parsed.Claims.(jwt.MapClaims)
		assert.Equal(t, "demo", claims["iss"], "client_assertion iss MUST equal client_id")
		assert.Equal(t, "demo", claims["sub"], "client_assertion sub MUST equal client_id")

		// The grant-payload assertion ("signed-jwt-assertion") is opaque
		// to this test — RFC 7523 §3 leaves its validation to the AS.
		_ = strings.TrimSpace(r.FormValue("assertion"))
		_ = base64.StdEncoding // keep imports referenced even if unused
	})
	defer srv.Close()

	c := NewAuthClient(srv.URL, nil, WithASMetadata(&ASMetadata{
		TokenEndpoint:            srv.URL + "/token",
		TokenEndpointAuthMethods: []string{"private_key_jwt"},
	}))
	cred, err := c.JwtBearerGrant(context.Background(), &JwtBearerGrantRequest{
		ClientID:  "demo",
		Assertion: "signed-jwt-assertion",
		ClientAssertion: &ClientAssertionConfig{
			PrivateKey: priv,
			SigningAlg: "RS256",
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, cred.AccessToken)
}
