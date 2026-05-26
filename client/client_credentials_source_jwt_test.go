package client

// JWT-assertion (private_key_jwt) tests for ClientCredentialsSource.
//
// Exercises the path where the source authenticates to the token endpoint
// with a signed `client_assertion` instead of a `client_secret`, while
// still benefiting from the caching, OnToken, and proactive-refresh
// machinery that the secret-based path already provides.
//
// References:
//   - RFC 6749 §4.4   client_credentials grant
//   - RFC 7521 §4.2   client authentication via assertion
//   - RFC 7523 §2.2   JWT bearer client assertion
//   - OIDC Core §9    private_key_jwt
//   - Issue #211      ticket motivating this code path

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jwtTokenServer is the assertion-aware counterpart of tokenServer. It
// asserts that every token request carries a `client_assertion_type` of
// `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, parses the
// assertion, and forwards the parsed claims to `onAssertion` so the
// caller can make per-test assertions about the JWT shape.
func jwtTokenServer(t *testing.T, expiry time.Duration, requestCount *atomic.Int32, onAssertion func(*testing.T, jwt.MapClaims)) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		n := requestCount.Add(1)
		assert.Equal(t, "client_credentials", r.FormValue("grant_type"))
		assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", r.FormValue("client_assertion_type"))

		assertion := r.FormValue("client_assertion")
		require.NotEmpty(t, assertion, "client_assertion form value must be present")

		parsed, _, err := new(jwt.Parser).ParseUnverified(assertion, jwt.MapClaims{})
		require.NoError(t, err)
		claims, ok := parsed.Claims.(jwt.MapClaims)
		require.True(t, ok)
		if onAssertion != nil {
			onAssertion(t, claims)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("tok-%d", n),
			"token_type":   "Bearer",
			"expires_in":   int(expiry.Seconds()),
		})
	})
	return httptest.NewServer(mux)
}

// TestClientCredentialsSource_JWT_TokenRoundtrip verifies that a source
// configured with ClientAssertion uses the private_key_jwt path AND the
// existing cache: the second Token() within the cached window returns
// the same token without a new round-trip, and the third call after
// induced expiry re-fetches.
func TestClientCredentialsSource_JWT_TokenRoundtrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var count atomic.Int32
	srv := jwtTokenServer(t, 1*time.Hour, &count, nil)
	defer srv.Close()

	src := &ClientCredentialsSource{
		TokenEndpoint: srv.URL + "/token",
		ClientID:      "demo-client",
		ClientAssertion: &ClientAssertionConfig{
			PrivateKey: priv,
			SigningAlg: "RS256",
		},
	}

	tok1, err := src.Token()
	require.NoError(t, err)
	assert.NotEmpty(t, tok1)
	assert.Equal(t, int32(1), count.Load(), "first Token() must fetch")

	tok2, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, tok1, tok2, "cached token returned unchanged")
	assert.Equal(t, int32(1), count.Load(), "no extra fetch within cache window")

	src.mu.Lock()
	src.expiry = time.Now().Add(-1 * time.Minute)
	src.mu.Unlock()

	tok3, err := src.Token()
	require.NoError(t, err)
	assert.NotEqual(t, tok1, tok3, "post-expiry Token() must re-fetch")
	assert.Equal(t, int32(2), count.Load())
}

// TestClientCredentialsSource_JWT_AudienceFlowsThrough confirms that
// ClientAssertion.Audience reaches the AS — when set, the JWT's `aud`
// claim equals the override (the AS issuer URL) rather than the token
// endpoint URL that ClientCredentialsTokenWithAssertion would default
// to.
func TestClientCredentialsSource_JWT_AudienceFlowsThrough(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	const issuerAud = "https://issuer.example.com"

	var count atomic.Int32
	srv := jwtTokenServer(t, 1*time.Hour, &count, func(t *testing.T, claims jwt.MapClaims) {
		assert.Equal(t, issuerAud, claims["aud"], "aud claim MUST be the configured override")
	})
	defer srv.Close()

	src := &ClientCredentialsSource{
		TokenEndpoint: srv.URL + "/token",
		ClientID:      "demo-client",
		ClientAssertion: &ClientAssertionConfig{
			PrivateKey: priv,
			SigningAlg: "RS256",
			Audience:   issuerAud,
		},
	}

	_, err = src.Token()
	require.NoError(t, err)
	assert.Equal(t, int32(1), count.Load())
}
