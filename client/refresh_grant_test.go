package client

// Wire-level tests for AuthClient.RefreshToken — the standards-compliant
// RFC 6749 §6 refresh_token grant against an AS-discovered token endpoint.
//
// Distinct from refreshTokenLocked (legacy JSON path against the
// oneauth-native /auth/cli/token endpoint, reserved for credentials
// stored via Login). RefreshToken is the entrypoint used by the
// `oneauth token refresh` CLI subcommand against any RFC 8414 / OIDC AS.

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
)

// refreshCaptureServer accepts a refresh_token grant and invokes
// `inspect` with the parsed form so a test can assert on individual
// form values. Returns a fresh access token (with optional rotation
// controlled by `rotateRefresh`).
func refreshCaptureServer(t *testing.T, rotateRefresh bool, inspect func(*testing.T, *http.Request)) *httptest.Server {
	t.Helper()
	var count atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		inspect(t, r)
		n := count.Add(1)
		resp := map[string]any{
			"access_token": fmt.Sprintf("new-access-%d", n),
			"token_type":   "Bearer",
			"expires_in":   int((1 * time.Hour).Seconds()),
		}
		if rotateRefresh {
			resp["refresh_token"] = fmt.Sprintf("rotated-refresh-%d", n)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	return httptest.NewServer(mux)
}

// TestRefreshToken_WireShape — RFC 6749 §6: the form-encoded request
// MUST set grant_type=refresh_token and carry the supplied refresh_token
// verbatim. Scopes, when supplied, MUST round-trip as a space-delimited
// `scope` form value.
func TestRefreshToken_WireShape(t *testing.T) {
	srv := refreshCaptureServer(t, false, func(t *testing.T, r *http.Request) {
		assert.Equal(t, "refresh_token", r.FormValue("grant_type"))
		assert.Equal(t, "the-refresh-token", r.FormValue("refresh_token"))
		assert.Equal(t, "read write", r.FormValue("scope"))
	})
	defer srv.Close()

	c := NewAuthClient(srv.URL, nil, WithASMetadata(&ASMetadata{TokenEndpoint: srv.URL + "/token"}))
	cred, err := c.RefreshToken(context.Background(), &RefreshTokenRequest{
		ClientID:     "demo",
		ClientSecret: "shh",
		RefreshToken: "the-refresh-token",
		Scopes:       []string{"read", "write"},
	})
	require.NoError(t, err)
	assert.Equal(t, "new-access-1", cred.AccessToken)
	// AS did not rotate — caller-supplied refresh token carries forward.
	assert.Equal(t, "the-refresh-token", cred.RefreshToken,
		"unrotated refresh tokens MUST carry forward per RFC 6749 §6")
}

// TestRefreshToken_RotatedRefreshTokenAdopted — when the AS rotates the
// refresh token (RFC 6749 §6 — "optionally issue a new refresh token"),
// the new token replaces the caller-supplied one in the returned
// credential.
func TestRefreshToken_RotatedRefreshTokenAdopted(t *testing.T) {
	srv := refreshCaptureServer(t, true, func(t *testing.T, r *http.Request) {})
	defer srv.Close()

	c := NewAuthClient(srv.URL, nil, WithASMetadata(&ASMetadata{TokenEndpoint: srv.URL + "/token"}))
	cred, err := c.RefreshToken(context.Background(), &RefreshTokenRequest{
		ClientID:     "demo",
		RefreshToken: "old-refresh",
	})
	require.NoError(t, err)
	assert.Equal(t, "rotated-refresh-1", cred.RefreshToken)
}

// TestRefreshToken_Validation — req and refresh_token are required;
// missing inputs surface a typed error before any HTTP call.
func TestRefreshToken_Validation(t *testing.T) {
	c := NewAuthClient("http://unused", nil)
	_, err := c.RefreshToken(context.Background(), nil)
	require.ErrorContains(t, err, "req is required")

	_, err = c.RefreshToken(context.Background(), &RefreshTokenRequest{ClientID: "demo"})
	require.ErrorContains(t, err, "refresh_token is required")
}

// TestRefreshToken_ASError — when the AS rejects the refresh, the
// error from requestTokenForm bubbles up unchanged.
func TestRefreshToken_ASError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(OAuth2TokenResponse{
			Error:     "invalid_grant",
			ErrorDesc: "Token expired",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewAuthClient(srv.URL, nil, WithASMetadata(&ASMetadata{TokenEndpoint: srv.URL + "/token"}))
	_, err := c.RefreshToken(context.Background(), &RefreshTokenRequest{
		ClientID:     "demo",
		RefreshToken: "expired",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Token expired")
}
