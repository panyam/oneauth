package client

// Tests for the headless OAuth authorization code + PKCE flow (RFC 8252).
// These tests simulate the browser's role using HTTP clients, so no actual
// browser is opened. The mock auth server implements a minimal authorize +
// token endpoint that validates PKCE and state.
//
// References:
//   - RFC 8252 (https://www.rfc-editor.org/rfc/rfc8252):
//     "OAuth 2.0 for Native Apps" — loopback redirect pattern
//   - RFC 7636 (https://www.rfc-editor.org/rfc/rfc7636):
//     "Proof Key for Code Exchange" — PKCE
//   - See: https://github.com/panyam/oneauth/issues/54

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAuthServer creates a test OAuth authorization server that:
//   - GET /authorize: validates PKCE challenge + state, redirects to redirect_uri with code
//   - POST /token: validates authorization_code grant with PKCE verifier, returns tokens
//
// The "browser" in these tests is an HTTP client that follows redirects.
func mockAuthServer(t *testing.T) *httptest.Server {
	t.Helper()
	var storedChallenge, storedState, storedRedirectURI string

	mux := http.NewServeMux()

	// Authorization endpoint — simulates what the user would see in a browser
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		storedChallenge = q.Get("code_challenge")
		storedState = q.Get("state")
		storedRedirectURI = q.Get("redirect_uri")

		if q.Get("response_type") != "code" {
			http.Error(w, "invalid response_type", http.StatusBadRequest)
			return
		}
		if q.Get("code_challenge_method") != "S256" {
			http.Error(w, "invalid code_challenge_method", http.StatusBadRequest)
			return
		}

		// Simulate user completing login — redirect with code
		redirectURL := fmt.Sprintf("%s?code=test-auth-code&state=%s",
			storedRedirectURI, storedState)
		http.Redirect(w, r, redirectURL, http.StatusFound)
	})

	// Token endpoint — validates code + PKCE verifier
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		if r.FormValue("grant_type") != "authorization_code" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "unsupported_grant_type"})
			return
		}

		// Verify PKCE: SHA256(code_verifier) should match stored challenge
		verifier := r.FormValue("code_verifier")
		hash := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(hash[:])
		if computed != storedChallenge {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "PKCE verification failed"})
			return
		}

		if r.FormValue("code") != "test-auth-code" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "mock-access-token",
			"refresh_token": "mock-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    900,
		})
	})

	// OIDC Discovery — so DiscoverAS works
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		srv := r.Host // will be localhost:PORT
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "http://" + srv,
			"authorization_endpoint": "http://" + srv + "/authorize",
			"token_endpoint":         "http://" + srv + "/token",
			"jwks_uri":               "http://" + srv + "/.well-known/jwks.json",
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// simulateBrowser acts as the "browser" — follows the authorization URL redirect
// to deliver the code to the loopback server.
func simulateBrowser(authURL string) error {
	// Follow redirects — the auth server will redirect to localhost callback
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // follow all redirects
		},
	}
	resp, err := client.Get(authURL)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// TestLoginWithBrowser_FullFlow verifies the complete authorization code + PKCE
// flow: PKCE generation → loopback server → browser redirect → code exchange →
// credential stored. The "browser" is simulated by an HTTP client.
//
// See: https://www.rfc-editor.org/rfc/rfc8252
func TestLoginWithBrowser_FullFlow(t *testing.T) {
	authSrv := mockAuthServer(t)
	store := newMockCredentialStore()
	authClient := NewAuthClient(authSrv.URL, store)

	var capturedAuthURL string
	cred, err := authClient.LoginWithBrowser(BrowserLoginConfig{
		ClientID: "test-cli",
		Scopes:   []string{"openid", "read"},
		Timeout:  5 * time.Second,
		OpenBrowser: func(authURL string) error {
			capturedAuthURL = authURL
			// Simulate browser: follow the auth URL which redirects to our callback
			go simulateBrowser(authURL)
			return nil
		},
	})

	require.NoError(t, err, "LoginWithBrowser should succeed")
	require.NotNil(t, cred)
	assert.Equal(t, "mock-access-token", cred.AccessToken)
	assert.Equal(t, "mock-refresh-token", cred.RefreshToken)

	// Verify the auth URL had PKCE params
	u, _ := url.Parse(capturedAuthURL)
	assert.Equal(t, "code", u.Query().Get("response_type"))
	assert.Equal(t, "test-cli", u.Query().Get("client_id"))
	assert.Equal(t, "S256", u.Query().Get("code_challenge_method"))
	assert.NotEmpty(t, u.Query().Get("code_challenge"), "should have PKCE challenge")
	assert.NotEmpty(t, u.Query().Get("state"), "should have state")
	assert.Contains(t, u.Query().Get("scope"), "openid")

	// Verify credential was stored
	stored, err := store.GetCredential(authSrv.URL)
	require.NoError(t, err)
	assert.Equal(t, "mock-access-token", stored.AccessToken)
}

// TestLoginWithBrowser_Timeout verifies that the flow times out if the browser
// never completes the redirect (user closes the browser or takes too long).
//
// See: https://www.rfc-editor.org/rfc/rfc8252
func TestLoginWithBrowser_Timeout(t *testing.T) {
	authSrv := mockAuthServer(t)
	store := newMockCredentialStore()
	authClient := NewAuthClient(authSrv.URL, store)

	_, err := authClient.LoginWithBrowser(BrowserLoginConfig{
		ClientID: "test-cli",
		Timeout:  500 * time.Millisecond,
		OpenBrowser: func(url string) error {
			// Don't simulate browser — let it timeout
			return nil
		},
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
}

// TestLoginWithBrowser_StateMismatch verifies that a state mismatch (potential
// CSRF attack) is detected and rejected. The mock browser delivers a different
// state value than what was generated.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-10.12
func TestLoginWithBrowser_StateMismatch(t *testing.T) {
	// Create a server that redirects with wrong state
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("redirect_uri")
		// Send back a DIFFERENT state
		http.Redirect(w, r, redirectURI+"?code=test-code&state=wrong-state", http.StatusFound)
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "http://" + r.Host,
			"authorization_endpoint": "http://" + r.Host + "/authorize",
			"token_endpoint":         "http://" + r.Host + "/token",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	store := newMockCredentialStore()
	authClient := NewAuthClient(srv.URL, store)

	_, err := authClient.LoginWithBrowser(BrowserLoginConfig{
		ClientID: "test-cli",
		Timeout:  2 * time.Second,
		OpenBrowser: func(authURL string) error {
			go simulateBrowser(authURL)
			return nil
		},
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "state mismatch")
}

// TestLoginWithBrowser_MissingClientID verifies that LoginWithBrowser returns
// an error when ClientID is not provided.
func TestLoginWithBrowser_MissingClientID(t *testing.T) {
	store := newMockCredentialStore()
	authClient := NewAuthClient("http://localhost", store)

	_, err := authClient.LoginWithBrowser(BrowserLoginConfig{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ClientID")
}

// TestLoginWithBrowser_AuthorizationError verifies that authorization errors
// from the auth server (e.g., access_denied) are properly propagated.
func TestLoginWithBrowser_AuthorizationError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		http.Redirect(w, r, redirectURI+"?error=access_denied&error_description=user+denied&state="+state, http.StatusFound)
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "http://" + r.Host,
			"authorization_endpoint": "http://" + r.Host + "/authorize",
			"token_endpoint":         "http://" + r.Host + "/token",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	store := newMockCredentialStore()
	authClient := NewAuthClient(srv.URL, store)

	_, err := authClient.LoginWithBrowser(BrowserLoginConfig{
		ClientID: "test-cli",
		Timeout:  2 * time.Second,
		OpenBrowser: func(authURL string) error {
			go simulateBrowser(authURL)
			return nil
		},
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access_denied")
}

// TestLoginWithBrowser_ExplicitEndpoints verifies that LoginWithBrowser works
// when authorization and token endpoints are explicitly provided (no discovery).
func TestLoginWithBrowser_ExplicitEndpoints(t *testing.T) {
	authSrv := mockAuthServer(t)
	store := newMockCredentialStore()
	authClient := NewAuthClient(authSrv.URL, store)

	cred, err := authClient.LoginWithBrowser(BrowserLoginConfig{
		ClientID:              "test-cli",
		AuthorizationEndpoint: authSrv.URL + "/authorize",
		TokenEndpoint:         authSrv.URL + "/token",
		Timeout:               5 * time.Second,
		OpenBrowser: func(authURL string) error {
			go simulateBrowser(authURL)
			return nil
		},
	})

	require.NoError(t, err)
	assert.Equal(t, "mock-access-token", cred.AccessToken)
}
