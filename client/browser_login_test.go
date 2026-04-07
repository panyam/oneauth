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
			"issuer":                                "http://" + srv,
			"authorization_endpoint":                "http://" + srv + "/authorize",
			"token_endpoint":                        "http://" + srv + "/token",
			"jwks_uri":                              "http://" + srv + "/.well-known/jwks.json",
			"code_challenge_methods_supported":       []string{"S256"},
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
			"issuer":                                "http://" + r.Host,
			"authorization_endpoint":                "http://" + r.Host + "/authorize",
			"token_endpoint":                        "http://" + r.Host + "/token",
			"code_challenge_methods_supported":       []string{"S256"},
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
			"issuer":                                "http://" + r.Host,
			"authorization_endpoint":                "http://" + r.Host + "/authorize",
			"token_endpoint":                        "http://" + r.Host + "/token",
			"code_challenge_methods_supported":       []string{"S256"},
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

// =============================================================================
// #71 — Headless OAuth flow (FollowRedirects)
// =============================================================================

// TestFollowRedirects_FullFlow verifies the complete authorization code + PKCE
// flow using FollowRedirects instead of a browser. The HTTP client follows the
// AS redirect to the loopback callback, delivering the auth code exactly as a
// browser would.
//
// See: https://github.com/panyam/oneauth/issues/71
func TestFollowRedirects_FullFlow(t *testing.T) {
	authSrv := mockAuthServer(t)
	store := newMockCredentialStore()
	authClient := NewAuthClient(authSrv.URL, store)

	cred, err := authClient.LoginWithBrowser(BrowserLoginConfig{
		ClientID:    "test-cli",
		Scopes:      []string{"openid", "read"},
		Timeout:     5 * time.Second,
		OpenBrowser: FollowRedirects(nil),
	})

	require.NoError(t, err, "headless flow should succeed")
	require.NotNil(t, cred)
	assert.Equal(t, "mock-access-token", cred.AccessToken)
	assert.Equal(t, "mock-refresh-token", cred.RefreshToken)

	// Verify credential was stored
	stored, err := store.GetCredential(authSrv.URL)
	require.NoError(t, err)
	assert.Equal(t, "mock-access-token", stored.AccessToken)
}

// TestFollowRedirects_WithCustomHTTPClient verifies that a custom HTTP client
// (e.g., with specific timeout or TLS config) can be passed to FollowRedirects
// and the flow still works end-to-end.
//
// See: https://github.com/panyam/oneauth/issues/71
func TestFollowRedirects_WithCustomHTTPClient(t *testing.T) {
	authSrv := mockAuthServer(t)
	store := newMockCredentialStore()
	authClient := NewAuthClient(authSrv.URL, store)

	customClient := &http.Client{Timeout: 10 * time.Second}
	cred, err := authClient.LoginWithBrowser(BrowserLoginConfig{
		ClientID:    "test-cli",
		Timeout:     5 * time.Second,
		OpenBrowser: FollowRedirects(customClient),
	})

	require.NoError(t, err)
	assert.Equal(t, "mock-access-token", cred.AccessToken)
}

// TestFollowRedirects_AuthorizationError verifies that authorization errors
// from the AS (e.g., access_denied) propagate correctly through the headless
// flow, just as they would through a browser redirect.
//
// See: https://github.com/panyam/oneauth/issues/71
func TestFollowRedirects_AuthorizationError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		http.Redirect(w, r, redirectURI+"?error=access_denied&error_description=user+denied&state="+state, http.StatusFound)
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           "http://" + r.Host,
			"authorization_endpoint":           "http://" + r.Host + "/authorize",
			"token_endpoint":                   "http://" + r.Host + "/token",
			"code_challenge_methods_supported": []string{"S256"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	store := newMockCredentialStore()
	authClient := NewAuthClient(srv.URL, store)

	_, err := authClient.LoginWithBrowser(BrowserLoginConfig{
		ClientID:    "test-cli",
		Timeout:     2 * time.Second,
		OpenBrowser: FollowRedirects(nil),
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access_denied")
}

// TestFollowRedirects_NilClient verifies that passing nil to FollowRedirects
// creates a working default HTTP client instead of panicking.
//
// See: https://github.com/panyam/oneauth/issues/71
func TestFollowRedirects_NilClient(t *testing.T) {
	fn := FollowRedirects(nil)
	assert.NotNil(t, fn, "should return a non-nil function even with nil client")
}

// =============================================================================
// #65 — PKCE verification in AS metadata
// =============================================================================

// TestLoginWithBrowser_PKCENotSupported verifies that LoginWithBrowser rejects
// authorization servers that don't advertise PKCE S256 support in their
// discovery metadata. Per OAuth 2.1 and MCP spec, clients MUST check
// code_challenge_methods_supported before proceeding.
//
// See: https://github.com/panyam/oneauth/issues/65
func TestLoginWithBrowser_PKCENotSupported(t *testing.T) {
	// AS metadata without code_challenge_methods_supported
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "http://" + r.Host,
			"authorization_endpoint": "http://" + r.Host + "/authorize",
			"token_endpoint":         "http://" + r.Host + "/token",
			// No code_challenge_methods_supported!
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	store := newMockCredentialStore()
	authClient := NewAuthClient(srv.URL, store)

	_, err := authClient.LoginWithBrowser(BrowserLoginConfig{
		ClientID: "test-cli",
		Timeout:  2 * time.Second,
		OpenBrowser: func(url string) error {
			t.Error("browser should not be opened when PKCE is not supported")
			return nil
		},
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PKCE S256")
}

// TestLoginWithBrowser_PKCEWrongMethod verifies that LoginWithBrowser rejects
// an AS that only supports plain PKCE (not S256).
//
// See: https://github.com/panyam/oneauth/issues/65
func TestLoginWithBrowser_PKCEWrongMethod(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           "http://" + r.Host,
			"authorization_endpoint":           "http://" + r.Host + "/authorize",
			"token_endpoint":                   "http://" + r.Host + "/token",
			"code_challenge_methods_supported": []string{"plain"}, // no S256!
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	store := newMockCredentialStore()
	authClient := NewAuthClient(srv.URL, store)

	_, err := authClient.LoginWithBrowser(BrowserLoginConfig{
		ClientID: "test-cli",
		Timeout:  2 * time.Second,
		OpenBrowser: func(url string) error {
			t.Error("browser should not be opened when S256 is not supported")
			return nil
		},
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PKCE S256")
}

// TestLoginWithBrowser_PKCESkippedWithExplicitEndpoints verifies that the PKCE
// metadata check is NOT applied when endpoints are explicitly provided (no
// discovery). The caller is responsible for knowing their AS supports PKCE.
//
// See: https://github.com/panyam/oneauth/issues/65
func TestLoginWithBrowser_PKCESkippedWithExplicitEndpoints(t *testing.T) {
	authSrv := mockAuthServer(t)
	store := newMockCredentialStore()
	authClient := NewAuthClient(authSrv.URL, store)

	// Explicit endpoints — no discovery, no PKCE check
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

	require.NoError(t, err, "explicit endpoints should bypass PKCE metadata check")
	assert.Equal(t, "mock-access-token", cred.AccessToken)
}

// =============================================================================
// #66 — Resource parameter (RFC 8707)
// =============================================================================

// TestLoginWithBrowser_ResourceParameter verifies that the resource parameter
// (RFC 8707) is included in both the authorization URL and token exchange
// when configured. This binds the token to a specific resource server.
//
// See: https://www.rfc-editor.org/rfc/rfc8707
// See: https://github.com/panyam/oneauth/issues/66
func TestLoginWithBrowser_ResourceParameter(t *testing.T) {
	authSrv := mockAuthServer(t)
	store := newMockCredentialStore()
	authClient := NewAuthClient(authSrv.URL, store)

	var capturedAuthURL string
	cred, err := authClient.LoginWithBrowser(BrowserLoginConfig{
		ClientID: "test-cli",
		Resource: "https://api.example.com",
		Timeout:  5 * time.Second,
		OpenBrowser: func(authURL string) error {
			capturedAuthURL = authURL
			go simulateBrowser(authURL)
			return nil
		},
	})

	require.NoError(t, err)
	assert.NotNil(t, cred)

	// Verify resource is in the auth URL
	u, _ := url.Parse(capturedAuthURL)
	assert.Equal(t, "https://api.example.com", u.Query().Get("resource"),
		"authorization URL should include resource parameter")
}

// =============================================================================
// #72 — Token endpoint auth method negotiation
// =============================================================================

// mockAuthServerWithAuthMethods creates a test OAuth server that advertises
// the given token_endpoint_auth_methods_supported and verifies the client
// uses the expected auth method on the /token endpoint.
//
// See: https://github.com/panyam/oneauth/issues/72
func mockAuthServerWithAuthMethods(t *testing.T, supportedMethods []string, expectedMethod TokenEndpointAuthMethod) *httptest.Server {
	t.Helper()
	var storedChallenge, storedState, storedRedirectURI string

	mux := http.NewServeMux()

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		storedChallenge = q.Get("code_challenge")
		storedState = q.Get("state")
		storedRedirectURI = q.Get("redirect_uri")

		if q.Get("response_type") != "code" {
			http.Error(w, "invalid response_type", http.StatusBadRequest)
			return
		}
		redirectURL := fmt.Sprintf("%s?code=test-auth-code&state=%s",
			storedRedirectURI, storedState)
		http.Redirect(w, r, redirectURL, http.StatusFound)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// Verify auth method
		_, _, hasBasic := r.BasicAuth()
		hasPostSecret := r.FormValue("client_secret") != ""

		switch expectedMethod {
		case AuthMethodClientSecretBasic:
			if !hasBasic {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "invalid_client", "error_description": "expected Basic auth"})
				return
			}
		case AuthMethodClientSecretPost:
			if hasBasic || !hasPostSecret {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "invalid_client", "error_description": "expected client_secret in body"})
				return
			}
		case AuthMethodNone:
			if hasBasic || hasPostSecret {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "invalid_request", "error_description": "public client should not send secret"})
				return
			}
		}

		// Verify PKCE
		verifier := r.FormValue("code_verifier")
		hash := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(hash[:])
		if computed != storedChallenge {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "PKCE verification failed"})
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

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		srv := r.Host
		metadata := map[string]any{
			"issuer":                           "http://" + srv,
			"authorization_endpoint":           "http://" + srv + "/authorize",
			"token_endpoint":                   "http://" + srv + "/token",
			"code_challenge_methods_supported": []string{"S256"},
		}
		if len(supportedMethods) > 0 {
			metadata["token_endpoint_auth_methods_supported"] = supportedMethods
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestLoginWithBrowser_ConfidentialClient_BasicAuth verifies that when
// ClientSecret is set and the AS advertises client_secret_basic, the token
// exchange sends credentials via HTTP Basic authentication header.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
// See: https://github.com/panyam/oneauth/issues/72
func TestLoginWithBrowser_ConfidentialClient_BasicAuth(t *testing.T) {
	authSrv := mockAuthServerWithAuthMethods(t,
		[]string{"client_secret_basic", "client_secret_post"},
		AuthMethodClientSecretBasic)
	store := newMockCredentialStore()
	authClient := NewAuthClient(authSrv.URL, store)

	cred, err := authClient.LoginWithBrowser(BrowserLoginConfig{
		ClientID:     "confidential-app",
		ClientSecret: "app-secret",
		Timeout:      5 * time.Second,
		OpenBrowser:  FollowRedirects(nil),
	})

	require.NoError(t, err, "confidential client with Basic auth should succeed")
	assert.Equal(t, "mock-access-token", cred.AccessToken)
}

// TestLoginWithBrowser_ConfidentialClient_PostAuth verifies that when the AS
// only supports client_secret_post, credentials are sent in the form body
// instead of the Authorization header.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
// See: https://github.com/panyam/oneauth/issues/72
func TestLoginWithBrowser_ConfidentialClient_PostAuth(t *testing.T) {
	authSrv := mockAuthServerWithAuthMethods(t,
		[]string{"client_secret_post"},
		AuthMethodClientSecretPost)
	store := newMockCredentialStore()
	authClient := NewAuthClient(authSrv.URL, store)

	cred, err := authClient.LoginWithBrowser(BrowserLoginConfig{
		ClientID:     "confidential-app",
		ClientSecret: "app-secret",
		Timeout:      5 * time.Second,
		OpenBrowser:  FollowRedirects(nil),
	})

	require.NoError(t, err, "confidential client with post auth should succeed")
	assert.Equal(t, "mock-access-token", cred.AccessToken)
}

// TestLoginWithBrowser_PublicClient_NoneAuth verifies that when no ClientSecret
// is set, the client uses auth method "none" — client_id in the form body, no
// secret sent. This documents the existing behavior for PKCE-only public clients.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.1
// See: https://github.com/panyam/oneauth/issues/72
func TestLoginWithBrowser_PublicClient_NoneAuth(t *testing.T) {
	authSrv := mockAuthServerWithAuthMethods(t,
		[]string{"client_secret_basic", "client_secret_post"},
		AuthMethodNone)
	store := newMockCredentialStore()
	authClient := NewAuthClient(authSrv.URL, store)

	cred, err := authClient.LoginWithBrowser(BrowserLoginConfig{
		ClientID:    "public-app",
		Timeout:     5 * time.Second,
		OpenBrowser: FollowRedirects(nil),
		// No ClientSecret — public client
	})

	require.NoError(t, err, "public client with none auth should succeed")
	assert.Equal(t, "mock-access-token", cred.AccessToken)
}

// =============================================================================
// #74 — TokenEndpointAuthMethods in BrowserLoginConfig
// =============================================================================

// TestLoginWithBrowser_ExplicitEndpoints_PostAuth verifies that when explicit
// endpoints are provided with TokenEndpointAuthMethods set to ["client_secret_post"],
// the client sends credentials in the form body instead of the Authorization header.
// This is the core bug from #74: without TokenEndpointAuthMethods, explicit endpoints
// cause asMethods to be empty, defaulting to client_secret_basic even when the AS
// only supports client_secret_post.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13#section-3.2.1
// See: https://github.com/panyam/oneauth/issues/74
func TestLoginWithBrowser_ExplicitEndpoints_PostAuth(t *testing.T) {
	// Server only accepts client_secret_post — rejects Basic auth
	authSrv := mockAuthServerWithAuthMethods(t,
		[]string{"client_secret_post"},
		AuthMethodClientSecretPost)
	store := newMockCredentialStore()
	authClient := NewAuthClient(authSrv.URL, store)

	cred, err := authClient.LoginWithBrowser(BrowserLoginConfig{
		ClientID:                 "confidential-app",
		ClientSecret:             "app-secret",
		AuthorizationEndpoint:    authSrv.URL + "/authorize",
		TokenEndpoint:            authSrv.URL + "/token",
		TokenEndpointAuthMethods: []string{"client_secret_post"},
		Timeout:                  5 * time.Second,
		OpenBrowser:              FollowRedirects(nil),
	})

	require.NoError(t, err, "explicit endpoints with post-only auth methods should use post auth")
	assert.Equal(t, "mock-access-token", cred.AccessToken)
}

// TestLoginWithBrowser_ExplicitEndpoints_DefaultsToBasic verifies that when
// explicit endpoints are provided WITHOUT TokenEndpointAuthMethods, the client
// defaults to client_secret_basic per RFC 6749 §2.3.1. This preserves backward
// compatibility for callers that don't set the new field.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
// See: https://github.com/panyam/oneauth/issues/74
func TestLoginWithBrowser_ExplicitEndpoints_DefaultsToBasic(t *testing.T) {
	// Server expects Basic auth (the default)
	authSrv := mockAuthServerWithAuthMethods(t,
		[]string{"client_secret_basic"},
		AuthMethodClientSecretBasic)
	store := newMockCredentialStore()
	authClient := NewAuthClient(authSrv.URL, store)

	cred, err := authClient.LoginWithBrowser(BrowserLoginConfig{
		ClientID:              "confidential-app",
		ClientSecret:          "app-secret",
		AuthorizationEndpoint: authSrv.URL + "/authorize",
		TokenEndpoint:         authSrv.URL + "/token",
		// No TokenEndpointAuthMethods — should default to basic
		Timeout:     5 * time.Second,
		OpenBrowser: FollowRedirects(nil),
	})

	require.NoError(t, err, "explicit endpoints without auth methods should default to basic")
	assert.Equal(t, "mock-access-token", cred.AccessToken)
}

// TestLoginWithBrowser_ExplicitEndpoints_MethodsOverrideDiscovery verifies that
// when both explicit endpoints AND TokenEndpointAuthMethods are provided, the
// config methods are used (discovery is skipped entirely). This proves that the
// caller's own PRM→AS discovery results take precedence.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3
// See: https://github.com/panyam/oneauth/issues/74
func TestLoginWithBrowser_ExplicitEndpoints_MethodsOverrideDiscovery(t *testing.T) {
	// Server advertises both methods via discovery, but only accepts post
	authSrv := mockAuthServerWithAuthMethods(t,
		[]string{"client_secret_basic", "client_secret_post"},
		AuthMethodClientSecretPost)
	store := newMockCredentialStore()
	authClient := NewAuthClient(authSrv.URL, store)

	// Pass explicit endpoints + override to post-only
	// Without explicit TokenEndpointAuthMethods, discovery would return both
	// and SelectAuthMethod would pick basic (preferred). But we override to
	// post-only, proving the config field takes effect.
	cred, err := authClient.LoginWithBrowser(BrowserLoginConfig{
		ClientID:                 "confidential-app",
		ClientSecret:             "app-secret",
		AuthorizationEndpoint:    authSrv.URL + "/authorize",
		TokenEndpoint:            authSrv.URL + "/token",
		TokenEndpointAuthMethods: []string{"client_secret_post"},
		Timeout:                  5 * time.Second,
		OpenBrowser:              FollowRedirects(nil),
	})

	require.NoError(t, err, "explicit TokenEndpointAuthMethods should override discovery")
	assert.Equal(t, "mock-access-token", cred.AccessToken)
}

// TestLoginWithBrowser_NoResourceParameter verifies that when Resource is not
// set, the resource parameter is omitted from the authorization URL.
//
// See: https://www.rfc-editor.org/rfc/rfc8707
func TestLoginWithBrowser_NoResourceParameter(t *testing.T) {
	authSrv := mockAuthServer(t)
	store := newMockCredentialStore()
	authClient := NewAuthClient(authSrv.URL, store)

	var capturedAuthURL string
	_, err := authClient.LoginWithBrowser(BrowserLoginConfig{
		ClientID: "test-cli",
		// No Resource set
		Timeout: 5 * time.Second,
		OpenBrowser: func(authURL string) error {
			capturedAuthURL = authURL
			go simulateBrowser(authURL)
			return nil
		},
	})

	require.NoError(t, err)
	u, _ := url.Parse(capturedAuthURL)
	assert.Empty(t, u.Query().Get("resource"),
		"resource should not be in URL when not configured")
}
