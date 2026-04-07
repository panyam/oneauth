package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// BrowserLoginConfig configures the authorization code + PKCE flow
// for CLI and headless clients.
type BrowserLoginConfig struct {
	// AuthorizationEndpoint is the AS authorization URL.
	// If empty, auto-discovered via DiscoverAS(serverURL) using the
	// AuthClient's server URL.
	AuthorizationEndpoint string

	// TokenEndpoint is the AS token URL for code exchange.
	// If empty, uses the AuthClient's configured tokenEndpoint.
	TokenEndpoint string

	// ClientID identifies this client to the authorization server.
	// Required.
	ClientID string

	// Scopes to request (e.g., []string{"openid", "read", "write"}).
	Scopes []string

	// CallbackPort is the port for the loopback redirect server.
	// If 0, a random available port is chosen.
	CallbackPort int

	// Timeout for the entire flow (waiting for user to complete browser login).
	// Defaults to 5 minutes.
	Timeout time.Duration

	// OpenBrowser is called to open the authorization URL in the user's browser.
	// If nil, uses the platform default (open/xdg-open/start).
	// Set to a custom function for testing or headless environments.
	OpenBrowser func(url string) error

	// HTTPClient is used for the token exchange request.
	// If nil, uses http.DefaultClient.
	HTTPClient *http.Client

	// Resource is the RFC 8707 resource indicator — the canonical URI of the
	// target resource server (e.g., "https://api.example.com"). When set, it's
	// included in both the authorization request and token exchange to bind the
	// token to a specific audience. MCP spec requires this parameter.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8707
	Resource string

	// ClientSecret is the client's secret for confidential clients.
	// If empty, the client is treated as a public client (auth method "none")
	// and only client_id is sent in the token exchange.
	// When set, the auth method is negotiated based on AS metadata
	// (token_endpoint_auth_methods_supported) per RFC 6749 §2.3.
	//
	// See: https://github.com/panyam/oneauth/issues/72
	ClientSecret string
}

// callbackResult holds the result received on the loopback redirect.
type callbackResult struct {
	Code  string
	State string
	Err   error
}

// LoginWithBrowser performs an OAuth 2.0 authorization code flow with PKCE
// for CLI/headless clients (RFC 8252). It:
//
//  1. Generates PKCE verifier + challenge
//  2. Generates a random state parameter for CSRF protection
//  3. Starts a temporary loopback HTTP server to catch the redirect
//  4. Opens the user's browser to the authorization URL
//  5. Waits for the callback with the authorization code
//  6. Validates the state parameter
//  7. Exchanges the code for tokens using the code_verifier
//  8. Stores the credential via the AuthClient's CredentialStore
//
// See: https://www.rfc-editor.org/rfc/rfc8252 (OAuth 2.0 for Native Apps)
// See: https://www.rfc-editor.org/rfc/rfc7636 (PKCE)
func (c *AuthClient) LoginWithBrowser(cfg BrowserLoginConfig) (*ServerCredential, error) {
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("ClientID is required")
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	// Generate PKCE verifier + challenge (RFC 7636)
	verifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE verifier: %w", err)
	}
	challenge := computeCodeChallenge(verifier)

	// Generate state for CSRF protection
	state, err := generateState()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	// Start loopback server
	listener, err := startLoopbackListener(cfg.CallbackPort)
	if err != nil {
		return nil, fmt.Errorf("failed to start callback server: %w", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://localhost:%d/callback", port)

	// Channel to receive the callback result
	resultCh := make(chan callbackResult, 1)

	// Serve the callback
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if errParam := q.Get("error"); errParam != "" {
			desc := q.Get("error_description")
			resultCh <- callbackResult{Err: fmt.Errorf("authorization error: %s: %s", errParam, desc)}
			w.Header().Set("Content-Type", "text/html")
			// Use static HTML — don't embed untrusted error params in response (G705/CWE-79)
			fmt.Fprint(w, "<html><body><h1>Authorization Failed</h1><p>Check the terminal for details.</p><p>You can close this tab.</p></body></html>")
			return
		}
		code := q.Get("code")
		callbackState := q.Get("state")
		resultCh <- callbackResult{Code: code, State: callbackState}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body><h1>Login Successful</h1><p>You can close this tab and return to the terminal.</p></body></html>")
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second, // Prevent Slowloris (G112/CWE-400)
	}
	go server.Serve(listener)
	defer server.Shutdown(context.Background())

	// Resolve endpoints — use config or auto-discover
	authEndpoint := cfg.AuthorizationEndpoint
	tokenEndpoint := cfg.TokenEndpoint
	var asMethods []string
	if authEndpoint == "" || tokenEndpoint == "" {
		discoveryOpts := []DiscoveryOption{}
		if cfg.HTTPClient != nil {
			discoveryOpts = append(discoveryOpts, WithHTTPClientForDiscovery(cfg.HTTPClient))
		}
		meta, discErr := DiscoverAS(c.serverURL, discoveryOpts...)
		if discErr != nil {
			return nil, fmt.Errorf("endpoint discovery failed: %w", discErr)
		}
		if authEndpoint == "" {
			authEndpoint = meta.AuthorizationEndpoint
		}
		if tokenEndpoint == "" {
			tokenEndpoint = meta.TokenEndpoint
		}
		asMethods = meta.TokenEndpointAuthMethods

		// Verify PKCE S256 support (#65). Per OAuth 2.1 and MCP spec, clients
		// MUST check code_challenge_methods_supported before proceeding.
		// Only enforced when we used discovery — if endpoints are explicit,
		// the caller is responsible for knowing their AS supports PKCE.
		if !containsString(meta.CodeChallengeMethodsSupported, "S256") {
			return nil, fmt.Errorf("authorization server does not support PKCE S256 (code_challenge_methods_supported missing or lacks S256)")
		}
	}
	if authEndpoint == "" {
		return nil, fmt.Errorf("authorization_endpoint not found")
	}
	if tokenEndpoint == "" {
		return nil, fmt.Errorf("token_endpoint not found")
	}

	// Negotiate token endpoint auth method (#72)
	authMethod := SelectAuthMethod(cfg.ClientSecret, asMethods)

	authURL := buildAuthorizationURL(authEndpoint, cfg.ClientID, redirectURI, challenge, state, cfg.Scopes, cfg.Resource)

	// Open browser
	openFn := cfg.OpenBrowser
	if openFn == nil {
		openFn = openBrowserDefault
	}
	if err := openFn(authURL); err != nil {
		return nil, fmt.Errorf("failed to open browser (URL: %s): %w", authURL, err)
	}

	// Wait for callback or timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var result callbackResult
	select {
	case result = <-resultCh:
	case <-ctx.Done():
		return nil, fmt.Errorf("login timed out after %s", timeout)
	}

	if result.Err != nil {
		return nil, result.Err
	}

	// Validate state
	if result.State != state {
		return nil, fmt.Errorf("state mismatch: possible CSRF attack")
	}

	if result.Code == "" {
		return nil, fmt.Errorf("no authorization code received")
	}

	// Exchange code for tokens
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	cred, err := c.exchangeCode(httpClient, tokenEndpoint, result.Code, verifier, redirectURI, cfg.ClientID, cfg.ClientSecret, cfg.Resource, authMethod)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	// Store credential
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.store.SetCredential(c.serverURL, cred); err != nil {
		return nil, fmt.Errorf("failed to store credential: %w", err)
	}
	if err := c.store.Save(); err != nil {
		return nil, fmt.Errorf("failed to save credentials: %w", err)
	}

	return cred, nil
}

// exchangeCode exchanges an authorization code for tokens via the token endpoint.
// The auth method determines how client credentials are sent (Basic header vs
// form body vs none). If resource is non-empty, it's included per RFC 8707.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3
// See: https://github.com/panyam/oneauth/issues/72
func (c *AuthClient) exchangeCode(httpClient *http.Client, tokenEndpoint, code, verifier, redirectURI, clientID, clientSecret, resource string, authMethod TokenEndpointAuthMethod) (*ServerCredential, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
	}
	if resource != "" {
		data.Set("resource", resource)
	}

	// Apply client authentication to form data
	applyAuthToForm(authMethod, clientID, clientSecret, data)

	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// For Basic auth, set the Authorization header
	if authMethod == AuthMethodClientSecretBasic {
		req.SetBasicAuth(clientID, clientSecret)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenResp OAuth2TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}
	if tokenResp.Error != "" {
		return nil, fmt.Errorf("%s: %s", tokenResp.Error, tokenResp.ErrorDesc)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}

	return &ServerCredential{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}, nil
}

// buildAuthorizationURL constructs the full authorization URL with PKCE, state,
// and optional resource indicator (RFC 8707).
func buildAuthorizationURL(endpoint, clientID, redirectURI, challenge, state string, scopes []string, resource string) string {
	u, _ := url.Parse(endpoint)
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	if len(scopes) > 0 {
		q.Set("scope", strings.Join(scopes, " "))
	}
	if resource != "" {
		q.Set("resource", resource)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// startLoopbackListener starts a TCP listener on localhost.
// If port is 0, a random available port is chosen.
func startLoopbackListener(port int) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
}

// generateState creates a random state parameter for CSRF protection.
func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateCodeVerifier creates a cryptographically random PKCE code verifier
// per RFC 7636 §4.1.
func generateCodeVerifier() (string, error) {
	b := make([]byte, 32) // 32 bytes → 43 base64url characters
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// computeCodeChallenge computes the S256 PKCE code challenge from a verifier
// per RFC 7636 §4.2: BASE64URL(SHA256(code_verifier)).
func computeCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// containsString checks if a string slice contains a value.
func containsString(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// FollowRedirects returns an OpenBrowser function that performs the OAuth
// authorization flow by following HTTP redirects instead of opening a browser.
// This enables headless environments: CI, conformance testing, CLI tools.
//
// The returned function GETs the authorization URL using the provided HTTP client.
// The authorization server redirects to the loopback callback URI, which the
// LoginWithBrowser loopback server catches — exactly as a browser would.
//
// Usage:
//
//	cred, err := authClient.LoginWithBrowser(client.BrowserLoginConfig{
//	    ClientID:    "my-cli",
//	    OpenBrowser: client.FollowRedirects(nil),
//	})
//
// The httpClient should follow redirects (default http.Client behavior). If nil,
// a default client is used. For authorization servers that require form-based
// login (e.g., Keycloak), the httpClient must handle cookie/session management
// and form POST — FollowRedirects is designed for AS endpoints that auto-approve
// (test/mock servers) or for pre-authenticated sessions.
//
// See: https://github.com/panyam/oneauth/issues/71
func FollowRedirects(httpClient *http.Client) func(string) error {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return func(authURL string) error {
		resp, err := httpClient.Get(authURL)
		if err != nil {
			return fmt.Errorf("headless redirect failed: %w", err)
		}
		resp.Body.Close()
		return nil
	}
}

// openBrowserDefault opens a URL in the user's default browser.
func openBrowserDefault(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

