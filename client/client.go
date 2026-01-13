package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// RefreshThreshold is how long before expiry to proactively refresh
const RefreshThreshold = 5 * time.Minute

// AuthClient is an HTTP client with automatic token management
type AuthClient struct {
	mu            sync.Mutex
	serverURL     string
	store         CredentialStore
	httpClient    *http.Client
	baseTransport http.RoundTripper
	tokenEndpoint string // e.g., "/auth/cli/token"
}

// OAuth2TokenRequest is the request body for token endpoint
type OAuth2TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
}

// OAuth2TokenResponse is the response from token endpoint
type OAuth2TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	Error        string `json:"error,omitempty"`
	ErrorDesc    string `json:"error_description,omitempty"`
}

// ClientOption configures an AuthClient
type ClientOption func(*AuthClient)

// WithTokenEndpoint sets a custom token endpoint path
func WithTokenEndpoint(path string) ClientOption {
	return func(c *AuthClient) {
		c.tokenEndpoint = path
	}
}

// WithHTTPClient sets a custom base HTTP client (for timeouts, TLS config, etc.)
// The transport from this client will be wrapped with auth handling.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *AuthClient) {
		if client != nil && client.Transport != nil {
			c.baseTransport = client.Transport
		}
		// Copy timeout and other settings
		if client != nil {
			c.httpClient.Timeout = client.Timeout
			c.httpClient.CheckRedirect = client.CheckRedirect
			c.httpClient.Jar = client.Jar
		}
	}
}

// WithTransport sets a custom base transport (for connection pooling, proxies, etc.)
func WithTransport(transport http.RoundTripper) ClientOption {
	return func(c *AuthClient) {
		c.baseTransport = transport
	}
}

// NewAuthClient creates a new authenticated HTTP client for a server
func NewAuthClient(serverURL string, store CredentialStore, opts ...ClientOption) *AuthClient {
	// Normalize server URL
	u, err := url.Parse(serverURL)
	if err == nil && u.Scheme != "" && u.Host != "" {
		serverURL = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	}

	c := &AuthClient{
		serverURL:     serverURL,
		store:         store,
		httpClient:    &http.Client{},
		baseTransport: http.DefaultTransport,
		tokenEndpoint: "/auth/cli/token", // default
	}

	for _, opt := range opts {
		opt(c)
	}

	// Wrap the base transport with auth handling
	c.httpClient.Transport = &refreshTransport{
		client: c,
		base:   c.baseTransport,
	}

	return c
}

// HTTPClient returns the underlying HTTP client with auth handling
func (c *AuthClient) HTTPClient() *http.Client {
	return c.httpClient
}

// ServerURL returns the server URL this client is configured for
func (c *AuthClient) ServerURL() string {
	return c.serverURL
}

// GetToken returns the current access token, refreshing if needed
func (c *AuthClient) GetToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cred, err := c.store.GetCredential(c.serverURL)
	if err != nil {
		return "", err
	}

	if cred == nil {
		return "", nil
	}

	// Check if we need to refresh
	if cred.IsExpiringSoon(RefreshThreshold) && cred.HasRefreshToken() {
		if err := c.refreshTokenLocked(cred); err != nil {
			// If refresh fails but token isn't actually expired yet, use it anyway
			if !cred.IsExpired() {
				return cred.AccessToken, nil
			}
			return "", fmt.Errorf("token expired and refresh failed: %w", err)
		}
		// Re-fetch after refresh
		cred, _ = c.store.GetCredential(c.serverURL)
	}

	if cred == nil || cred.IsExpired() {
		return "", nil
	}

	return cred.AccessToken, nil
}

// GetCredential returns the stored credential for this server
func (c *AuthClient) GetCredential() (*ServerCredential, error) {
	return c.store.GetCredential(c.serverURL)
}

// Login authenticates with username/password and stores the credential
func (c *AuthClient) Login(username, password, scope string) (*ServerCredential, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	req := OAuth2TokenRequest{
		GrantType: "password",
		Username:  username,
		Password:  password,
		Scope:     scope,
		ClientID:  "cli",
	}

	cred, err := c.requestToken(req)
	if err != nil {
		return nil, err
	}

	cred.UserEmail = username

	if err := c.store.SetCredential(c.serverURL, cred); err != nil {
		return nil, fmt.Errorf("failed to store credential: %w", err)
	}

	if err := c.store.Save(); err != nil {
		return nil, fmt.Errorf("failed to save credentials: %w", err)
	}

	return cred, nil
}

// Logout removes the credential for this server
func (c *AuthClient) Logout() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.store.RemoveCredential(c.serverURL); err != nil {
		return err
	}

	return c.store.Save()
}

// IsLoggedIn returns true if there is a valid (non-expired) credential
func (c *AuthClient) IsLoggedIn() bool {
	cred, err := c.store.GetCredential(c.serverURL)
	if err != nil || cred == nil {
		return false
	}
	return !cred.IsExpired()
}

// refreshTokenLocked refreshes the access token using the refresh token
// Caller must hold c.mu
func (c *AuthClient) refreshTokenLocked(cred *ServerCredential) error {
	req := OAuth2TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: cred.RefreshToken,
		ClientID:     "cli",
	}

	newCred, err := c.requestToken(req)
	if err != nil {
		return err
	}

	// Preserve user info from old credential
	newCred.UserID = cred.UserID
	newCred.UserEmail = cred.UserEmail

	// Use new refresh token if provided, otherwise keep the old one
	if newCred.RefreshToken == "" {
		newCred.RefreshToken = cred.RefreshToken
	}

	if err := c.store.SetCredential(c.serverURL, newCred); err != nil {
		return fmt.Errorf("failed to store refreshed credential: %w", err)
	}

	return c.store.Save()
}

// requestToken makes a token request to the server
func (c *AuthClient) requestToken(req OAuth2TokenRequest) (*ServerCredential, error) {
	tokenURL := c.serverURL + c.tokenEndpoint

	jsonBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	// Use base transport directly to avoid auth loop
	httpClient := &http.Client{Transport: c.baseTransport}
	resp, err := httpClient.Post(tokenURL, "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var tokenResp OAuth2TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("invalid response from server: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if tokenResp.ErrorDesc != "" {
			return nil, fmt.Errorf("authentication failed: %s", tokenResp.ErrorDesc)
		}
		if tokenResp.Error != "" {
			return nil, fmt.Errorf("authentication failed: %s", tokenResp.Error)
		}
		return nil, fmt.Errorf("authentication failed: HTTP %d", resp.StatusCode)
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return &ServerCredential{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		Scope:        tokenResp.Scope,
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
	}, nil
}

// refreshTransport is an http.RoundTripper that adds auth and handles refresh
type refreshTransport struct {
	client *AuthClient
	base   http.RoundTripper
}

func (t *refreshTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Get current token (may trigger refresh)
	token, err := t.client.GetToken()
	if err != nil {
		return nil, err
	}

	// Clone request and add auth header if we have a token
	if token != "" {
		req = req.Clone(req.Context())
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// Make the request using base transport
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// If we get 401 and have a refresh token, try to refresh and retry once
	if resp.StatusCode == http.StatusUnauthorized && token != "" {
		t.client.mu.Lock()
		cred, _ := t.client.store.GetCredential(t.client.serverURL)
		if cred != nil && cred.HasRefreshToken() {
			if refreshErr := t.client.refreshTokenLocked(cred); refreshErr == nil {
				t.client.mu.Unlock()

				// Close original response body
				resp.Body.Close()

				// Get new token and retry
				newToken, _ := t.client.GetToken()
				if newToken != "" {
					req = req.Clone(req.Context())
					req.Header.Set("Authorization", "Bearer "+newToken)
					return t.base.RoundTrip(req)
				}
			} else {
				t.client.mu.Unlock()
			}
		} else {
			t.client.mu.Unlock()
		}
	}

	return resp, nil
}
