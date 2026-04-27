package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/panyam/oneauth/core"
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
	tokenEndpoint string      // e.g., "/auth/cli/token"
	cachedASMeta  *ASMetadata // cached AS discovery metadata for auth method negotiation

	// OnToken is an optional callback invoked after a successful token
	// refresh (the refresh_token grant path through refreshTokenLocked).
	// It fires AFTER the new credential has been stored via CredentialStore,
	// so consumers can use the callback for side-effects (logging, metrics,
	// external persistence) that should observe the post-refresh state.
	//
	// Thread safety: the callback is invoked synchronously from whichever
	// goroutine triggered the refresh. Implementations must be thread-safe
	// if the AuthClient is shared across goroutines.
	//
	// Lock contract: the callback runs while the AuthClient internal mutex
	// is held — same as CredentialStore.SetCredential. Callbacks must NOT
	// re-enter AuthClient methods (GetToken, GetCredential, Login,
	// refreshTokenLocked) or they will deadlock. Callbacks should be
	// lightweight and non-blocking.
	//
	// Does NOT fire for initial logins (Login, LoginWithBrowser) — those
	// return the credential directly to the caller, who can persist it
	// explicitly. Only the automatic refresh_token grant path fires this.
	OnToken func(*ServerCredential)
}

// OAuth2TokenRequest is the request body for token endpoint
type OAuth2TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Code         string `json:"code,omitempty"`          // For authorization_code grant
	CodeVerifier string `json:"code_verifier,omitempty"` // PKCE verifier for authorization_code grant
	RedirectURI  string `json:"redirect_uri,omitempty"`  // Redirect URI for authorization_code grant
}

// OAuth2TokenResponse is the response from token endpoint
type OAuth2TokenResponse struct {
	AccessToken          string `json:"access_token"`
	TokenType            string `json:"token_type"`
	ExpiresIn            int64  `json:"expires_in"`
	RefreshToken         string `json:"refresh_token,omitempty"`
	Scope                string `json:"scope,omitempty"`
	AuthorizationDetails []any  `json:"authorization_details,omitempty"` // RFC 9396 (raw JSON)
	Error                string `json:"error,omitempty"`
	ErrorDesc            string `json:"error_description,omitempty"`
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

// WithASMetadata pre-populates AS discovery metadata, enabling auth method
// negotiation in ClientCredentialsToken without a separate discovery request.
// Useful when DiscoverAS has already been called or for testing.
//
// See: https://github.com/panyam/oneauth/issues/72
func WithASMetadata(meta *ASMetadata) ClientOption {
	return func(c *AuthClient) {
		c.cachedASMeta = meta
	}
}

// NewAuthClient creates a new authenticated HTTP client for a server.
// If store is nil, a no-op store is used — methods that return credentials
// (Login, LoginWithBrowser, ClientCredentialsToken) still work and return
// the credential to the caller, but tokens are not persisted between calls.
func NewAuthClient(serverURL string, store CredentialStore, opts ...ClientOption) *AuthClient {
	// Normalize server URL
	u, err := url.Parse(serverURL)
	if err == nil && u.Scheme != "" && u.Host != "" {
		serverURL = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	}

	if store == nil {
		store = noopCredentialStore{}
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

// ClientCredentialsToken authenticates using the client_credentials grant
// (RFC 6749 §4.4). This is for machine-to-machine authentication where there
// is no user context — the client authenticates on its own behalf using its
// client_id and client_secret. No refresh token is issued.
//
// The request is sent as application/x-www-form-urlencoded (RFC 6749 §4.4.2).
// Client credentials are sent using the negotiated auth method:
//   - If AS metadata was provided via WithASMetadata, SelectAuthMethod picks
//     the best method from token_endpoint_auth_methods_supported
//   - Without metadata, defaults to client_secret_basic (RFC 6749 §2.3.1)
//
// The resulting access token is stored in the credential store for use by
// subsequent API calls via the AuthClient's HTTP transport.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
// See: https://github.com/panyam/oneauth/issues/72
func (c *AuthClient) ClientCredentialsToken(clientID, clientSecret string, scopes []string) (*ServerCredential, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Negotiate auth method based on cached AS metadata
	var asMethods []string
	if c.cachedASMeta != nil {
		asMethods = c.cachedASMeta.TokenEndpointAuthMethods
	}
	authMethod := SelectAuthMethod(clientSecret, asMethods)

	// Use discovered token endpoint URL if available (may include path like
	// /realms/oneauth-test/protocol/openid-connect/token for Keycloak).
	// Fall back to serverURL + tokenEndpoint path for simple deployments.
	tokenEndpoint := c.serverURL + c.tokenEndpoint
	if c.cachedASMeta != nil && c.cachedASMeta.TokenEndpoint != "" {
		tokenEndpoint = c.cachedASMeta.TokenEndpoint
	}

	data := url.Values{
		"grant_type": {"client_credentials"},
	}
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}

	cred, err := c.requestTokenForm(tokenEndpoint, data, authMethod, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

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

// refreshTokenLocked refreshes the access token using the refresh token.
// Caller must hold c.mu.
//
// On success, stores the new credential via the CredentialStore and then
// invokes OnToken (if set) with a copy of the new credential. Both run
// under the caller's lock — callers must not re-enter AuthClient methods
// from within OnToken (see the OnToken doc for the full contract).
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

	if err := c.store.Save(); err != nil {
		return err
	}

	// Fire OnToken after successful store+save. Pass a copy so the
	// callback cannot mutate the stored value.
	if c.OnToken != nil {
		cp := *newCred
		c.OnToken(&cp)
	}
	return nil
}

// requestTokenForm sends a form-encoded (application/x-www-form-urlencoded)
// token request to the given endpoint with proper auth method negotiation
// per RFC 6749. This is the standards-compliant token request path, used by
// ClientCredentialsToken and exchangeCode.
//
// Unlike the legacy requestToken (which sends JSON to the oneauth-specific
// /auth/cli/token endpoint), this method follows the OAuth 2.0 spec exactly:
// form-encoded body, auth method applied via applyAuthToForm + SetBasicAuth.
//
// Uses baseTransport directly (not the auth-wrapping refreshTransport) to
// avoid circular auth dependencies when obtaining the initial token.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4.2
func (c *AuthClient) requestTokenForm(tokenEndpoint string, data url.Values, authMethod TokenEndpointAuthMethod, clientID, clientSecret string) (*ServerCredential, error) {
	// Apply client authentication to form data
	applyAuthToForm(authMethod, clientID, clientSecret, data)

	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// For Basic auth, set the Authorization header
	if authMethod == AuthMethodClientSecretBasic {
		req.SetBasicAuth(clientID, clientSecret)
	}

	// Use base transport directly to avoid auth loop
	httpClient := &http.Client{Transport: c.baseTransport}
	resp, err := httpClient.Do(req)
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

	cred := &ServerCredential{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		Scope:        tokenResp.Scope,
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
	}
	cred.AuthorizationDetails = parseAuthzDetailsFromRaw(tokenResp.AuthorizationDetails)
	return cred, nil
}

// requestToken makes a token request to the server using JSON encoding.
// This is the legacy path used by Login and refreshTokenLocked for the
// oneauth-specific /auth/cli/token endpoint.
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

	cred := &ServerCredential{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		Scope:        tokenResp.Scope,
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
	}
	cred.AuthorizationDetails = parseAuthzDetailsFromRaw(tokenResp.AuthorizationDetails)
	return cred, nil
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

// parseAuthzDetailsFromRaw converts raw JSON authorization_details ([]any from
// token response) into typed AuthorizationDetail structs via JSON re-marshal.
func parseAuthzDetailsFromRaw(raw []any) []core.AuthorizationDetail {
	if len(raw) == 0 {
		return nil
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var details []core.AuthorizationDetail
	if err := json.Unmarshal(data, &details); err != nil {
		return nil
	}
	return details
}
