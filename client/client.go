package client

import (
	"bytes"
	"context"
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

// LoginRequest is the input to AuthClient.Login. It carries the
// resource-owner password credentials grant inputs (RFC 6749 §4.3).
// The ClientID defaults to "cli" if unset, matching the oneauth /api/token
// endpoint's expected value for first-party CLI clients.
type LoginRequest struct {
	// Username is the resource-owner identifier (email / username).
	Username string

	// Password is the resource-owner secret.
	Password string

	// Scope is the requested OAuth scope (space-delimited).
	Scope string

	// ClientID identifies the client. Defaults to "cli" when empty.
	ClientID string
}

// Login authenticates with username/password (RFC 6749 §4.3 resource-owner
// password credentials grant) and stores the resulting credential.
func (c *AuthClient) Login(ctx context.Context, req *LoginRequest) (*ServerCredential, error) {
	if req == nil {
		return nil, fmt.Errorf("Login: req is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	clientID := req.ClientID
	if clientID == "" {
		clientID = "cli"
	}
	tokReq := OAuth2TokenRequest{
		GrantType: "password",
		Username:  req.Username,
		Password:  req.Password,
		Scope:     req.Scope,
		ClientID:  clientID,
	}

	cred, err := c.requestToken(ctx, tokReq)
	if err != nil {
		return nil, err
	}

	cred.UserEmail = req.Username

	if err := c.store.SetCredential(c.serverURL, cred); err != nil {
		return nil, fmt.Errorf("failed to store credential: %w", err)
	}

	if err := c.store.Save(); err != nil {
		return nil, fmt.Errorf("failed to save credentials: %w", err)
	}

	return cred, nil
}

// ClientCredentialsRequest is the gRPC-shape input to ClientCredentials:
// every parameter the client_credentials grant accepts, in one place.
// Use the request struct directly for new code; ClientCredentialsToken
// and ClientCredentialsTokenWithAssertion remain as 3-line wrappers for
// existing callers.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
type ClientCredentialsRequest struct {
	// ClientID identifies the client to the AS. Required.
	ClientID string

	// ClientSecret authenticates the client when ClientAssertion is nil.
	// Sent via the negotiated client_secret_basic / client_secret_post
	// method (RFC 6749 §2.3.1).
	ClientSecret string

	// ClientAssertion, when non-nil, switches client authentication to
	// the private_key_jwt path (RFC 7521 §4.2 / RFC 7523 §2.2 / OIDC
	// Core §9). ClientSecret is ignored when this is set.
	ClientAssertion *ClientAssertionConfig

	// Scopes requested for the access token. Sent as the space-delimited
	// `scope` form value.
	Scopes []string

	// Resources are RFC 8707 resource indicators — absolute URIs naming
	// the resource server(s) the token will be used at. Emitted as
	// repeated `resource` form values per §2.
	Resources []string

	// AuthorizationDetails carries RFC 9396 rich authorization
	// requirements. JSON-encoded into a single `authorization_details`
	// form value per §6.1.
	AuthorizationDetails []core.AuthorizationDetail
}

// ClientCredentials is the consolidated client_credentials grant entry
// point (RFC 6749 §4.4). It selects the client-authentication method
// (`client_secret_basic` / `client_secret_post` when ClientSecret is
// set; `private_key_jwt` when ClientAssertion is non-nil), assembles
// the form-encoded request — including RFC 8707 `resource` indicators
// and RFC 9396 `authorization_details` when present — and persists the
// resulting credential.
func (c *AuthClient) ClientCredentials(ctx context.Context, req *ClientCredentialsRequest) (*ServerCredential, error) {
	if req == nil {
		return nil, fmt.Errorf("ClientCredentials: req is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	tokenEndpoint := c.serverURL + c.tokenEndpoint
	if c.cachedASMeta != nil && c.cachedASMeta.TokenEndpoint != "" {
		tokenEndpoint = c.cachedASMeta.TokenEndpoint
	}

	data := url.Values{
		"grant_type": {"client_credentials"},
	}
	if len(req.Scopes) > 0 {
		data.Set("scope", strings.Join(req.Scopes, " "))
	}
	for _, r := range req.Resources {
		data.Add("resource", r)
	}
	if len(req.AuthorizationDetails) > 0 {
		ad, err := json.Marshal(req.AuthorizationDetails)
		if err != nil {
			return nil, fmt.Errorf("ClientCredentials: marshal authorization_details: %w", err)
		}
		data.Set("authorization_details", string(ad))
	}

	var (
		cred *ServerCredential
		err  error
	)
	if req.ClientAssertion != nil {
		cred, err = c.requestTokenFormWithAssertion(ctx, tokenEndpoint, data, req.ClientID, tokenEndpoint, *req.ClientAssertion)
	} else {
		var asMethods []string
		if c.cachedASMeta != nil {
			asMethods = c.cachedASMeta.TokenEndpointAuthMethods
		}
		authMethod := SelectAuthMethod(req.ClientSecret, asMethods)
		cred, err = c.requestTokenForm(ctx, tokenEndpoint, data, authMethod, req.ClientID, req.ClientSecret)
	}
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

// ClientCredentialsToken authenticates using the client_credentials grant
// (RFC 6749 §4.4) with `client_secret_basic` / `client_secret_post`. Thin
// wrapper over ClientCredentials — use the request struct directly for
// RFC 8707 `resource` or RFC 9396 `authorization_details`.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
// See: https://github.com/panyam/oneauth/issues/72
//
// Deprecated: use ClientCredentials directly with a context. This wrapper
// is retained for compatibility and passes context.Background() under the hood.
func (c *AuthClient) ClientCredentialsToken(clientID, clientSecret string, scopes []string) (*ServerCredential, error) {
	return c.ClientCredentials(context.Background(), &ClientCredentialsRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
	})
}

// ClientCredentialsTokenWithAssertion is the private_key_jwt wrapper
// over ClientCredentials (RFC 6749 §4.4 with RFC 7521 §4.2 / RFC 7523
// §2.2). Use ClientCredentials directly for resource / authorization
// detail parameters.
//
// See: https://www.rfc-editor.org/rfc/rfc7523#section-2.2
//
// Deprecated: use ClientCredentials directly with a context. This wrapper
// is retained for compatibility and passes context.Background() under the hood.
func (c *AuthClient) ClientCredentialsTokenWithAssertion(clientID string, cfg ClientAssertionConfig, scopes []string) (*ServerCredential, error) {
	return c.ClientCredentials(context.Background(), &ClientCredentialsRequest{
		ClientID:        clientID,
		ClientAssertion: &cfg,
		Scopes:          scopes,
	})
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

	newCred, err := c.requestToken(context.Background(), req)
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
func (c *AuthClient) requestTokenForm(ctx context.Context, tokenEndpoint string, data url.Values, authMethod TokenEndpointAuthMethod, clientID, clientSecret string) (*ServerCredential, error) {
	// Apply client authentication to form data
	applyAuthToForm(authMethod, clientID, clientSecret, data)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// For Basic auth, set the Authorization header
	if authMethod == AuthMethodClientSecretBasic {
		req.SetBasicAuth(clientID, clientSecret)
	}
	return c.executeTokenRequest(req)
}

// requestTokenFormWithAssertion is the private_key_jwt counterpart of
// requestTokenForm. The audience is typically the token endpoint URL
// (per OIDC Core §9); pass it explicitly so this works with non-default
// deployments.
func (c *AuthClient) requestTokenFormWithAssertion(ctx context.Context, tokenEndpoint string, data url.Values, clientID, audience string, cfg ClientAssertionConfig) (*ServerCredential, error) {
	assertion, err := MintClientAssertion(clientID, audience, cfg)
	if err != nil {
		return nil, fmt.Errorf("mint client_assertion: %w", err)
	}
	applyAssertionToForm(clientID, assertion, data)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.executeTokenRequest(req)
}

// executeTokenRequest dispatches a fully-prepared token request and
// decodes the OAuth response into a ServerCredential. Shared by
// requestTokenForm and requestTokenFormWithAssertion.
func (c *AuthClient) executeTokenRequest(req *http.Request) (*ServerCredential, error) {

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
func (c *AuthClient) requestToken(ctx context.Context, req OAuth2TokenRequest) (*ServerCredential, error) {
	tokenURL := c.serverURL + c.tokenEndpoint

	jsonBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", tokenURL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Use base transport directly to avoid auth loop
	httpClient := &http.Client{Transport: c.baseTransport}
	resp, err := httpClient.Do(httpReq)
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
