package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DeviceCodeGrantType is the OAuth grant-type URI for the RFC 8628
// device authorization grant. Exported so callers can advertise it,
// register it with discovery clients, or branch on it.
//
// See: https://www.rfc-editor.org/rfc/rfc8628#section-3.4
const DeviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// RFC 8628 §3.5 polling error codes mapped to typed sentinels. Use
// errors.Is to branch — the polling loop in `cmd/oneauth token device`
// is the canonical consumer:
//
//   - ErrAuthorizationPending: continue polling at the current interval.
//   - ErrSlowDown: bump the polling interval by 5s, then continue.
//   - ErrAccessDenied: terminal — user rejected. Surface to the user.
//   - ErrExpiredToken: terminal — code expired. Restart the flow.
var (
	// ErrAuthorizationPending signals that the user has not yet completed
	// the verification step. Keep polling at the current interval.
	ErrAuthorizationPending = errors.New("RFC 8628 authorization_pending")

	// ErrSlowDown signals that the client polled faster than the AS-advised
	// interval. The caller MUST raise its interval by at least 5 seconds
	// (RFC 8628 §3.5) before the next poll.
	ErrSlowDown = errors.New("RFC 8628 slow_down")

	// ErrAccessDenied signals that the user explicitly rejected the
	// authorization. Terminal — do not poll further.
	ErrAccessDenied = errors.New("RFC 8628 access_denied")

	// ErrExpiredToken signals that the device_code's expires_in window
	// elapsed before the user approved. Terminal — restart the flow.
	ErrExpiredToken = errors.New("RFC 8628 expired_token")
)

// DeviceAuthorizationRequest is the input to AuthClient.DeviceAuthorization.
type DeviceAuthorizationRequest struct {
	// ClientID is the OAuth client identifier. Required.
	ClientID string

	// ClientSecret authenticates a confidential client to the
	// device_authorization endpoint. Empty for public clients.
	ClientSecret string

	// Scopes is the list of OAuth scopes to request. Empty omits the
	// `scope` form value entirely (AS-default scope set).
	Scopes []string

	// Audience populates the RFC 8707 `audience` form value when set.
	Audience string
}

// DeviceAuthorizationResponse is the AS's RFC 8628 §3.2 response.
type DeviceAuthorizationResponse struct {
	// DeviceCode is the high-entropy code the device polls with.
	DeviceCode string `json:"device_code"`

	// UserCode is the short, human-typeable code the user enters on the
	// verification URI. Already formatted by the AS (e.g. "WDJB-MJHT").
	UserCode string `json:"user_code"`

	// VerificationURI is the URL the user opens to enter the user_code.
	VerificationURI string `json:"verification_uri"`

	// VerificationURIComplete is the convenience URL with the user_code
	// pre-encoded as a query parameter (RFC 8628 §3.3.1). Empty when the
	// AS doesn't advertise this field; clients SHOULD prefer it when
	// rendering a QR code or opening a browser.
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`

	// ExpiresIn is the seconds until the device_code expires.
	ExpiresIn int64 `json:"expires_in"`

	// Interval is the AS-advised minimum polling interval in seconds.
	// Clients MUST respect this; the AS may raise it via slow_down.
	Interval int `json:"interval,omitempty"`
}

// DeviceAuthorization initiates an RFC 8628 device authorization flow.
// Resolves `device_authorization_endpoint` from cached AS metadata; if
// the metadata wasn't pre-loaded or the field is empty, returns an error
// (no fallback URL — RFC 8628 doesn't define a well-known path).
func (c *AuthClient) DeviceAuthorization(ctx context.Context, req *DeviceAuthorizationRequest) (*DeviceAuthorizationResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("DeviceAuthorization: req is required")
	}
	if req.ClientID == "" {
		return nil, fmt.Errorf("DeviceAuthorization: client_id is required")
	}
	c.mu.Lock()
	endpoint := ""
	if c.cachedASMeta != nil {
		endpoint = c.cachedASMeta.DeviceAuthorizationEndpoint
	}
	httpClient := c.httpClient
	c.mu.Unlock()
	if endpoint == "" {
		return nil, fmt.Errorf("DeviceAuthorization: device_authorization_endpoint not advertised by AS metadata")
	}

	form := url.Values{
		"client_id": {req.ClientID},
	}
	if req.ClientSecret != "" {
		form.Set("client_secret", req.ClientSecret)
	}
	if len(req.Scopes) > 0 {
		form.Set("scope", strings.Join(req.Scopes, " "))
	}
	if req.Audience != "" {
		form.Set("audience", req.Audience)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("DeviceAuthorization: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("DeviceAuthorization: POST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("DeviceAuthorization: %s returned %d: %s", endpoint, resp.StatusCode, string(body))
	}
	var out DeviceAuthorizationResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("DeviceAuthorization: decode response: %w (body: %s)", err, string(body))
	}
	if out.DeviceCode == "" || out.UserCode == "" || out.VerificationURI == "" {
		return nil, fmt.Errorf("DeviceAuthorization: response missing required fields")
	}
	return &out, nil
}

// PollDeviceTokenRequest is the input to AuthClient.PollDeviceToken.
type PollDeviceTokenRequest struct {
	// DeviceCode is the device_code from DeviceAuthorizationResponse.
	DeviceCode string

	// ClientID is the OAuth client identifier. Required.
	ClientID string

	// ClientSecret authenticates a confidential client (issue 266 — the
	// AS REQUIRES this when the client is registered confidential).
	ClientSecret string
}

// PollDeviceToken executes one poll attempt against the AS's token
// endpoint. Maps the four RFC 8628 §3.5 polling errors to typed
// sentinels (ErrAuthorizationPending, ErrSlowDown, ErrAccessDenied,
// ErrExpiredToken) so callers can branch via errors.Is. Other failures
// (invalid_grant, invalid_client, network errors) bubble up as a
// generic error.
//
// On success returns the issued credential. The caller is responsible
// for the polling loop, interval enforcement, and timeout.
func (c *AuthClient) PollDeviceToken(ctx context.Context, req *PollDeviceTokenRequest) (*ServerCredential, error) {
	if req == nil {
		return nil, fmt.Errorf("PollDeviceToken: req is required")
	}
	if req.DeviceCode == "" {
		return nil, fmt.Errorf("PollDeviceToken: device_code is required")
	}
	if req.ClientID == "" {
		return nil, fmt.Errorf("PollDeviceToken: client_id is required")
	}
	c.mu.Lock()
	tokenEndpoint := c.serverURL + c.tokenEndpoint
	if c.cachedASMeta != nil && c.cachedASMeta.TokenEndpoint != "" {
		tokenEndpoint = c.cachedASMeta.TokenEndpoint
	}
	httpClient := c.httpClient
	c.mu.Unlock()

	form := url.Values{
		"grant_type":  {DeviceCodeGrantType},
		"device_code": {req.DeviceCode},
		"client_id":   {req.ClientID},
	}
	if req.ClientSecret != "" {
		form.Set("client_secret", req.ClientSecret)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("PollDeviceToken: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("PollDeviceToken: POST %s: %w", tokenEndpoint, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var raw struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token,omitempty"`
			TokenType    string `json:"token_type,omitempty"`
			ExpiresIn    int64  `json:"expires_in,omitempty"`
			Scope        string `json:"scope,omitempty"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, fmt.Errorf("PollDeviceToken: decode success response: %w (body: %s)", err, string(body))
		}
		cred := &ServerCredential{
			AccessToken:  raw.AccessToken,
			RefreshToken: raw.RefreshToken,
			TokenType:    raw.TokenType,
			Scope:        raw.Scope,
		}
		if raw.ExpiresIn > 0 {
			cred.ExpiresAt = time.Now().Add(time.Duration(raw.ExpiresIn) * time.Second)
		}
		return cred, nil
	}

	// Non-2xx: try to map to a typed sentinel.
	var oauthErr struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description,omitempty"`
	}
	_ = json.Unmarshal(body, &oauthErr)
	switch oauthErr.Error {
	case "authorization_pending":
		return nil, ErrAuthorizationPending
	case "slow_down":
		return nil, ErrSlowDown
	case "access_denied":
		return nil, ErrAccessDenied
	case "expired_token":
		return nil, ErrExpiredToken
	}
	if oauthErr.Error != "" {
		return nil, fmt.Errorf("PollDeviceToken: %s: %s", oauthErr.Error, oauthErr.ErrorDescription)
	}
	return nil, fmt.Errorf("PollDeviceToken: %s returned %d: %s", tokenEndpoint, resp.StatusCode, string(body))
}
