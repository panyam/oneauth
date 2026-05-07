package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Method-shape convention (issue 169): every transport-agnostic SDK call
// follows MethodName(ctx context.Context, req *XRequest) (*XResponse, error).
// Two-arg / two-return signatures map cleanly to gRPC stub generation should
// we ever need it. Helpers that only make HTTP calls (RegisterClient — the
// pre-convention shape) are kept as-is for now; converting them lives under
// issue 175.

// ClientRegistrationRequest is the payload for RFC 7591 Dynamic Client
// Registration and the RFC 7592 §2.2 update body. This represents a client
// requesting registration (or replacing its registration) at an authorization
// server's endpoint.
//
// On register the ClientID field is unused (the server assigns the value).
// On update the ClientID MUST equal the client's existing identifier — the
// server returns 400 otherwise. UpdateRegistration auto-fills it for callers.
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-2
// See: https://www.rfc-editor.org/rfc/rfc7592#section-2.2
type ClientRegistrationRequest struct {
	ClientID                string   `json:"client_id,omitempty"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

// ClientRegistrationResponse is the parsed response from a DCR endpoint,
// extended with the RFC 7592 §3 management credentials so callers can
// subsequently use GetRegistration / UpdateRegistration / DeleteRegistration
// against the issuer's management endpoint.
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1
// See: https://www.rfc-editor.org/rfc/rfc7592#section-3
type ClientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string   `json:"scope,omitempty"`

	// RFC 7592 §3 — management credentials. RegistrationClientURI is the
	// management endpoint for this specific registration; RegistrationAccessToken
	// is the Bearer token that authorizes calls against it.
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string `json:"registration_client_uri,omitempty"`
}

// RegisterClient performs RFC 7591 Dynamic Client Registration against the
// given endpoint. Returns the assigned client_id and optional client_secret.
//
// If httpClient is nil, http.DefaultClient is used.
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-3
func RegisterClient(endpoint string, meta ClientRegistrationRequest, httpClient *http.Client) (*ClientRegistrationResponse, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	body, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("marshal DCR request: %w", err)
	}

	resp, err := httpClient.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("DCR POST: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read DCR response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DCR returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result ClientRegistrationResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse DCR response: %w (body: %s)", err, string(respBody))
	}
	if result.ClientID == "" {
		return nil, fmt.Errorf("DCR returned empty client_id: %s", string(respBody))
	}

	return &result, nil
}

// ErrRegistrationUnauthorized is returned by GetRegistration (and, in #169 / #170,
// UpdateRegistration / DeleteRegistration) when the authorization server rejects
// the registration access token. Per RFC 7592 the server returns 401 for any
// auth failure — wrong token, missing token, or unknown client_id — so callers
// cannot use this error to distinguish those cases.
var ErrRegistrationUnauthorized = fmt.Errorf("registration management: unauthorized")

// GetRegistrationRequest is the input to GetRegistration.
type GetRegistrationRequest struct {
	// RegistrationClientURI is the management endpoint returned at
	// registration time (RFC 7592 §3 registration_client_uri).
	RegistrationClientURI string
	// RegistrationAccessToken authorizes calls to RegistrationClientURI
	// (RFC 7592 §3).
	RegistrationAccessToken string
	// HTTPClient is used to make the request. nil → http.DefaultClient.
	// Conceptually this is a transport option (analog of gRPC CallOption);
	// it lives on the request struct so the method retains a strict
	// (ctx, req) → (resp, err) signature.
	HTTPClient *http.Client
}

// GetRegistrationResponse wraps the parsed registration metadata. Wrapped
// (rather than returning *ClientRegistrationResponse directly) for symmetry
// with the server-side ClientRegistrationManager interface and so future
// fields can be added without changing the method signature.
type GetRegistrationResponse struct {
	Registration *ClientRegistrationResponse
}

// GetRegistration performs an RFC 7592 §2.1 read of a previously-registered
// client.
//
// The server is required to return 401 for any authentication failure; this
// function maps that case to ErrRegistrationUnauthorized so callers can branch
// on errors.Is. Other non-2xx responses surface as a generic error including
// status code and body for diagnostics.
//
// See: https://www.rfc-editor.org/rfc/rfc7592#section-2.1
func GetRegistration(ctx context.Context, req *GetRegistrationRequest) (*GetRegistrationResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request is required")
	}
	if req.RegistrationClientURI == "" {
		return nil, fmt.Errorf("registration_client_uri is required")
	}
	if req.RegistrationAccessToken == "" {
		return nil, fmt.Errorf("registration_access_token is required")
	}
	httpClient := req.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, req.RegistrationClientURI, nil)
	if err != nil {
		return nil, fmt.Errorf("build GetRegistration request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+req.RegistrationAccessToken)
	httpReq.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("GetRegistration GET: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read GetRegistration response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrRegistrationUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GetRegistration returned %d: %s", resp.StatusCode, string(body))
	}

	var result ClientRegistrationResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse GetRegistration response: %w (body: %s)", err, string(body))
	}
	if result.ClientID == "" {
		return nil, fmt.Errorf("GetRegistration returned empty client_id: %s", string(body))
	}
	return &GetRegistrationResponse{Registration: &result}, nil
}

// UpdateRegistrationRequest is the input to UpdateRegistration.
type UpdateRegistrationRequest struct {
	RegistrationClientURI   string
	RegistrationAccessToken string
	// ClientID is the client's existing client_id. Required by RFC 7592 §2.2;
	// auto-filled into Metadata.ClientID by the SDK before sending if the
	// caller hasn't already set it.
	ClientID string
	// Metadata is the full RFC 7591/7592 client metadata that will replace
	// the existing registration. Treated as a full replacement (not PATCH).
	Metadata ClientRegistrationRequest
	// HTTPClient — see GetRegistrationRequest for rationale.
	HTTPClient *http.Client
}

// UpdateRegistrationResponse wraps the post-update registration. Registration
// includes the rotated registration_access_token, which supersedes the one in
// the request. Callers MUST persist the new token before discarding the old
// one.
type UpdateRegistrationResponse struct {
	Registration *ClientRegistrationResponse
}

// UpdateRegistration performs an RFC 7592 §2.2 full-replace update.
//
// On success the AS rotates the registration_access_token; the new token
// surfaces on the response.
//
// Maps server responses:
//   - 200 OK → returns the parsed response (with the rotated token)
//   - 401 → ErrRegistrationUnauthorized
//   - 400 → returns a generic error including the AS's error_description
//   - others → generic error including status + body
//
// See: https://www.rfc-editor.org/rfc/rfc7592#section-2.2
func UpdateRegistration(ctx context.Context, req *UpdateRegistrationRequest) (*UpdateRegistrationResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request is required")
	}
	if req.RegistrationClientURI == "" {
		return nil, fmt.Errorf("registration_client_uri is required")
	}
	if req.RegistrationAccessToken == "" {
		return nil, fmt.Errorf("registration_access_token is required")
	}
	if req.ClientID == "" {
		return nil, fmt.Errorf("clientID is required (RFC 7592 §2.2)")
	}
	httpClient := req.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	// RFC 7592 §2.2 requires the body's client_id to match the registered
	// identifier; auto-fill if the caller hasn't set it explicitly.
	md := req.Metadata
	if md.ClientID == "" {
		md.ClientID = req.ClientID
	}

	body, err := json.Marshal(md)
	if err != nil {
		return nil, fmt.Errorf("marshal UpdateRegistration request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, req.RegistrationClientURI, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build UpdateRegistration request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+req.RegistrationAccessToken)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("UpdateRegistration PUT: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read UpdateRegistration response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrRegistrationUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("UpdateRegistration returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result ClientRegistrationResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse UpdateRegistration response: %w (body: %s)", err, string(respBody))
	}
	if result.ClientID == "" {
		return nil, fmt.Errorf("UpdateRegistration returned empty client_id: %s", string(respBody))
	}
	if result.RegistrationAccessToken == "" {
		return nil, fmt.Errorf("UpdateRegistration response missing registration_access_token")
	}
	return &UpdateRegistrationResponse{Registration: &result}, nil
}
