package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// ClientRegistrationRequest is the payload for RFC 7591 Dynamic Client
// Registration. This represents a client requesting registration at an
// authorization server's registration endpoint.
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-2
type ClientRegistrationRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
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

// GetRegistration performs an RFC 7592 §2.1 read of a previously-registered
// client. The caller supplies the registration_client_uri and
// registration_access_token returned at registration time (see
// ClientRegistrationResponse), and gets back the current registration metadata.
//
// The server is required to return 401 for any authentication failure; this
// function maps that case to ErrRegistrationUnauthorized so callers can branch
// on errors.Is. Other non-2xx responses surface as a generic error including
// status code and body for diagnostics.
//
// If httpClient is nil, http.DefaultClient is used.
//
// See: https://www.rfc-editor.org/rfc/rfc7592#section-2.1
func GetRegistration(registrationClientURI, registrationAccessToken string, httpClient *http.Client) (*ClientRegistrationResponse, error) {
	if registrationClientURI == "" {
		return nil, fmt.Errorf("registration_client_uri is required")
	}
	if registrationAccessToken == "" {
		return nil, fmt.Errorf("registration_access_token is required")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	req, err := http.NewRequest(http.MethodGet, registrationClientURI, nil)
	if err != nil {
		return nil, fmt.Errorf("build GetRegistration request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+registrationAccessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
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
	return &result, nil
}
