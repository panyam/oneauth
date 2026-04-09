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
// containing the assigned client_id and optional client_secret.
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1
type ClientRegistrationResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
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
