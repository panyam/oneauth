// Package provisioner automates Authlete service configuration for the
// tests/authlete interop suite. It uses Authlete's management REST API
// (V3) to ensure the service has the JWKS, RAR types, and introspector
// client needed to flip the interop suite's SKIPs into PASSes — and to
// reverse those changes via a snapshot-based deprovision.
//
// The package is test-scoped (only used by tests/authlete/ and its CLI
// wrappers). Production deployments do not import it.
package provisioner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ErrAuthleteAPI wraps a non-2xx response from the Authlete management
// API. The wrapped error includes the HTTP status and response body so
// callers can distinguish transient failures (5xx, timeouts) from
// configuration mismatches (4xx + a meaningful resultMessage).
var ErrAuthleteAPI = errors.New("authlete management API error")

// Client is a thin REST client for Authlete's V3 management API. It
// targets a single service identified by ServiceID + AccessToken; all
// methods are scoped to that service via the URL path.
//
// Pass HTTPClient to inject a test-mode client (httptest) — when nil,
// a default client with a 30s timeout is used.
type Client struct {
	BaseURL     string // e.g., "https://us.authlete.com"
	ServiceID   string // numeric service ID as a string
	AccessToken string // service-level access token (Bearer)
	HTTPClient  *http.Client
}

// New constructs a Client with sensible defaults. baseURL is the Authlete
// cloud endpoint (e.g., "https://us.authlete.com" or "https://api.authlete.com").
// serviceID is the numeric tenant identifier; accessToken is the
// service-level token used for Bearer auth on every call.
func New(baseURL, serviceID, accessToken string) *Client {
	return &Client{
		BaseURL:     baseURL,
		ServiceID:   serviceID,
		AccessToken: accessToken,
		HTTPClient:  &http.Client{Timeout: 30 * time.Second},
	}
}

// GetService returns the full service configuration as a map. We use
// map[string]any rather than a typed struct because Authlete's service
// schema has 100+ fields, evolves frequently, and we only mutate a
// handful — preserving unknown fields on round-trip avoids accidentally
// clobbering operator-set values.
func (c *Client) GetService(ctx context.Context) (map[string]any, error) {
	var svc map[string]any
	if err := c.do(ctx, http.MethodGet, "/service/get", nil, &svc); err != nil {
		return nil, err
	}
	return svc, nil
}

// UpdateService POSTs the supplied service JSON to /service/update. The
// caller is responsible for ensuring svc is a complete, valid service
// document (typically produced by GetService + targeted field mutations,
// not constructed from scratch).
func (c *Client) UpdateService(ctx context.Context, svc map[string]any) (map[string]any, error) {
	var updated map[string]any
	if err := c.do(ctx, http.MethodPost, "/service/update", svc, &updated); err != nil {
		return nil, err
	}
	return updated, nil
}

// ListClients returns the slice of clients registered in this service.
// Order is Authlete-determined; callers should not rely on it.
func (c *Client) ListClients(ctx context.Context) ([]map[string]any, error) {
	var resp struct {
		TotalCount int              `json:"totalCount"`
		Clients    []map[string]any `json:"clients"`
	}
	if err := c.do(ctx, http.MethodGet, "/client/get/list", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Clients, nil
}

// CreateClient registers a new OAuth client in the service and returns
// the created client (including Authlete-assigned numeric clientId and
// the generated clientSecret). The input must satisfy Authlete's client
// schema — minimum fields: clientName, clientType.
func (c *Client) CreateClient(ctx context.Context, client map[string]any) (map[string]any, error) {
	var created map[string]any
	if err := c.do(ctx, http.MethodPost, "/client/create", client, &created); err != nil {
		return nil, err
	}
	return created, nil
}

// UpdateClient persists changes to an existing client. The full client
// JSON must be supplied (typically produced by ListClients + targeted
// field mutations) — Authlete replaces the stored client with the
// supplied document.
func (c *Client) UpdateClient(ctx context.Context, clientID int64, client map[string]any) (map[string]any, error) {
	var updated map[string]any
	if err := c.do(ctx, http.MethodPost, fmt.Sprintf("/client/update/%d", clientID), client, &updated); err != nil {
		return nil, err
	}
	return updated, nil
}

// DeleteClient removes the client with the given numeric clientId from
// the service. Authlete returns 204 on success and 4xx if the client
// does not exist — both surface to the caller, who is expected to know
// whether the client should exist.
func (c *Client) DeleteClient(ctx context.Context, clientID int64) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("/client/delete/%d", clientID), nil, nil)
}

// do issues a request to /api/{serviceID}{path} with Bearer auth. body
// is JSON-encoded when non-nil; out is JSON-decoded from the response
// body when non-nil. Non-2xx responses produce an ErrAuthleteAPI-wrapped
// error carrying the status and body for diagnostic context.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	url := fmt.Sprintf("%s/api/%s%s", c.BaseURL, c.ServiceID, path)
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal %s body: %w", path, err)
		}
		reqBody = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return fmt.Errorf("build %s %s: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, url, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: %s %s returned %d: %s",
			ErrAuthleteAPI, method, path, resp.StatusCode, string(respBody))
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decode %s response: %w", path, err)
		}
	}
	return nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}
