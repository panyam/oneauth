// Package harness drives the OpenID Foundation conformance suite via its
// REST API. The suite runs as a Java application in Docker (brought up by
// `make upoidf`); this package automates the plan-create → test-run →
// poll-for-completion → fetch-log lifecycle.
//
// Why a Go client rather than shell: the harness emits structured JSON
// logs (see baselines/2026-05-09/config-cert-discovery.json for shape),
// and the ratchet runner consumes structured results. Driving it in Go
// keeps types end-to-end and avoids brittle shell-json juggling.
package harness

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client talks to a running OIDF conformance harness instance over its
// REST API.
//
// TLS posture: the harness self-signs an HTTPS cert at
// `localhost.emobix.co.uk:8443` (the hostname resolves publicly to
// 127.0.0.1). The default HTTPClient configured by New skips TLS
// verification because:
//
//  1. The connection target is always loopback (the harness runs in
//     local Docker; the hostname is a DNS convenience, not a public
//     endpoint). An attacker capable of MITMing 127.0.0.1 already owns
//     the host.
//  2. The harness's cert chain is not rooted in any public CA and
//     varies across harness versions, so pinning would mean baking a
//     version-specific cert into the repo for every upstream image
//     bump (issue 197 phase 3 — separate ticket).
//
// This package is therefore safe for local test orchestration only.
// **Never** reuse this Client (or its TLS posture) against a remote
// harness or any non-loopback endpoint. Callers who need stricter
// verification can supply their own HTTPClient via the field below.
type Client struct {
	// BaseURL is the harness UI/API origin, typically
	// "https://localhost.emobix.co.uk:8443".
	BaseURL string

	// HTTPClient is used for every request. When nil, New populates a
	// loopback-only client (see the type doc for the TLS rationale).
	// Tests inject httptest.Server clients to bypass real network calls.
	HTTPClient *http.Client
}

// New returns a Client targeting the supplied baseURL with the
// loopback-only TLS posture described on Client. The baseURL must point
// at a local harness — see the type doc for the threat-model caveats.
func New(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				// Loopback-only test harness; see Client godoc for the
				// security rationale and limitations.
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
		},
	}
}

// CreatePlan instantiates an OIDF test plan against the harness. config
// is the JSON config block the plan needs (e.g., the AS's discovery URL
// and any per-plan options). The returned PlanID is opaque and must be
// passed to RunTest to start a test under the plan.
func (c *Client) CreatePlan(ctx context.Context, planName string, config any) (string, error) {
	body, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("marshal plan config: %w", err)
	}
	u := fmt.Sprintf("%s/api/plan?%s", c.BaseURL, url.Values{"planName": {planName}}.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	var resp struct {
		ID string `json:"id"`
	}
	if err := c.do(req, &resp); err != nil {
		return "", fmt.Errorf("create plan %s: %w", planName, err)
	}
	if resp.ID == "" {
		return "", fmt.Errorf("create plan %s: harness returned empty id", planName)
	}
	return resp.ID, nil
}

// RunTest starts a test within an existing plan. variant is the
// per-test variant JSON map (e.g., {"server_metadata":"discovery"}).
// Returns the test instance ID for polling.
func (c *Client) RunTest(ctx context.Context, planID, testName string, variant map[string]string) (string, error) {
	variantJSON, err := json.Marshal(variant)
	if err != nil {
		return "", fmt.Errorf("marshal variant: %w", err)
	}
	q := url.Values{
		"test":    {testName},
		"plan":    {planID},
		"variant": {string(variantJSON)},
	}
	u := fmt.Sprintf("%s/api/runner?%s", c.BaseURL, q.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return "", err
	}
	var resp struct {
		ID string `json:"id"`
	}
	if err := c.do(req, &resp); err != nil {
		return "", fmt.Errorf("run test %s in plan %s: %w", testName, planID, err)
	}
	if resp.ID == "" {
		return "", fmt.Errorf("run test %s: harness returned empty id", testName)
	}
	return resp.ID, nil
}

// TestInfo summarises a test's current state. status is the harness
// status field — relevant terminal values are "FINISHED" (test completed,
// pass/fail recorded in the log) and "INTERRUPTED" (test aborted at a
// gating check, often before any HTTP traffic). Anything else means the
// test is still in flight or waiting on a user action that won't come.
type TestInfo struct {
	Status string `json:"status"`
	Result string `json:"result"`
}

// GetInfo returns the current status of a test instance.
func (c *Client) GetInfo(ctx context.Context, testID string) (*TestInfo, error) {
	u := fmt.Sprintf("%s/api/info/%s", c.BaseURL, url.PathEscape(testID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	var info TestInfo
	if err := c.do(req, &info); err != nil {
		return nil, fmt.Errorf("get info %s: %w", testID, err)
	}
	return &info, nil
}

// WaitForCompletion polls GetInfo until the test reaches a terminal
// status (FINISHED or INTERRUPTED) or the context expires. Returns the
// final TestInfo. Callers should follow up with GetLog to inspect the
// per-check results.
//
// Polling cadence is 1s; the harness's typical test takes 1-10s.
func (c *Client) WaitForCompletion(ctx context.Context, testID string) (*TestInfo, error) {
	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()
	for {
		info, err := c.GetInfo(ctx, testID)
		if err != nil {
			return nil, err
		}
		switch info.Status {
		case "FINISHED", "INTERRUPTED":
			return info, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-tick.C:
		}
	}
}

// GetLog returns the structured log entries the harness recorded during
// a test run. Each entry has a `src` (the check class — e.g.,
// `OIDCCCheckDiscEndpointResponseTypesSupported`), a `result`
// (SUCCESS / FAILURE / WARNING / INFO), and a human-readable `msg`.
// See result.go for the typed shape and helpers.
func (c *Client) GetLog(ctx context.Context, testID string) ([]LogEntry, error) {
	u := fmt.Sprintf("%s/api/log/%s", c.BaseURL, url.PathEscape(testID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	var entries []LogEntry
	if err := c.do(req, &entries); err != nil {
		return nil, fmt.Errorf("get log %s: %w", testID, err)
	}
	return entries, nil
}

func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("harness returned %d: %.200s", resp.StatusCode, string(body))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w; body=%.200s", err, string(body))
	}
	return nil
}
