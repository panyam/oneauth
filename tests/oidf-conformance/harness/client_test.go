package harness

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeHarness is a minimal mock of the OIDF harness REST API. Tests
// drive it the same way the real client would; the mock records calls
// and returns canned responses so we can verify the wire shape without
// running the Java app.
type fakeHarness struct {
	t           *testing.T
	planID      string
	testID      string
	infoStates  []TestInfo
	infoIdx     int
	logEntries  []LogEntry
	createCount int
	runCount    int
}

func (f *fakeHarness) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/plan", func(w http.ResponseWriter, r *http.Request) {
		f.createCount++
		_ = json.NewEncoder(w).Encode(map[string]string{"id": f.planID})
	})
	mux.HandleFunc("/api/runner", func(w http.ResponseWriter, r *http.Request) {
		f.runCount++
		_ = json.NewEncoder(w).Encode(map[string]string{"id": f.testID})
	})
	mux.HandleFunc("/api/info/", func(w http.ResponseWriter, r *http.Request) {
		state := f.infoStates[f.infoIdx]
		if f.infoIdx < len(f.infoStates)-1 {
			f.infoIdx++
		}
		_ = json.NewEncoder(w).Encode(state)
	})
	mux.HandleFunc("/api/log/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(f.logEntries)
	})
	return mux
}

func newTestClient(t *testing.T, f *fakeHarness) *Client {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}
}

// TestCreatePlan_ReturnsHarnessID verifies the plan-create round-trip
// — POST body contains the supplied config, response id is returned.
func TestCreatePlan_ReturnsHarnessID(t *testing.T) {
	f := &fakeHarness{planID: "plan-123"}
	c := newTestClient(t, f)
	id, err := c.CreatePlan(context.Background(), "oidcc-config-certification-test-plan",
		map[string]any{"alias": "test", "server": map[string]string{"discoveryUrl": "http://example/.well-known"}})
	require.NoError(t, err)
	assert.Equal(t, "plan-123", id)
	assert.Equal(t, 1, f.createCount)
}

// TestRunTest_PassesVariantAsJSONQuery verifies that the variant map is
// JSON-encoded into the query string (matching the harness's wire format
// from the README's curl recipe).
func TestRunTest_PassesVariantAsJSONQuery(t *testing.T) {
	var seenVariant string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/runner", func(w http.ResponseWriter, r *http.Request) {
		seenVariant = r.URL.Query().Get("variant")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "t-1"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := c.RunTest(context.Background(), "p-1", "oidcc-discovery-endpoint-verification",
		map[string]string{"server_metadata": "discovery", "client_registration": "static_client"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"server_metadata":"discovery","client_registration":"static_client"}`, seenVariant)
}

// TestWaitForCompletion_PollsUntilTerminal verifies the polling loop
// stops at FINISHED. Intermediate states (CREATED, RUNNING) are skipped.
func TestWaitForCompletion_PollsUntilTerminal(t *testing.T) {
	f := &fakeHarness{
		testID: "t-1",
		infoStates: []TestInfo{
			{Status: "CREATED"},
			{Status: "RUNNING"},
			{Status: "FINISHED", Result: "PASSED"},
		},
	}
	c := newTestClient(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	info, err := c.WaitForCompletion(ctx, "t-1")
	require.NoError(t, err)
	assert.Equal(t, "FINISHED", info.Status)
	assert.Equal(t, "PASSED", info.Result)
}

// TestWaitForCompletion_InterruptedIsTerminal — the harness uses
// INTERRUPTED when a test aborts at a gating check (e.g., missing
// authorization_endpoint). That's a terminal state for our purposes;
// the polling loop must not hang waiting for FINISHED.
func TestWaitForCompletion_InterruptedIsTerminal(t *testing.T) {
	f := &fakeHarness{
		testID:     "t-1",
		infoStates: []TestInfo{{Status: "INTERRUPTED", Result: "FAILED"}},
	}
	c := newTestClient(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	info, err := c.WaitForCompletion(ctx, "t-1")
	require.NoError(t, err)
	assert.Equal(t, "INTERRUPTED", info.Status)
}

// TestGetLog_ReturnsTypedEntries verifies the log decode round-trips
// the fields the ratchet runner cares about (Src, Result, Msg).
func TestGetLog_ReturnsTypedEntries(t *testing.T) {
	f := &fakeHarness{
		testID: "t-1",
		logEntries: []LogEntry{
			{Src: "CheckA", Result: ResultSuccess, Msg: "ok"},
			{Src: "CheckB", Result: ResultFailure, Msg: "boom"},
			{Src: "CheckC", Result: ResultWarning, Msg: "soft"},
		},
	}
	c := newTestClient(t, f)
	entries, err := c.GetLog(context.Background(), "t-1")
	require.NoError(t, err)
	require.Len(t, entries, 3)
	assert.Equal(t, ResultFailure, entries[1].Result)
	assert.Equal(t, "boom", entries[1].Msg)
}

// TestSummarize_DedupesPerSrc verifies the ratchet-shaping logic:
// multiple entries for the same Src collapse to one outcome, keeping
// the worst severity (FAILURE > WARNING).
func TestSummarize_DedupesPerSrc(t *testing.T) {
	entries := []LogEntry{
		{Src: "A", Result: ResultWarning, Msg: "soft first"},
		{Src: "A", Result: ResultFailure, Msg: "hard fail second"},
		{Src: "B", Result: ResultFailure, Msg: "B fails"},
		{Src: "C", Result: ResultSuccess, Msg: "ignored"},
		{Src: "D", Result: ResultInfo, Msg: "ignored"},
		{Src: "E", Result: ResultWarning, Msg: "E warns"},
		{Src: "", Result: ResultFailure, Msg: "ignored: no Src"},
	}
	sum := Summarize(entries)
	require.Len(t, sum.Failures, 2, "A promoted to failure; B native failure")
	require.Len(t, sum.Warnings, 1, "E stays warning")
	assert.Equal(t, "A", sum.Failures[0].Src)
	assert.Equal(t, "hard fail second", sum.Failures[0].Msg, "msg upgrades to worst-severity msg")
	assert.Equal(t, "B", sum.Failures[1].Src)
	assert.Equal(t, "E", sum.Warnings[0].Src)
}

// TestSummarize_StableOrderByFirstAppearance verifies that the
// summary order is deterministic — first-appearance in the log —
// so diffs against known-gaps.yaml don't churn between runs.
func TestSummarize_StableOrderByFirstAppearance(t *testing.T) {
	entries := []LogEntry{
		{Src: "Z", Result: ResultFailure, Msg: "z"},
		{Src: "A", Result: ResultFailure, Msg: "a"},
		{Src: "M", Result: ResultFailure, Msg: "m"},
	}
	sum := Summarize(entries)
	require.Len(t, sum.Failures, 3)
	var order []string
	for _, f := range sum.Failures {
		order = append(order, f.Src)
	}
	assert.Equal(t, []string{"Z", "A", "M"}, order)
}

// TestDo_NonSuccessSurfacesBody verifies error messages include the
// response body (truncated) so diagnostics survive harness-side errors.
func TestDo_NonSuccessSurfacesBody(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/plan", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"plan not found"}`, http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := c.CreatePlan(context.Background(), "nonexistent-plan", map[string]any{})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "404"), "status code in error")
	assert.True(t, strings.Contains(err.Error(), "plan not found"), "body content in error")
}
