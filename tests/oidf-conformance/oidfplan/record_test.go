package oidfplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The run record carries each module's outcome with the known-gaps.yaml
// entry it was judged against, and counts the verdicts the same way the
// exercise's summary line does.
func TestNewPlanRecord_JoinsResultsWithTheManifest(t *testing.T) {
	results := []ModuleResult{
		{Module: "oidcc-server", Status: "FINISHED", Result: "WARNING", Warnings: []string{"x"}},
		{Module: "oidcc-codereuse", Status: "FINISHED", Result: "PASSED"},
		{Module: "oidcc-prompt-login", Status: "FINISHED", Result: "FAILED", FirstFailure: "boom"},
	}
	expected := map[string]Expectation{
		"oidcc-server": {Module: "oidcc-server", Status: StatusExpectedWarning, Evidence: "x", Issue: 339},
		"oidcc-gone":   {Module: "oidcc-gone", Status: StatusExpectedFail, Issue: 7},
	}
	rec := NewPlanRecord(Plan{Name: "p", Variant: map[string]string{"a": "b"}}, "plan-1", results, expected)

	assert.Equal(t, "p", rec.Plan)
	assert.Equal(t, "plan-1", rec.PlanID)
	assert.Equal(t, map[string]int{"WARNING": 1, "PASSED": 1, "FAILED": 1}, rec.Counts)
	assert.Equal(t, 2, rec.Against, "the unexpected failure and the entry that didn't run")
	require.Len(t, rec.Modules, 4)

	byName := map[string]ModuleRecord{}
	for _, m := range rec.Modules {
		byName[m.Module] = m
	}
	assert.Equal(t, ModuleRecord{Module: "oidcc-server", Status: "FINISHED", Result: "WARNING", Verdict: "ok", Expected: StatusExpectedWarning, Issue: 339, Note: "x"}, byName["oidcc-server"])
	assert.Equal(t, "ok", byName["oidcc-codereuse"].Verdict)
	assert.Equal(t, "REGRESSION", byName["oidcc-prompt-login"].Verdict)
	assert.Equal(t, "boom", byName["oidcc-prompt-login"].Note)
	assert.Equal(t, "RATCHET-UP", byName["oidcc-gone"].Verdict, "an entry whose module didn't run is listed too")
	assert.Equal(t, 7, byName["oidcc-gone"].Issue)
}

func TestWritePlanRecord_RoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "p.json")
	rec := PlanRecord{Plan: "p", Counts: map[string]int{"PASSED": 1}, Modules: []ModuleRecord{{Module: "m", Result: "PASSED", Verdict: "ok"}}}
	require.NoError(t, WritePlanRecord(path, rec))
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var got PlanRecord
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, rec, got)
}
