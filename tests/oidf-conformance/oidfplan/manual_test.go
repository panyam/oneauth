package oidfplan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/panyam/oneauth/tests/oidf-conformance/harness"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJudge_ManualModule(t *testing.T) {
	expected := map[string]Expectation{"rotate": {Module: "rotate", Status: StatusExpectedManual}}
	tests := []struct {
		name string
		r    ModuleResult
		want VerdictKind
	}{
		{"recorded as manual", ModuleResult{Module: "rotate", Status: StatusNotRun, Result: ResultManual}, VerdictOK},
		{"ran and timed out", ModuleResult{Module: "rotate", Status: "TIMEOUT (CONFIGURED)", Result: "UNKNOWN"}, VerdictRegression},
		{"ran and passed", ModuleResult{Module: "rotate", Result: "PASSED"}, VerdictRatchetUp},
		{"manual with no entry", ModuleResult{Module: "other", Status: StatusNotRun, Result: ResultManual}, VerdictRegression},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Judge([]ModuleResult{tc.r}, expected)[0].Kind)
		})
	}
}

func TestLoadExpectations_AcceptsManual(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-gaps.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
- suite: oidf
  plan: p
  test: oidcc-server-rotate-keys
  status: expected-manual
  reason: needs a person to rotate the server's keys
`), 0o644))
	got, err := LoadExpectations(path, "p")
	require.NoError(t, err)
	assert.Equal(t, StatusExpectedManual, got["oidcc-server-rotate-keys"].Status)
	assert.Equal(t, map[string]bool{"oidcc-server-rotate-keys": true}, ManualModules(got))
}

// RunPlan records a manual module without asking the harness to run it,
// so a nil harness client is never touched for it.
func TestRunPlan_DoesNotRunManualModules(t *testing.T) {
	r := runOrRecord(context.Background(), nil, "plan", harness.PlanModule{TestModule: "oidcc-server-rotate-keys"}, map[string]bool{"oidcc-server-rotate-keys": true}, 0)
	assert.Equal(t, ModuleResult{Module: "oidcc-server-rotate-keys", Status: StatusNotRun, Result: ResultManual}, r)
}

// An entry with a plans list applies to each plan it names.
func TestLoadExpectations_PlansList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-gaps.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
- suite: oidf
  plans: [dyn, tp-post]
  test: oidcc-registration-logo-uri
  status: expected-review
  evidence: Authorize
`), 0o644))
	for _, p := range []string{"dyn", "tp-post"} {
		got, err := LoadExpectations(path, p)
		require.NoError(t, err)
		assert.Contains(t, got, "oidcc-registration-logo-uri", p)
	}
	got, err := LoadExpectations(path, "basic")
	require.NoError(t, err)
	assert.Empty(t, got)
}
