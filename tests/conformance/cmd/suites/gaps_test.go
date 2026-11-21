package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var repoManifest = filepath.Join("..", "..", "known-gaps.yaml")

func writeManifest(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "known-gaps.yaml")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	return p
}

func TestLoadGaps_ReadsPlansIDsAndClasses(t *testing.T) {
	p := writeManifest(t, `
- suite: oidf
  plan: fapi2
  test: happy-flow
  status: expected-warning
  class: accepted
  issue: 339
  reason: |
    kept on purpose
- suite: mcp
  plans: [a, b]
  test: cimd
  status: expected-warning
  class: open
  issue: 532
  reason: not yet
- suite: as_metadata
  id: TestX
  status: expected-fail
  class: open
  issue: 7
  reason: r
`)
	gaps, err := LoadGaps(p)
	require.NoError(t, err)
	require.Len(t, gaps, 3)
	assert.Equal(t, Gap{Suite: "oidf", Check: "happy-flow", Plans: []string{"fapi2"}, Status: "expected-warning", Class: "accepted", Issue: 339, Reason: "kept on purpose"}, gaps[0])
	assert.Equal(t, []string{"a", "b"}, gaps[1].Plans)
	assert.Equal(t, "TestX", gaps[2].Check)
}

func TestLoadGaps_RefusesAnEntryWithoutAClass(t *testing.T) {
	p := writeManifest(t, `
- suite: oidf
  plan: fapi2
  test: happy-flow
  status: expected-warning
  issue: 339
  reason: r
`)
	_, err := LoadGaps(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "class")
}

func TestRender_LabelsModuleRowsAndListsGapsOpenFirst(t *testing.T) {
	r := Merge(nil, reg3(), []Result{
		{Suite: reg3().Suites[1], Result: ResultPass, Detail: "1 module", Plan: &PlanRecord{
			Plan: "oidcc-basic-certification-test-plan", Counts: map[string]int{"REVIEW": 1},
			Modules: []ModuleRecord{{Module: "oidcc-prompt-login", Result: "REVIEW", Verdict: "ok", Expected: "expected-review", Issue: 477}},
		}},
	}, t0, "abc1234")
	r.Gaps = []Gap{
		{Suite: "oidf", Check: "oidcc-prompt-login", Plans: []string{"oidcc-basic-certification-test-plan", "x"}, Status: "expected-review", Class: "accepted", Issue: 477, Reason: "the login page,\nscreenshotted"},
		{Suite: "mcp", Check: "authorization-server-metadata-cimd", Plans: []string{"mcp-auth-as"}, Status: "expected-warning", Class: "open", Issue: 532, Reason: "no CIMD yet"},
	}
	md := Render(r)
	assert.Contains(t, md, "| `oidcc-prompt-login` | REVIEW | accepted, expected-review, issue 477 |  |")
	assert.Contains(t, md, "## Known gaps")
	assert.Contains(t, md, "lists 2 expected outcomes. 1 are open gaps")
	open := strings.Index(md, "| open | mcp | `authorization-server-metadata-cimd` (1 plan) | expected-warning | 532 | no CIMD yet |")
	accepted := strings.Index(md, "| accepted | oidf | `oidcc-prompt-login` (2 plans) | expected-review | 477 | the login page, screenshotted |")
	require.NotEqual(t, -1, open)
	require.NotEqual(t, -1, accepted)
	assert.Less(t, open, accepted, "open gaps come first")
}

// Editing known-gaps.yaml without re-rendering the report fails here, so the
// docsite never shows a stale list.
func TestReport_CommittedGapsMatchTheManifest(t *testing.T) {
	want, err := LoadGaps(repoManifest)
	require.NoError(t, err)
	rep, err := LoadReport(repoReportJSON)
	require.NoError(t, err)
	assert.Equal(t, want, rep.Gaps, "docs/conformance/report.json's gaps are out of step with known-gaps.yaml; run `make conformance-report`")
}
