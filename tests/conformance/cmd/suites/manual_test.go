package main

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A manual suite (OAuch, issue 497) is run by a person, and its entry
// records the run. make conformance never runs it, the drift check wants
// no conf- target for it, and the report shows the recorded result.
func manualRegistry() *Registry {
	return &Registry{Suites: []Suite{
		{Name: "native", Kind: KindGating, Covers: "c"},
		{Name: "oauch", Kind: KindManual, Covers: "OAuch", LastRun: &ManualRun{
			Date: "2026-11-20", Commit: "abc1234", Result: "13 of 107 tests failed, each triaged", Doc: "docs/conformance/oauch.md",
		}},
	}}
}

func TestManualSuite_NotRunAndNoTarget(t *testing.T) {
	reg := manualRegistry()
	assert.Empty(t, reg.Validate())
	assert.Empty(t, Drift(reg, []string{"conf-native"}), "no conf-oauch target needed")

	var ran []string
	r := &Runner{Make: fakeMake(nil, nil), Getenv: func(string) string { return "" }, Logs: t.TempDir()}
	r.Make = func(_ context.Context, target string, _ io.Writer) error { ran = append(ran, target); return nil }
	results, ok := r.Run(reg, "")
	require.True(t, ok)
	assert.Equal(t, []string{"conf-native"}, ran)
	assert.Len(t, results, 1)
}

func TestManualSuite_ReportShowsTheRecordedRun(t *testing.T) {
	rep := Merge(&Report{}, manualRegistry(), nil, time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC), "def5678")
	require.Len(t, rep.Suites, 2)
	m := rep.Suites[1]
	assert.Equal(t, ResultManual, m.Result)
	assert.Equal(t, "2026-11-20, abc1234", m.RanAt+", "+m.Commit)
	assert.Contains(t, m.Detail, "13 of 107")
	md := Render(rep)
	assert.True(t, strings.Contains(md, "| oauch | manual | manual | 13 of 107 tests failed, each triaged (docs/conformance/oauch.md) | 2026-11-20, abc1234 |"), md)
}

func TestValidate_ManualSuiteNeedsItsRun(t *testing.T) {
	reg := &Registry{Suites: []Suite{{Name: "oauch", Kind: KindManual, Covers: "c"}}}
	assert.NotEmpty(t, reg.Validate())
	reg.Suites[0].LastRun = &ManualRun{Date: "2026-11-20", Result: "r"}
	assert.Empty(t, reg.Validate())
	reg.Suites = append(reg.Suites, Suite{Name: "x", Kind: KindGating, Covers: "c", LastRun: &ManualRun{Date: "d", Result: "r"}})
	assert.NotEmpty(t, reg.Validate(), "last_run is for manual suites only")
}
