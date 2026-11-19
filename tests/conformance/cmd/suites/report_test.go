package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	repoReportJSON = filepath.Join("..", "..", "..", "..", "docs", "conformance", "report.json")
	repoReportMD   = filepath.Join("..", "..", "..", "..", "docs", "conformance", "REPORT.md")
)

var t0 = time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)

func reg3() *Registry {
	return &Registry{Suites: []Suite{
		{Name: "native", Kind: KindGating, Covers: "fixtures"},
		{Name: "oidf-basic-op", Kind: KindGating, Covers: "Basic OP", Plan: "oidcc-basic-certification-test-plan"},
		{Name: "authlete", Kind: KindInfo, Covers: "Authlete"},
	}}
}

func TestMerge_AFullRunRecordsEverySuite(t *testing.T) {
	plan := &PlanRecord{Plan: "oidcc-basic-certification-test-plan", Counts: map[string]int{"PASSED": 2}, Modules: []ModuleRecord{{Module: "oidcc-server", Result: "PASSED", Verdict: "ok"}}}
	got := Merge(nil, reg3(), []Result{
		{Suite: reg3().Suites[0], Result: ResultPass, Detail: "ratchet OK"},
		{Suite: reg3().Suites[1], Result: ResultPass, Detail: "2 modules", Plan: plan},
		{Suite: reg3().Suites[2], Result: ResultFail, Detail: "exit status 1"},
	}, t0, "abc1234")
	require.Len(t, got.Suites, 3)
	assert.Equal(t, SuiteReport{Name: "native", Kind: KindGating, Covers: "fixtures", Result: ResultPass, Detail: "ratchet OK", RanAt: "2026-11-19 10:00 UTC", Commit: "abc1234"}, got.Suites[0])
	assert.Equal(t, plan, got.Suites[1].Plan)
	assert.Equal(t, ResultFail, got.Suites[2].Result)
}

// A run of one suite replaces only that suite's record.
func TestMerge_APartialRunKeepsTheOthers(t *testing.T) {
	prev := Merge(nil, reg3(), []Result{
		{Suite: reg3().Suites[0], Result: ResultPass, Detail: "old native"},
		{Suite: reg3().Suites[1], Result: ResultPass, Detail: "old basic"},
	}, t0, "aaa1111")
	got := Merge(prev, reg3(), []Result{{Suite: reg3().Suites[1], Result: ResultFail, Detail: "new basic"}}, t0.Add(time.Hour), "bbb2222")
	assert.Equal(t, "old native", got.Suites[0].Detail)
	assert.Equal(t, "aaa1111", got.Suites[0].Commit)
	assert.Equal(t, "new basic", got.Suites[1].Detail)
	assert.Equal(t, "bbb2222", got.Suites[1].Commit)
	assert.Equal(t, ResultNotRun, got.Suites[2].Result, "a registered suite that never ran is listed as not run")
}

// A suite skipped on this machine keeps its last real result, with a note
// saying it was skipped and why.
func TestMerge_ASkipKeepsThePreviousResult(t *testing.T) {
	prev := Merge(nil, reg3(), []Result{{Suite: reg3().Suites[2], Result: ResultPass, Detail: "ok authlete"}}, t0, "aaa1111")
	got := Merge(prev, reg3(), []Result{{Suite: reg3().Suites[2], Result: ResultSkip, Detail: "AUTHLETE_CLIENTID is not set"}}, t0.Add(time.Hour), "bbb2222")
	s := got.Suites[2]
	assert.Equal(t, ResultPass, s.Result)
	assert.Equal(t, "ok authlete", s.Detail)
	assert.Equal(t, "aaa1111", s.Commit)
	assert.Equal(t, "skipped 2026-11-19 11:00 UTC at bbb2222: AUTHLETE_CLIENTID is not set", s.SkipNote)

	fresh := Merge(nil, reg3(), []Result{{Suite: reg3().Suites[2], Result: ResultSkip, Detail: "AUTHLETE_CLIENTID is not set"}}, t0, "ccc3333")
	assert.Equal(t, ResultSkip, fresh.Suites[2].Result, "with nothing to keep, the skip is the result")
}

// Suites removed from the registry drop out of the report, and the report
// follows registry order.
func TestMerge_FollowsTheRegistry(t *testing.T) {
	prev := &Report{Suites: []SuiteReport{{Name: "gone", Result: ResultPass}, {Name: "authlete", Result: ResultPass}}}
	got := Merge(prev, reg3(), nil, t0, "x")
	var names []string
	for _, s := range got.Suites {
		names = append(names, s.Name)
	}
	assert.Equal(t, []string{"native", "oidf-basic-op", "authlete"}, names)
}

func TestRender_TableAndPlanSections(t *testing.T) {
	r := Merge(nil, reg3(), []Result{
		{Suite: reg3().Suites[0], Result: ResultPass, Detail: "ratchet OK"},
		{Suite: reg3().Suites[1], Result: ResultPass, Detail: "2 modules", Plan: &PlanRecord{
			Plan: "oidcc-basic-certification-test-plan", PlanID: "p1", Counts: map[string]int{"PASSED": 1, "WARNING": 1},
			Modules: []ModuleRecord{
				{Module: "oidcc-server", Result: "WARNING", Verdict: "ok", Expected: "expected-warning", Issue: 339, Note: "typ | claim"},
				{Module: "oidcc-codereuse", Result: "PASSED", Verdict: "ok"},
			},
		}},
	}, t0, "abc1234")
	md := Render(r)
	assert.Contains(t, md, "| native | gating | PASS | ratchet OK | 2026-11-19 10:00 UTC, abc1234 |")
	assert.Contains(t, md, "| authlete | info | not run |")
	assert.Contains(t, md, "## oidf-basic-op")
	assert.Contains(t, md, "PASSED 1, WARNING 1; 0 against known-gaps.yaml")
	assert.Contains(t, md, "| `oidcc-server` | WARNING | expected-warning, issue 339 | typ \\| claim |", "pipes in notes are escaped")
	assert.Equal(t, md, Render(r), "rendering is deterministic")
}

// The committed report names exactly the registered suites, and REPORT.md
// is the render of report.json, so neither can drift from the other. It
// can't check the results are recent: that needs a run with Docker.
func TestReport_CommittedReportMatchesTheRegistry(t *testing.T) {
	reg, err := LoadRegistry(repoRegistry)
	require.NoError(t, err)
	rep, err := LoadReport(repoReportJSON)
	require.NoError(t, err, "run `make conformance` to create it")
	var want, got []string
	for _, s := range reg.Suites {
		want = append(want, s.Name)
	}
	for _, s := range rep.Suites {
		got = append(got, s.Name)
	}
	assert.Equal(t, want, got, "docs/conformance/report.json is out of step with conformance/suites.yaml; run `make conformance-report` (no Docker needed) or `make conformance`")

	md, err := os.ReadFile(repoReportMD)
	require.NoError(t, err)
	assert.Equal(t, Render(rep), string(md), "docs/conformance/REPORT.md isn't the render of report.json; run `make conformance-report`")
	assert.False(t, strings.Contains(string(md), "\r"))
}
