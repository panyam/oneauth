package oauch

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func outcome(o Outcome) *Outcome { return &o }

func TestCompare_UnlistedFailureFailsTheRun(t *testing.T) {
	rep := Compare([]Result{
		{TestID: "A", Outcome: outcome(Passed)},
		{TestID: "B", Outcome: outcome(Failed)},
	}, Expected{})
	assert.False(t, rep.OK())
	assert.Equal(t, []string{"B: failed, not in expected.yaml"}, rep.Unexpected)
	assert.Equal(t, 1, rep.Passed)
}

func TestCompare_ListedFailureIsKnown(t *testing.T) {
	rep := Compare([]Result{{TestID: "B", Outcome: outcome(NotImplemented)}},
		Expected{NotPassing: map[string]Entry{"B": {Outcome: "not-implemented"}}})
	assert.True(t, rep.OK())
	assert.Equal(t, 1, rep.Known)
}

func TestCompare_OutcomeChangeFailsTheRun(t *testing.T) {
	// A test listed as skipped that now reports not-implemented ran this
	// time and found the feature missing, which is news.
	rep := Compare([]Result{{TestID: "B", Outcome: outcome(NotImplemented)}},
		Expected{NotPassing: map[string]Entry{"B": {Outcome: "skipped"}}})
	assert.Equal(t, []string{"B: not-implemented, expected skipped"}, rep.Unexpected)
}

func TestCompare_ListedTestThatPassesIsReported(t *testing.T) {
	rep := Compare([]Result{{TestID: "B", Outcome: outcome(Passed)}},
		Expected{NotPassing: map[string]Entry{"B": {Outcome: "not-implemented"}}})
	assert.True(t, rep.OK())
	assert.Equal(t, []string{"B"}, rep.NowPassing)
}

func TestCompare_PendingAndMissingFailTheRun(t *testing.T) {
	rep := Compare([]Result{{TestID: "Timed"}},
		Expected{NotPassing: map[string]Entry{"Gone": {Outcome: "failed"}}})
	assert.Equal(t, []string{"Timed: still pending"}, rep.Unexpected)
	assert.Equal(t, []string{"Gone"}, rep.Missing)
	assert.Equal(t, "1 OAuch tests: 0 passed, 0 known, 0 now passing, 2 against expected.yaml", rep.Summary())
}

// exportFixture has the shape of GET /Dashboard/ExportData: two runs, the
// later one with a timed test still pending.
const exportFixture = `[{"Name":"oneauth","CurrentConfiguration":{},"TestRuns":[
 {"StartedAt":"2026-11-23T00:34:25.4397272","TestResults":[
   {"TestId":"OAuch.Compliance.Tests.Old.Test","Outcome":4}]},
 {"StartedAt":"2026-11-23T00:36:40.5776548","TestResults":[
   {"TestId":"OAuch.Compliance.Tests.Features.PlainPkceTest","Outcome":1,"ExtraInfo":null},
   {"TestId":"OAuch.Compliance.Tests.Tokens.TokenTimeoutTest","Outcome":null,
    "ExtraInfo":{"AccessToken":"x","ResumeWhen":"2026-11-23T00:52:38.7441616+00:00"}}]}]}]`

func TestParseExport_ReadsTheLatestRun(t *testing.T) {
	results, started, err := ParseExport([]byte(exportFixture))
	require.NoError(t, err)
	assert.Equal(t, 36, started.Minute())
	require.Len(t, results, 2)
	assert.Equal(t, "Features.PlainPkceTest", results[0].TestID)
	assert.Equal(t, NotImplemented, *results[0].Outcome)

	ids, when := Pending(results)
	assert.Equal(t, []string{"Tokens.TokenTimeoutTest"}, ids)
	assert.Equal(t, time.Date(2026, 11, 23, 0, 52, 38, 744161600, time.UTC), when.UTC())
}

func TestLoadExpected_RejectsUnknownOutcome(t *testing.T) {
	p := filepath.Join(t.TempDir(), "expected.yaml")
	require.NoError(t, os.WriteFile(p, []byte("not_passing:\n  A:\n    outcome: broken\n"), 0o644))
	_, err := LoadExpected(p)
	assert.ErrorContains(t, err, `unknown outcome "broken"`)
}

// TestLoadExpected_CheckedInFile keeps expected.yaml parseable, since only
// a full run reads it otherwise.
func TestLoadExpected_CheckedInFile(t *testing.T) {
	e, err := LoadExpected("expected.yaml")
	require.NoError(t, err)
	for id, entry := range e.NotPassing {
		assert.NotEmpty(t, entry.Verdict, "%s needs a verdict", id)
	}
}
