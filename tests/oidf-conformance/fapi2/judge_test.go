package fapi2

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const errorPage = `<h1 id="authorize-error">Authorization error</h1>
<p><strong>invalid_request</strong>: request_uri has already been used</p>`

func TestJudge_EachModuleAgainstItsExpectation(t *testing.T) {
	expected := map[string]Expectation{
		"review": {Module: "review", Status: StatusExpectedReview, Evidence: "request_uri has already been used"},
		"skip":   {Module: "skip", Status: StatusExpectedSkip},
		"fail":   {Module: "fail", Status: StatusExpectedFail, Evidence: "wrong aud"},
	}
	tests := []struct {
		name string
		r    ModuleResult
		want VerdictKind
	}{
		{"passed with no entry", ModuleResult{Module: "plain", Result: "PASSED"}, VerdictOK},
		{"failed with no entry", ModuleResult{Module: "plain", Result: "FAILED", FirstFailure: "x"}, VerdictRegression},
		{"warning with no entry", ModuleResult{Module: "plain", Result: "WARNING"}, VerdictRegression},
		{"timeout with no entry", ModuleResult{Module: "plain", Status: "TIMEOUT (WAITING)", Result: "UNKNOWN"}, VerdictRegression},
		{"review with no entry", ModuleResult{Module: "plain", Result: "REVIEW", ReviewPage: errorPage}, VerdictRegression},
		{"skipped with no entry", ModuleResult{Module: "plain", Result: "SKIPPED"}, VerdictRegression},
		{"review showing the evidence", ModuleResult{Module: "review", Result: "REVIEW", ReviewPage: errorPage}, VerdictOK},
		{"review showing another page", ModuleResult{Module: "review", Result: "REVIEW", ReviewPage: "<h1>Internal Server Error</h1>"}, VerdictRegression},
		{"review with no page captured", ModuleResult{Module: "review", Result: "REVIEW"}, VerdictRegression},
		{"expected review now passes", ModuleResult{Module: "review", Result: "PASSED"}, VerdictRatchetUp},
		{"expected review fails", ModuleResult{Module: "review", Result: "FAILED"}, VerdictRegression},
		{"expected skip skipped", ModuleResult{Module: "skip", Result: "SKIPPED"}, VerdictOK},
		{"expected skip now passes", ModuleResult{Module: "skip", Result: "PASSED"}, VerdictRatchetUp},
		{"expected skip fails", ModuleResult{Module: "skip", Result: "FAILED"}, VerdictRegression},
		{"expected fail with its failure", ModuleResult{Module: "fail", Result: "FAILED", FirstFailure: "Check: wrong aud"}, VerdictOK},
		{"expected fail with another failure", ModuleResult{Module: "fail", Result: "FAILED", FirstFailure: "Check: bad nonce"}, VerdictRegression},
		{"expected fail now passes", ModuleResult{Module: "fail", Result: "PASSED"}, VerdictRatchetUp},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Judge([]ModuleResult{tt.r}, expected)
			require.NotEmpty(t, got)
			assert.Equal(t, tt.r.Module, got[0].Module)
			assert.Equal(t, tt.want, got[0].Kind, got[0].Detail)
		})
	}
}

func TestJudge_EntryForAModuleThatDidNotRunIsRatchetUp(t *testing.T) {
	expected := map[string]Expectation{
		"gone": {Module: "gone", Status: StatusExpectedSkip},
	}
	got := Judge([]ModuleResult{{Module: "plain", Result: "PASSED"}}, expected)
	require.Len(t, got, 2)
	assert.Equal(t, Verdict{Module: "plain", Kind: VerdictOK}, Verdict{Module: got[0].Module, Kind: got[0].Kind})
	assert.Equal(t, "gone", got[1].Module)
	assert.Equal(t, VerdictRatchetUp, got[1].Kind)
}

func TestLoadExpectations_KeepsOnlyThisPlansEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-gaps.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
- suite: oidf
  plan: oidcc-config-certification-test-plan
  test: CheckDiscEndpointUserinfoEndpoint
  status: expected-fail
  issue: 1
- suite: oidf
  plan: `+PlanName+`
  test: fapi2-security-profile-final-par-attempt-reuse-request_uri
  status: expected-review
  evidence: request_uri has already been used
  issue: 98
  reason: the error page is the refusal
- suite: oidf
  plan: `+PlanName+`
  test: fapi2-security-profile-final-ensure-signed-client-assertion-with-RS256-fails
  status: expected-skip
  issue: 330
`), 0o644))

	got, err := LoadExpectations(path)
	require.NoError(t, err)
	require.Len(t, got, 2)
	reuse := got["fapi2-security-profile-final-par-attempt-reuse-request_uri"]
	assert.Equal(t, StatusExpectedReview, reuse.Status)
	assert.Equal(t, "request_uri has already been used", reuse.Evidence)
	assert.Equal(t, 98, reuse.Issue)
	assert.Equal(t, StatusExpectedSkip, got["fapi2-security-profile-final-ensure-signed-client-assertion-with-RS256-fails"].Status)
}

func TestLoadExpectations_RefusesAReviewWithoutEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-gaps.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
- suite: oidf
  plan: `+PlanName+`
  test: some-module
  status: expected-review
  issue: 98
`), 0o644))

	_, err := LoadExpectations(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "evidence")
}

// The real manifest has to load, and every entry has to name a module this
// plan's config knows how to drive.
func TestLoadExpectations_RepositoryManifest(t *testing.T) {
	got, err := LoadExpectations(filepath.Join("..", "..", "conformance", "known-gaps.yaml"))
	require.NoError(t, err)
	assert.Equal(t, StatusExpectedSkip, got["fapi2-security-profile-final-ensure-signed-client-assertion-with-RS256-fails"].Status)
	reviews := 0
	for _, e := range got {
		if e.Status == StatusExpectedReview {
			reviews++
			assert.Contains(t, ModuleBrowsers(testSetup(t)), e.Module, "a REVIEW module needs an error-page browser override")
		}
	}
	assert.Equal(t, 4, reviews)
}
