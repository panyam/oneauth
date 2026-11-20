package judge

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const manifest = `
- suite: mcp
  plans: [mcp-auth-gosdk, mcp-auth-mcpkit]
  test: auth-iss-param-redirect
  status: expected-skip
  issue: 495
  owner: panyam
  reason: no flow driver
  expires: 2027-12-31
- suite: mcp
  plan: mcp-auth-mcpkit
  test: auth-jwt-validation-www-authenticate-shape
  status: expected-warning
  evidence: resource_metadata
  issue: 495
  owner: panyam
  reason: x
  expires: 2027-12-31
- suite: oidf
  plan: mcp-auth-gosdk
  test: ignored-other-suite
  status: expected-fail
  issue: 1
  owner: panyam
  reason: x
  expires: 2027-12-31
`

func loadFor(t *testing.T, plan string) map[string]Expectation {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known-gaps.yaml")
	require.NoError(t, os.WriteFile(path, []byte(manifest), 0o600))
	got, err := LoadExpectations(path, plan)
	require.NoError(t, err)
	return got
}

func TestLoadExpectations_OnlyThisPlansMCPEntries(t *testing.T) {
	assert.Len(t, loadFor(t, "mcp-auth-gosdk"), 1)
	assert.Len(t, loadFor(t, "mcp-auth-mcpkit"), 2)
}

func TestLoadExpectations_RefusesUnknownStatusAndBareWarning(t *testing.T) {
	for _, body := range []string{
		"- {suite: mcp, plan: p, test: t, status: expected-review, evidence: x}",
		"- {suite: mcp, plan: p, test: t, status: expected-warning}",
	} {
		path := filepath.Join(t.TempDir(), "m.yaml")
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
		_, err := LoadExpectations(path, "p")
		assert.Error(t, err, body)
	}
}

func verdicts(checks []Check, expected map[string]Expectation) map[string]string {
	out := map[string]string{}
	for _, v := range Judge(checks, expected) {
		out[v.Check] = v.Kind
	}
	return out
}

func TestJudge(t *testing.T) {
	exp := loadFor(t, "mcp-auth-mcpkit")
	got := verdicts([]Check{
		{ID: "pass", Status: Success},
		{ID: "unlisted-failure", Status: Failure},
		{ID: "unlisted-info", Status: Info},
		{ID: "auth-iss-param-redirect", Status: Skipped},
		{ID: "auth-jwt-validation-www-authenticate-shape", Status: Warning, ErrorMessage: "missing resource_metadata"},
	}, exp)
	assert.Equal(t, map[string]string{
		"pass":                    OK,
		"unlisted-failure":        Regression,
		"unlisted-info":           Regression,
		"auth-iss-param-redirect": OK,
		"auth-jwt-validation-www-authenticate-shape": OK,
	}, got)
}

func TestJudge_ListedChecksThatChange(t *testing.T) {
	exp := loadFor(t, "mcp-auth-mcpkit")
	got := verdicts([]Check{
		{ID: "auth-iss-param-redirect", Status: Success},
		{ID: "auth-jwt-validation-www-authenticate-shape", Status: Warning, ErrorMessage: "some other warning"},
	}, exp)
	assert.Equal(t, RatchetUp, got["auth-iss-param-redirect"], "passes now")
	assert.Equal(t, Regression, got["auth-jwt-validation-www-authenticate-shape"], "a warning without the evidence")

	got = verdicts(nil, exp)
	assert.Equal(t, RatchetUp, got["auth-iss-param-redirect"], "listed but didn't run")
}

func TestMerge_KeepsTheWorstStatusOfARepeatedCheck(t *testing.T) {
	got := Merge(
		[]Check{{ID: "wire", Status: Success}, {ID: "a", Status: Success}},
		[]Check{{ID: "wire", Status: Failure, ErrorMessage: "bad"}, {ID: "b", Status: Info}},
	)
	require.Len(t, got, 3)
	assert.Equal(t, Check{ID: "wire", Status: Failure, ErrorMessage: "bad"}, got[0])
}

func TestPlanRecord_SummaryMatchesTheRunnersPattern(t *testing.T) {
	rec := NewPlanRecord("mcp-auth-gosdk", []Check{{ID: "a", Status: Success}, {ID: "b", Status: Failure}}, nil)
	assert.Equal(t, 1, rec.Against)
	assert.Equal(t, "2 modules: map[FAILURE:1 SUCCESS:1], 1 against known-gaps.yaml", rec.Summary())
	path := filepath.Join(t.TempDir(), "r", "mcp-auth-gosdk.json")
	require.NoError(t, rec.Write(path))
	_, err := os.Stat(path)
	assert.NoError(t, err)
}
