package oauch

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Outcome is OAuch's TestOutcomes.
type Outcome int

// OAuch's outcomes, in its enum order. NotImplemented on a feature probe
// (implicit grant, plain PKCE) is often what a secure server should say;
// expected.yaml records which are which.
const (
	Passed Outcome = iota
	NotImplemented
	Partial
	Skipped
	Failed
)

var outcomeNames = map[Outcome]string{
	Passed:         "passed",
	NotImplemented: "not-implemented",
	Partial:        "partial",
	Skipped:        "skipped",
	Failed:         "failed",
}

func (o Outcome) String() string {
	if s, ok := outcomeNames[o]; ok {
		return s
	}
	return fmt.Sprintf("outcome(%d)", int(o))
}

func parseOutcome(s string) (Outcome, error) {
	for o, name := range outcomeNames {
		if name == s {
			return o, nil
		}
	}
	return 0, fmt.Errorf("unknown outcome %q", s)
}

// testIDPrefix is the namespace every OAuch test ID starts with.
// expected.yaml and the report leave it off.
const testIDPrefix = "OAuch.Compliance.Tests."

// Result is one test's result in a run. Outcome is nil while a timed test
// waits for its resume, and ResumeWhen says when it can go on.
type Result struct {
	TestID     string
	Outcome    *Outcome
	ResumeWhen *time.Time
}

// ParseExport reads the JSON from GET /Dashboard/ExportData/{site} and
// returns the latest run's results and its start time.
func ParseExport(raw []byte) ([]Result, time.Time, error) {
	var sites []struct {
		TestRuns []struct {
			StartedAt   string
			TestResults []struct {
				TestId    string
				Outcome   *Outcome
				ExtraInfo *struct {
					ResumeWhen *time.Time
				}
			}
		}
	}
	if err := json.Unmarshal(raw, &sites); err != nil {
		return nil, time.Time{}, fmt.Errorf("parse OAuch export: %w", err)
	}
	if len(sites) != 1 || len(sites[0].TestRuns) == 0 {
		return nil, time.Time{}, fmt.Errorf("OAuch export has %d sites and no run to read", len(sites))
	}
	runs := sites[0].TestRuns
	latest := 0
	for i := range runs {
		if runs[i].StartedAt > runs[latest].StartedAt {
			latest = i
		}
	}
	started, _ := time.Parse("2006-01-02T15:04:05.9999999", runs[latest].StartedAt)
	var out []Result
	for _, tr := range runs[latest].TestResults {
		r := Result{TestID: strings.TrimPrefix(tr.TestId, testIDPrefix), Outcome: tr.Outcome}
		if tr.ExtraInfo != nil {
			r.ResumeWhen = tr.ExtraInfo.ResumeWhen
		}
		out = append(out, r)
	}
	return out, started, nil
}

// Pending returns the timed tests still waiting, and the latest time any of
// them can resume.
func Pending(results []Result) ([]string, time.Time) {
	var ids []string
	var when time.Time
	for _, r := range results {
		if r.Outcome != nil {
			continue
		}
		ids = append(ids, r.TestID)
		if r.ResumeWhen != nil && r.ResumeWhen.After(when) {
			when = *r.ResumeWhen
		}
	}
	return ids, when
}

// Expected is expected.yaml: every test whose outcome isn't "passed", with
// the reason.
type Expected struct {
	NotPassing map[string]Entry `yaml:"not_passing"`
}

// Entry is one test's expected outcome and the reason for it.
type Entry struct {
	Outcome string `yaml:"outcome"`
	Verdict string `yaml:"verdict"`
}

// LoadExpected reads expected.yaml and checks every outcome name.
func LoadExpected(path string) (Expected, error) {
	var e Expected
	raw, err := os.ReadFile(path)
	if err != nil {
		return e, err
	}
	if err := yaml.Unmarshal(raw, &e); err != nil {
		return e, fmt.Errorf("parse %s: %w", path, err)
	}
	for id, entry := range e.NotPassing {
		if _, err := parseOutcome(entry.Outcome); err != nil {
			return e, fmt.Errorf("%s: %s: %w", path, id, err)
		}
	}
	return e, nil
}

// Report is a run checked against expected.yaml.
type Report struct {
	Total, Passed, Known int
	// Unexpected are tests that don't pass and aren't listed, or are
	// listed with another outcome. Each fails the run.
	Unexpected []string
	// Missing are listed tests the run didn't report. They fail the run,
	// since expected.yaml no longer matches this OAuch.
	Missing []string
	// NowPassing are listed tests that passed. They don't fail the run;
	// their lines can come out of expected.yaml.
	NowPassing []string
}

// OK reports whether the run matches expected.yaml.
func (r Report) OK() bool { return len(r.Unexpected) == 0 && len(r.Missing) == 0 }

// Summary is the one line the conformance runner shows for the suite.
func (r Report) Summary() string {
	return fmt.Sprintf("%d OAuch tests: %d passed, %d known, %d now passing, %d against expected.yaml",
		r.Total, r.Passed, r.Known, len(r.NowPassing), len(r.Unexpected)+len(r.Missing))
}

// Compare checks results against e. A test still pending counts as
// unexpected, since a finished run has none.
func Compare(results []Result, e Expected) Report {
	var rep Report
	seen := map[string]bool{}
	for _, r := range results {
		seen[r.TestID] = true
		rep.Total++
		entry, listed := e.NotPassing[r.TestID]
		switch {
		case r.Outcome == nil:
			rep.Unexpected = append(rep.Unexpected, r.TestID+": still pending")
		case *r.Outcome == Passed:
			rep.Passed++
			if listed {
				rep.NowPassing = append(rep.NowPassing, r.TestID)
			}
		case !listed:
			rep.Unexpected = append(rep.Unexpected, fmt.Sprintf("%s: %s, not in expected.yaml", r.TestID, *r.Outcome))
		case entry.Outcome != r.Outcome.String():
			rep.Unexpected = append(rep.Unexpected, fmt.Sprintf("%s: %s, expected %s", r.TestID, *r.Outcome, entry.Outcome))
		default:
			rep.Known++
		}
	}
	for id := range e.NotPassing {
		if !seen[id] {
			rep.Missing = append(rep.Missing, id)
		}
	}
	sort.Strings(rep.Unexpected)
	sort.Strings(rep.Missing)
	sort.Strings(rep.NowPassing)
	return rep
}
