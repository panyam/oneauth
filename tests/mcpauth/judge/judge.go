// Package judge compares the checks an MCP conformance scenario reports
// with tests/conformance/known-gaps.yaml, and writes the run record
// `make conformance` puts in docs/conformance/REPORT.md (issue 495).
//
// It works like the OIDF adapter (tests/oidf-conformance/oidfplan), with a
// conformance check in place of an OIDF module. Each check that doesn't end
// SUCCESS needs an entry with suite "mcp" naming the run's plan. A check
// that ended INFO or SKIPPED didn't really run, so it needs an entry too;
// otherwise a missing token would pass silently.
package judge

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Check statuses the conformance framework reports.
const (
	Success = "SUCCESS"
	Failure = "FAILURE"
	Warning = "WARNING"
	Info    = "INFO"
	Skipped = "SKIPPED"
)

// Manifest statuses this adapter accepts.
const (
	// ExpectedFail is a check that ends FAILURE for a tracked reason.
	// Evidence, when set, must appear in its error message.
	ExpectedFail = "expected-fail"
	// ExpectedWarning is a check that ends WARNING. Evidence is required
	// and must appear in its error message.
	ExpectedWarning = "expected-warning"
	// ExpectedSkip is a check that ends INFO or SKIPPED because the
	// fixture or the framework can't exercise it yet.
	ExpectedSkip = "expected-skip"
)

// Check is one entry of a scenario's checks.json.
type Check struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Status       string `json:"status"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

// ReadChecks reads a checks.json the conformance CLI wrote.
func ReadChecks(path string) ([]Check, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Check
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

// Merge combines several scenarios' checks into one list keyed by ID. A
// check ID that appears more than once keeps its worst status, since the
// framework appends the same wire-schema checks to every scenario.
func Merge(lists ...[]Check) []Check {
	byID := map[string]Check{}
	var order []string
	for _, list := range lists {
		for _, c := range list {
			prev, seen := byID[c.ID]
			if !seen {
				order = append(order, c.ID)
			}
			if !seen || rank(c.Status) > rank(prev.Status) {
				byID[c.ID] = c
			}
		}
	}
	out := make([]Check, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out
}

func rank(status string) int {
	return map[string]int{Success: 0, Info: 1, Skipped: 2, Warning: 3, Failure: 4}[status]
}

// Expectation is one known-gaps.yaml entry for a check.
type Expectation struct {
	Check    string
	Status   string
	Evidence string
	Issue    int
}

// LoadExpectations returns the manifest's entries with suite "mcp" whose
// plan is plan or whose plans list names it, keyed by check ID. An unknown
// status, or an expected-warning without evidence, is an error, since a
// typo there would hide the check.
func LoadExpectations(path, plan string) (map[string]Expectation, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var entries []struct {
		Suite    string   `yaml:"suite"`
		Plan     string   `yaml:"plan"`
		Plans    []string `yaml:"plans"`
		Test     string   `yaml:"test"`
		Status   string   `yaml:"status"`
		Evidence string   `yaml:"evidence"`
		Issue    int      `yaml:"issue"`
	}
	if err := yaml.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	out := map[string]Expectation{}
	for _, e := range entries {
		if e.Suite != "mcp" || (e.Plan != plan && !slices.Contains(e.Plans, plan)) {
			continue
		}
		switch e.Status {
		case ExpectedFail, ExpectedSkip:
		case ExpectedWarning:
			if e.Evidence == "" {
				return nil, fmt.Errorf("manifest entry %s: expected-warning needs evidence", e.Test)
			}
		default:
			return nil, fmt.Errorf("manifest entry %s: unknown status %q for suite mcp", e.Test, e.Status)
		}
		out[e.Test] = Expectation{Check: e.Test, Status: e.Status, Evidence: e.Evidence, Issue: e.Issue}
	}
	return out, nil
}

// Verdict kinds, matching the OIDF adapter's so the report reads the same.
const (
	OK         = "ok"
	Regression = "REGRESSION"
	RatchetUp  = "RATCHET-UP"
)

// Verdict is Judge's finding for one check.
type Verdict struct {
	Check  string
	Kind   string
	Detail string
}

// Judge compares each check with its manifest entry. It returns one Verdict
// per check, in order, then a RATCHET-UP for each entry whose check didn't
// run (sorted by check ID).
func Judge(checks []Check, expected map[string]Expectation) []Verdict {
	var out []Verdict
	seen := map[string]bool{}
	for _, c := range checks {
		seen[c.ID] = true
		out = append(out, judgeOne(c, expected[c.ID]))
	}
	var stale []string
	for id := range expected {
		if !seen[id] {
			stale = append(stale, id)
		}
	}
	sort.Strings(stale)
	for _, id := range stale {
		out = append(out, Verdict{Check: id, Kind: RatchetUp, Detail: "in known-gaps.yaml but the check didn't run; remove the entry"})
	}
	return out
}

func judgeOne(c Check, e Expectation) Verdict {
	v := Verdict{Check: c.ID, Kind: OK}
	if e.Status == "" {
		if c.Status != Success {
			v.Kind, v.Detail = Regression, "ended "+c.Status+" and has no known-gaps.yaml entry"
		}
		return v
	}
	if c.Status == Success {
		v.Kind, v.Detail = RatchetUp, "passes now; remove its known-gaps.yaml entry ("+e.Status+")"
		return v
	}
	want := map[string][]string{ExpectedFail: {Failure}, ExpectedWarning: {Warning}, ExpectedSkip: {Info, Skipped}}[e.Status]
	switch {
	case !slices.Contains(want, c.Status):
		v.Kind, v.Detail = Regression, fmt.Sprintf("ended %s, known-gaps.yaml expects %s", c.Status, strings.Join(want, " or "))
	case e.Evidence != "" && !strings.Contains(c.ErrorMessage, e.Evidence):
		v.Kind, v.Detail = Regression, fmt.Sprintf("ended %s but without %q", c.Status, e.Evidence)
	}
	return v
}

// PlanRecord is the run record `make conformance` reads from
// $CONFORMANCE_RESULTS_DIR/<plan>.json. Its JSON matches oidfplan's, so
// the report renders an MCP run the same way, one check per module row.
type PlanRecord struct {
	Plan    string         `json:"plan"`
	Counts  map[string]int `json:"counts"`
	Against int            `json:"against"`
	Modules []ModuleRecord `json:"modules"`
}

// ModuleRecord is one check's row in a PlanRecord.
type ModuleRecord struct {
	Module   string `json:"module"`
	Result   string `json:"result,omitempty"`
	Verdict  string `json:"verdict"`
	Expected string `json:"expected,omitempty"`
	Issue    int    `json:"issue,omitempty"`
	Note     string `json:"note,omitempty"`
}

// NewPlanRecord builds the record from the checks and the entries they were
// judged against, through Judge, so the record and the summary agree.
func NewPlanRecord(plan string, checks []Check, expected map[string]Expectation) PlanRecord {
	rec := PlanRecord{Plan: plan, Counts: map[string]int{}}
	byID := map[string]Check{}
	for _, c := range checks {
		byID[c.ID] = c
		rec.Counts[c.Status]++
	}
	for _, v := range Judge(checks, expected) {
		m := ModuleRecord{Module: v.Check, Verdict: v.Kind}
		if e, ok := expected[v.Check]; ok {
			m.Expected, m.Issue = e.Status, e.Issue
		}
		if c, ok := byID[v.Check]; ok {
			m.Result, m.Note = c.Status, c.ErrorMessage
		}
		if v.Kind != OK {
			rec.Against++
			if m.Note == "" {
				m.Note = v.Detail
			}
		}
		rec.Modules = append(rec.Modules, m)
	}
	sort.SliceStable(rec.Modules, func(i, j int) bool { return rec.Modules[i].Module < rec.Modules[j].Module })
	return rec
}

// Summary is the line the suites runner reads as the suite's detail. It
// uses the OIDF exercise's wording, which the runner's pattern matches.
func (r PlanRecord) Summary() string {
	n := 0
	for _, c := range r.Counts {
		n += c
	}
	return fmt.Sprintf("%d modules: %v, %d against known-gaps.yaml", n, r.Counts, r.Against)
}

// Write writes the record as indented JSON to path, creating its directory.
func (r PlanRecord) Write(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}
