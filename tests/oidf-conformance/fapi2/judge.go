package fapi2

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manifest statuses for this plan's entries in tests/conformance/known-gaps.yaml.
// Unlike the discovery plan, whose entries name single checks, these name a
// whole module (the entry's `test` is the module name).
const (
	// StatusExpectedFail is a module that fails today for a tracked reason.
	// An entry's Evidence, when set, must appear in the module's first
	// failure, so a different failure still counts as a regression.
	StatusExpectedFail = "expected-fail"
	// StatusExpectedReview is a module that ends in REVIEW, the harness's
	// result for a check a person signs off on from a screenshot. Evidence
	// is required and must appear in the captured page.
	StatusExpectedReview = "expected-review"
	// StatusExpectedSkip is a module the harness skips for this plan's
	// configuration.
	StatusExpectedSkip = "expected-skip"
	// StatusExpectedWarning is a module that passes apart from a warning
	// oneauth accepts on purpose. Evidence is required: one warning must
	// contain it, and every other warning must come from the same check,
	// so a warning from anywhere else is still a regression.
	StatusExpectedWarning = "expected-warning"
)

// Expectation is one known-gaps.yaml entry for PlanName.
type Expectation struct {
	Module   string
	Status   string
	Evidence string
	Issue    int
	Reason   string
}

// LoadExpectations reads the known-gaps.yaml manifest at path and returns
// its entries for PlanName, keyed by module name. Entries for other plans
// and suites are ignored. An entry with an unknown status, or an
// expected-review entry without evidence, is an error rather than being
// skipped, since a typo there would otherwise hide the module.
func LoadExpectations(path string) (map[string]Expectation, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var entries []struct {
		Suite    string `yaml:"suite"`
		Plan     string `yaml:"plan"`
		Test     string `yaml:"test"`
		Status   string `yaml:"status"`
		Evidence string `yaml:"evidence"`
		Issue    int    `yaml:"issue"`
		Reason   string `yaml:"reason"`
	}
	if err := yaml.Unmarshal(buf, &entries); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	out := map[string]Expectation{}
	for _, e := range entries {
		if e.Suite != "oidf" || e.Plan != PlanName {
			continue
		}
		switch e.Status {
		case StatusExpectedFail, StatusExpectedSkip:
		case StatusExpectedReview:
			if e.Evidence == "" {
				return nil, fmt.Errorf("manifest entry %s: expected-review needs evidence, the text the captured page must show", e.Test)
			}
		case StatusExpectedWarning:
			if e.Evidence == "" {
				return nil, fmt.Errorf("manifest entry %s: expected-warning needs evidence, the text the warning must show", e.Test)
			}
		default:
			return nil, fmt.Errorf("manifest entry %s: unknown status %q", e.Test, e.Status)
		}
		out[e.Test] = Expectation{Module: e.Test, Status: e.Status, Evidence: e.Evidence, Issue: e.Issue, Reason: strings.TrimSpace(e.Reason)}
	}
	return out, nil
}

// VerdictKind is how one module's result compares to the manifest.
type VerdictKind string

const (
	// VerdictOK is a module that passed with no manifest entry, or ended
	// the way its entry says.
	VerdictOK VerdictKind = "ok"
	// VerdictRegression is a module that ended worse than the manifest
	// allows. It fails the ratchet.
	VerdictRegression VerdictKind = "REGRESSION"
	// VerdictRatchetUp is a manifest entry that no longer describes the
	// run: its module passed, or didn't run at all. It fails the ratchet
	// too, so the entry gets removed.
	VerdictRatchetUp VerdictKind = "RATCHET-UP"
)

// Verdict is Judge's finding for one module.
type Verdict struct {
	Module string
	Kind   VerdictKind
	Detail string
}

// Judge compares each module's result with its manifest entry. It returns
// one Verdict per result, in order, followed by a RATCHET-UP for each entry
// whose module isn't among the results (sorted by module). A caller running
// only some of the plan's modules passes only those modules' entries.
func Judge(results []ModuleResult, expected map[string]Expectation) []Verdict {
	var out []Verdict
	seen := map[string]bool{}
	for _, r := range results {
		seen[r.Module] = true
		out = append(out, judgeOne(r, expected[r.Module], expected[r.Module].Status != ""))
	}
	var stale []string
	for m := range expected {
		if !seen[m] {
			stale = append(stale, m)
		}
	}
	sort.Strings(stale)
	for _, m := range stale {
		out = append(out, Verdict{Module: m, Kind: VerdictRatchetUp, Detail: "in known-gaps.yaml but the module didn't run; remove the entry"})
	}
	return out
}

func judgeOne(r ModuleResult, e Expectation, listed bool) Verdict {
	v := Verdict{Module: r.Module, Kind: VerdictOK}
	got := r.Result
	if got == "" || got == "UNKNOWN" {
		got = r.Status
	}
	if !listed {
		if r.Result != "PASSED" {
			v.Kind, v.Detail = VerdictRegression, "ended "+got+" and has no known-gaps.yaml entry"
		}
		return v
	}
	if r.Result == "PASSED" {
		v.Kind, v.Detail = VerdictRatchetUp, "passes now; remove its known-gaps.yaml entry ("+e.Status+")"
		return v
	}
	want, evidenceIn := map[string]string{
		StatusExpectedFail:    "FAILED",
		StatusExpectedReview:  "REVIEW",
		StatusExpectedSkip:    "SKIPPED",
		StatusExpectedWarning: "WARNING",
	}[e.Status], ""
	switch e.Status {
	case StatusExpectedFail:
		evidenceIn = r.FirstFailure
	case StatusExpectedReview:
		evidenceIn = r.ReviewPage
	}
	if e.Status == StatusExpectedWarning && r.Result == want {
		if !warningsMatch(r.Warnings, e.Evidence) {
			v.Kind, v.Detail = VerdictRegression, fmt.Sprintf("ended WARNING but not only with %q: %v", e.Evidence, r.Warnings)
		}
		return v
	}
	switch {
	case r.Result != want:
		v.Kind, v.Detail = VerdictRegression, "ended "+got+", known-gaps.yaml expects "+want
	case e.Evidence != "" && !strings.Contains(evidenceIn, e.Evidence):
		v.Kind, v.Detail = VerdictRegression, fmt.Sprintf("ended %s but without %q", want, e.Evidence)
	}
	return v
}

// warningsMatch reports whether one of warnings contains evidence and every
// warning comes from the same check (the "Src" before the colon) as that one.
func warningsMatch(warnings []string, evidence string) bool {
	src := ""
	for _, w := range warnings {
		if strings.Contains(w, evidence) {
			src, _, _ = strings.Cut(w, ":")
			break
		}
	}
	if src == "" {
		return false
	}
	for _, w := range warnings {
		if s, _, _ := strings.Cut(w, ":"); s != src {
			return false
		}
	}
	return true
}
