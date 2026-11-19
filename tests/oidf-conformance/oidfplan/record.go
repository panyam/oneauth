package oidfplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// PlanRecord is the machine-readable result of one plan run, which `make
// conformance` turns into the committed conformance report. It holds the
// same facts as the exercise's printed lines: each module's outcome, the
// known-gaps.yaml entry it was judged against, and the verdict.
type PlanRecord struct {
	Plan    string            `json:"plan"`
	Variant map[string]string `json:"variant,omitempty"`
	PlanID  string            `json:"plan_id,omitempty"`
	// Counts is the number of modules per harness result (PASSED,
	// WARNING, REVIEW, SKIPPED, FAILED, ...).
	Counts map[string]int `json:"counts"`
	// Against counts the verdicts that aren't ok, the number the
	// exercise's summary line reports as "against known-gaps.yaml".
	Against int            `json:"against"`
	Modules []ModuleRecord `json:"modules"`
}

// ModuleRecord is one module's line in a PlanRecord. Expected and Issue
// come from the module's known-gaps.yaml entry and are empty without one.
// A module listed in the manifest that didn't run has a record with only
// Module, Verdict, Expected and Issue set.
type ModuleRecord struct {
	Module   string `json:"module"`
	Status   string `json:"status,omitempty"`
	Result   string `json:"result,omitempty"`
	Verdict  string `json:"verdict"`
	Expected string `json:"expected,omitempty"`
	Issue    int    `json:"issue,omitempty"`
	// Note is the first failure or warning, or the verdict's detail when
	// the module is against the manifest.
	Note string `json:"note,omitempty"`
}

// NewPlanRecord builds the record of a run from its results and the
// manifest entries it was judged against, using Judge, so the record and
// the printed summary always agree.
func NewPlanRecord(plan Plan, planID string, results []ModuleResult, expected map[string]Expectation) PlanRecord {
	rec := PlanRecord{Plan: plan.Name, Variant: plan.Variant, PlanID: planID, Counts: map[string]int{}}
	byModule := map[string]ModuleResult{}
	for _, r := range results {
		byModule[r.Module] = r
		result := r.Result
		if result == "" {
			result = "-"
		}
		rec.Counts[result]++
	}
	for _, v := range Judge(results, expected) {
		m := ModuleRecord{Module: v.Module, Verdict: string(v.Kind)}
		if e, ok := expected[v.Module]; ok {
			m.Expected, m.Issue = e.Status, e.Issue
		}
		if r, ok := byModule[v.Module]; ok {
			m.Status, m.Result = r.Status, r.Result
			switch {
			case r.FirstFailure != "":
				m.Note = r.FirstFailure
			case len(r.Warnings) > 0:
				m.Note = r.Warnings[0]
			}
		}
		if v.Kind != VerdictOK {
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

// WritePlanRecord writes rec as indented JSON to path, creating its
// directory.
func WritePlanRecord(path string, rec PlanRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}
