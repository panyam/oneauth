package main

import (
	"fmt"
	"sort"
	"strings"
)

// Result is a single observed test outcome.
//
// Suite is the package's last path component (e.g., "as_metadata") for
// Go-native results. Plan/Test are populated only for external-suite
// adapters (none yet — kept here so the diff logic is uniform).
type Result struct {
	Suite  string
	ID     string // Go-native: full test name including subtests
	Plan   string // External suites only
	Test   string // External suites only
	Status TestStatus
}

type TestStatus int

const (
	StatusPass TestStatus = iota
	StatusFail
	StatusSkip
)

func (s TestStatus) String() string {
	switch s {
	case StatusPass:
		return "PASS"
	case StatusFail:
		return "FAIL"
	case StatusSkip:
		return "SKIP"
	}
	return fmt.Sprintf("Status(%d)", int(s))
}

// Key matches Entry.Key.
func (r Result) Key() string {
	if r.ID != "" {
		return r.Suite + "::" + r.ID
	}
	return r.Suite + "::" + r.Plan + "::" + r.Test
}

// Issue is a single ratchet violation. Multiple Issues may be returned
// from one Diff call.
type Issue struct {
	Kind    IssueKind
	Key     string
	Message string
}

type IssueKind int

const (
	// Test failed but isn't listed in known-gaps.
	IssueRegression IssueKind = iota
	// Test passed but is listed in known-gaps. Author should remove the
	// entry to ratchet up.
	IssueRatchetUp
	// A registered test emitted t.Skip(). Forbidden by the model: every
	// known test runs every time.
	IssueSkipped
	// Manifest entry has no corresponding observed test result. Likely
	// the test was renamed or deleted.
	IssueStaleManifest
)

func (k IssueKind) String() string {
	switch k {
	case IssueRegression:
		return "regression"
	case IssueRatchetUp:
		return "ratchet-up"
	case IssueStaleManifest:
		return "stale-manifest"
	case IssueSkipped:
		return "skipped-test"
	}
	return fmt.Sprintf("IssueKind(%d)", int(k))
}

// Diff compares observed test results against the manifest of known
// expected-fails and returns every violation found, sorted for stable
// output. Passing tests not in the manifest, and failing tests in the
// manifest, are both fine.
func Diff(results []Result, manifest map[string]Entry) []Issue {
	var issues []Issue
	seenKeys := make(map[string]bool, len(results))

	for _, r := range results {
		k := r.Key()
		seenKeys[k] = true
		_, gapped := manifest[k]

		switch r.Status {
		case StatusSkip:
			issues = append(issues, Issue{
				Kind:    IssueSkipped,
				Key:     k,
				Message: fmt.Sprintf("test %s was skipped; the ratchet model forbids t.Skip() — every known test must run every time", k),
			})
		case StatusPass:
			if gapped {
				issues = append(issues, Issue{
					Kind:    IssueRatchetUp,
					Key:     k,
					Message: fmt.Sprintf("test %s is now passing; remove the entry from known-gaps.yaml to ratchet up", k),
				})
			}
		case StatusFail:
			if !gapped {
				issues = append(issues, Issue{
					Kind:    IssueRegression,
					Key:     k,
					Message: fmt.Sprintf("test %s failed but is not listed in known-gaps.yaml — regression", k),
				})
			}
		}
	}

	for k, e := range manifest {
		if seenKeys[k] {
			continue
		}
		issues = append(issues, Issue{
			Kind: IssueStaleManifest,
			Key:  k,
			Message: fmt.Sprintf(
				"manifest entry %s (issue %d) has no observed test result — was the test renamed or deleted?",
				k, e.Issue,
			),
		})
	}

	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Kind != issues[j].Kind {
			return issues[i].Kind < issues[j].Kind
		}
		return issues[i].Key < issues[j].Key
	})
	return issues
}

// FormatIssues renders a list of issues as a human-readable report.
func FormatIssues(issues []Issue) string {
	if len(issues) == 0 {
		return "ratchet OK — no diff against known-gaps.yaml\n"
	}
	var b strings.Builder
	byKind := map[IssueKind][]Issue{}
	for _, iss := range issues {
		byKind[iss.Kind] = append(byKind[iss.Kind], iss)
	}
	for _, kind := range []IssueKind{IssueRegression, IssueRatchetUp, IssueSkipped, IssueStaleManifest} {
		group := byKind[kind]
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(&b, "## %s (%d)\n", kind, len(group))
		for _, iss := range group {
			fmt.Fprintf(&b, "  - %s\n", iss.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
