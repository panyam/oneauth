package main

import (
	"strings"
	"testing"
)

func mustEntry(t *testing.T, e Entry) Entry {
	t.Helper()
	if err := e.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return e
}

func validGap(suite, id string) Entry {
	return Entry{
		Suite:   suite,
		ID:      id,
		Status:  "expected-fail",
		Issue:   1,
		Owner:   "test-owner",
		Reason:  "placeholder",
		Expires: "2099-01-01",
	}
}

func TestDiff_HappyPath(t *testing.T) {
	results := []Result{
		{Suite: "as_metadata", ID: "TestX", Status: StatusPass},
	}
	manifest := map[string]Entry{}
	if got := Diff(results, manifest); len(got) != 0 {
		t.Fatalf("expected 0 issues, got %v", got)
	}
}

func TestDiff_KnownGap(t *testing.T) {
	e := mustEntry(t, validGap("as_metadata", "TestX"))
	results := []Result{
		{Suite: "as_metadata", ID: "TestX", Status: StatusFail},
	}
	manifest := map[string]Entry{e.Key(): e}
	if got := Diff(results, manifest); len(got) != 0 {
		t.Fatalf("expected 0 issues for known gap, got %v", got)
	}
}

func TestDiff_Regression(t *testing.T) {
	results := []Result{
		{Suite: "as_metadata", ID: "TestX", Status: StatusFail},
	}
	issues := Diff(results, map[string]Entry{})
	if len(issues) != 1 || issues[0].Kind != IssueRegression {
		t.Fatalf("expected 1 regression, got %v", issues)
	}
	if !strings.Contains(issues[0].Message, "TestX") {
		t.Errorf("message lacks test ID: %s", issues[0].Message)
	}
}

func TestDiff_RatchetUp(t *testing.T) {
	e := mustEntry(t, validGap("as_metadata", "TestX"))
	results := []Result{
		{Suite: "as_metadata", ID: "TestX", Status: StatusPass},
	}
	manifest := map[string]Entry{e.Key(): e}
	issues := Diff(results, manifest)
	if len(issues) != 1 || issues[0].Kind != IssueRatchetUp {
		t.Fatalf("expected 1 ratchet-up, got %v", issues)
	}
}

func TestDiff_StaleManifest(t *testing.T) {
	e := mustEntry(t, validGap("as_metadata", "TestGone"))
	manifest := map[string]Entry{e.Key(): e}
	issues := Diff(nil, manifest)
	if len(issues) != 1 || issues[0].Kind != IssueStaleManifest {
		t.Fatalf("expected 1 stale-manifest, got %v", issues)
	}
	if !strings.Contains(issues[0].Message, "TestGone") {
		t.Errorf("message lacks key: %s", issues[0].Message)
	}
}

func TestDiff_SkipForbidden(t *testing.T) {
	results := []Result{
		{Suite: "as_metadata", ID: "TestX", Status: StatusSkip},
	}
	issues := Diff(results, map[string]Entry{})
	if len(issues) != 1 || issues[0].Kind != IssueSkipped {
		t.Fatalf("expected 1 skipped, got %v", issues)
	}
}

func TestDiff_SkipForbiddenEvenWhenInManifest(t *testing.T) {
	e := mustEntry(t, validGap("as_metadata", "TestX"))
	results := []Result{
		{Suite: "as_metadata", ID: "TestX", Status: StatusSkip},
	}
	manifest := map[string]Entry{e.Key(): e}
	issues := Diff(results, manifest)
	if len(issues) != 1 || issues[0].Kind != IssueSkipped {
		t.Fatalf("expected 1 skipped (skip forbidden regardless of manifest), got %v", issues)
	}
}

func TestDiff_MultipleIssuesSorted(t *testing.T) {
	gap := mustEntry(t, validGap("as_metadata", "TestRatchet"))
	stale := mustEntry(t, validGap("as_metadata", "TestStale"))
	manifest := map[string]Entry{
		gap.Key():   gap,
		stale.Key(): stale,
	}
	results := []Result{
		{Suite: "as_metadata", ID: "TestRegress", Status: StatusFail},
		{Suite: "as_metadata", ID: "TestRatchet", Status: StatusPass},
		{Suite: "as_metadata", ID: "TestSkip", Status: StatusSkip},
	}
	issues := Diff(results, manifest)
	if len(issues) != 4 {
		t.Fatalf("expected 4 issues, got %d: %v", len(issues), issues)
	}
	want := []IssueKind{IssueRegression, IssueRatchetUp, IssueSkipped, IssueStaleManifest}
	for i, w := range want {
		if issues[i].Kind != w {
			t.Errorf("issue[%d]: want %s, got %s", i, w, issues[i].Kind)
		}
	}
}

func TestEntry_Validate(t *testing.T) {
	tests := []struct {
		name    string
		entry   Entry
		wantErr string
	}{
		{
			name:    "missing suite",
			entry:   Entry{ID: "X", Status: "expected-fail", Issue: 1, Owner: "o", Reason: "r", Expires: "2099-01-01"},
			wantErr: "suite",
		},
		{
			name:    "neither id nor plan/test",
			entry:   Entry{Suite: "s", Status: "expected-fail", Issue: 1, Owner: "o", Reason: "r", Expires: "2099-01-01"},
			wantErr: "id (Go-native) or both plan+test",
		},
		{
			name:    "id and plan together",
			entry:   Entry{Suite: "s", ID: "X", Plan: "p", Test: "t", Status: "expected-fail", Issue: 1, Owner: "o", Reason: "r", Expires: "2099-01-01"},
			wantErr: "cannot mix shapes",
		},
		{
			name:    "wrong status",
			entry:   Entry{Suite: "s", ID: "X", Status: "skip", Issue: 1, Owner: "o", Reason: "r", Expires: "2099-01-01"},
			wantErr: "expected-fail",
		},
		{
			name:    "missing issue",
			entry:   Entry{Suite: "s", ID: "X", Status: "expected-fail", Owner: "o", Reason: "r", Expires: "2099-01-01"},
			wantErr: "issue",
		},
		{
			name:    "bad date",
			entry:   Entry{Suite: "s", ID: "X", Status: "expected-fail", Issue: 1, Owner: "o", Reason: "r", Expires: "next tuesday"},
			wantErr: "ISO date",
		},
		{
			name:    "external suite ok",
			entry:   Entry{Suite: "oidf", Plan: "basic", Test: "x", Status: "expected-fail", Issue: 1, Owner: "o", Reason: "r", Expires: "2099-01-01"},
			wantErr: "",
		},
		{
			name:    "go-native ok",
			entry:   Entry{Suite: "as_metadata", ID: "TestX", Status: "expected-fail", Issue: 1, Owner: "o", Reason: "r", Expires: "2099-01-01"},
			wantErr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.entry.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestParseGoTestJSON_DropsParentOfSubtests(t *testing.T) {
	in := strings.NewReader(`
{"Action":"run","Package":"x/as_metadata","Test":"TestX"}
{"Action":"run","Package":"x/as_metadata","Test":"TestX/sub_a"}
{"Action":"pass","Package":"x/as_metadata","Test":"TestX/sub_a"}
{"Action":"run","Package":"x/as_metadata","Test":"TestX/sub_b"}
{"Action":"fail","Package":"x/as_metadata","Test":"TestX/sub_b"}
{"Action":"fail","Package":"x/as_metadata","Test":"TestX"}
`)
	results, err := parseGoTestJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 leaf results (parent dropped), got %d: %+v", len(results), results)
	}
	for _, r := range results {
		if r.ID == "TestX" {
			t.Fatalf("parent test should have been dropped: %+v", r)
		}
	}
}

func TestParseGoTestJSON_SkipsRunnerCmdPackages(t *testing.T) {
	in := strings.NewReader(`
{"Action":"run","Package":"x/cmd/runner","Test":"TestRunnerInternal"}
{"Action":"pass","Package":"x/cmd/runner","Test":"TestRunnerInternal"}
{"Action":"run","Package":"x/as_metadata","Test":"TestReal"}
{"Action":"pass","Package":"x/as_metadata","Test":"TestReal"}
`)
	results, err := parseGoTestJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].ID != "TestReal" {
		t.Fatalf("expected only TestReal, got %+v", results)
	}
}
