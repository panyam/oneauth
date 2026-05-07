// Command runner enforces the conformance ratchet.
//
// It runs `go test -json` over the given package pattern, compares the
// observed test outcomes to the entries in known-gaps.yaml, and exits
// non-zero on any diff. See tests/conformance/README.md and
// docs/CONFORMANCE.md §1 for the model.
//
// Exit codes:
//
//	0 — manifest matches reality
//	1 — diff detected (regression, ratchet-up, stale entry, or skipped)
//	2 — manifest invalid
//	3 — go test infrastructure failure (compile error, etc.)
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	manifestPath := flag.String("manifest", "known-gaps.yaml", "path to known-gaps manifest")
	pkg := flag.String("package", "./...", "Go package pattern to test (excludes ./cmd/...)")
	report := flag.String("report", "", "if set, write a Markdown report to this path")
	flag.Parse()

	manifest, err := LoadManifest(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "manifest error: %v\n", err)
		os.Exit(2)
	}

	results, err := RunGoTests(*pkg, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "go test failed: %v\n", err)
		os.Exit(3)
	}

	issues := Diff(results, manifest)

	out := FormatIssues(issues)
	fmt.Fprint(os.Stderr, out)

	if *report != "" {
		if err := writeReport(*report, results, manifest, issues); err != nil {
			fmt.Fprintf(os.Stderr, "report error: %v\n", err)
			os.Exit(3)
		}
		fmt.Fprintf(os.Stderr, "report written: %s\n", *report)
	}

	if len(issues) > 0 {
		os.Exit(1)
	}
}

// goTestEvent is the subset of `go test -json` event records we care about.
// See `go doc cmd/test2json`.
type goTestEvent struct {
	Action  string  `json:"Action"`
	Package string  `json:"Package"`
	Test    string  `json:"Test,omitempty"`
	Elapsed float64 `json:"Elapsed,omitempty"`
	Output  string  `json:"Output,omitempty"`
}

// RunGoTests invokes `go test -json -count=1 <pkg>` and returns the
// per-test results. Build errors and other infra failures are surfaced
// via the returned error; legitimate test failures are reported as
// Result records with StatusFail.
//
// Subpackages under <root>/cmd/ are excluded automatically — those host
// the runner itself and any future helper binaries; their unit tests
// are not part of the conformance suite.
func RunGoTests(pkg string, stderr io.Writer) ([]Result, error) {
	cmd := exec.Command("go", "test", "-json", "-count=1", pkg)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = stderr

	runErr := cmd.Run()

	results, parseErr := parseGoTestJSON(&stdout)
	if parseErr != nil {
		return nil, parseErr
	}

	if runErr != nil {
		// `go test` returns non-zero if any test fails. Distinguish a
		// build failure (no test events at all, exit code != 0) from
		// real failures (events present, some FAIL).
		if len(results) == 0 {
			return nil, fmt.Errorf("go test produced no test events: %w", runErr)
		}
	}

	return results, nil
}

// parseGoTestJSON streams events and emits one Result per top-level
// test or subtest. Subtests are first-class entries — the ID is the
// full slash-separated test path (e.g., "TestX/subtest"). Tests under
// any package whose import path contains "/cmd/" are dropped — those
// are the runner's own unit tests, not part of the suite.
func parseGoTestJSON(r io.Reader) ([]Result, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1<<20), 1<<24)

	type key struct {
		pkg  string
		test string
	}
	status := map[key]TestStatus{}
	order := []key{}

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev goTestEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("decode test2json event: %w", err)
		}
		if ev.Test == "" {
			continue
		}
		if isRunnerPackage(ev.Package) {
			continue
		}
		k := key{pkg: ev.Package, test: ev.Test}
		switch ev.Action {
		case "run":
			if _, ok := status[k]; !ok {
				order = append(order, k)
				status[k] = StatusFail
			}
		case "pass":
			status[k] = StatusPass
		case "fail":
			status[k] = StatusFail
		case "skip":
			status[k] = StatusSkip
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan test2json output: %w", err)
	}

	// Drop non-leaves: a parent test (e.g., "TestX") is implicit when a
	// subtest "TestX/sub" is present. Otherwise the parent's PASS/FAIL
	// would be a separate ratchet entry duplicating each subtest.
	hasChild := make(map[key]bool, len(order))
	for k := range status {
		if i := strings.LastIndex(k.test, "/"); i >= 0 {
			parent := key{pkg: k.pkg, test: k.test[:i]}
			hasChild[parent] = true
		}
	}

	results := make([]Result, 0, len(order))
	for _, k := range order {
		if hasChild[k] {
			continue
		}
		results = append(results, Result{
			Suite:  filepath.Base(k.pkg),
			ID:     k.test,
			Status: status[k],
		})
	}
	return results, nil
}

// isRunnerPackage reports whether a Go test event's package path belongs
// to the runner's own command (e.g., .../tests/conformance/cmd/runner).
// The runner's unit tests are not part of the conformance suite.
func isRunnerPackage(pkg string) bool {
	return strings.Contains(pkg, "/cmd/")
}
