// Command suites runs the conformance suites registered in
// conformance/suites.yaml and prints one line per suite (mission 489).
// `make conformance` at the repo root runs it through conformance/Makefile.
// Its tests include the drift check between the registry and that
// Makefile.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	registry := flag.String("registry", "../../conformance/suites.yaml", "path to suites.yaml")
	makeDir := flag.String("make-dir", "../../conformance", "directory holding the conf-* targets")
	logs := flag.String("logs", "../../test-reports/conformance", "directory for per-suite logs")
	only := flag.String("suite", "", "run only this suite")
	reportJSON := flag.String("report-json", "../../docs/conformance/report.json", "the committed report data, merged with this run")
	reportMD := flag.String("report-md", "../../docs/conformance/REPORT.md", "the committed report, rendered from -report-json")
	manifest := flag.String("manifest", "known-gaps.yaml", "tests/conformance/known-gaps.yaml, copied into the report")
	renderOnly := flag.Bool("render-only", false, "re-render -report-md from -report-json and exit, running nothing")
	flag.Parse()

	reg, err := LoadRegistry(*registry)
	if err != nil {
		fail(err)
	}
	if problems := reg.Validate(); len(problems) > 0 {
		fail(fmt.Errorf("conformance/suites.yaml:\n  %s", strings.Join(problems, "\n  ")))
	}
	prev, err := LoadReport(*reportJSON)
	if err != nil {
		fail(err)
	}

	// Without a run, follow the registry (new suites appear as not run,
	// removed ones drop out) and re-render, so a registry change needs no
	// Docker to keep the stale check passing.
	gaps, err := LoadGaps(*manifest)
	if err != nil {
		fail(err)
	}
	if *renderOnly {
		rep := Merge(prev, reg, nil, time.Now(), commitID())
		rep.Gaps = gaps
		if err := SaveReport(rep, *reportJSON, *reportMD); err != nil {
			fail(err)
		}
		return
	}

	resultsDir, err := filepath.Abs(*logs)
	if err != nil {
		fail(err)
	}
	r := &Runner{
		Make: func(ctx context.Context, target string, w io.Writer) error {
			fmt.Fprintf(os.Stderr, "=== %s (log: %s)\n", target, *logs)
			return runMake(ctx, *makeDir, target, w, "CONFORMANCE_RESULTS_DIR="+resultsDir)
		},
		Getenv:  os.Getenv,
		Logs:    *logs,
		Results: resultsDir,
	}
	results, ok := r.Run(reg, *only)
	if *only != "" && len(results) == 0 {
		fail(fmt.Errorf("no suite named %q in %s", *only, *registry))
	}

	rep := Merge(prev, reg, results, time.Now(), commitID())
	rep.Gaps = gaps
	if err := SaveReport(rep, *reportJSON, *reportMD); err != nil {
		fail(err)
	}
	fmt.Println()
	WriteTable(os.Stdout, results)
	WriteFailures(os.Stdout, results)
	if !ok {
		os.Exit(1)
	}
}

// commitID is the checkout's short commit, with "-dirty" when the tree has
// uncommitted changes outside docs/conformance (the run's own output), or
// "unknown" outside git.
func commitID() string {
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	id := strings.TrimSpace(string(out))
	// The reports a run writes don't count: the run changes them itself.
	st, err := exec.Command("git", "status", "--porcelain", "--untracked-files=no", "--", ".", ":(top,exclude)docs/conformance").Output()
	if err == nil && len(strings.TrimSpace(string(st))) > 0 {
		id += "-dirty"
	}
	return id
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "conformance:", err)
	os.Exit(2)
}
