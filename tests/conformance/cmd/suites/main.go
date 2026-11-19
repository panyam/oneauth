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
	"strings"
)

func main() {
	registry := flag.String("registry", "../../conformance/suites.yaml", "path to suites.yaml")
	makeDir := flag.String("make-dir", "../../conformance", "directory holding the conf-* targets")
	logs := flag.String("logs", "../../test-reports/conformance", "directory for per-suite logs")
	only := flag.String("suite", "", "run only this suite")
	flag.Parse()

	reg, err := LoadRegistry(*registry)
	if err != nil {
		fail(err)
	}
	if problems := reg.Validate(); len(problems) > 0 {
		fail(fmt.Errorf("conformance/suites.yaml:\n  %s", strings.Join(problems, "\n  ")))
	}

	r := &Runner{
		Make: func(ctx context.Context, target string, w io.Writer) error {
			fmt.Fprintf(os.Stderr, "=== %s (log: %s)\n", target, *logs)
			return runMake(ctx, *makeDir, target, w)
		},
		Getenv: os.Getenv,
		Logs:   *logs,
	}
	results, ok := r.Run(reg, *only)
	if *only != "" && len(results) == 0 {
		fail(fmt.Errorf("no suite named %q in %s", *only, *registry))
	}
	fmt.Println()
	WriteTable(os.Stdout, results)
	WriteFailures(os.Stdout, results)
	if !ok {
		os.Exit(1)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "conformance:", err)
	os.Exit(2)
}
