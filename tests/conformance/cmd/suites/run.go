package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"
)

// Results of one suite.
const (
	ResultPass = "PASS"
	ResultFail = "FAIL"
	ResultSkip = "SKIP"
	// ResultNotRun marks a registered suite the report has no run for.
	ResultNotRun = "not run"
	// ResultManual is a manual suite's result in the report: it shows the
	// run recorded in its suites.yaml entry.
	ResultManual = "manual"
)

// Result is one suite's outcome. Detail is the suite's own summary line
// when its output has one, so the table says why without opening the log.
type Result struct {
	Suite  Suite
	Result string
	Detail string
	Log    string
	// Plan is an OIDF suite's run record, nil for other suites or when
	// the exercise didn't write one.
	Plan *PlanRecord
}

// Runner runs registered suites. Make runs a conformance/Makefile target
// with its output going to w, and must stop when ctx is done, which is how
// a suite's timeout ends it; Getenv reads prerequisites; Logs is the
// directory each suite's log is written to.
type Runner struct {
	Make   func(ctx context.Context, target string, w io.Writer) error
	Getenv func(string) string
	Logs   string
	// Results is the directory OIDF exercises write their run records to
	// (CONFORMANCE_RESULTS_DIR). Empty skips reading them.
	Results string
}

// Run runs every suite, or only the one named by only, in registry order.
// ok is false when a gating suite failed, or when only names no suite.
func (r *Runner) Run(reg *Registry, only string) (results []Result, ok bool) {
	ok = true
	matched := false
	for _, s := range reg.Suites {
		if only != "" && s.Name != only {
			continue
		}
		matched = true
		if s.Kind == KindManual {
			continue // run by a person; Merge reports its recorded run
		}
		res := r.runOne(s)
		if res.Result == ResultFail && s.Kind == KindGating {
			ok = false
		}
		results = append(results, res)
	}
	if !matched {
		return nil, false
	}
	return results, ok
}

func (r *Runner) runOne(s Suite) Result {
	if v := s.MissingEnv(r.Getenv); v != "" {
		return Result{Suite: s, Result: ResultSkip, Detail: v + " is not set"}
	}
	if err := os.MkdirAll(r.Logs, 0o755); err != nil {
		return Result{Suite: s, Result: ResultFail, Detail: err.Error()}
	}
	logPath := filepath.Join(r.Logs, s.Name+".log")
	f, err := os.Create(logPath)
	if err != nil {
		return Result{Suite: s, Result: ResultFail, Detail: err.Error()}
	}
	recordPath := ""
	if s.Plan != "" && r.Results != "" {
		recordPath = filepath.Join(r.Results, s.Plan+".json")
		_ = os.Remove(recordPath)
	}
	var out strings.Builder
	ctx, cancel := context.WithTimeout(context.Background(), s.RunTimeout())
	defer cancel()
	runErr := r.Make(ctx, s.Target(), io.MultiWriter(f, &out))
	f.Close()
	res := Result{Suite: s, Result: ResultPass, Detail: summaryLine(out.String()), Log: logPath}
	// A suite whose every test skipped proved nothing: report why, as a
	// skip, rather than a pass.
	if c := countGoTests(out.String()); runErr == nil && c.total() > 0 && c.skipped == c.total() {
		res.Result, res.Detail = ResultSkip, "every test skipped: "+c.firstSkip
	}
	if recordPath != "" {
		res.Plan = readPlanRecord(recordPath)
	}
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		res.Result = ResultFail
		res.Detail = "timed out after " + s.RunTimeout().String()
	case runErr != nil:
		res.Result = ResultFail
		if res.Detail == "" {
			res.Detail = runErr.Error()
		}
	}
	return res
}

// suiteEnv is env without GOWORK. The runner runs with GOWORK=off, since
// it lives in its own module, but the suites build oneauth-server from
// this checkout through go.work; with GOWORK=off they would build it
// against the last tagged release, or fail to find it at all.
func suiteEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if !strings.HasPrefix(kv, "GOWORK=") {
			out = append(out, kv)
		}
	}
	return out
}

// logTailLines is how much of a failed suite's log WriteFailures shows.
const logTailLines = 15

// WriteFailures writes the last lines of each failed suite's log, so the
// reason is on screen without opening the file.
func WriteFailures(w io.Writer, results []Result) {
	for _, r := range results {
		if r.Result != ResultFail || r.Log == "" {
			continue
		}
		raw, err := os.ReadFile(r.Log)
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
		if len(lines) > logTailLines {
			lines = lines[len(lines)-logTailLines:]
		}
		fmt.Fprintf(w, "\n--- %s failed; last lines of %s:\n%s\n", r.Suite.Name, r.Log, strings.Join(lines, "\n"))
	}
}

// summaryPatterns are the summary lines the registered suites print: the
// OIDF exercise's per-plan total, the native ratchet's verdict, and, for
// go test without -v, its package result.
var summaryPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\d+ modules: map\[[^\]]*\], \d+ against known-gaps\.yaml`),
	regexp.MustCompile(`ratchet OK.*`),
	regexp.MustCompile(`(?m)^(ok|FAIL)\s+\S+.*$`),
}

// summaryLine returns the suite's summary: the OIDF total or the ratchet
// verdict when present, else the count of go test's top-level tests when
// it ran with -v, else the last package line, or "".
func summaryLine(out string) string {
	for _, p := range summaryPatterns[:2] {
		if all := p.FindAllString(out, -1); len(all) > 0 {
			return strings.TrimSpace(all[len(all)-1])
		}
	}
	if c := countGoTests(out); c.total() > 0 {
		return fmt.Sprintf("go test: %d passed, %d skipped, %d failed (top-level tests)", c.passed, c.skipped, c.failed)
	}
	if all := summaryPatterns[2].FindAllString(out, -1); len(all) > 0 {
		return strings.TrimSpace(all[len(all)-1])
	}
	return ""
}

// goTestCounts are go test -v's top-level results. Subtests are indented
// and not counted.
type goTestCounts struct {
	passed, skipped, failed int
	firstSkip               string
}

func (c goTestCounts) total() int { return c.passed + c.skipped + c.failed }

var goTestLine = regexp.MustCompile(`^--- (PASS|SKIP|FAIL): `)

// countGoTests counts go test -v's top-level result lines in out, and
// keeps the first skip's reason: the indented line that precedes it.
func countGoTests(out string) goTestCounts {
	var c goTestCounts
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		m := goTestLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		switch m[1] {
		case "PASS":
			c.passed++
		case "FAIL":
			c.failed++
		case "SKIP":
			c.skipped++
			if c.firstSkip == "" && i > 0 {
				reason := strings.TrimSpace(lines[i-1])
				if j := strings.Index(reason, ": "); j >= 0 && strings.Contains(reason[:j], ".go:") {
					reason = reason[j+2:]
				}
				c.firstSkip = reason
			}
		}
	}
	return c
}

// WriteTable writes a header and one line per result.
func WriteTable(w io.Writer, results []Result) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SUITE\tKIND\tRESULT\tDETAIL")
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Suite.Name, r.Suite.Kind, r.Result, r.Detail)
	}
	tw.Flush()
}
