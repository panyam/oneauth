package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeMake writes out[target] to the log and fails the targets in fail.
func fakeMake(out map[string]string, fail map[string]bool) func(context.Context, string, io.Writer) error {
	return func(_ context.Context, target string, w io.Writer) error {
		fmt.Fprint(w, out[target])
		if fail[target] {
			return errors.New("exit status 2")
		}
		return nil
	}
}

func registry() *Registry {
	return &Registry{Suites: []Suite{
		{Name: "native", Kind: KindGating, Covers: "x"},
		{Name: "oidf-basic-op", Kind: KindGating, Covers: "x", Needs: []string{"docker"}},
		{Name: "authlete", Kind: KindInfo, Covers: "x", Needs: []string{"env:AUTHLETE_CLIENTID"}},
	}}
}

func TestRun_AllPassing(t *testing.T) {
	r := &Runner{
		Make: fakeMake(map[string]string{
			"conf-native":        "ratchet OK — no diff against known-gaps.yaml\n",
			"conf-oidf-basic-op": "  PASSED  ...\n35 modules: map[PASSED:28 REVIEW:4], 0 against known-gaps.yaml\nplan: https://x\n",
		}, nil),
		Getenv: func(string) string { return "set" },
		Logs:   t.TempDir(),
	}
	results, ok := r.Run(registry(), "")
	require.True(t, ok)
	require.Len(t, results, 3)
	assert.Equal(t, ResultPass, results[0].Result)
	assert.Equal(t, "ratchet OK — no diff against known-gaps.yaml", results[0].Detail)
	assert.Equal(t, "35 modules: map[PASSED:28 REVIEW:4], 0 against known-gaps.yaml", results[1].Detail)
}

// A suite whose env prerequisite is unset is skipped with the reason, and
// its target never runs.
func TestRun_SkipsAMissingEnvPrerequisite(t *testing.T) {
	ran := map[string]bool{}
	r := &Runner{
		Make:   func(_ context.Context, target string, w io.Writer) error { ran[target] = true; return nil },
		Getenv: func(string) string { return "" },
		Logs:   t.TempDir(),
	}
	results, ok := r.Run(registry(), "authlete")
	require.True(t, ok)
	require.Len(t, results, 1)
	assert.Equal(t, ResultSkip, results[0].Result)
	assert.Contains(t, results[0].Detail, "AUTHLETE_CLIENTID is not set")
	assert.False(t, ran["conf-authlete"])
}

// A gating suite's failure fails the run; an info suite's doesn't.
func TestRun_OnlyGatingFailuresFailTheRun(t *testing.T) {
	env := func(string) string { return "set" }
	r := &Runner{Make: fakeMake(nil, map[string]bool{"conf-authlete": true}), Getenv: env, Logs: t.TempDir()}
	results, ok := r.Run(registry(), "")
	assert.True(t, ok, "an info suite failing leaves the run passing")
	assert.Equal(t, ResultFail, results[2].Result)

	r = &Runner{Make: fakeMake(map[string]string{"conf-oidf-basic-op": "35 modules: map[FAILED:1], 1 against known-gaps.yaml\n"}, map[string]bool{"conf-oidf-basic-op": true}), Getenv: env, Logs: t.TempDir()}
	results, ok = r.Run(registry(), "")
	assert.False(t, ok)
	assert.Equal(t, ResultFail, results[1].Result)
	assert.Equal(t, "35 modules: map[FAILED:1], 1 against known-gaps.yaml", results[1].Detail, "the summary line says why")
}

func TestRun_UnknownSuiteFilter(t *testing.T) {
	r := &Runner{Make: fakeMake(nil, nil), Getenv: func(string) string { return "" }, Logs: t.TempDir()}
	results, ok := r.Run(registry(), "nope")
	assert.False(t, ok)
	assert.Empty(t, results)
}

func TestTable_OneLinePerSuite(t *testing.T) {
	var buf bytes.Buffer
	WriteTable(&buf, []Result{
		{Suite: Suite{Name: "native", Kind: KindGating}, Result: ResultPass, Detail: "ratchet OK"},
		{Suite: Suite{Name: "authlete", Kind: KindInfo}, Result: ResultSkip, Detail: "AUTHLETE_CLIENTID is not set"},
	})
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Len(t, lines, 3, "a header and one line per suite")
	assert.Contains(t, lines[1], "native")
	assert.Contains(t, lines[1], "PASS")
	assert.Contains(t, lines[2], "SKIP")
}

// A suite that runs past its timeout is stopped and reported as failed,
// and the run goes on to the next suite. The timeout comes from the
// registry entry, or DefaultTimeout.
func TestRun_TimesOutAStuckSuite(t *testing.T) {
	reg := &Registry{Suites: []Suite{
		{Name: "stuck", Kind: KindGating, Covers: "x", Timeout: "50ms"},
		{Name: "after", Kind: KindGating, Covers: "x"},
	}}
	var sawDeadline time.Duration
	r := &Runner{
		Make: func(ctx context.Context, target string, w io.Writer) error {
			if target == "conf-after" {
				d, _ := ctx.Deadline()
				sawDeadline = time.Until(d)
				return nil
			}
			fmt.Fprintln(w, "waiting for a server that never answers")
			<-ctx.Done()
			return ctx.Err()
		},
		Getenv: func(string) string { return "" },
		Logs:   t.TempDir(),
	}
	start := time.Now()
	results, ok := r.Run(reg, "")
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.False(t, ok)
	require.Len(t, results, 2)
	assert.Equal(t, ResultFail, results[0].Result)
	assert.Equal(t, "timed out after 50ms", results[0].Detail)
	assert.Equal(t, ResultPass, results[1].Result, "the run continues after a timeout")
	assert.Greater(t, sawDeadline, DefaultTimeout-time.Minute, "an entry without a timeout gets the default")
}

func TestValidate_RejectsABadTimeout(t *testing.T) {
	reg := &Registry{Suites: []Suite{{Name: "a", Kind: KindGating, Covers: "x", Timeout: "soon"}}}
	assert.Contains(t, strings.Join(reg.Validate(), "\n"), `"a": timeout "soon" is not a duration`)
}

// The runner itself runs with GOWORK=off (it lives in its own module), but
// the suites build the server from this checkout through go.work, so the
// variable must not reach them.
func TestSuiteEnv_DropsGOWORK(t *testing.T) {
	env := suiteEnv([]string{"PATH=/bin", "GOWORK=off", "HOME=/h"})
	assert.Equal(t, []string{"PATH=/bin", "HOME=/h"}, env)
}

// A failed suite's log tail is printed under the table, so the reason is
// on screen without opening the log.
func TestWriteFailures_ShowsTheLogTail(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/x.log"
	var lines []string
	for i := 1; i <= 30; i++ {
		lines = append(lines, fmt.Sprintf("line %d", i))
	}
	require.NoError(t, os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644))
	var buf bytes.Buffer
	WriteFailures(&buf, []Result{
		{Suite: Suite{Name: "ok"}, Result: ResultPass, Log: logPath},
		{Suite: Suite{Name: "x"}, Result: ResultFail, Log: logPath},
	})
	out := buf.String()
	assert.Contains(t, out, "x")
	assert.Contains(t, out, "line 30")
	assert.Contains(t, out, "line 16")
	assert.NotContains(t, out, "line 15\n", "only the last 15 lines")
	assert.Equal(t, 1, strings.Count(out, "--- "), "passing suites print nothing")
}

// An OIDF suite's run record is read back from the results directory and
// attached to its result, and a stale record from an earlier run is not.
func TestRun_AttachesThePlanRecord(t *testing.T) {
	dir := t.TempDir()
	reg := &Registry{Suites: []Suite{{Name: "oidf-basic-op", Kind: KindGating, Covers: "x", Plan: "p"}}}
	stale := dir + "/p.json"
	require.NoError(t, os.WriteFile(stale, []byte(`{"plan":"p","against":9}`), 0o644))
	r := &Runner{
		Make: func(_ context.Context, _ string, _ io.Writer) error {
			return os.WriteFile(stale, []byte(`{"plan":"p","counts":{"PASSED":3},"against":0}`), 0o644)
		},
		Getenv:  func(string) string { return "" },
		Logs:    dir,
		Results: dir,
	}
	results, ok := r.Run(reg, "")
	require.True(t, ok)
	require.NotNil(t, results[0].Plan)
	assert.Equal(t, 3, results[0].Plan.Counts["PASSED"])

	r.Make = func(_ context.Context, _ string, _ io.Writer) error { return errors.New("died before writing") }
	results, _ = r.Run(reg, "")
	assert.Nil(t, results[0].Plan, "a record left by an earlier run is removed first")
}

const allSkippedLog = `=== RUN   TestAuthlete_OIDCDiscovery
    interop_test.go:55: Authlete AS discovery returned status 500 (run 'make upauthlete')
--- SKIP: TestAuthlete_OIDCDiscovery (0.07s)
=== RUN   TestAuthlete_RARRoundTrip
    interop_test.go:90: Authlete AS discovery returned status 500 (run 'make upauthlete')
--- SKIP: TestAuthlete_RARRoundTrip (0.06s)
PASS
ok  	github.com/panyam/oneauth/tests/authlete	0.512s
ok  	github.com/panyam/oneauth/tests/authlete/provisioner	(cached)
`

// A suite whose every test skipped proved nothing, so it is SKIP with the
// first skip's reason, not PASS. The Authlete suite did this when its
// server answered discovery with a 500.
func TestRun_EveryTestSkippedIsASkip(t *testing.T) {
	reg := &Registry{Suites: []Suite{{Name: "authlete", Kind: KindInfo, Covers: "x"}}}
	r := &Runner{Make: fakeMake(map[string]string{"conf-authlete": allSkippedLog}, nil), Getenv: func(string) string { return "set" }, Logs: t.TempDir()}
	results, ok := r.Run(reg, "")
	require.True(t, ok)
	assert.Equal(t, ResultSkip, results[0].Result)
	assert.Equal(t, "every test skipped: Authlete AS discovery returned status 500 (run 'make upauthlete')", results[0].Detail)
}

// A go test suite's summary counts its tests instead of quoting the last
// package line.
func TestSummaryLine_CountsGoTests(t *testing.T) {
	out := "--- PASS: TestA (0.01s)\n    --- PASS: TestA/sub (0.00s)\n--- SKIP: TestB (0.00s)\n--- PASS: TestC (0.02s)\nok  \tpkg/one\t0.1s\nok  \tpkg/two\t(cached)\n"
	assert.Equal(t, "go test: 2 passed, 1 skipped, 0 failed (top-level tests)", summaryLine(out))
	assert.Equal(t, "ok  \tpkg\t1.2s", summaryLine("ok  \tpkg\t1.2s\n"), "without -v there are no test lines, so the package line stands")
}
