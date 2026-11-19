package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tempMakefile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Makefile"), []byte(body), 0o644))
	return dir
}

// A suite that hangs is stopped at its timeout, and so is the background
// process it started, which is what kept the first `make conformance` run
// waiting forever.
func TestRunMake_TimeoutKillsTheWholeGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	dir := tempMakefile(t, "hang:\n\tsleep 300 & echo $$! > "+pidFile+"; sleep 300\n")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var out strings.Builder
	errc := make(chan error, 1)
	go func() { errc <- runMake(ctx, dir, "hang", &out) }()
	var err error
	select {
	case err = <-errc:
	case <-time.After(15 * time.Second):
		t.Fatal("runMake did not return after its timeout: a leftover child is holding it")
	}
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	raw, err := os.ReadFile(pidFile)
	require.NoError(t, err)
	pid := strings.TrimSpace(string(raw))
	require.Eventually(t, func() bool {
		_, statErr := os.Stat("/proc/" + pid)
		return processGone(pid) || os.IsNotExist(statErr)
	}, 5*time.Second, 50*time.Millisecond, "the background child %s survived the timeout", pid)
}

// The runner runs with GOWORK=off; the suites must not inherit it.
func TestRunMake_SuitesDoNotSeeGOWORK(t *testing.T) {
	t.Setenv("GOWORK", "off")
	dir := tempMakefile(t, "show:\n\t@echo \"gowork=[$$GOWORK]\"\n")
	var out strings.Builder
	require.NoError(t, runMake(context.Background(), dir, "show", &out))
	assert.Contains(t, out.String(), "gowork=[]")
}

func TestRunMake_ReportsAFailingTarget(t *testing.T) {
	dir := tempMakefile(t, "bad:\n\t@echo nope; exit 3\n")
	var out strings.Builder
	err := runMake(context.Background(), dir, "bad", &out)
	assert.Error(t, err)
	assert.Contains(t, out.String(), "nope")
}
