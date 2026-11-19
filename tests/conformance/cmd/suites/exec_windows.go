package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"time"
)

// runMake on Windows kills only the make process on timeout: there are no
// process groups to signal. The suites' Docker and shell targets are Unix
// only today, so this keeps the module building rather than claiming the
// same cleanup as exec_unix.go.
func runMake(ctx context.Context, dir, target string, w io.Writer, extraEnv ...string) error {
	cmd := exec.CommandContext(ctx, "make", "-C", dir, target)
	cmd.Stdout, cmd.Stderr = w, w
	cmd.Env = append(suiteEnv(os.Environ()), extraEnv...)
	cmd.WaitDelay = 10 * time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
