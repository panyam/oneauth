//go:build !windows

package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// runMake runs `make -C dir target` in its own process group, with GOWORK
// removed from its environment (suiteEnv) and extraEnv added. When ctx is done it kills the
// whole group, so a suite's background servers and containers' clients
// don't outlive its timeout, and waits up to five seconds for the output
// to drain.
func runMake(ctx context.Context, dir, target string, w io.Writer, extraEnv ...string) error {
	cmd := exec.Command("make", "-C", dir, target)
	cmd.Stdout, cmd.Stderr = w, w
	cmd.Env = append(suiteEnv(os.Environ()), extraEnv...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// A child that escapes the group kill and keeps the output pipe open
	// can't hold Wait past this.
	cmd.WaitDelay = 10 * time.Second
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
		return ctx.Err()
	}
}
