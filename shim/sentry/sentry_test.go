//go:build linux

package sentry_test

import (
	"bytes"
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/alatticeio/lattice-shim/shim/sentry"
)

func hasRunsc(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("runsc"); err != nil {
		t.Skip("runsc not installed, skipping sentry tests")
	}
}

func TestSentryStartEcho(t *testing.T) {
	hasRunsc(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var stdout bytes.Buffer
	proc, err := sentry.Start(ctx, sentry.Config{
		Args:   []string{"/bin/echo", "hello-sentry"},
		Stdout: &stdout,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	code, err := proc.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	if got := stdout.String(); got != "hello-sentry\n" {
		t.Errorf("expected 'hello-sentry\\n', got %q", got)
	}
}

func TestSentryStartExitCode(t *testing.T) {
	hasRunsc(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	proc, err := sentry.Start(ctx, sentry.Config{
		Args: []string{"/bin/sh", "-c", "exit 42"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	code, err := proc.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if code != 42 {
		t.Errorf("expected exit 42, got %d", code)
	}
}

func TestSentryKill(t *testing.T) {
	hasRunsc(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	proc, err := sentry.Start(ctx, sentry.Config{
		Args: []string{"/bin/sleep", "60"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := proc.Kill(); err != nil {
		t.Fatalf("Kill: %v", err)
	}

	code, err := proc.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if code == 0 {
		t.Error("expected non-zero exit after Kill")
	}
}
