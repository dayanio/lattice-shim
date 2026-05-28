//go:build linux

// Copyright 2026 The Lattice Authors, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package sentry provides process sandboxing via gVisor runsc.
// Sentry intercepts all child syscalls (file, process, memory) via ptrace.
// Network uses --network=host so the caller's iptables + tproxy can
// intercept and route traffic through the WireGuard overlay.
//
// Requires runsc (gVisor) to be installed on the host system, or the
// caller to set the RUNSC_PATH environment variable.
package sentry

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// Config describes the sandboxed process to launch.
type Config struct {
	// Args is the command to execute (e.g. ["python", "agent.py"]).
	Args []string
	// Env is environment variables. nil = inherit parent's env.
	Env []string
	// WorkDir is the working directory. "" = inherit parent's cwd.
	WorkDir string
	// Stdout is the writer for the child's stdout. nil = os.Stdout.
	Stdout io.Writer
	// Stderr is the writer for the child's stderr. nil = os.Stderr.
	Stderr io.Writer
	// Stdin is the reader for the child's stdin. nil = os.Stdin.
	Stdin io.Reader
	// RunscPath overrides the runsc binary path. "" = auto-detect.
	RunscPath string
}

// Process represents a running runsc-sandboxed child process.
type Process struct {
	cmd *exec.Cmd
}

// Start launches a child process under gVisor Sentry via runsc do.
// Sentry intercepts all syscalls, providing full isolation.
func Start(ctx context.Context, cfg Config) (*Process, error) {
	if len(cfg.Args) == 0 {
		return nil, fmt.Errorf("sentry: no command to run")
	}

	runscPath := cfg.RunscPath
	if runscPath == "" {
		runscPath = os.Getenv("RUNSC_PATH")
	}
	if runscPath == "" {
		var err error
		runscPath, err = exec.LookPath("runsc")
		if err != nil {
			return nil, fmt.Errorf("sentry: runsc not found in PATH (install gVisor or set RUNSC_PATH): %w", err)
		}
	}

	// runsc --network=host do <cmd> [args...]
	args := []string{"--network=host", "do"}
	args = append(args, cfg.Args...)

	cmd := exec.CommandContext(ctx, runscPath, args...)
	cmd.Stdout = cfg.Stdout
	cmd.Stderr = cfg.Stderr
	cmd.Stdin = cfg.Stdin
	cmd.Env = cfg.Env
	cmd.Dir = cfg.WorkDir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("sentry: runsc start: %w", err)
	}

	return &Process{cmd: cmd}, nil
}

// Wait blocks until the process exits and returns its exit code.
func (p *Process) Wait() (int, error) {
	if p.cmd.Process == nil {
		return -1, fmt.Errorf("sentry: process not started")
	}
	err := p.cmd.Wait()
	if err == nil {
		return 0, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), nil
	}
	return -1, err
}

// Kill forcefully terminates the sandboxed process.
func (p *Process) Kill() error {
	if p.cmd.Process == nil {
		return nil
	}
	return p.cmd.Process.Signal(syscall.SIGKILL)
}

// Signal sends a signal to the sandboxed process.
func (p *Process) Signal(sig syscall.Signal) error {
	if p.cmd.Process == nil {
		return nil
	}
	return p.cmd.Process.Signal(sig)
}

// SignalForward forwards incoming signals (SIGINT, SIGTERM) to the
// sandboxed process. Call as a goroutine after Start.
func SignalForward(ctx context.Context, proc *Process) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case sig := <-sigCh:
		_ = proc.Signal(sig.(syscall.Signal))
	case <-ctx.Done():
	}
}
