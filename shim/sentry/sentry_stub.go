//go:build !linux

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

package sentry

import (
	"context"
	"fmt"
)

// Config describes the sandboxed process to launch.
type Config struct {
	Args      []string
	Env       []string
	WorkDir   string
	RunscPath string
}

// Process represents a running sandboxed child process.
type Process struct{}

// Start returns an error on non-Linux platforms — Sentry requires ptrace.
func Start(ctx context.Context, cfg Config) (*Process, error) {
	return nil, fmt.Errorf("sentry: process sandboxing requires Linux (ptrace)")
}

// Wait returns an error.
func (p *Process) Wait() (int, error) {
	return -1, fmt.Errorf("sentry: not supported on this platform")
}

// Kill is a no-op.
func (p *Process) Kill() error { return nil }

// Signal is a no-op.
func (p *Process) Signal(_ any) error { return nil }
