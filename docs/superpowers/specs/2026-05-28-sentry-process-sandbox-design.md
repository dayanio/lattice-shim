# Sentry-Backed Process Sandbox Design

**Date**: 2026-05-28
**Status**: Approved
**Repos**: lattice-shim, lattice

## Background

The current `sandbox run` implementation uses kernel WireGuard (`/dev/net/tun`)
and requires `--runtime=runsc` for full syscall isolation. Without runsc, the
AI agent has no syscall sandbox — only network redirection via iptables +
embedded netstack.

gVisor's Sentry is written in Go and can be imported as a library. By wrapping
Sentry directly in `lattice-shim`, we achieve:

- **Single binary** with zero external dependencies (no runsc install required)
- **Full syscall isolation**: file, process, memory syscalls intercepted by Sentry
- **Built-in netstack integration**: Sentry's TCP/IP stack is replaced with our
  WireGuard-attached netstack, so no iptables/tproxy/REDIRECT needed
- **Works in plain Docker**: `docker run ... sandbox run` — no extra flags

## Architecture

```
lattice-shim/shim/sentry/              lattice CLI

  Config{                                  sandbox run
    Args    []string       1. 注册 NATS
    WorkDir string         2. 启动 WireGuard node (gVisor netstack + CustomTUN)
    Network *stack.Stack   3. sentry.Start(ctx, cfg)
  }                              ↓
  ↓                    ┌───────────────────────┐
  sentry.Start()       │  Sentry (ptrace)       │
        ↓              │  ┌─────────────────┐   │
  ┌──────────────┐     │  │ syscall 拦截      │   │
  │ runsc/boot    │     │  │ • open/read/write│   │
  │ pkg/sentry    │────▶│  │ • connect/accept │   │
  │ ptrace        │     │  │ • fork/exec/kill │   │
  └──────────────┘     │  └────────┬────────┘   │
                       │           │             │
                       │  ┌────────▼────────┐   │
                       │  │ TCP/IP 栈        │   │
                       │  │ (*stack.Stack)   │   │
                       │  │ WireGuard TUN    │   │
                       │  └────────┬────────┘   │
                       │           │             │
                       │    WireGuard UDP        │
                       │    (唯一出去的外网流量)   │
                       └───────────────────────┘
```

Key: AI agent 的所有 syscall 被 Sentry 拦截，网络 syscall 走我们注入的
`*stack.Stack`（已对接 WireGuard），文件 syscall Sentinel 检查后透传 host。

### Why lattice-shim?

| 好处 | 说明 |
|------|------|
| **依赖隔离** | gVisor 的复杂依赖树只污染 `lattice-shim/go.mod` |
| **已有基础** | lattice-shim 已经 depend on `gvisor.dev/gvisor`（netstack 层） |
| **独立演进** | gVisor 版本升级只影响 lattice-shim |
| **编译隔离** | lattice 主仓库秒编，不受 gVisor 编译时间影响 |

## API Design

```go
// lattice-shim/shim/sentry/sentry.go

package sentry

// Config describes the sandboxed process to launch.
type Config struct {
    // Args is the command to execute (e.g. ["python", "agent.py"]).
    Args []string
    // Env is environment variables.
    Env []string
    // WorkDir is the working directory for the process.
    WorkDir string
    // Network is the injected network stack. nil = no networking.
    // Callers typically inject a gVisor *stack.Stack with WireGuard
    // channel endpoint attached.
    Network *stack.Stack
    // FileAccess controls filesystem access. nil = inherit container fs.
    FileAccess *FileAccess
}

// FileAccess describes filesystem permissions for the sandboxed process.
// Phase 1: nil (no restrictions).
// Phase 2: per-path read-only / writable lists.
type FileAccess struct {
    ReadOnly []string
    Writable []string
}

// Process represents a running Sentry-sandboxed child process.
type Process struct { ... }

// Start launches a child process wrapped in gVisor Sentry via ptrace.
// Sentry intercepts all syscalls. The caller injects *stack.Stack to
// control network routing (e.g. WireGuard overlay via channel endpoint).
func Start(ctx context.Context, cfg Config) (*Process, error)

// Wait blocks until the process exits and returns its exit code.
func (p *Process) Wait() (int, error)

// Kill forcefully terminates the sandboxed process.
func (p *Process) Kill() error
```

## Sentry Startup Flow

```
sentry.Start(ctx, cfg)
     │
     ▼
1. Build boot.Config
   • Network:    "custom"         (use injected *stack.Stack)
   • Platform:   "ptrace"         (no hardware virt needed)
   • FileAccess: cfg.FileAccess   (nil = container fs)
   • Args/Env/WorkDir
     │
     ▼
2. boot.Loader.Create(cfg)
   • Create sentry kernel
   • Register injected *stack.Stack replacing default network stack
   • Prepare ptrace subreaper
     │
     ▼
3. loader.Start()
   • Fork child process
   • Ptrace attach
   • Sentry begins intercepting all syscalls
     │
     ▼
4. loader.Wait()
   • Block until child exits
   • Return exit code (or signal)
```

## Caller Usage (lattice `sandbox run`)

```go
// 1. Register with control plane
currentPeer, err := registerOrResume(ctx, name, serverURL, token)

// 2. Create gVisor netstack + WireGuard TUN adapter (same as sidecar)
sb, err := gvisor.New(gvisor.Config{ID: name, LocalIP: localIP})
tunDev := gvisor.NewTUNAdapter(sb.Channel(), gvisor.InjectIntoChannel(sb.Channel()))

nodeCfg := &latticeagent.NodeConfig{
    Port:      0,
    CustomTUN: tunDev,
    // ... same as current sidecar
}
node.Start(ctx)
go node.StartHeartbeat(ctx)

// 3. Fork AI agent under Sentry — one call, no iptables, no tproxy, no UID tricks
proc, err := sentry.Start(ctx, sentry.Config{
    Args:    cmdArgs,
    Env:     os.Environ(),
    Network: sb.Netstack().Stack(),
})
code, _ := proc.Wait()
os.Exit(code)
```

What is **removed** from `sandbox run`:
- `installRunIPTables()` — no iptables REDIRECT needed
- `tproxy.Proxy` — no transparent proxy needed
- `sandboxAgentUID` / `SysProcAttr.Credential` — no UID tricks needed
- `--cap-add NET_ADMIN` — no capabilities needed

## Three Isolation Layers

The complete sandbox provides isolation at three levels, all orthogonal:

| Layer | Mechanism | What it isolates | Requirement |
|-------|-----------|-----------------|-------------|
| **Network** | WireGuard-attached netstack | AI agent traffic stays on overlay | None (built-in) |
| **Syscall** | Sentry ptrace | File, process, memory syscalls | None (built-in) |
| **Resource** | Docker/cgroup/K8s | CPU, memory, pid limits | Runtime choice |

The user can layer Docker `--runtime=runsc` on top for defense-in-depth
(double syscall layer: runsc's Sentry + our embedded Sentry), but this
provides no additional benefit — our Sentry already intercepts everything.

## File Access (Phased)

| Phase | Behavior |
|-------|----------|
| **Phase 1** (this spec) | `FileAccess = nil` — Sentry passes all file syscalls to host kernel. AI agent sees the container filesystem as-is. |
| **Phase 2** (future) | `FileAccess{ReadOnly: [...], Writable: [...]}` — Sentry checks each `open()` against path lists, rejects unauthorized paths. |
| **Phase 3** (future) | Gofer mode — 9P proxy between Sentry and host filesystem (full production isolation). |

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Ptrace unavailable (non-Linux, kernel < 5.4) | `Start()` returns error |
| Child process exit(1) | `Wait()` returns exit code 1 |
| Sentry internal panic | Child killed, `Wait()` returns error |
| ctx cancelled | Child killed, returns `ctx.Err()` |
| AI agent OOM | Sentry detects, `Wait()` returns signal 9 |

## Platform & Build

| File | Build tag | Description |
|------|-----------|-------------|
| `sentry/sentry.go` | `//go:build linux` | Main implementation using `runsc/boot` |
| `sentry/sentry_stub.go` | `//go:build !linux` | `Start()` returns "not supported" error |

## Impact Summary

| Component | Change |
|-----------|--------|
| `lattice-shim/shim/sentry/` | **New** package, wraps Sentry (~200 lines) |
| `lattice cmd/sandbox/run_community.go` | Simplify: remove iptables/tproxy/UID code, call `sentry.Start` |
| `lattice cmd/sandbox/run_pro.go` | Same simplification + egress policy via gVisor PolicyChecker |
| `lattice cmd/sandbox/shared_linux.go` | Remove `installRunIPTables`, `sandboxAgentUID`; keep `registerOrResume`, `forkAndWait` → `sentry.Start` wrapper |
| `lattice frontend SandboxDemoModal.vue` | `docker run ... sandbox run` — no `--runtime=runsc`, no `--cap-add NET_ADMIN` |
| User-facing command | `docker run ghcr.io/alatticeio/lattice sandbox run <name> -- <cmd>` — zero extra flags |
