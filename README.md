# lattice-shim

Zero-privilege user-space TCP/IP network stack backed by **gVisor**, with
optional **wireguard-go** attachment and pluggable **policy** and **audit** hooks.

This library has **no dependency** on Lattice CRDs, NATS, or any Lattice
control-plane components — it can be used in any project that needs a
user-space TCP/IP stack.

---

## How this avoids TUN devices

A standard WireGuard setup requires a **TUN device** — a virtual network
interface created by the kernel via `ioctl SIOCSIFFLAGS`, which needs
`CAP_NET_ADMIN` (typically root).

```
Standard approach (needs root):
  wireguard-go ──bind──▶ wf0 TUN device (kernel)
                          ├─ ioctl SIOCSIFFLAGS  ← needs CAP_NET_ADMIN
                          ├─ eBPF TC hook        ← needs CAP_BPF
                          └─ kernel TCP/IP stack

lattice-shim approach (zero privilege):
  wireguard-go ──bind──▶ gVisor netstack link endpoint (pure Go)
                          ├─ user-space TCP/IP   ← no kernel involvement
                          ├─ Go hooks            ← no eBPF needed
                          └─ Go audit callbacks  ← no ring buffer needed
```

**Key insight:** gVisor provides a complete, production-grade TCP/IP stack
implemented entirely in Go. By attaching wireguard-go directly to a gVisor
`channel.Endpoint` (a pure-Go link-layer endpoint), the entire data path
runs in user space: no TUN device, no `CAP_NET_ADMIN`, no root.

### Comparison

| Capability | Kernel TUN | lattice-shim (gVisor) |
|---|---|---|
| wireguard-go crypto | user space | user space (same) |
| TCP/IP stack | kernel | gVisor Go netstack |
| Policy enforcement | eBPF TC hook | Go BeforeDial hook |
| TUN device creation | `ioctl SIOCSIFFLAGS` | **not needed** |
| Privilege needed | `CAP_NET_ADMIN`, `CAP_BPF` | **none** |
| Start command | `sudo ...` | runs as normal user |

---

## Architecture

The library has two layers:

**`Netstack`** — a user-space TCP/IP stack. Callers inject optional
**BeforeDial** / **AfterDial** hooks for policy checking, audit writing,
rate limiting, or metrics.

**`Sandbox`** — the top-level compositor. Wires together a `Netstack`,
`Socks5Server` (workload outbound proxy), `ForwardListener` (inbound relay),
and an optional `PeerManager` (WireGuard peer lifecycle). The caller injects
concrete implementations of `PolicyChecker`, `AuditWriter`, and `PeerManager`.

```
┌──────────────────────────────────────────────────────────┐
│  Sandbox                                                 │
│                                                          │
│  ┌─────────────────┐   ┌──────────────────────────────┐  │
│  │  Socks5Server   │   │  ForwardListener             │  │
│  │  outbound proxy │   │  overlay → workload inbound  │  │
│  └────────┬────────┘   └──────────────┬───────────────┘  │
│           │                           │                  │
│           ▼                           ▼                  │
│  ┌──────────────────────────────────────────────────┐    │
│  │  Netstack  (gVisor user-space TCP/IP)            │    │
│  │  BeforeDial → PolicyChecker.Allow(...)           │    │
│  │  AfterDial  → AuditWriter.Write(...)             │    │
│  └──────────────────────────────────────────────────┘    │
│                                                          │
│  PeerManager (injected) — AddPeer / RemovePeer           │
└──────────────────────────────────────────────────────────┘
```

### Package layout

```
shim/
├── shim.go            Sandbox compositor — New / Start / Close / AddPeer
├── server.go          Server — tsnet-style embeddable node: Dial / Listen / AddPeer
├── netstack_core.go   Netstack struct — user-space TCP/IP
├── netstack.go        NetstackOption + With* functions
├── forward.go         ForwardListener — overlay inbound relay
├── egress.go          EgressFilter — CIDR allowlist, implements PolicyChecker
├── policy.go          PolicyChecker interface
├── audit.go           AuditWriter interface + AuditEvent struct
├── wireguard.go       WireGuardEndpoint / WireGuardBind / PeerManager interfaces
└── internal/test/     Mock implementations for testing
```

**`Server`** — a tsnet-style alternative to `Sandbox` for callers that want
to embed overlay connectivity directly, without a local SOCKS5 proxy or
port-forward relay. `Server` exposes `Dial` and `Listen` as ordinary
`net.Conn`/`net.Listener` values backed by the netstack; the caller decides
what to do with each connection instead of the shim relaying it somewhere.
Use `Server` when the host process itself is the thing that should
dial/accept overlay connections (e.g. an app embedding overlay connectivity
without a kernel TUN device); use `Sandbox` when you need a local
SOCKS5/forward relay in front of a workload process you don't control.

```go
srv, _ := shim.NewServer("10.50.0.1", &WgAdapter{dev: wgDevice})
srv.AddPeer(peerPubKey, allowedIPs, "1.2.3.4:51820")

conn, _ := srv.Dial(ctx, "tcp", "10.50.0.2:8080")

ln, _ := srv.Listen("tcp", "10.50.0.1:8080")
for {
    conn, _ := ln.Accept()
    go handle(conn)
}
```

---

## Interfaces

### PolicyChecker

```go
type PolicyChecker interface {
    Allow(identity string, dstIP net.IP, dstPort uint16) bool
}
```

Called before every outbound connection (via `WithPolicy`). Return `false`
to deny. If no policy is set, all connections are allowed.

### AuditWriter

```go
type AuditWriter interface {
    Write(event AuditEvent) error
}

type AuditEvent struct {
    Identity string `json:"identity"`
    SrcIP    string `json:"src_ip"`
    DstIP    string `json:"dst_ip"`
    DstPort  uint16 `json:"dst_port"`
    Protocol string `json:"protocol"`
    Verdict  string `json:"verdict"` // "allow" | "drop"
}
```

Receives every allow/drop decision (via `WithAudit`). Your implementation
might batch events and POST them to a control plane, write to a local log,
or feed an alerting pipeline.

### PeerManager

```go
type PeerManager interface {
    AddPeer(pubKey [32]byte, allowedIPs []net.IPNet, endpoint string) error
    RemovePeer(pubKey [32]byte) error
    SetPrivateKey(key [32]byte) error
}
```

Manages WireGuard peers. The implementation (typically a wireguard-go device
wrapper) is injected by the caller. The shim itself does not import
wireguard-go, keeping the dependency boundary clean. The caller's
`WireGuardManager` subscribes to topology changes (e.g. via NATS) and calls
`sb.AddPeer` / `sb.RemovePeer` in response.

### WireGuardBind

```go
type WireGuardBind interface {
    Write(packet []byte) error
    Read() ([]byte, error)
    Close() error
}
```

Minimal packet I/O interface that bridges gVisor's link endpoint to
wireguard-go's device bind.

---

## Usage

### 1. Install

```bash
go get github.com/alatticeio/lattice-shim
```

### 2. Full Sandbox (recommended)

The `Sandbox` is the primary entry point. It wires everything together:

```go
package main

import (
    "context"
    "net"

    "github.com/alatticeio/lattice-shim/shim"
)

func main() {
    sb, err := shim.New("10.100.0.1",
        // Netstack options: identity, policy, audit.
        shim.WithNetstack(
            shim.WithIdentity("sandbox:agent-1"),
            shim.WithPolicy(myPolicy),   // implements shim.PolicyChecker
            shim.WithAudit(myAudit),     // implements shim.AuditWriter
        ),
        // Workload outbound proxy — set ALL_PROXY=socks5://127.0.0.1:1080.
        shim.WithSOCKS5("127.0.0.1:1080"),
        // Inbound relay: overlay :8080 → workload local :8080.
        shim.WithForwardRule(8080, "127.0.0.1:8080"),
        // WireGuard peer manager (wireguard-go device wrapper from caller).
        shim.WithPeerManager(myWgDevice),
    )
    if err != nil {
        panic(err)
    }
    defer sb.Close()

    ctx := context.Background()
    if err := sb.Start(ctx); err != nil {
        panic(err)
    }

    // Caller's WireGuardManager subscribes to NATS / topology changes
    // and calls sb.AddPeer / sb.RemovePeer accordingly.
    var pubKey [32]byte
    copy(pubKey[:], peerPublicKey)
    _, subnet, _ := net.ParseCIDR("10.100.0.2/32")
    sb.AddPeer(pubKey, []net.IPNet{*subnet}, "203.0.113.1:51820")

    // Workload subprocess sets ALL_PROXY=socks5://127.0.0.1:1080 and runs
    // normally — all outbound traffic routes through the Sandbox netstack,
    // through PolicyChecker, and out via wireguard-go.
    select {}
}
```

### 3. Netstack only (lower-level)

```go
ns, err := shim.NewNetstack("10.100.0.1",
    shim.WithIdentity("my-service/instance-3"),
    shim.WithPolicy(myPolicy),
    shim.WithAudit(myAudit),
)
if err != nil {
    panic(err)
}
defer ns.Close()

// Dial through the user-space stack.
conn, err := ns.DialContext(context.Background(), "tcp", "10.200.0.5:443")
// conn is a standard net.Conn.

// Listen on the overlay IP (for inbound connections).
ln, err := ns.ListenTCP("10.100.0.1:8080")
```

### 4. EgressFilter — built-in CIDR allowlist

`EgressFilter` implements `PolicyChecker` with atomic hot-reload:

```go
filter := shim.NewEgressFilter(shim.EgressPolicy{
    DefaultDeny:  true,
    AllowedCIDRs: []net.IPNet{overlaySubnet},
})

sb, _ := shim.New("10.100.0.1",
    shim.WithNetstack(shim.WithPolicy(filter)),
    shim.WithSOCKS5("127.0.0.1:1080"),
)

// Hot-reload policy without restart (e.g. after receiving a NATS update).
filter.Update(shim.EgressPolicy{
    DefaultDeny:  true,
    AllowedCIDRs: []net.IPNet{overlaySubnet, apiSubnet},
})
```

### 5. With WireGuard integration

```go
ns, _ := shim.NewNetstack("10.100.0.1",
    shim.WithIdentity("sandbox:agent-1"),
    shim.WithPolicy(myPolicy),
    shim.WithAudit(myAudit),
)
defer ns.Close()

// Attach wireguard-go to the netstack channel endpoint:
ep := &shim.WireGuardEndpoint{
    Outbound: func(packet []byte) error {
        // Encrypted WG packet → raw UDP socket to peer.
        return wgSocket.Write(packet)
    },
    Inbound: func(packet []byte) error {
        // Decrypted packet from WG → inject into gVisor netstack.
        ns.Channel().InjectInbound(header.IPv4ProtocolNumber, packetBuf)
        return nil
    },
    Close: func() error {
        return wgSocket.Close()
    },
}
// Ready: traffic from ns.DialContext() goes through:
//   gVisor TCP/IP → channel → wireguard-go encrypt → UDP socket → peer
```

---

## Communication paths

### Outbound (workload → overlay peer)

```
Workload subprocess
  ALL_PROXY=socks5://127.0.0.1:1080
  └─▶ Socks5Server
        └─▶ EgressFilter.Allow(identity, dstIP, dstPort)
              ├─ deny  → EPERM + AuditWriter.Write(drop)
              └─ allow → AuditWriter.Write(allow)
                          └─▶ Netstack (gVisor TCP/IP)
                                └─▶ wireguard-go encrypt → UDP → peer
```

### Inbound (overlay peer → workload)

```
Remote peer → UDP → wireguard-go decrypt
  └─▶ Netstack (gVisor TCP/IP)
        └─▶ ForwardListener.ListenTCP(overlayIP:port)
              └─▶ dial(targetAddr) → Workload local service
```

Policy checks are performed on the **outbound side only**. The
`ForwardListener` does not re-check policy — the originating sandbox already
enforced it.

---

## API Reference

### Sandbox

```go
func New(overlayIP string, opts ...Option) (*Sandbox, error)
func (s *Sandbox) Start(ctx context.Context) error
func (s *Sandbox) Close() error
func (s *Sandbox) Netstack() *Netstack
func (s *Sandbox) Socks5Addr() string

// PeerManager delegation — returns error if no PeerManager configured.
func (s *Sandbox) AddPeer(pubKey [32]byte, allowedIPs []net.IPNet, endpoint string) error
func (s *Sandbox) RemovePeer(pubKey [32]byte) error
func (s *Sandbox) SetPrivateKey(key [32]byte) error
```

### Sandbox options

```go
func WithNetstack(opts ...NetstackOption) Option  // forwards to Netstack
func WithSOCKS5(addr string) Option               // e.g. "127.0.0.1:1080"
func WithForwardRule(overlayPort uint16, targetAddr string) Option
func WithPeerManager(pm PeerManager) Option
```

### Netstack

```go
func NewNetstack(localIP string, opts ...NetstackOption) (*Netstack, error)
func (ns *Netstack) DialContext(ctx context.Context, network, addr string) (net.Conn, error)
func (ns *Netstack) ListenTCP(addr string) (net.Listener, error)
func (ns *Netstack) Channel() *channel.Endpoint
func (ns *Netstack) Stack() *stack.Stack
func (ns *Netstack) Close() error
```

### Netstack options

```go
func WithIdentity(id string) NetstackOption
func WithBeforeDial(fn func(identity, network, addr string) error) NetstackOption
func WithAfterDial(fn func(identity, network, addr string, conn net.Conn, err error)) NetstackOption
func WithPolicy(pc PolicyChecker) NetstackOption
func WithAudit(aw AuditWriter) NetstackOption
```

### EgressFilter

```go
func NewEgressFilter(initial EgressPolicy) *EgressFilter
func (f *EgressFilter) Allow(identity string, dstIP net.IP, dstPort uint16) bool
func (f *EgressFilter) Update(p EgressPolicy)

type EgressPolicy struct {
    AllowedCIDRs []net.IPNet
    DefaultDeny  bool
}
```

---

## Integrating into Lattice

The Lattice main repo integrates `lattice-shim` via a thin adapter layer
under `internal/agent/gvisor/`:

```
lattice/internal/agent/gvisor/
├── manager.go           # SandboxManager → creates Sandbox for each agent
├── policy_adapter.go    # PolicyCache → shim.PolicyChecker adapter
├── audit_adapter.go     # AuditBatcher → shim.AuditWriter adapter
├── wg_adapter.go        # wireguard-go device → shim.PeerManager adapter
└── ...
```

### Adapter examples

**Policy adapter:**

```go
type PolicyAdapter struct {
    cache     *sidecar.PolicyCache
    sandboxID string
}

func (a *PolicyAdapter) Allow(identity string, dstIP net.IP, dstPort uint16) bool {
    return a.cache.Query(a.sandboxID, dstIP, dstPort)
}
```

**WireGuard peer manager adapter:**

```go
type WgAdapter struct{ dev *device.Device }

func (a *WgAdapter) AddPeer(pubKey [32]byte, allowedIPs []net.IPNet, endpoint string) error {
    // configure wireguard-go device peer
}
func (a *WgAdapter) RemovePeer(pubKey [32]byte) error { ... }
func (a *WgAdapter) SetPrivateKey(key [32]byte) error { ... }
```

**Usage in manager.go:**

```go
sb, _ := shim.New(agentOverlayIP,
    shim.WithNetstack(
        shim.WithIdentity("sandbox:"+sandboxID),
        shim.WithPolicy(&PolicyAdapter{cache: policyCache, sandboxID: sandboxID}),
        shim.WithAudit(&AuditAdapter{batcher: auditBatcher}),
    ),
    shim.WithSOCKS5("127.0.0.1:1080"),
    shim.WithForwardRule(8080, "127.0.0.1:8080"),
    shim.WithPeerManager(&WgAdapter{dev: wgDevice}),
)
sb.Start(ctx)

// WireGuardManager subscribes to NATS NetMap and calls:
sb.AddPeer(pubKey, allowedIPs, endpoint)
```

### Dependency flow

```
lattice-shim (zero Lattice deps)
  └─ gvisor.dev/gvisor

lattice/internal/agent/gvisor/ (Lattice main repo)
  ├─ github.com/alatticeio/lattice-shim
  ├─ golang.zx2c4.com/wireguard      ← wireguard-go (main repo, not shim)
  ├─ lattice/internal/agent/sidecar  ← PolicyCache implementation
  ├─ lattice/internal/agent/audit    ← AuditBatcher implementation
  └─ ...
```

The shim stays pure: it does not know about wireguard-go internals, Lattice
CRDs, NATS, or control-plane protocols. The adapter layer in the Lattice main
repo translates between Lattice concepts and shim interfaces.

---

## Integrating into other projects

Since `lattice-shim` has **zero Lattice-specific dependencies**, you can use
it in any Go project that needs:

- A user-space TCP/IP stack (gVisor) without root
- SOCKS5 proxy for workload outbound traffic with policy enforcement
- Inbound port forwarding over a WireGuard overlay
- Pluggable hooks for outbound connections and audit logging

### Example use cases

| Use case | Policy | Inbound | Audit |
|---|---|---|---|
| AI agent sandbox | EgressFilter CIDR allowlist | ForwardListener | Batch → control plane |
| VPN client app | Allow-all | — | Local log file |
| IoT device mesh | Identity-based | — | MQTT publish |
| Testing / CI | None | — | None |

---

## Build and test

```bash
go build ./shim
go test ./shim
go vet ./shim
```

The library imports only the Go standard library plus `gvisor.dev/gvisor`.
wireguard-go is an optional integration — inject it via `PeerManager` and
`WireGuardEndpoint` from the caller.

---

## Design principles

- **Zero Lattice deps.** The shim imports no Lattice packages. The Lattice
  main repo implements `PolicyChecker`, `AuditWriter`, and `PeerManager` by
  adapting its own policy cache, audit batcher, and wireguard-go device.
- **Interfaces, not frameworks.** The shim defines narrow interfaces and the
  caller injects concrete implementations.
- **Zero privilege.** The entire data path runs in user space — no TUN
  device, no `CAP_NET_ADMIN`, no root.
- **Standard `net.Conn`.** Connections returned by `DialContext` are ordinary
  `net.Conn` values, so all standard Go networking code works unchanged.
- **Hot-reload.** `EgressFilter.Update()` and `Sandbox.AddPeer()` replace
  policy and peer state atomically without restarting the sandbox process.

---

## License

Apache 2.0 — see [LICENSE](LICENSE)
