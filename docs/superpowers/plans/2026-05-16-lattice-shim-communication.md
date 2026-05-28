# lattice-shim Communication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add ForwardListener (inbound overlay→workload), EgressFilter (CIDR-based outbound policy), PeerManager interface, and Sandbox compositor to complete lattice-shim's communication stack.

**Architecture:** Sandbox wraps Netstack + Socks5Server + ForwardListener + EgressFilter into a single compositor; the caller injects PolicyChecker (e.g. EgressFilter), AuditWriter, and PeerManager. No NATS or Lattice-specific deps — wireguard-go peer management is abstracted via a PeerManager interface injected at runtime.

**Tech Stack:** Go 1.25, gvisor.dev/gvisor (pkg/tcpip, gonet), stdlib (net, sync/atomic, io, context)

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `shim/wireguard.go` | Modify | Add `PeerManager` interface |
| `shim/forward.go` | Create | `ForwardListener` — overlay→workload inbound relay |
| `shim/forward_test.go` | Create | ForwardListener tests |
| `shim/egress.go` | Create | `EgressFilter` — CIDR allowlist, implements `PolicyChecker` |
| `shim/egress_test.go` | Create | EgressFilter tests |
| `shim/shim.go` | Create | `Sandbox` compositor — `New`, `Start`, `Close`, peer delegation |
| `shim/shim_test.go` | Create | Sandbox integration tests |
| `shim/internal/test/mock.go` | Modify | Add `MockPeerManager` |

---

## Task 1: PeerManager interface + MockPeerManager

**Files:**
- Modify: `shim/wireguard.go`
- Modify: `shim/internal/test/mock.go`

- [ ] **Step 1: Write the failing test for PeerManager delegation**

Create `shim/shim_test.go` with just this test (the rest comes in Task 4):

```go
// Copyright 2026 The Lattice Authors, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// ...

package shim_test

import (
	"net"
	"testing"

	"github.com/alatticeio/lattice-shim/shim"
	"github.com/alatticeio/lattice-shim/shim/internal/test"
)

func TestSandbox_PeerManager(t *testing.T) {
	pm := &test.MockPeerManager{}

	sb, err := shim.New("10.0.0.1", shim.WithPeerManager(pm))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	var key [32]byte
	key[0] = 1
	_, subnet, _ := net.ParseCIDR("10.0.0.2/32")
	if err := sb.AddPeer(key, []net.IPNet{*subnet}, "1.2.3.4:51820"); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	if !pm.HasPeer(key) {
		t.Error("expected peer to be added to MockPeerManager")
	}

	if err := sb.RemovePeer(key); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if pm.HasPeer(key) {
		t.Error("expected peer to be removed from MockPeerManager")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd /Users/francis/workspc/lattice-shim && go test ./shim/... 2>&1 | head -20
```

Expected: compile error — `shim.New`, `shim.WithPeerManager`, `sb.AddPeer`, `sb.RemovePeer`, `test.MockPeerManager` not defined.

- [ ] **Step 3: Add PeerManager interface to wireguard.go**

Append to the end of `shim/wireguard.go` (after line 40):

```go

// PeerManager manages WireGuard peers. The implementation (typically a
// wireguard-go device wrapper) is injected by the caller; shim itself does
// not import wireguard-go.
type PeerManager interface {
	AddPeer(pubKey [32]byte, allowedIPs []net.IPNet, endpoint string) error
	RemovePeer(pubKey [32]byte) error
	SetPrivateKey(key [32]byte) error
}
```

Also add `"net"` to the import block in wireguard.go (currently it has no imports).

The full updated `shim/wireguard.go`:

```go
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

package shim

import "net"

// WireGuardBind describes the minimal interface the netstack bridge needs to
// hand packets to wireguard-go for encryption and UDP delivery.
type WireGuardBind interface {
	Write(packet []byte) error
	Read() ([]byte, error)
	Close() error
}

// WireGuardEndpoint bridges the gVisor netstack (via a channel endpoint or
// equivalent packet I/O) to wireguard-go. The concrete implementation is
// provided by the caller (the Lattice main repo injects gVisor's
// channel.Endpoint and wireguard-go's device.Bind).
type WireGuardEndpoint struct {
	// Outbound receives raw IP packets from the netstack and feeds them to
	// wireguard-go for encryption.
	Outbound func(packet []byte) error

	// Inbound receives decrypted IP packets from wireguard-go and injects
	// them into the netstack.
	Inbound func(packet []byte) error

	// Close releases the underlying resources.
	Close func() error
}

// PeerManager manages WireGuard peers. The implementation (typically a
// wireguard-go device wrapper) is injected by the caller; shim itself does
// not import wireguard-go.
type PeerManager interface {
	AddPeer(pubKey [32]byte, allowedIPs []net.IPNet, endpoint string) error
	RemovePeer(pubKey [32]byte) error
	SetPrivateKey(key [32]byte) error
}
```

- [ ] **Step 4: Add MockPeerManager to shim/internal/test/mock.go**

Append to the end of `shim/internal/test/mock.go`:

```go

// MockPeerManager records peer operations for testing.
type MockPeerManager struct {
	mu    sync.Mutex
	peers map[[32]byte]mockPeerEntry
}

type mockPeerEntry struct {
	allowedIPs []net.IPNet
	endpoint   string
}

// AddPeer implements shim.PeerManager.
func (m *MockPeerManager) AddPeer(pubKey [32]byte, allowedIPs []net.IPNet, endpoint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.peers == nil {
		m.peers = make(map[[32]byte]mockPeerEntry)
	}
	m.peers[pubKey] = mockPeerEntry{allowedIPs: allowedIPs, endpoint: endpoint}
	return nil
}

// RemovePeer implements shim.PeerManager.
func (m *MockPeerManager) RemovePeer(pubKey [32]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.peers, pubKey)
	return nil
}

// SetPrivateKey implements shim.PeerManager.
func (m *MockPeerManager) SetPrivateKey(_ [32]byte) error { return nil }

// HasPeer returns true if the given public key is currently tracked.
func (m *MockPeerManager) HasPeer(pubKey [32]byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.peers[pubKey]
	return ok
}

// PeerCount returns the number of tracked peers.
func (m *MockPeerManager) PeerCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.peers)
}
```

- [ ] **Step 5: Create minimal shim/shim.go to make Task 1 test compile**

```go
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

package shim

import (
	"fmt"
	"net"
	"sync"
)

// Sandbox wires together a Netstack, Socks5Server, ForwardListener, and an
// optional PeerManager into a single coherent network subsystem.
// The caller injects policy, audit, and peer management via options.
type Sandbox struct {
	ns      *Netstack
	socks5  *Socks5Server    // nil if WithSOCKS5 not used
	forward *ForwardListener // nil if no WithForwardRule calls
	peers   PeerManager      // nil if WithPeerManager not used
	wg      sync.WaitGroup
}

type sandboxConfig struct {
	nsOpts       []NetstackOption
	socks5Addr   string
	forwardRules []ForwardRule
	peers        PeerManager
}

// Option configures a Sandbox.
type Option func(*sandboxConfig)

// WithNetstack passes NetstackOptions (WithIdentity, WithPolicy, WithAudit,
// etc.) through to the underlying Netstack.
func WithNetstack(opts ...NetstackOption) Option {
	return func(c *sandboxConfig) {
		c.nsOpts = append(c.nsOpts, opts...)
	}
}

// WithSOCKS5 starts a SOCKS5 proxy at addr (e.g. "127.0.0.1:1080").
// Workload processes set ALL_PROXY=socks5://127.0.0.1:1080 to route
// outbound traffic through the netstack (and thus through policy checks).
func WithSOCKS5(addr string) Option {
	return func(c *sandboxConfig) { c.socks5Addr = addr }
}

// WithForwardRule registers an inbound port-forward rule: connections
// arriving on overlayPort within the netstack are relayed to targetAddr on
// the host. Multiple calls add multiple rules.
func WithForwardRule(overlayPort uint16, targetAddr string) Option {
	return func(c *sandboxConfig) {
		c.forwardRules = append(c.forwardRules, ForwardRule{
			OverlayPort: overlayPort,
			TargetAddr:  targetAddr,
		})
	}
}

// WithPeerManager injects a PeerManager (typically a wireguard-go device
// wrapper from the caller). The main repo's WireGuardManager calls
// sb.AddPeer / sb.RemovePeer after subscribing to NATS NetMap changes.
func WithPeerManager(pm PeerManager) Option {
	return func(c *sandboxConfig) { c.peers = pm }
}

// New creates a Sandbox with the given overlay IP and options.
// overlayIP is the WireGuard overlay address assigned to this node (e.g.
// "10.100.0.1"). It is used as both the Netstack local address and the
// listen address for ForwardListener rules.
func New(overlayIP string, opts ...Option) (*Sandbox, error) {
	cfg := &sandboxConfig{}
	for _, o := range opts {
		o(cfg)
	}

	ns, err := NewNetstack(overlayIP, cfg.nsOpts...)
	if err != nil {
		return nil, fmt.Errorf("netstack: %w", err)
	}

	sb := &Sandbox{ns: ns, peers: cfg.peers}

	if cfg.socks5Addr != "" {
		srv, err := NewSocks5Server(ns, cfg.socks5Addr)
		if err != nil {
			ns.Close()
			return nil, fmt.Errorf("socks5: %w", err)
		}
		sb.socks5 = srv
	}

	if len(cfg.forwardRules) > 0 {
		sb.forward = NewForwardListener(ns, overlayIP, cfg.forwardRules)
	}

	return sb, nil
}

// Start launches background goroutines for the SOCKS5 server and
// ForwardListener. It returns immediately; use Close to stop.
func (s *Sandbox) Start(ctx context.Context) error {
	if s.socks5 != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.socks5.Serve()
		}()
	}
	if s.forward != nil {
		if err := s.forward.Start(ctx); err != nil {
			return fmt.Errorf("forward listener: %w", err)
		}
	}
	return nil
}

// Close stops all components and waits for goroutines to exit.
func (s *Sandbox) Close() error {
	var firstErr error
	set := func(err error) {
		if firstErr == nil && err != nil {
			firstErr = err
		}
	}
	if s.socks5 != nil {
		set(s.socks5.Close())
	}
	if s.forward != nil {
		set(s.forward.Close())
	}
	set(s.ns.Close())
	s.wg.Wait()
	return firstErr
}

// Netstack returns the underlying gVisor netstack for advanced use (e.g.
// attaching a wireguard-go channel endpoint).
func (s *Sandbox) Netstack() *Netstack { return s.ns }

// AddPeer delegates to the injected PeerManager.
// Returns an error if no PeerManager was configured.
func (s *Sandbox) AddPeer(pubKey [32]byte, allowedIPs []net.IPNet, endpoint string) error {
	if s.peers == nil {
		return fmt.Errorf("sandbox: no PeerManager configured")
	}
	return s.peers.AddPeer(pubKey, allowedIPs, endpoint)
}

// RemovePeer delegates to the injected PeerManager.
func (s *Sandbox) RemovePeer(pubKey [32]byte) error {
	if s.peers == nil {
		return fmt.Errorf("sandbox: no PeerManager configured")
	}
	return s.peers.RemovePeer(pubKey)
}

// SetPrivateKey delegates to the injected PeerManager.
func (s *Sandbox) SetPrivateKey(key [32]byte) error {
	if s.peers == nil {
		return fmt.Errorf("sandbox: no PeerManager configured")
	}
	return s.peers.SetPrivateKey(key)
}
```

Note: `shim.go` imports `context` — add it to the import block. Also note that `ForwardListener` and `ForwardRule` don't exist yet; shim.go will fail to compile until Task 2. That's fine — Task 2 fixes it.

- [ ] **Step 6: Stub out ForwardListener to unblock compilation**

Create `shim/forward.go` with a minimal stub:

```go
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

package shim

import "context"

// ForwardRule maps an overlay TCP port to a local target address.
type ForwardRule struct {
	OverlayPort uint16 // port to listen on within the netstack at overlayIP
	TargetAddr  string // local address to forward to, e.g. "127.0.0.1:8080"
}

// ForwardListener listens on the netstack's overlay IP for each ForwardRule
// and relays accepted TCP connections to the corresponding local target.
type ForwardListener struct{}

// NewForwardListener creates a ForwardListener. Call Start to begin accepting.
func NewForwardListener(ns *Netstack, overlayIP string, rules []ForwardRule) *ForwardListener {
	return &ForwardListener{}
}

// Start begins listening. Stub — always returns nil.
func (f *ForwardListener) Start(ctx context.Context) error { return nil }

// Close stops all listeners and waits for goroutines to finish.
func (f *ForwardListener) Close() error { return nil }
```

Also fix shim.go — add `"context"` to imports. The full import block for shim.go:

```go
import (
	"context"
	"fmt"
	"net"
	"sync"
)
```

- [ ] **Step 7: Run Task 1 test to verify it passes**

```bash
cd /Users/francis/workspc/lattice-shim && go test ./shim/... -run TestSandbox_PeerManager -v
```

Expected output:
```
--- PASS: TestSandbox_PeerManager (0.00s)
PASS
```

- [ ] **Step 8: Run full test suite to verify nothing broken**

```bash
cd /Users/francis/workspc/lattice-shim && go test ./shim/... -v 2>&1 | tail -20
```

Expected: all existing tests still PASS.

- [ ] **Step 9: Commit**

```bash
cd /Users/francis/workspc/lattice-shim && git add shim/wireguard.go shim/shim.go shim/forward.go shim/shim_test.go shim/internal/test/mock.go && git commit -m "$(cat <<'EOF'
feat: add PeerManager interface and Sandbox compositor skeleton

- PeerManager interface (AddPeer/RemovePeer/SetPrivateKey) in wireguard.go
- Sandbox compositor in shim.go with WithNetstack/WithSOCKS5/WithForwardRule/WithPeerManager options
- MockPeerManager in internal/test for unit testing
- ForwardListener stub to unblock compilation (implementation in next commit)

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: ForwardListener

**Files:**
- Modify: `shim/forward.go` (replace stub with full implementation)
- Create: `shim/forward_test.go`

- [ ] **Step 1: Write the failing tests**

Create `shim/forward_test.go`:

```go
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

package shim_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/alatticeio/lattice-shim/shim"
)

// startEchoServer starts a real TCP echo server on the host OS and returns
// its address. The server echoes each read back to the sender.
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo server listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestForwardListener_BasicRelay(t *testing.T) {
	echoAddr := startEchoServer(t)

	ns, err := shim.NewNetstack("127.0.0.1")
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	fwd := shim.NewForwardListener(ns, "127.0.0.1", []shim.ForwardRule{
		{OverlayPort: 9200, TargetAddr: echoAddr},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := fwd.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer fwd.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := ns.DialContext(ctx, "tcp", "127.0.0.1:9200")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello forward")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("expected %q, got %q", msg, buf)
	}
}

func TestForwardListener_MultipleRules(t *testing.T) {
	echo1 := startEchoServer(t)
	echo2 := startEchoServer(t)

	ns, err := shim.NewNetstack("127.0.0.1")
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	fwd := shim.NewForwardListener(ns, "127.0.0.1", []shim.ForwardRule{
		{OverlayPort: 9201, TargetAddr: echo1},
		{OverlayPort: 9202, TargetAddr: echo2},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := fwd.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer fwd.Close()

	time.Sleep(50 * time.Millisecond)

	for _, tc := range []struct {
		port string
		msg  string
	}{
		{"9201", "msg-to-echo1"},
		{"9202", "msg-to-echo2"},
	} {
		conn, err := ns.DialContext(ctx, "tcp", "127.0.0.1:"+tc.port)
		if err != nil {
			t.Fatalf("port %s DialContext: %v", tc.port, err)
		}
		if _, err := conn.Write([]byte(tc.msg)); err != nil {
			conn.Close()
			t.Fatalf("port %s Write: %v", tc.port, err)
		}
		buf := make([]byte, len(tc.msg))
		if _, err := io.ReadFull(conn, buf); err != nil {
			conn.Close()
			t.Fatalf("port %s ReadFull: %v", tc.port, err)
		}
		if string(buf) != tc.msg {
			t.Errorf("port %s: expected %q, got %q", tc.port, tc.msg, buf)
		}
		conn.Close()
	}
}

func TestForwardListener_CloseStops(t *testing.T) {
	echoAddr := startEchoServer(t)

	ns, err := shim.NewNetstack("127.0.0.1")
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	fwd := shim.NewForwardListener(ns, "127.0.0.1", []shim.ForwardRule{
		{OverlayPort: 9203, TargetAddr: echoAddr},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := fwd.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Verify active before close.
	conn, err := ns.DialContext(ctx, "tcp", "127.0.0.1:9203")
	if err != nil {
		t.Fatalf("expected listener active: %v", err)
	}
	conn.Close()

	// Close the forward listener.
	if err := fwd.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Dialing should now fail.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	_, err = ns.DialContext(ctx2, "tcp", "127.0.0.1:9203")
	if err == nil {
		t.Error("expected dial to fail after Close")
	}
}
```

- [ ] **Step 2: Run to verify tests fail**

```bash
cd /Users/francis/workspc/lattice-shim && go test ./shim/... -run TestForwardListener -v 2>&1 | head -30
```

Expected: `TestForwardListener_BasicRelay` FAIL — stub `Start` does nothing so dial to 9200 fails.

- [ ] **Step 3: Replace forward.go stub with full implementation**

```go
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

package shim

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
)

// ForwardRule maps an overlay TCP port to a local target address.
type ForwardRule struct {
	OverlayPort uint16 // port to listen on within the netstack at overlayIP
	TargetAddr  string // local address to forward to, e.g. "127.0.0.1:8080"
}

// ForwardListener listens on the netstack's overlay IP for each ForwardRule
// and relays accepted TCP connections to the corresponding local target.
// Policy checks are NOT performed here — they are enforced on the outbound
// side by the originating sandbox's EgressFilter.
type ForwardListener struct {
	ns        *Netstack
	overlayIP string
	rules     []ForwardRule

	listeners []net.Listener
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// NewForwardListener creates a ForwardListener. Call Start to begin accepting.
func NewForwardListener(ns *Netstack, overlayIP string, rules []ForwardRule) *ForwardListener {
	return &ForwardListener{ns: ns, overlayIP: overlayIP, rules: rules}
}

// Start binds a TCP listener on the netstack for each ForwardRule and
// launches accept goroutines. Returns an error if any listener fails to bind;
// on error, all already-bound listeners are closed before returning.
func (f *ForwardListener) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	f.cancel = cancel

	for _, rule := range f.rules {
		addr := net.JoinHostPort(f.overlayIP, fmt.Sprintf("%d", rule.OverlayPort))
		ln, err := f.ns.ListenTCP(addr)
		if err != nil {
			cancel()
			for _, l := range f.listeners {
				l.Close()
			}
			f.listeners = nil
			return fmt.Errorf("forward listen %s: %w", addr, err)
		}
		f.listeners = append(f.listeners, ln)

		target := rule.TargetAddr
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			f.acceptLoop(ctx, ln, target)
		}()
	}
	return nil
}

// Close stops all listeners and waits for all goroutines to finish.
func (f *ForwardListener) Close() error {
	if f.cancel != nil {
		f.cancel()
	}
	for _, ln := range f.listeners {
		ln.Close()
	}
	f.wg.Wait()
	return nil
}

func (f *ForwardListener) acceptLoop(ctx context.Context, ln net.Listener, targetAddr string) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			f.forwardConn(ctx, conn, targetAddr)
		}()
	}
}

func (f *ForwardListener) forwardConn(ctx context.Context, src net.Conn, targetAddr string) {
	defer src.Close()
	dst, err := (&net.Dialer{}).DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return
	}
	defer dst.Close()
	relay(src, dst)
}

// relay copies data bidirectionally between a and b, using half-close when
// available so each side can observe EOF cleanly.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copy := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go copy(b, a)
	go copy(a, b)
	wg.Wait()
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/francis/workspc/lattice-shim && go test ./shim/... -run TestForwardListener -v
```

Expected:
```
--- PASS: TestForwardListener_BasicRelay (0.05s)
--- PASS: TestForwardListener_MultipleRules (0.05s)
--- PASS: TestForwardListener_CloseStops (0.05s)
PASS
```

- [ ] **Step 5: Run full suite**

```bash
cd /Users/francis/workspc/lattice-shim && go test ./shim/... -v 2>&1 | tail -20
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/francis/workspc/lattice-shim && git add shim/forward.go shim/forward_test.go && git commit -m "$(cat <<'EOF'
feat: implement ForwardListener for overlay inbound relay

Listens on the gVisor netstack at overlayIP:overlayPort for each
ForwardRule and relays accepted TCP connections to the local target.
No policy check — callers enforce policy on the outbound side.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: EgressFilter

**Files:**
- Create: `shim/egress.go`
- Create: `shim/egress_test.go`

- [ ] **Step 1: Write the failing tests**

Create `shim/egress_test.go`:

```go
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

package shim_test

import (
	"net"
	"testing"

	"github.com/alatticeio/lattice-shim/shim"
)

func parseCIDR(t *testing.T, s string) net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return *n
}

func parseIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("ParseIP(%q) returned nil", s)
	}
	return ip
}

func TestEgressFilter_DefaultAllowAll(t *testing.T) {
	// DefaultDeny=false with no CIDRs: allow everything.
	f := shim.NewEgressFilter(shim.EgressPolicy{DefaultDeny: false})

	cases := []string{"10.0.0.1", "192.168.1.1", "8.8.8.8", "172.16.0.1"}
	for _, ip := range cases {
		if !f.Allow("sandbox-a", parseIP(t, ip), 443) {
			t.Errorf("expected Allow for %s, got deny", ip)
		}
	}
}

func TestEgressFilter_DefaultDenyNoRules(t *testing.T) {
	// DefaultDeny=true with no CIDRs: deny everything.
	f := shim.NewEgressFilter(shim.EgressPolicy{DefaultDeny: true})

	cases := []string{"10.0.0.1", "192.168.1.1", "8.8.8.8"}
	for _, ip := range cases {
		if f.Allow("sandbox-a", parseIP(t, ip), 443) {
			t.Errorf("expected Deny for %s, got allow", ip)
		}
	}
}

func TestEgressFilter_CIDRAllows(t *testing.T) {
	// DefaultDeny=true, only 10.0.0.0/8 allowed.
	f := shim.NewEgressFilter(shim.EgressPolicy{
		DefaultDeny:  true,
		AllowedCIDRs: []net.IPNet{parseCIDR(t, "10.0.0.0/8")},
	})

	allowed := []string{"10.0.0.1", "10.255.255.255", "10.100.0.2"}
	for _, ip := range allowed {
		if !f.Allow("sandbox-a", parseIP(t, ip), 80) {
			t.Errorf("expected Allow for %s (in 10.0.0.0/8), got deny", ip)
		}
	}

	denied := []string{"192.168.1.1", "172.16.0.1", "8.8.8.8"}
	for _, ip := range denied {
		if f.Allow("sandbox-a", parseIP(t, ip), 80) {
			t.Errorf("expected Deny for %s (not in 10.0.0.0/8), got allow", ip)
		}
	}
}

func TestEgressFilter_MultipleCIDRs(t *testing.T) {
	f := shim.NewEgressFilter(shim.EgressPolicy{
		DefaultDeny: true,
		AllowedCIDRs: []net.IPNet{
			parseCIDR(t, "10.0.0.0/8"),
			parseCIDR(t, "192.168.0.0/16"),
		},
	})

	if !f.Allow("x", parseIP(t, "10.1.2.3"), 80) {
		t.Error("expected allow for 10.1.2.3")
	}
	if !f.Allow("x", parseIP(t, "192.168.99.1"), 80) {
		t.Error("expected allow for 192.168.99.1")
	}
	if f.Allow("x", parseIP(t, "8.8.8.8"), 80) {
		t.Error("expected deny for 8.8.8.8")
	}
}

func TestEgressFilter_Update(t *testing.T) {
	// Start as allow-all, then switch to deny-all.
	f := shim.NewEgressFilter(shim.EgressPolicy{DefaultDeny: false})

	ip := parseIP(t, "10.0.0.1")
	if !f.Allow("sandbox", ip, 443) {
		t.Fatal("expected allow before Update")
	}

	f.Update(shim.EgressPolicy{DefaultDeny: true})

	if f.Allow("sandbox", ip, 443) {
		t.Error("expected deny after Update to DefaultDeny=true")
	}
}

func TestEgressFilter_UpdateCIDR(t *testing.T) {
	// Start deny-all, then add a CIDR, verify previously-denied IP is now allowed.
	f := shim.NewEgressFilter(shim.EgressPolicy{DefaultDeny: true})

	ip := parseIP(t, "10.0.0.1")
	if f.Allow("sandbox", ip, 443) {
		t.Fatal("expected deny before Update")
	}

	f.Update(shim.EgressPolicy{
		DefaultDeny:  true,
		AllowedCIDRs: []net.IPNet{parseCIDR(t, "10.0.0.0/8")},
	})

	if !f.Allow("sandbox", ip, 443) {
		t.Error("expected allow after adding 10.0.0.0/8 CIDR")
	}
}

func TestEgressFilter_ImplementsPolicyChecker(t *testing.T) {
	// Compile-time check: EgressFilter implements PolicyChecker.
	var _ shim.PolicyChecker = shim.NewEgressFilter(shim.EgressPolicy{})
}
```

- [ ] **Step 2: Run to verify they fail**

```bash
cd /Users/francis/workspc/lattice-shim && go test ./shim/... -run TestEgressFilter -v 2>&1 | head -10
```

Expected: compile error — `shim.EgressFilter`, `shim.NewEgressFilter`, `shim.EgressPolicy` not defined.

- [ ] **Step 3: Implement egress.go**

```go
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

package shim

import (
	"net"
	"sync/atomic"
)

// EgressPolicy defines which outbound destinations are permitted.
type EgressPolicy struct {
	// AllowedCIDRs is the list of IP ranges that are always permitted.
	AllowedCIDRs []net.IPNet

	// DefaultDeny controls what happens when dstIP matches no AllowedCIDR.
	// true  → deny (whitelist mode)
	// false → allow (audit-only / allow-all mode)
	DefaultDeny bool
}

// EgressFilter implements PolicyChecker using a CIDR-based allowlist.
// The policy can be replaced atomically at runtime via Update — no restart
// required. This makes it suitable for NATS-pushed policy changes where the
// main repo calls Update after receiving a new policy payload.
type EgressFilter struct {
	policy atomic.Pointer[EgressPolicy]
}

// NewEgressFilter creates an EgressFilter with the given initial policy.
func NewEgressFilter(initial EgressPolicy) *EgressFilter {
	f := &EgressFilter{}
	f.policy.Store(&initial)
	return f
}

// Allow implements PolicyChecker. It returns true if dstIP is covered by any
// AllowedCIDR, or if DefaultDeny is false (allow-all mode). The identity and
// dstPort parameters are accepted for interface compatibility but are not used
// in CIDR matching — port-level policy is enforced at the application layer.
func (f *EgressFilter) Allow(_ string, dstIP net.IP, _ uint16) bool {
	p := f.policy.Load()
	for i := range p.AllowedCIDRs {
		if p.AllowedCIDRs[i].Contains(dstIP) {
			return true
		}
	}
	return !p.DefaultDeny
}

// Update atomically replaces the current policy. Ongoing Allow calls that
// began before Update returns may observe the old or new policy; calls that
// begin after Update returns always observe the new policy.
func (f *EgressFilter) Update(p EgressPolicy) {
	f.policy.Store(&p)
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/francis/workspc/lattice-shim && go test ./shim/... -run TestEgressFilter -v
```

Expected:
```
--- PASS: TestEgressFilter_DefaultAllowAll (0.00s)
--- PASS: TestEgressFilter_DefaultDenyNoRules (0.00s)
--- PASS: TestEgressFilter_CIDRAllows (0.00s)
--- PASS: TestEgressFilter_MultipleCIDRs (0.00s)
--- PASS: TestEgressFilter_Update (0.00s)
--- PASS: TestEgressFilter_UpdateCIDR (0.00s)
--- PASS: TestEgressFilter_ImplementsPolicyChecker (0.00s)
PASS
```

- [ ] **Step 5: Run full suite**

```bash
cd /Users/francis/workspc/lattice-shim && go test ./shim/... -v 2>&1 | tail -20
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/francis/workspc/lattice-shim && git add shim/egress.go shim/egress_test.go && git commit -m "$(cat <<'EOF'
feat: implement EgressFilter CIDR-based outbound policy

EgressFilter implements PolicyChecker with atomic policy hot-reload.
DefaultDeny=true enables whitelist mode; Update() replaces the policy
without restarting. Designed for NATS-pushed policy changes from main repo.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Sandbox integration tests

**Files:**
- Modify: `shim/shim_test.go` (add remaining tests to the file created in Task 1)

- [ ] **Step 1: Add integration tests to shim_test.go**

Append to `shim/shim_test.go` (after `TestSandbox_PeerManager`):

```go

func TestSandbox_SOCKSProxy(t *testing.T) {
	// Verify that the SOCKS5 server started by Sandbox routes through the netstack.
	ns_target, err := shim.NewNetstack("127.0.0.1")
	if err != nil {
		t.Fatalf("target NewNetstack: %v", err)
	}
	defer ns_target.Close()

	// Echo server on the target netstack.
	ln, err := ns_target.ListenTCP("127.0.0.1:9300")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	// Sandbox with SOCKS5 on a separate netstack (same localIP for loopback).
	sb, err := shim.New("127.0.0.1", shim.WithSOCKS5("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	proxyAddr := sb.Socks5Addr()
	conn, err := socks5Dial(proxyAddr, "127.0.0.1:9300")
	if err != nil {
		t.Fatalf("socks5Dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("via sandbox socks5")
	conn.Write(msg)
	buf := make([]byte, len(msg))
	io.ReadFull(conn, buf)
	if string(buf) != string(msg) {
		t.Errorf("expected %q, got %q", msg, buf)
	}
}

func TestSandbox_ForwardRule(t *testing.T) {
	echoAddr := startEchoServer(t)

	sb, err := shim.New("127.0.0.1",
		shim.WithForwardRule(9301, echoAddr),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	conn, err := sb.Netstack().DialContext(ctx, "tcp", "127.0.0.1:9301")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	msg := []byte("via sandbox forward")
	conn.Write(msg)
	buf := make([]byte, len(msg))
	io.ReadFull(conn, buf)
	if string(buf) != string(msg) {
		t.Errorf("expected %q, got %q", msg, buf)
	}
}

func TestSandbox_EgressPolicyDeny(t *testing.T) {
	// Sandbox with deny-all EgressFilter: SOCKS5 connect should be refused.
	filter := shim.NewEgressFilter(shim.EgressPolicy{DefaultDeny: true})

	sb, err := shim.New("10.100.0.1",
		shim.WithNetstack(
			shim.WithIdentity("sandbox-test"),
			shim.WithPolicy(filter),
			shim.WithAudit(&test.MockAuditWriter{}),
		),
		shim.WithSOCKS5("127.0.0.1:0"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	_, err = socks5Dial(sb.Socks5Addr(), "10.0.0.1:443")
	if err == nil {
		t.Fatal("expected SOCKS5 failure when EgressFilter denies all")
	}
}

func TestSandbox_Close(t *testing.T) {
	sb, err := shim.New("127.0.0.1", shim.WithSOCKS5("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sb.Start(ctx)

	time.Sleep(50 * time.Millisecond)

	addr := sb.Socks5Addr()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("expected SOCKS5 active before Close: %v", err)
	}
	conn.Close()

	sb.Close()

	_, err = net.Dial("tcp", addr)
	if err == nil {
		t.Error("expected SOCKS5 unreachable after Close")
	}
}

func TestSandbox_NoPeerManager(t *testing.T) {
	sb, err := shim.New("10.0.0.1")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	var key [32]byte
	_, subnet, _ := net.ParseCIDR("10.0.0.2/32")
	err = sb.AddPeer(key, []net.IPNet{*subnet}, "1.2.3.4:51820")
	if err == nil {
		t.Error("expected error when no PeerManager configured")
	}
}
```

The test `TestSandbox_SOCKSProxy` and `TestSandbox_EgressPolicyDeny` use `sb.Socks5Addr()` — add that method to `shim/shim.go`:

```go
// Socks5Addr returns the address the SOCKS5 server is listening on, or ""
// if WithSOCKS5 was not used.
func (s *Sandbox) Socks5Addr() string {
	if s.socks5 == nil {
		return ""
	}
	return s.socks5.Addr().String()
}
```

Also add required imports to `shim_test.go`:

```go
import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/alatticeio/lattice-shim/shim"
	"github.com/alatticeio/lattice-shim/shim/internal/test"
)
```

- [ ] **Step 2: Run to verify tests fail**

```bash
cd /Users/francis/workspc/lattice-shim && go test ./shim/... -run TestSandbox -v 2>&1 | head -20
```

Expected: compile error or failures from `sb.Socks5Addr()` not existing.

- [ ] **Step 3: Add Socks5Addr to shim.go**

Add after the `Netstack()` method in `shim/shim.go`:

```go
// Socks5Addr returns the listening address of the SOCKS5 server, or ""
// if WithSOCKS5 was not configured.
func (s *Sandbox) Socks5Addr() string {
	if s.socks5 == nil {
		return ""
	}
	return s.socks5.Addr().String()
}
```

- [ ] **Step 4: Run Sandbox tests**

```bash
cd /Users/francis/workspc/lattice-shim && go test ./shim/... -run TestSandbox -v
```

Expected:
```
--- PASS: TestSandbox_PeerManager (0.00s)
--- PASS: TestSandbox_SOCKSProxy (0.05s)
--- PASS: TestSandbox_ForwardRule (0.05s)
--- PASS: TestSandbox_EgressPolicyDeny (0.05s)
--- PASS: TestSandbox_Close (0.05s)
--- PASS: TestSandbox_NoPeerManager (0.00s)
PASS
```

- [ ] **Step 5: Run full test suite**

```bash
cd /Users/francis/workspc/lattice-shim && go test ./shim/... -v 2>&1 | grep -E "^(--- |PASS|FAIL|ok)"
```

Expected: all lines show PASS, final line `ok github.com/alatticeio/lattice-shim/shim`.

- [ ] **Step 6: Commit**

```bash
cd /Users/francis/workspc/lattice-shim && git add shim/shim.go shim/shim_test.go && git commit -m "$(cat <<'EOF'
feat: complete Sandbox compositor with integration tests

- Socks5Addr() accessor for test and operational use
- Integration tests: SOCKS5 relay, forward rules, egress deny, close, no-PeerManager guard

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Self-Review

**Spec coverage:**
- PolicyChecker interface `Allow(identity string, dstIP net.IP, dstPort uint16) bool` → already existed, confirmed in Task 1 ✅
- AuditWriter / AuditEvent → already existed ✅
- WireGuardBind + WireGuardEndpoint → already existed; PeerManager added in Task 1 ✅
- ForwardListener (inbound overlay→workload relay) → Task 2 ✅
- EgressFilter (CIDR allowlist, hot-reload) → Task 3 ✅
- Sandbox compositor (New/Start/Close/AddPeer/RemovePeer/SetPrivateKey) → Tasks 1 & 4 ✅
- WithNetstack/WithSOCKS5/WithForwardRule/WithPeerManager options → Task 1 ✅
- Zero Lattice deps (no NATS in shim) → PeerManager is an interface, injected by caller ✅
- Public internet out of scope → no gateway peer logic anywhere in plan ✅

**Placeholder scan:** No TBDs or TODOs — every step has complete code.

**Type consistency:**
- `ForwardRule` defined in Task 1 stub, fully implemented in Task 2 — same struct fields throughout ✅
- `EgressFilter.Allow` signature matches `PolicyChecker` interface ✅
- `MockPeerManager` in test/mock.go implements `PeerManager` interface ✅
- `sb.Socks5Addr()` referenced in Task 4 tests, added to shim.go in Task 4 Step 3 ✅
- `shim.WithIdentity` / `shim.WithPolicy` / `shim.WithAudit` are `NetstackOption` constructors, passed via `shim.WithNetstack(...)` — no name conflict ✅
