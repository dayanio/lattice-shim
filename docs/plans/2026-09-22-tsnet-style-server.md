# tsnet 风格 Server 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 `lattice-shim` 里新增一个 tsnet 风格的顶层类型 `Server`：Netstack + PeerManager，直接暴露 `Dial`/`Listen`（标准 `net.Conn`/`net.Listener`），不经过 `Sandbox` 的 `ForwardListener`/`Socks5Server` 中继层。

**Architecture:** `Server`是 `Sandbox` 的平级新增，不是替代——内部持有一个 `*Netstack` 和一个 `PeerManager`，`Dial`/`Listen` 直接委托给 `Netstack.DialContext`/`Netstack.ListenTCP`，`AddPeer`/`RemovePeer` 直接委托给注入的 `PeerManager`。`PeerManager` 作为必填的构造参数传入（而非像 `Sandbox` 那样通过 functional option 注入），因为 `Server` 存在的意义就是承载 peer 连接，跟 `Sandbox` 里"可选的转发/代理场景"语义不同。

**Tech Stack:** Go 1.25.8、`gvisor.dev/gvisor`（已 pin，见 go.mod）、标准库 `net`/`context`。

## Global Constraints

- 模块路径：`github.com/alatticeio/lattice-shim`，Go 1.25.8（见 go.mod，勿改）。
- 零 Lattice 依赖：`shim` 包只能 import 标准库 + `gvisor.dev/gvisor`，不能 import 任何 `lattice`/`lattice-cast` 等主仓库包（见 `CLAUDE.md` 设计原则）。
- `Server` 与 `Sandbox` 平级新增，不修改 `Sandbox`/`Netstack`/`PeerManager` 现有签名。
- 本仓库提交走普通 `git commit -s`（Signed-off-by），不加 `Co-Authored-By`。
- 测试文件放在 `shim_test` 外部测试包（`package shim_test`），跟现有 `shim_test.go` 风格一致；复用 `shim/internal/test` 里已有的 `MockPeerManager`。

---

## Task 1: `Server` 骨架 — 构造、PeerManager 委托、Close

**Files:**
- Create: `shim/server.go`
- Test: `shim/server_test.go`

**Interfaces:**
- Produces: `type Server struct{...}`；`func NewServer(overlayIP string, pm PeerManager, opts ...NetstackOption) (*Server, error)`；`func (s *Server) AddPeer(pubKey [32]byte, allowedIPs []net.IPNet, endpoint string) error`；`func (s *Server) RemovePeer(pubKey [32]byte) error`；`func (s *Server) Close() error`。
- Consumes：`shim.PeerManager`、`shim.NetstackOption`、`shim.NewNetstack`（均已存在，见 `shim/wireguard.go`、`shim/netstack.go`、`shim/netstack_core.go`，不改动）。

- [ ] **Step 1: 写失败测试 `shim/server_test.go`**

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
	"github.com/alatticeio/lattice-shim/shim/internal/test"
)

func TestServer_PeerManagerDelegation(t *testing.T) {
	pm := &test.MockPeerManager{}

	srv, err := shim.NewServer("10.50.0.1", pm)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	var key [32]byte
	key[0] = 1
	_, subnet, _ := net.ParseCIDR("10.50.0.2/32")
	if err := srv.AddPeer(key, []net.IPNet{*subnet}, "1.2.3.4:51820"); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if !pm.HasPeer(key) {
		t.Error("expected peer to be added to MockPeerManager")
	}

	if err := srv.RemovePeer(key); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if pm.HasPeer(key) {
		t.Error("expected peer to be removed from MockPeerManager")
	}
}

func TestServer_NilPeerManager(t *testing.T) {
	srv, err := shim.NewServer("10.50.0.1", nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	var key [32]byte
	_, subnet, _ := net.ParseCIDR("10.50.0.2/32")
	err = srv.AddPeer(key, []net.IPNet{*subnet}, "1.2.3.4:51820")
	if err == nil {
		t.Error("expected error when PeerManager is nil")
	}
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cd /Users/francis/workspc/lattice-shim && go test ./shim/ -run TestServer -v`
Expected: FAIL（`undefined: shim.NewServer`）

- [ ] **Step 3: 实现 `shim/server.go`**

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
)

// Server is a tsnet-style embeddable network node: a Netstack plus a
// PeerManager, exposing Dial and Listen directly. Unlike Sandbox, Server
// does not wire up a SOCKS5 proxy or ForwardListener relay — callers get
// raw net.Conn/net.Listener values backed by the user-space netstack.
//
// Server is intended for embedding overlay connectivity into a host
// process that does not want (or cannot get) a kernel TUN device — for
// example a mobile app extension with no elevated network privilege.
type Server struct {
	ns    *Netstack
	peers PeerManager
}

// NewServer creates a Server bound to overlayIP. pm is the PeerManager
// that will receive AddPeer/RemovePeer calls; it may be nil, in which case
// AddPeer/RemovePeer return an error (mirroring Sandbox's behavior with no
// PeerManager configured). opts configures the underlying Netstack (e.g.
// WithIdentity, WithPolicy, WithAudit).
func NewServer(overlayIP string, pm PeerManager, opts ...NetstackOption) (*Server, error) {
	ns, err := NewNetstack(overlayIP, opts...)
	if err != nil {
		return nil, fmt.Errorf("netstack: %w", err)
	}
	return &Server{ns: ns, peers: pm}, nil
}

// AddPeer delegates to the injected PeerManager.
// Returns an error if no PeerManager was configured.
func (s *Server) AddPeer(pubKey [32]byte, allowedIPs []net.IPNet, endpoint string) error {
	if s.peers == nil {
		return fmt.Errorf("server: no PeerManager configured")
	}
	return s.peers.AddPeer(pubKey, allowedIPs, endpoint)
}

// RemovePeer delegates to the injected PeerManager.
// Returns an error if no PeerManager was configured.
func (s *Server) RemovePeer(pubKey [32]byte) error {
	if s.peers == nil {
		return fmt.Errorf("server: no PeerManager configured")
	}
	return s.peers.RemovePeer(pubKey)
}

// Close destroys the underlying netstack.
func (s *Server) Close() error {
	return s.ns.Close()
}
```

`Dial`/`Listen`/`Channel` are added in Task 2, once their tests exist — this task only implements what `TestServer_PeerManagerDelegation`/`TestServer_NilPeerManager` require.

- [ ] **Step 4: 运行确认通过**

Run: `cd /Users/francis/workspc/lattice-shim && go test ./shim/ -run TestServer -v`
Expected: `--- PASS: TestServer_PeerManagerDelegation` and `--- PASS: TestServer_NilPeerManager`, `ok`

- [ ] **Step 5: Commit**

```bash
cd /Users/francis/workspc/lattice-shim
git add shim/server.go shim/server_test.go
git commit -s -m "feat(shim): add tsnet-style Server skeleton with PeerManager delegation"
```

---

## Task 2: `Dial`/`Listen` 端到端验证 — 两个 Server 互联

**Files:**
- Modify: `shim/server.go`（新增 `Dial`/`Listen`/`Channel` 方法）
- Modify: `shim/server_test.go`

**Interfaces:**
- Consumes: Task 1 产物 `shim.NewServer`、`(*Server).AddPeer`、`(*Server).Close`；`Netstack.DialContext`/`Netstack.ListenTCP`/`Netstack.Channel`（`shim/netstack_core.go`，已存在）；gVisor 包 `gvisor.dev/gvisor/pkg/buffer`、`gvisor.dev/gvisor/pkg/tcpip/header`、`gvisor.dev/gvisor/pkg/tcpip/link/channel`、`gvisor.dev/gvisor/pkg/tcpip/stack`（均已是 `go.mod` 里 `gvisor.dev/gvisor` 的子包，无需新增依赖）。
- Produces: `(*Server).Dial(ctx context.Context, network, addr string) (net.Conn, error)`、`(*Server).Listen(network, addr string) (net.Listener, error)`、`(*Server).Channel() *channel.Endpoint`。
- Produces：测试内部辅助函数 `pumpPackets(ctx context.Context, from, to *channel.Endpoint)`，仅测试范围内使用，不导出。

这一步不需要真实 WireGuard——用一个小的包泵函数直接在两个 `Server` 的 `channel.Endpoint` 之间互相转发原始包，模拟 wireguard-go 在两端之间做的加密/解密透传（本测试不关心加密，只验证 netstack 层的 Dial/Listen 语义）。`channel.Endpoint.ReadContext` 和 `InjectInbound` 的具体用法参照 `lattice` 主仓库 `internal/agent/gvisor/wg_device.go` 里已经验证过的桥接模式。

- [ ] **Step 1: 追加失败测试到 `shim/server_test.go`**

在文件顶部 import 块追加：

```go
import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/alatticeio/lattice-shim/shim"
	"github.com/alatticeio/lattice-shim/shim/internal/test"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)
```

在文件末尾追加：

```go
// pumpPackets relays every outbound packet on `from` into `to` as an
// inbound packet, until ctx is canceled. It stands in for wireguard-go's
// encrypt/decrypt/deliver loop between two peers, which Server.Dial and
// Server.Listen do not need to know about.
func pumpPackets(ctx context.Context, from, to *channel.Endpoint) {
	for {
		pkt := from.ReadContext(ctx)
		if pkt == nil {
			return // ctx canceled
		}
		view := pkt.ToView()
		pkt.DecRef()
		if view == nil || view.Size() == 0 {
			continue
		}
		data := append([]byte(nil), view.AsSlice()...)
		relayView := buffer.NewViewWithData(data)
		var relayBuf buffer.Buffer
		_ = relayBuf.Append(relayView)
		relayPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: relayBuf})
		to.InjectInbound(header.IPv4ProtocolNumber, relayPkt)
		relayPkt.DecRef()
	}
}

func TestServer_DialListen(t *testing.T) {
	a, err := shim.NewServer("10.50.0.1", &test.MockPeerManager{})
	if err != nil {
		t.Fatalf("NewServer(a): %v", err)
	}
	defer a.Close()

	b, err := shim.NewServer("10.50.0.2", &test.MockPeerManager{})
	if err != nil {
		t.Fatalf("NewServer(b): %v", err)
	}
	defer b.Close()

	pumpCtx, stopPump := context.WithCancel(context.Background())
	defer stopPump()
	go pumpPackets(pumpCtx, a.Channel(), b.Channel())
	go pumpPackets(pumpCtx, b.Channel(), a.Channel())

	ln, err := b.Listen("tcp", "10.50.0.2:9400")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer conn.Close()
		accepted <- nil
		io.Copy(conn, conn)
	}()

	dialCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := a.Dial(dialCtx, "tcp", "10.50.0.2:9400")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Accept")
	}

	msg := []byte("hello across two Server instances")
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

func TestServer_ListenRejectsUDP(t *testing.T) {
	srv, err := shim.NewServer("10.50.0.1", nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	_, err = srv.Listen("udp", "10.50.0.1:9401")
	if err == nil {
		t.Error("expected error for unsupported network \"udp\"")
	}
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cd /Users/francis/workspc/lattice-shim && go test ./shim/ -run TestServer -v`
Expected: FAIL to compile（`s.Dial undefined`、`s.Listen undefined`、`s.Channel undefined` — Task 1 只实现了 `AddPeer`/`RemovePeer`/`Close`）

- [ ] **Step 3: 追加 `Dial`/`Listen`/`Channel` 到 `shim/server.go`**

在 `shim/server.go` 顶部 import 块里把

```go
import (
	"fmt"
	"net"
)
```

替换成

```go
import (
	"context"
	"fmt"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
)
```

在 `RemovePeer` 方法之后、`Close` 方法之前插入：

```go
// Dial dials a remote address through the user-space netstack. See
// Netstack.DialContext for supported network values ("tcp", "tcp4",
// "udp", "udp4").
func (s *Server) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return s.ns.DialContext(ctx, network, addr)
}

// Listen creates a TCP listener on the netstack at addr. network must be
// "tcp" or "tcp4".
func (s *Server) Listen(network, addr string) (net.Listener, error) {
	switch network {
	case "tcp", "tcp4":
		return s.ns.ListenTCP(addr)
	default:
		return nil, fmt.Errorf("unsupported network: %s", network)
	}
}

// Channel returns the channel endpoint for wireguard-go attachment — the
// caller's WireGuard bridge (e.g. a tun.Device adapter) reads outbound
// packets from and injects inbound packets into this endpoint.
func (s *Server) Channel() *channel.Endpoint { return s.ns.Channel() }
```

- [ ] **Step 4: 运行确认通过**

Run: `cd /Users/francis/workspc/lattice-shim && go test ./shim/ -run TestServer -v`
Expected: `--- PASS: TestServer_PeerManagerDelegation`、`--- PASS: TestServer_NilPeerManager`、`--- PASS: TestServer_DialListen`、`--- PASS: TestServer_ListenRejectsUDP`，全部 `ok`

- [ ] **Step 5: 跑全量 shim 测试确认没有破坏现有功能**

Run: `cd /Users/francis/workspc/lattice-shim && go test ./... -v`
Expected: 全部 PASS，包括之前已有的 `TestSandbox_*` 系列测试

- [ ] **Step 6: Commit**

```bash
cd /Users/francis/workspc/lattice-shim
git add shim/server.go shim/server_test.go
git commit -s -m "feat(shim): add Dial/Listen to Server, verified by two-instance round-trip test"
```

---

## Task 3: 文档 — README 补充 `Server` 用法

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: Task 1-2 产物（`NewServer`/`Dial`/`Listen`/`AddPeer`/`RemovePeer`）
- Produces: 无新代码，仅文档

- [ ] **Step 1: 在 README 的 "Architecture" 一节后面追加 `Server` 说明**

在 README.md 中找到 "## Architecture" 一节结尾（`Sandbox` 结构图之后、"## Integrating into other projects" 之前），插入以下内容：

```markdown
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
```

- [ ] **Step 2: Commit**

```bash
cd /Users/francis/workspc/lattice-shim
git add README.md
git commit -s -m "docs: document tsnet-style Server usage"
```

---

## Self-Review 记录

- **Spec 覆盖**：本计划实现设计文档（`lattice` 主仓库 `docs/superpowers/specs/2026-09-22-apple-embedded-sdk-design.md`）§四.1 定义的 `shim.Server` 全部方法（`NewServer`/`Dial`/`Listen`/`AddPeer`/`RemovePeer`/`Channel`/`Close`），对应该文档的里程碑 M0。§四.2-4.3（`apple/engine/embedded`、gomobile、Swift Package）不在本计划范围，依赖本计划先发布新版本后再单独立计划。
- **占位符扫描**：无 TBD/TODO；所有步骤含完整代码；gVisor API（`ReadContext`/`InjectInbound`/`ToView`/`NewViewWithData`）均已对照本机 module cache（`~/go/pkg/mod/github.com/google/gvisor@v0.0.0-20260508212337-96dad6a2da94`）核实签名存在。
- **类型一致性**：`Server` 的 `AddPeer`/`RemovePeer` 签名跟 `shim.PeerManager` 接口（`shim/wireguard.go`）逐字一致；`Dial`/`Listen` 返回类型跟 `Netstack.DialContext`/`Netstack.ListenTCP`（`shim/netstack_core.go`）一致；`NewServer` 的 `pm PeerManager` 是必填位置参数而非 functional option，这个决定在 Architecture 一节已说明原因（避免跟 `Sandbox` 的 `WithPeerManager` 选项重名）。

---

## 后续（不在本计划内）

`lattice` 主仓库这边（`apple/engine/embedded/` + gomobile 导出 + Swift Package）依赖本计划发布的新版本：

```bash
cd /Users/francis/workspc/lattice
go get github.com/alatticeio/lattice-shim@<本计划落地后的新 commit>
```

升级依赖之后，需要另开一份实现计划覆盖设计文档 §四.2-4.3 和 §七 M1-M3，届时需要先读一遍 `apple/engine/engine.go`、`apple/engine/peers.go`、`apple/engine/provisioner.go` 里现成的 NATS 注册/ICE-LRP 建连代码,以及确认现有 `apple/` 目录下 gomobile 构建脚本的位置和用法。
