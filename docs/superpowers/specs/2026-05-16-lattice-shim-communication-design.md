# lattice-shim 通信设计

> 日期：2026-05-16
> 关联：`docs/design/2026-05-11-agent-sandbox-and-ecosystem-design.md`、`docs/design/2026-05-16-agent-sandbox-network-isolation-design.md`

## 背景

本文档综合 05-11 和 05-16 两份设计，给出 lattice-shim 的完整通信设计。

05-11 设计了 gVisor netstack ↔ wireguard-go 桥接核心，但缺少：
- 入站路径（其他 Agent 主动连接 sandbox）
- 出站访问控制（域名/CIDR 白名单）
- Workload 出站代理入口

05-16 补充了上述缺口，但引入了两个需要修正的问题：
- `WireGuardManager` 直接依赖 NATS（违反 shim 零 Lattice 依赖原则）
- `PolicyChecker.Allow()` 签名与 05-11 不一致

本设计解决上述冲突，给出统一接口和完整通信路径。

---

## 设计原则

- **零 Lattice 依赖**：shim 只引入 `gvisor.dev/gvisor` 和 `golang.zx2c4.com/wireguard`，不引入 NATS、CRD 或控制面任何类型
- **接口注入**：PolicyChecker 和 AuditWriter 由调用方（主 repo）注入实现
- **原子 peer 操作**：shim 暴露 `AddPeer`/`RemovePeer`，WireGuardManager 的 NATS 订阅逻辑留在主 repo
- **公网出口不在 shim 范围**：由 gateway peer 处理，shim 不感知

---

## 部署场景

宿主机进程模式：sandbox 进程直接在 Linux 宿主机上运行，Workload 是其子进程。

---

## 包结构

```
shim/
├── shim.go        Sandbox — 顶层组装器，New(overlayIP, opts...) 启动所有组件
├── netstack.go    NetstackBridge — gVisor netstack ↔ wireguard-go link endpoint
├── wireguard.go   WireGuard 原子 peer 操作（AddPeer/RemovePeer/SetPrivateKey）
├── forward.go     ForwardListener — overlay 入站端口转发
├── egress.go      EgressFilter — 出站访问控制，实现 PolicyChecker
├── socks5.go      SOCKS5Server — Workload 出站代理入口
├── policy.go      PolicyChecker interface
└── audit.go       AuditWriter interface + AuditEvent struct
```

---

## 核心接口

```go
// policy.go
type PolicyChecker interface {
    Allow(identity string, dstIP net.IP, dstPort uint16) bool
}

// audit.go
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

// wireguard.go — 主 repo 的 WireGuardManager 调这些原子操作
type WireGuardBind interface {
    AddPeer(pubKey [32]byte, allowedIPs []net.IPNet, endpoint string) error
    RemovePeer(pubKey [32]byte) error
    SetPrivateKey(key [32]byte) error
}

// shim.go — 顶层入口
type Sandbox struct { /* 内部组合所有组件 */ }

type Option func(*Sandbox)

func New(overlayIP net.IP, opts ...Option) (*Sandbox, error)
func WithPolicy(p PolicyChecker) Option
func WithAudit(w AuditWriter) Option
func WithForwardRule(overlayPort uint16, targetAddr string) Option
func WithSOCKS5(listenAddr string) Option
```

主 repo 使用示例：

```go
sb, _ := shim.New(overlayIP,
    shim.WithPolicy(myPolicyCache),   // 主 repo 实现
    shim.WithAudit(myAuditBatcher),   // 主 repo 实现
    shim.WithSOCKS5("127.0.0.1:1080"),
    shim.WithForwardRule(8080, "127.0.0.1:8080"),
)
sb.Start(ctx)

// 主 repo WireGuardManager 订阅 NATS 后调原子操作
sb.AddPeer(pubKeyB, allowedIPs, endpoint)
```

---

## 出站通信路径

Workload 子进程调用 overlay 内另一个 Agent 的服务：

```
┌─────────────────────────────────────────────────────────┐
│  宿主机 Sandbox 进程                                      │
│                                                         │
│  ┌─────────────────┐                                    │
│  │  Workload 子进程  │                                    │
│  │  ALL_PROXY=      │                                    │
│  │  socks5://       │                                    │
│  │  127.0.0.1:1080  │                                    │
│  └────────┬────────┘                                    │
│           │ CONNECT 10.100.0.2:8080                     │
│           ▼                                             │
│  ┌─────────────────────────────────────────────────┐   │
│  │  shim.SOCKS5Server (:1080)                      │   │
│  │  解析目标地址 → identity = sandbox-id            │   │
│  └─────────────────┬───────────────────────────────┘   │
│                    │                                    │
│                    ▼                                    │
│  ┌─────────────────────────────────────────────────┐   │
│  │  shim.EgressFilter                              │   │
│  │  PolicyChecker.Allow(identity,                  │   │
│  │                      10.100.0.2, 8080)          │   │
│  │                                                 │   │
│  │  命中 → 继续        未命中 → EPERM + Audit(drop) │   │
│  └─────────────────┬───────────────────────────────┘   │
│                    │ allow + Audit(allow)               │
│                    ▼                                    │
│  ┌─────────────────────────────────────────────────┐   │
│  │  shim.NetstackBridge                            │   │
│  │  DialContext(ctx, "tcp", "10.100.0.2:8080")     │   │
│  │  gVisor netstack 路由 → link endpoint           │   │
│  └─────────────────┬───────────────────────────────┘   │
│                    │ IP 包                              │
│                    ▼                                    │
│  ┌─────────────────────────────────────────────────┐   │
│  │  wireguard-go                                   │   │
│  │  查 AllowedIPs → 找到 peer(10.100.0.2)          │   │
│  │  ChaCha20 加密 → UDP :51820                     │   │
│  └─────────────────┬───────────────────────────────┘   │
└────────────────────┼────────────────────────────────────┘
                     │ UDP（加密 WireGuard 载荷）
                     ▼
             ICE P2P 直连 / LRP Relay
                     │
                     ▼
             远端 Sandbox（入站路径）
```

---

## 入站通信路径

另一个 Agent 主动连接本 Sandbox 的服务：

```
             远端 Sandbox（出站方）
                     │ UDP（加密 WireGuard 载荷）
                     ▼
┌─────────────────────────────────────────────────────────┐
│  宿主机 Sandbox 进程                                      │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │  wireguard-go (:51820)                          │   │
│  │  验证 peer 公钥 → ChaCha20 解密                  │   │
│  │  还原 IP 包 (src=10.0.0.2, dst=10.0.0.1)        │   │
│  └─────────────────┬───────────────────────────────┘   │
│                    │ IP 包注入 link endpoint             │
│                    ▼                                    │
│  ┌─────────────────────────────────────────────────┐   │
│  │  shim.NetstackBridge                            │   │
│  │  gVisor netstack 接收并重组 TCP 流               │   │
│  └─────────────────┬───────────────────────────────┘   │
│                    │ TCP accept                         │
│                    ▼                                    │
│  ┌─────────────────────────────────────────────────┐   │
│  │  shim.ForwardListener                           │   │
│  │  ListenTCP(overlayIP:8080)                      │   │
│  │  ForwardRule{ overlayPort: 8080,                │   │
│  │               targetAddr: "127.0.0.1:8080" }   │   │
│  └─────────────────┬───────────────────────────────┘   │
│                    │ dial("127.0.0.1:8080")             │
│                    ▼                                    │
│  ┌─────────────────┐                                   │
│  │  Workload 子进程  │                                   │
│  │  本地服务 :8080   │                                   │
│  └─────────────────┘                                   │
└─────────────────────────────────────────────────────────┘
```

入站路径**不经过 EgressFilter 和 PolicyChecker**——策略检查已在发起方（远端 Sandbox 出站时）完成。

---

## 完整端到端通信路径

```
控制面 (Lattice 主 repo)
┌─────────────────────────────────────────────────────────────────────┐
│  NATS NetMap 变更                                                    │
│       │                                                             │
│       ▼                                                             │
│  WireGuardManager          PolicyCache          AuditBatcher        │
│  (主 repo)                 (主 repo)            (主 repo)           │
│  sb.AddPeer(pubKey,        实现 PolicyChecker   实现 AuditWriter     │
│    allowedIPs, endpoint)   接口                 接口                │
└──────┬──────────────────────────┬───────────────────┬──────────────┘
       │ AddPeer                  │ 注入               │ 注入
       │                          │                   │
       ▼                          ▼                   ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│  Sandbox A (宿主机进程)                                                           │
│                                                                                  │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │  shim.Sandbox                                                             │  │
│  │                                                                           │  │
│  │  ┌─────────────┐   CONNECT       ┌──────────────────────────────────┐    │  │
│  │  │ Workload A  │ ─────────────→  │ SOCKS5Server (:1080)             │    │  │
│  │  │ (子进程)     │ dst=10.0.0.2:80 │                                  │    │  │
│  │  └─────────────┘                 └─────────────────┬────────────────┘    │  │
│  │                                                    │                     │  │
│  │                                                    ▼                     │  │
│  │                                  ┌──────────────────────────────────┐    │  │
│  │                                  │ EgressFilter                     │    │  │
│  │                                  │ PolicyChecker.Allow(             │    │  │
│  │                                  │   "sandbox-a", 10.0.0.2, 80)    │    │  │
│  │                                  │                                  │    │  │
│  │                                  │ drop → Audit(drop) + EPERM       │    │  │
│  │                                  │ allow → Audit(allow) ↓           │    │  │
│  │                                  └─────────────────┬────────────────┘    │  │
│  │                                                    │                     │  │
│  │                                                    ▼                     │  │
│  │  ┌─────────────────────────────→ ┌──────────────────────────────────┐    │  │
│  │  │ ForwardListener               │ NetstackBridge                   │    │  │
│  │  │ overlayIP:port                │ gVisor netstack (用户态 TCP/IP)  │    │  │
│  │  │ → Workload A 本地端口         │ DialContext / ListenTCP          │    │  │
│  │  │                               └─────────────────┬────────────────┘    │  │
│  │  │                                                 │ link endpoint       │  │
│  │  │                                                 ▼                     │  │
│  │  │                               ┌──────────────────────────────────┐    │  │
│  │  │                               │ wireguard-go                     │    │  │
│  │  │                               │ AddPeer: pubKey-B,               │    │  │
│  │  │                               │   allowedIPs=10.0.0.2/32        │    │  │
│  │  │                               │   endpoint=<B's UDP addr>        │    │  │
│  │  │                               │ ChaCha20 加密                    │    │  │
│  │  │                               └─────────────────┬────────────────┘    │  │
│  └──┼──────────────────────────────────────────────────────────────────────┘  │
└─────┼────────────────────────────────────────────────┼──────────────────────────┘
      │ 入站 UDP                                        │ 出站 UDP :51820
      │                                                 │
      │             ICE P2P 直连 / LRP Relay            │
      │ ◄─────────────────────────────────────────────  │
      │
┌─────┼──────────────────────────────────────────────────────────────────────────┐
│  Sandbox B (宿主机进程)                                                         │
│     │                                                                          │
│  ┌──┼──────────────────────────────────────────────────────────────────────┐  │
│  │  shim.Sandbox                                                           │  │
│  │  │                                                                      │  │
│  │  │  ┌──────────────────────────────────────────────────────────────┐   │  │
│  │  └→ │ wireguard-go                                                 │   │  │
│  │     │ 验证 peer-A 公钥 → ChaCha20 解密                             │   │  │
│  │     │ 还原 IP 包 (src=10.0.0.1, dst=10.0.0.2)                     │   │  │
│  │     └────────────────────────────┬─────────────────────────────────┘   │  │
│  │                                  │ 注入 link endpoint                   │  │
│  │                                  ▼                                      │  │
│  │     ┌──────────────────────────────────────────────────────────────┐   │  │
│  │     │ NetstackBridge                                               │   │  │
│  │     │ gVisor netstack 重组 TCP 流                                   │   │  │
│  │     └────────────────────────────┬─────────────────────────────────┘   │  │
│  │                                  │ TCP accept                           │  │
│  │                                  ▼                                      │  │
│  │     ┌──────────────────────────────────────────────────────────────┐   │  │
│  │     │ ForwardListener                                              │   │  │
│  │     │ ListenTCP(10.0.0.2:80)                                       │   │  │
│  │     │ → dial("127.0.0.1:80")                                       │   │  │
│  │     └────────────────────────────┬─────────────────────────────────┘   │  │
│  │                                  │                                      │  │
│  │                                  ▼                                      │  │
│  │     ┌─────────────┐                                                    │  │
│  │     │ Workload B  │ ← 收到来自 Sandbox A 的连接                        │  │
│  │     │ (子进程)     │                                                    │  │
│  │     └─────────────┘                                                    │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 路径汇总

| 路径 | 经过的 shim 组件 | 策略检查 | 审计 |
|------|----------------|---------|------|
| Workload → overlay | SOCKS5 → EgressFilter → NetstackBridge → WireGuard | 发起方 | allow/drop 均记录 |
| overlay → Workload | WireGuard → NetstackBridge → ForwardListener | 已在发起方完成 | 不重复记录 |
| 公网出口 | 不在 shim 范围，由 gateway peer 处理 | — | — |
| Peer 热更新 | 主 repo WireGuardManager → `sb.AddPeer()` | — | — |

---

## 与现有设计文档的关系

| 问题 | 本设计的决策 |
|------|------------|
| 05-11 PolicyChecker 签名 `pid uint32` vs 05-16 `identity string` | 采用 `identity string`，宿主机模式下 sandbox-id 比 PID 更稳定 |
| 05-16 WireGuardManager 引入 NATS 依赖 | WireGuardManager 留在主 repo，shim 只暴露 AddPeer/RemovePeer 原子操作 |
| 05-11 无入站路径 | 由 ForwardListener 补全 |
| 05-11 无出站代理入口 | 由 SOCKS5Server 补全 |
| 公网出口 | 不在 shim 范围，gateway peer 由主 repo 控制面配置 |

---

## 不在本设计范围

- 公网 gateway peer 的选择和路由策略
- Workload 网络隔离（路由截断、eBPF cgroup/connect4 透明代理）：宿主机模式下由调用方决定
- MCP Security Gateway、A2A 协议：控制面组件，独立设计
- Firecracker MicroVM：远期增强
