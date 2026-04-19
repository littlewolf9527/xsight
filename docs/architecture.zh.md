# xSight 架构指南

> 本文档为开发者、贡献者和高级运维人员介绍 xSight 的系统架构。
> 涵盖系统设计、数据流和关键子系统约定。
> 面向用户的配置与操作说明，请参阅[用户指南](user-guide.md)。

---

## 目录

1. [系统概览](#1-系统概览)
2. [Node 数据平面](#2-node-数据平面)
3. [Controller 控制平面](#3-controller-控制平面)
4. [动作执行引擎](#4-动作执行引擎)
5. [自动配对动作生命周期](#5-自动配对动作生命周期)
6. [动作状态层 (v1.2)](#6-动作状态层-v12)
7. [可观测性 (v1.2.1)](#7-可观测性-v121)
8. [数据模型](#8-数据模型)
9. [前端架构](#9-前端架构)

---

## 1. 系统概览

xSight 是一个分布式 DDoS 检测与响应平台，由两个核心组件构成：

```
                          ┌─────────────────────────────────────────────┐
                          │              Controller                     │
                          │                                             │
 ┌──────────┐  gRPC      │  ┌───────────┐  ┌───────────┐  ┌────────┐ │
 │  Node    │─────────────▶│ Ingestion  │─▶│ Detection │─▶│Tracker │ │
 │ (XDP)    │  StatsReport │  Pipeline   │  │  Engine   │  │        │ │
 └──────────┘             │  └───────────┘  └───────────┘  └───┬────┘ │
                          │        │                            │      │
 ┌──────────┐  gRPC      │        ▼                            ▼      │
 │  Node    │─────────────▶ Ring Buffer     ┌───────────────────────┐ │
 │ (Flow)   │  StatsReport │  + ts_stats DB  │   Action Engine      │ │
 └──────────┘             │                  │  (BGP/xDrop/Webhook/ │ │
                          │                  │   Shell)             │ │
                          │                  └───────────────────────┘ │
                          │                                             │
                          │  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
                          │  │ REST API │  │ ConfigPub│  │ Web UI   │ │
                          │  │ (Gin)    │  │ (gRPC)   │  │ (Vue SPA)│ │
                          │  └──────────┘  └──────────┘  └──────────┘ │
                          └─────────────────────────────────────────────┘
```

**Node** — 部署在流量观测点。以 XDP 模式捕获数据包，或以 Flow 模式接收流量导出数据。通过 gRPC 流式传输将每秒聚合统计数据上报给 Controller。

**Controller** — 中央控制大脑。接收流量数据、运行检测算法、跟踪攻击状态、执行响应动作、提供 Web UI 和 REST API 服务，并向 Node 推送配置。

### 通信协议

Node 通过 gRPC（默认端口 50051）与 Controller 通信。协议定义了五个 RPC 方法：

| Method | Type | Purpose |
|--------|------|---------|
| `Handshake` | Unary | Node 认证 + 初始配置交换 |
| `StatsStream` | Client streaming | 每秒聚合流量统计（主要检测路径） |
| `SampleStream` | Client streaming | 数据包采样投递，用于攻击分类（尽力而为） |
| `CriticalEventStream` | Client streaming | 低延迟事件驱动告警 |
| `ControlStream` | Bidirectional | 配置推送（Controller → Node）和确认回执（Node → Controller） |

主要检测路径使用 `StatsReport` 消息，包含每目的 IP 统计、每前缀聚合、全局计数器以及可选的 Top Flow 摘要。

### 模块划分

**Controller 包（`controller/internal/`）：**

| Package | Purpose |
|---------|---------|
| `ingestion` | gRPC 服务端，接收 Node 流量上报，写入环形缓冲区和数据库 |
| `store/ring` | 内存环形缓冲区，存储每秒实时流量快照 |
| `store/postgres` | PostgreSQL 数据访问层，含 Schema 迁移 |
| `engine/threshold` | 阈值继承树与每秒检测 Tick |
| `engine/baseline` | 动态基线分析与异常检测 |
| `engine/classifier` | 基于数据包采样的攻击类型分类 |
| `engine/dedup` | 基于解码器层级的告警去重 |
| `tracker` | 攻击状态机（confirming、active、expiring、expired） |
| `action` | 动作执行引擎（BGP、xDrop、Webhook、Shell） |
| `configpub` | 通过 gRPC ControlStream 向 Node 推送配置 |
| `api` | REST API 及内嵌 Vue SPA 服务 |
| `config` | 配置加载与校验 |
| `retention` | 后台过期数据清理 |
| `netutil` | IP/CIDR 工具函数 |
| `watchdog` | Systemd watchdog 集成 |

**Node 包（`node/internal/`）：**

| Package | Purpose |
|---------|---------|
| `bpf` | BPF 程序绑定（由 C 源码生成） |
| `config` | Node 配置与快照管理 |
| `collector` | 每秒读取 BPF Map，计算增量，导出统计 |
| `flow` | 流量聚合及 sFlow/NetFlow/IPFIX 监听 |
| `reporter` | gRPC 客户端连接 Controller，维护三条上报流 |
| `sampler` | 并行数据包解析流水线（Reader → Workers → Aggregator） |
| `watchdog` | Systemd watchdog 集成 |

---

## 2. Node 数据平面

### XDP 模式

BPF/XDP 程序（`node/bpf/xsight.c`）挂载到网络接口，在内核网络协议栈的最早入口处理每一个数据包。

**数据包解析流水线：**

```
Ethernet frame
  ├─ ETH_P_8021Q (0x8100) → strip VLAN tag → re-parse inner EtherType
  ├─ ETH_P_IP (0x0800) → IPv4 header → L4 protocol
  ├─ ETH_P_IPV6 (0x86DD) → IPv6 header → L4 protocol
  └─ ETH_P_ARP (0x0806) → skip (counted for health stats)

L4 protocol decoding:
  ├─ TCP (6) → extract ports, flags → SYN-only detection (tcp_syn decoder)
  ├─ UDP (17) → extract ports
  ├─ ICMP (1) / ICMPv6 (58) → extract type/code
  ├─ GRE (47) → ERSPAN II (0x88BE) / ERSPAN III (0x22EB) → decapsulate → re-parse inner frame
  └─ Fragment detection → fragment_offset > 0
```

**解码器数组：** 每个目的 IP 拥有一个固定大小的计数器数组（`decoder_counts[16]`），按解码器类型索引。权威索引注册表定义在 `shared/decoder/decoder.go` 中——下表仅为镜像，并非独立定义。

| Index | Decoder | Description |
|-------|---------|-------------|
| 0 | tcp | 所有 TCP 数据包 |
| 1 | tcp_syn | 设置了 SYN 标志且 ACK 未设置的 TCP 数据包 |
| 2 | udp | 所有 UDP 数据包 |
| 3 | icmp | ICMP 和 ICMPv6 |
| 4 | fragment | IP 分片（任意 `MF=1` 或 `offset≠0`） |
| 5 | tcp_ack | 设置了 ACK 但未设置 SYN 的 TCP 数据包 — 无状态 ACK flood 识别 |
| 6 | tcp_rst | 设置了 RST 位的 TCP 数据包 — RST flood |
| 7 | tcp_fin | 设置了 FIN 位的 TCP 数据包 — FIN flood / 扫描 |
| 8 | gre | IP 协议号 47 |
| 9 | esp | IP 协议号 50 |
| 10 | igmp | IP 协议号 2 |
| 11 | ip_other | 其他未单独计数的 IP 协议兜底 |
| 12 | bad_fragment | Ping of Death 特征（`offset×8 + payload > 65535`）或首片过小（塞不下 L4 头） |
| 13 | invalid | `IHL < 5` / `IP total_length < IHL×4` / TCP `doff < 5` |
| 14-15 | (reserved) | 预留给未来的解码器 — 数组预分配以避免重建 BPF Map |

> **注意：** 不存在单独的 `ip` 解码器槽位。IP 层聚合统计（总包数/字节数）通过父级的 `pkt_count` / `byte_count` 字段跟踪，而非解码器索引。阈值规则中使用的 `ip` 解码器名称映射到聚合计数器，而非 decoder_counts 槽位。

计数器同时记录每个解码器的包计数和字节计数。此外，数据包按大小分桶（小/中/大）以进行流量特征刻画。

**前缀匹配：** BPF 程序使用 LPM（最长前缀匹配）Trie 来判断 IP 地址所属的监控前缀。只有匹配到已注册前缀的 IP 才会计入逐 IP 统计；未匹配的数据包仍会计入全局计数器。

**双向支持（v2.11+）：** BPF 程序为入站（基于目的地址）和出站（基于源地址）流量维护独立的统计 Map。这使得系统既能检测 DDoS 攻击（入站），也能发现被入侵主机的异常行为（出站）。

### Flow 模式

在 Flow 模式下，Node 从路由器和交换机接收流量导出数据包，而非直接捕获原始数据包。Flow 解析器支持以下协议：

| Protocol | Port (default) | Notes |
|----------|----------------|-------|
| sFlow v5 | 6343 | Counter + Flow 采样 |
| NetFlow v5 | 2055 | 固定格式，结构简单 |
| NetFlow v9 | 2055 | 基于模板 |
| IPFIX | 4739 | 基于模板（NetFlow v10） |

Flow 监听器和数据源由 Controller 配置（不在 Node 配置文件中）。Node 通过 `ControlStream` gRPC 通道接收监听器配置，作为 `WatchConfig` 下发的一部分。

Flow 解析器提取的逐 IP 和逐前缀统计与 XDP 模式类似，并应用采样率修正以产生准确的 PPS/BPS 数值。

**两种模式的能力差异：**

| Capability | XDP Mode | Flow Mode |
|-----------|----------|-----------|
| `StatsStream` (per-second stats) | Yes | Yes |
| `SampleStream` (raw packet samples) | Yes | No |
| Attack classifier (sample-driven type identification) | Yes | No |
| Top flows / flow_logs | Yes (from BPF ring buffer samples) | Yes (from flow records) |
| Sensor Logs (5-tuple breakdown in attack detail) | Yes | Yes |
| Per-packet TCP flags inspection | Yes | Depends on flow export fields |

Flow 模式不产生原始 `SampleBatch` 消息。攻击分类器（基于数据包级检查升级攻击类型）仅在 XDP 模式下可用。Flow 模式的攻击保留基于解码器检测的初始分类结果。

### Node → Controller 上报

每秒，Node 向 Controller 发送一条 `StatsReport` 消息，包含：

- **逐目的 IP 统计**：包含每解码器细分的包/字节计数
- **逐前缀聚合统计**：前缀级别总量及活跃 IP 数
- **逐源 IP 统计**：出站流量跟踪（用于 sends 检测）
- **全局统计**：总包数/字节数、匹配包数（监控前缀范围内）
- **Top Flow**：Top-N 五元组流聚合（用于流量指纹识别）
- **采样指标**：Ring 填充率、内核丢包、解码错误（Flow 模式下，这些字段复用于 Flow 摄取健康指标，如未知导出器数量和模板未命中次数）
- **Node 健康状态**：healthy / degraded / unhealthy

---

## 3. Controller 控制平面

### 数据摄取

数据摄取流水线处理传入的 `StatsReport` 消息：

1. **gRPC 处理器** 接收流式消息并验证 Node 身份。
2. **环形缓冲区写入器** 将逐 IP 和逐前缀数据点存入内存滑动窗口（每个 IP 每个 Node 每秒一个数据点）。
3. **数据库写入器** 批量积攒数据点，每 5 秒刷写到 `ts_stats` 表，用于长期存储和历史图表。
4. **Flow 写入器** 将 Top Flow 采样存入 `flow_logs` 表，用于攻击指纹识别（传感器日志）。

环形缓冲区是实时检测的主要数据源。数据库用于仪表盘、流量概览图表和基线计算。

### 检测引擎

检测引擎运行**每秒一次的 Tick 循环**：

1. **阈值树** 将每个已注册的前缀映射到其解析后的阈值规则集（包括从父前缀继承的规则）。
2. 对每个已连接的 Node 和每个前缀，引擎从环形缓冲区读取最新数据点。
3. **子网规则** 针对前缀级别的聚合值（该前缀的总 PPS/BPS）进行评估。
4. **内部 IP 规则** 针对前缀内的每个独立 IP 进行逐一评估。
5. 当规则被触发时，事件经过**告警去重**处理（抑制解码器层级中的冗余告警——例如，`tcp` 告警会抑制同一 IP 上同时触发的 `ip` 告警）。
6. 去重后的事件送入**攻击追踪器**。

### 动态基线

基线系统根据历史数据计算正常流量画像：

1. **小时级 P95 计算**：从 `ts_stats` 中为每个（Node、前缀）对计算 PPS 和 BPS 的第 95 百分位值。
2. **EWMA 平滑**：应用指数加权移动平均，生成稳定的基线，使其逐步适应流量变化。
3. **偏离检测**：当当前流量超过 `baseline * deviation_multiplier` 时，触发动态阈值告警。
4. **推荐值**：基线引擎基于历史画像提供推荐的静态阈值。

### 攻击追踪器

攻击追踪器通过状态机管理每次攻击的生命周期：

```
                    sustained breach
  [Not Detected] ──────────────────▶ [Confirming]
                                         │
                               confirm_seconds elapsed
                                         │
                                         ▼
                                    [Active] ◀──── re-breach ────┐
                                         │                       │
                              traffic drops below threshold       │
                                         │                       │
                                         ▼                       │
                                   [Expiring] ───────────────────┘
                                         │
                              expiry_interval elapsed
                                         │
                                         ▼
                                    [Expired]
```

状态转换触发回调：
- **Confirming → Active**：`on_detected` 事件 → 动作引擎触发 on_detected 动作。
- **Expiring → Active**（再次触发）：取消待执行的延迟撤回/解封操作。
- **Expiring → Expired**：`on_expired` 事件 → 动作引擎触发 on_expired 动作。

追踪器支持两种过期模式：
- **静态模式**：固定过期间隔（可配置，默认 300 秒）。
- **动态模式**：过期间隔随攻击持续时间弹性伸缩（持续时间越长，过期定时器越长，上限为可配置的最大倍数）。

### 配置下发

Controller 通过双向 `ControlStream` 向 Node 推送配置：

1. 当前缀、阈值或 Flow 监听器发生变更时，Controller 递增**下发版本号**。
2. 新的 `WatchConfig`（前缀列表 + 阈值 + Flow 监听器配置）发送给所有已连接的 Node。
3. 每个 Node 应用配置后，回送携带已应用版本号的 `ConfigAck`。
4. Controller 跟踪每个 Node 的 `config_status`（`synced` / `pending` / `failed`），并单独暴露**下发偏移**（即当前版本与已应用版本的差值）。

---

## 4. 动作执行引擎

当追踪器触发攻击事件时，动作引擎决定要执行哪些操作。

### 响应解析

解析路径取决于攻击方向：

**入站攻击（`receives`）：**
1. 检查攻击的 `threshold_rule_id`——如果触发规则设置了逐规则 `response_id`，则使用该响应。
2. 否则，回退到前缀的阈值模板 `response_id`。
3. 如果未找到任何响应，则仅通知全局 Webhook 连接器。

**出站攻击（`sends`）：**
1. 检查触发规则的逐规则 `response_id`——如果已设置，则使用该响应。
2. **不进行模板级别回退。** 出站攻击不继承模板的默认响应。这是有意为之——模板默认响应通常配置为入站缓解（BGP/xDrop），不应应用于出站流量。
3. 如果未设置逐规则响应，则仅通知全局 Webhook 连接器。

### 动作分派

引擎按 `(trigger_phase, priority)` 排序遍历响应中的动作：

1. **`action_engine.mode` 闸门**——全局 `action_engine.mode` 配置（`observe` | `auto`，默认 `observe`）仅对 xDrop 动作生效。`observe` 模式下所有 xDrop 动作以 `skip_reason=mode_observe` 跳过；BGP / Webhook / Shell 不受此设置影响。要启用 xDrop 封锁，需在 `config.yaml` 中显式设置 `mode: auto`。
2. **阶段匹配**：`on_detected` 动作在攻击确认时触发；`on_expired` 动作在攻击过期时触发。
3. **运行模式**：`once`（每次攻击触发一次）、`periodic`（在攻击存续期间每 N 秒触发一次）、`retry_until_success`（重试直到成功）。
4. **前置条件评估**：每个动作可以设置前置条件，按 `decoder`、`severity`、`domain`、`carpet_bomb`（`domain eq subnet` 的别名）、`cidr`、`node`、`pps`、`bps`、`attack_type`、dominant ports、unique source IPs 等属性过滤。所有条件使用 AND 逻辑——必须全部满足。
5. **首次匹配 ACL**：对于非 Webhook 类型（xDrop、BGP、Shell），每种类型仅执行第一个匹配的动作。Webhook 动作全部执行（多通道通知）。
6. **xDrop decoder 兼容闸门 (v1.2.1)**：首次匹配后，若 `action_type=xdrop` 且攻击的 `decoder_family` 不在 xDrop 兼容白名单（`tcp`、`tcp_syn`、`udp`、`icmp`、`fragment`）中，则以 `skip_reason=decoder_not_xdrop_compatible` 跳过该动作。`ip` decoder 被有意排除——它是 L3 聚合，若下发会退化为整前缀黑洞。此类攻击应使用 BGP null-route。
7. **执行**：动作分派到对应的处理器（Webhook POST、Shell 执行、xDrop API 调用、vtysh 命令）。

所有跳过结果都会写入 `action_execution_log` 的 `status=skipped` 行，并附带结构化 `skip_reason` 列。Prometheus `xsight_action_skip_total{skip_reason}` 计数器镜像每条跳过日志，运维可直接查速率而无需拉日志行。

### xDrop 执行

- **on_detected**（filter_l4 / rate_limit）：向 xDrop API 发送 POST 请求。返回的 `rule_id` 作为 `external_rule_id` 同时写入 `action_execution_log` 和 `xdrop_active_rules`（v1.2 权威状态表，见第 6 节）。
- **on_expired**（unblock）：查询该攻击的 `xdrop_active_rules` 行，逐一调用 xDrop API DELETE。每次成功删除都会在规则行上盖 `withdrawn_at` 并写入逐制品日志条目。
- **tcp_syn 自动注入**：当攻击解码器为 `tcp_syn` 时，引擎自动注入 `protocol: tcp` 和 `tcp_flags: SYN,!ACK`。
- **协议归一化 (v1.2.1)**：xDrop 的 `protocol` 字段只接受枚举 `{all, tcp, udp, icmp, icmpv6}`。xSight 在载荷产生时会把 `tcp_syn → tcp`、`fragment → all` 归一化。`ip` decoder 在分派步骤 6 的兼容闸门处已被拒绝。
- **自定义载荷**：支持动态变量展开——`{ip}`、`{dominant_src_port}`、`{dominant_dst_port}` 等。变量在执行时根据攻击记录和 Flow 分析数据解析。

### BGP 执行（Wanguard 风格共享公告）

v1.2 将 BGP 公告视为一个**以 `(prefix, route_map, connector_id)` 为业务键、带引用计数的资源**，而不是每攻击一次的副作用。多个攻击落到同一 prefix + route-map 时，会复用同一条 FRR 路由；仅当最后一个攻击解绑时才真正撤回。

**Attach 路径（on_detected）**：
1. `Attach(prefix, route_map, connector_id, attack_id, action_id, delay_minutes)` 运行在对业务键 `SELECT … FOR UPDATE` 的事务里。
2. 若无既有行，INSERT `bgp_announcements`（`status=announcing`、`refcount=1`）+ `bgp_announcement_attacks`，返回 `NeedAnnounce=true`。
3. 若已有行，递增 `refcount`、插入 `bgp_announcement_attacks`，返回 `NeedAnnounce=false`——调用方**不再**执行 vtysh。
4. 仅在 `NeedAnnounce=true` 时执行 `configure terminal → router bgp {ASN} → address-family {auto} → network {prefix} route-map {name}`。成功后行转为 `active`。

**Detach 路径（on_expired）**：
1. `Detach(announcement_id, attack_id)` 递减 `refcount`，并在 `bgp_announcement_attacks` 行盖 `detached_at`。
2. 若减完后 `refcount > 0`，公告保持 `active`——还有其他攻击依赖这条路由。
3. 若 `refcount == 0`，公告进入 `delayed`（若有效延迟 > 0）或 `withdrawing`（延迟为 0）。**有效延迟 = 本 cycle 内所有已 attach 攻击的 `delay_minutes` 最大值**（见下面 Cycle-Sticky MAX Delay）。
4. 延迟到期且期间没有新 attach，则执行 `no network …` 并转为 `withdrawn`。

**自动 AFI**：地址族在运行时根据前缀 IP 版本自动判断。IPv4 用 `ipv4 unicast`、IPv6 用 `ipv6 unicast`。单个 BGP 连接器同时处理两者。

**执行日志中的业务键**：`external_rule_id = {prefix}|{route_map}`（`|` 分隔符避免与 IPv6 地址的 `:` 冲突）。公告的 DB `id` 通过 `announcement_id` 列附带在每条 `action_execution_log` 上。

**Cycle-Sticky MAX Delay**：多个攻击共享同一公告时，有效撤回延迟 = 本次公告 cycle 内（从 `announced_at` 到最后一次把 refcount 降为 0 的 `Detach`）所有 attach 攻击 `delay_minutes` 的最大值。cycle 中途加入、延迟较短的攻击**无法**缩短已锁定的较长延迟；反之加入更长的延迟会延长 MAX。每个攻击的延迟快照记录在 `bgp_announcement_attacks.delay_minutes`，便于 cycle 后审计。

### 延迟执行（持久化）

xDrop 和 BGP 的延迟移除在 v1.2 中通过 `scheduled_actions` 表**持久化**，能跨 Controller 重启：

1. on_expired 触发且延迟 > 0 时，引擎在 `scheduled_actions` 中写入 `status=pending`、`scheduled_for={now + delay}`、完整业务键 `(attack_id, action_id, connector_id, external_rule_id)` 的行。BGP 行还携带 `announcement_id`。
2. 启动一个可取消的内存 timer。触发时将行翻为 `status=executing`（`MarkExecuting`），执行移除，然后通过 `Complete` / `Fail` 转为 `completed` / `failed`。
3. 攻击在延迟期间**再次触发**时，该攻击的所有 pending 行被标记为 `status=cancelled`、`cancel_reason=rebreach`。
4. 运维**强制移除**某个制品时，仅取消该制品对应的行（`cancel_reason=force_remove`）。
5. 启动时 `RecoverScheduledActions` 扫描 pending 行：`scheduled_for > now` 的 re-arm、已过期的立即 fire；`reconcileExecutingSchedules` 重试 `executing` 中悬挂的行（在 `MarkExecuting` 后、`Complete` 前崩溃）。结果计入 Prometheus `xsight_scheduled_actions_recovered_total{outcome}`（`armed`、`overdue_fired`、`executing_retried`）。

### 手动覆盖（强制移除）

运维人员可以在活跃缓解页面强制移除 BGP 路由或 xDrop 规则：

1. 首先执行实际的移除操作（vtysh 撤回或 xDrop DELETE）。
2. 写入一条 `manual_override` 执行日志条目，携带该制品的业务键。
3. 当攻击后续自然过期时，on_expired 处理器**逐制品**检查是否存在 manual_override 日志——如果存在，则跳过该特定制品。
4. 同一动作或攻击下的其他制品不受影响。

---

## 5. 自动配对动作生命周期

当创建 `trigger_phase: on_detected` 的 xDrop 或 BGP 动作时，系统自动创建匹配的 `on_expired` 子动作。

### 数据模型

- 父动作（on_detected）存储 `paired_with = child.id`。
- 子动作（on_expired）标记 `auto_generated = true`。
- 关联是单向的：父 → 子。子动作不引用父动作。

### CRUD 同步

| Operation on parent | Effect on child |
|--------------------|-----------------| 
| Create (xDrop/BGP on_detected) | Auto-create matching on_expired (unblock/withdraw) |
| Update (connector, delay, targets, enabled) | Propagate changes to child |
| Disable | Child also disabled |
| Enable | Child also enabled |
| Delete | Child deleted first, then parent |

父子 CRUD 操作在失败时包含补偿回滚——如果子操作失败，父操作通过应用层补偿回滚（而非单个数据库事务）。

### 执行日志与状态推导

活跃缓解页面从 `action_execution_log` 条目推导制品状态：

| Log State | Derived Status |
|-----------|---------------|
| on_detected success + attack active + no on_expired | **Active** |
| on_detected success + attack expired + scheduled_for in future | **Delayed** |
| on_detected success + attack expired + no on_expired | **Pending** |
| on_expired success (matching external_rule_id) | **Removed** (filtered from view) |
| on_expired failed | **Failed** |
| manual_override success | **Removed** |

每次成功的撤回/解封都会写入一条**逐制品**的执行日志条目，携带匹配的 `external_rule_id`，确保状态推导能正确识别已移除的条目。

---

## 6. 动作状态层 (v1.2)

v1.2 之前，活跃缓解页面从 `action_execution_log` 扫描出制品状态——这种日志派生查询在并发 attach/detach 时脆弱，且无法跨 Controller 重启保留状态。v1.2 引入显式的**动作状态层**，用专门的状态表作为单一事实之源。日志表保留为 append-only 审计，但 UI / API 查询改为直接读状态表。

### 状态表

| 表 | 用途 | 关键列 |
|---|---|---|
| `bgp_announcements` | 逐公告生命周期，带引用计数 | `prefix`、`route_map`、`connector_id`、`status`、`refcount`、`delay_minutes`、`announced_at`、`withdrawn_at` |
| `bgp_announcement_attacks` | 攻击 ↔ 公告的多对一映射 | `announcement_id`、`attack_id`、`action_id`、`delay_minutes`、`attached_at`、`detached_at` |
| `bgp_announcement_events` | 审计流水（announce/attach/detach/delay_started/withdrawn/orphan_detected） | `announcement_id`、`event_type`、`attack_id`、`detail`、`created_at` |
| `xdrop_active_rules` | 逐 xDrop 规则生命周期 | `attack_id`、`action_id`、`connector_id`、`external_rule_id`、`status`、`delay_started_at`、`delay_minutes`、`withdrawn_at` |
| `scheduled_actions` | 持久化的延迟任务（xdrop_unblock、bgp_withdraw） | `action_type`、`attack_id`、`action_id`、`external_rule_id`、`announcement_id`、`scheduled_for`、`status`、`cancel_reason` |
| `action_manual_overrides` | 运维强制移除审计（用于 on_expired 抑制） | `attack_id`、`action_id`、`connector_id`、`external_rule_id`、`created_by` |

`bgp_announcements.status` 枚举：`announcing` → `active` → (`delayed`|`withdrawing`) → `withdrawn` | `failed` | `orphan` | `dismissed` | `dismissed_on_upgrade`。

`xdrop_active_rules.status` 枚举：`active` → (`delayed`|`withdrawing`) → `withdrawn` | `failed`。

`scheduled_actions.status` 枚举：`pending` → `executing` → `completed` | `cancelled` | `failed`。

### FRR 孤儿检测（启动扫描）

Controller 启动时，`BootstrapBGPOrphans` 执行一次：

1. 对每个已注册的 BGP 连接器，通过 vtysh 查询当前 BGP RIB（`show bgp ipv4/ipv6 unicast`）。
2. 对每条 FRR 中存在、**但在 `bgp_announcements` 中没有 refcount > 0 的 active 行匹配**的前缀，向 `bgp_announcements` 插入一条孤儿标记行。
3. v1.2 首次启动（无历史公告记录）时，孤儿以 `status=dismissed_on_upgrade` 写入——这代表 v1.2 前残留的、xSight 并未创建的路由，不应声明所有权。运维可以在 UI 中审阅，选择采纳、撤回或保持 dismissed。
4. 后续启动时，新出现的孤儿（FRR 里有、xSight 无对应攻击）以 `status=orphan` 写入。运维可用 `POST /api/active-actions/bgp/orphan-force-withdraw` 或 `/orphan-dismiss` 解决。
5. 已被运维 dismiss 的行不会再被反复打扰——bootstrap 只覆盖 `withdrawn` 状态的行。

这填补了 v1.2 前的盲区：FRR 中可能存在比 xSight 存活更久的路由（如 announce 和 DB 写之间崩溃），此前无可视化。

### UI 状态派生

活跃缓解页面直接查状态表，不再扫日志：

- **BGP tab**：`SELECT FROM bgp_announcements WHERE status IN ('active', 'delayed', 'withdrawing', 'orphan')`。
- **xDrop tab**：`SELECT FROM xdrop_active_rules WHERE status IN ('active', 'delayed', 'withdrawing')`。
- **详情抽屉执行时间线**：BGP 合并 `bgp_announcement_events`；xDrop 合成 `action_execution_log` + `action_manual_overrides` 行。

### action-log 上的 bgp_role

因为一条 BGP 公告可以服务多个攻击，`GET /api/attacks/:id/action-log` 返回时会在每条 BGP on_detected 日志行上附加 `bgp_role` 字段：

| bgp_role | 含义 |
|---|---|
| `triggered` | 本攻击是当前 cycle 中首个 attach 的——真正触发 vtysh announce 副作用的就是本攻击。 |
| `attached_shared` | 本攻击加入了已经 `active` 的公告（refcount 已 ≥1），无 vtysh 副作用。 |
| （空） | 非 BGP on_detected 行，或公告查询失败。 |

`triggered` 攻击的判定方式：对 `bgp_announcement_attacks` 按 `(attached_at ASC, attack_id ASC)` 排序，取第一条。应用判定前先用 cycle 过滤器（`attached_at >= announced_at`）排除前一轮 cycle 的幽灵 attach。返回体还带上 `announcement_id` 和 `announcement_refcount`，供 UI 渲染"共享于 N 个攻击"类的 tooltip。

---

## 7. 可观测性 (v1.2.1)

### Prometheus `/metrics` 端点

Controller 在 `GET /metrics` 暴露 Prometheus 抓取端点。**按惯例不做认证**（与 kube-apiserver / etcd / Prometheus 自身一致）——依赖网络层隔离。

注册表在启动时由 `metrics.Register()` 填充。默认的 `promhttp.Handler()` 还会免费暴露 Go runtime 和 process 指标。

**Counter（调用点内联 +1）：**

| 指标 | Labels | 语义 |
|---|---|---|
| `xsight_vtysh_ops_total` | `operation`、`result` | vtysh announce/withdraw 结果。`operation ∈ {announce, withdraw}`、`result ∈ {success, failed, idempotent}`。`idempotent` = FRR 在 withdraw 时报告路由不存在，xSight 吞成功。 |
| `xsight_action_executions_total` | `action_type`、`status` | 动作分派结果。`action_type ∈ {bgp, xdrop, webhook, shell}`、`status ∈ {success, failed, timeout, skipped, scheduled}`。 |
| `xsight_action_skip_total` | `skip_reason` | `status=skipped` 的明细视图。`skip_reason ∈ {mode_observe, precondition_not_matched, first_match_suppressed, decoder_not_xdrop_compatible, manual_override_suppressed, force_removed}`。 |
| `xsight_scheduled_actions_recovered_total` | `outcome` | `scheduled_actions` 启动恢复结果。`outcome ∈ {armed, overdue_fired, executing_retried}`。`executing_retried` 非零是事故信号（MarkExecuting 与 Complete 之间崩溃）。 |

**Custom Collector（scrape 时读 DB，永远新鲜的 gauge）：**

| 指标 | Labels | 来源 |
|---|---|---|
| `xsight_bgp_announcements` | `status` | `SELECT status, count(*) FROM bgp_announcements GROUP BY status` |
| `xsight_xdrop_rules` | `status` | `SELECT status, count(*) FROM xdrop_active_rules GROUP BY status` |
| `xsight_scheduled_actions` | `status` | `SELECT status, count(*) FROM scheduled_actions GROUP BY status` |

每个 collector 有 5 秒 context timeout。查询报错时 collector 对该 scrape 不输出样本（Prometheus 标准的"collector error"信号），而不是返回 HTTP 500。

**攻击追踪 gauge（封装 `tracker.Tracker` 内的原子计数器）：**

| 指标 | 类型 | 来源 |
|---|---|---|
| `xsight_attacks_active` | Gauge | `tracker.ActiveCount()` |
| `xsight_attacks_created_total` | Counter | `tracker.CreatedTotal` |
| `xsight_attacks_suppressed_total` | Counter | `tracker.SuppressedTotal`（去重抑制） |
| `xsight_attacks_evicted_total` | Counter | `tracker.EvictedTotal`（容量上限触顶——非零代表要调大 `max_active_attacks`） |

### 埋点方式

引擎通过一个很薄的 decorator（`metrics.InstrumentStore`）在 `main.go` 里安装一次，把 `store.Store` 包一层。只有 `ActionExecLog().Create()` 路径被包——它用日志行自己的字段 +1 `xsight_action_executions_total{action_type, status}`。其他调用点原样透传。这样指标就是 DB 持久化写入的一个副作用（单一事实之源），日志行和计数器永远不会打架。

### xDrop Decoder 兼容闸门

xDrop 工作在 L4（protocol + 5-tuple）。L3 聚合的 decoder（`ip`）无法安全地翻译为 xDrop 规则——`protocol=all` 配合 `dst_ip` 匹配，在 flow 分析未能收窄 `dominant_src_port` / `dominant_dst_port` 时，会退化为整前缀黑洞。v1.2.1 因此强制执行兼容白名单：

| Decoder | xDrop 兼容 | 理由 |
|---|---|---|
| `tcp` | 是 | 映射到 `protocol=tcp` |
| `tcp_syn` | 是 | 映射到 `protocol=tcp` + `tcp_flags=SYN,!ACK` |
| `udp` | 是 | 映射到 `protocol=udp` |
| `icmp` | 是 | 映射到 `protocol=icmp`（或 `icmpv6`） |
| `fragment` | 是 | 归一化为 `protocol=all`；分片流量本身就是明确的攻击信号 |
| `ip` | **否** | L3 聚合——改用 BGP null-route |

`decoder_family` 不在白名单中的攻击，其 xDrop 动作以 `skip_reason=decoder_not_xdrop_compatible` 跳过。BGP / Webhook / Shell 不受影响。

---

## 8. 数据模型

### 核心表

| Table | Purpose |
|-------|---------|
| `attacks` | 攻击记录，含 dst_ip (INET)、方向、解码器、严重程度、峰值 PPS/BPS、response_id、threshold_rule_id |
| `watch_prefixes` | 监控 IP 范围及模板绑定 |
| `threshold_templates` | 命名规则集合，含默认 response_id |
| `thresholds` | 检测规则：domain、direction、decoder、unit、value；可选逐规则 response_id 覆盖 |
| `responses` | 响应定义（动作容器） |
| `response_actions` | 动作：类型、触发阶段、连接器、延迟、paired_with、auto_generated |
| `action_execution_log` | append-only 审计，记录每次分派：trigger_phase、status、skip_reason、external_rule_id、connector_id、scheduled_for |
| `action_preconditions` | 逐动作过滤条件（attribute、operator、value） |
| `ts_stats` | 时序流量数据（TimescaleDB 超表，支持压缩） |
| `flow_logs` | 采样 Flow 数据，用于攻击指纹识别 |
| `config_audit_log` | 配置变更审计轨迹 |

### 动作状态表 (v1.2)

生命周期语义见[第 6 节](#6-动作状态层-v12)。

| 表 | 用途 |
|---|---|
| `bgp_announcements` | 逐公告状态（共享、带引用计数）。`(prefix, route_map, connector_id)` 唯一 |
| `bgp_announcement_attacks` | 攻击 → 公告的 N:1 映射。PK `(announcement_id, attack_id)` |
| `bgp_announcement_events` | 活跃缓解详情抽屉用的 append-only 审计 |
| `xdrop_active_rules` | 逐 xDrop 规则状态。`(attack_id, action_id, connector_id, external_rule_id)` 唯一 |
| `scheduled_actions` | 持久化的延迟 withdraw/unblock 任务（跨重启存活） |
| `action_manual_overrides` | 运维强制移除审计，用于逐制品的 on_expired 抑制 |

### 附加表

| Table | Purpose |
|-------|---------|
| `nodes` | 已注册的 Node 代理，含模式、下发版本、配置状态 |
| `users` | 用户账户，密码使用 bcrypt 哈希，角色为 admin/operator/viewer |
| `webhook_connectors` | Webhook 集成端点 |
| `xdrop_connectors` | xDrop API 端点 |
| `shell_connectors` | Shell 命令配置 |
| `bgp_connectors` | BGP 连接器配置（ASN、vtysh 路径） |
| `flow_listeners` | 每 Node 的 Flow 模式监听器配置 |
| `flow_sources` | 每监听器的 Flow 导出设备 |
| `response_action_xdrop_targets` | 动作与 xDrop 连接器的多对多映射 |
| `dynamic_detection_config` | 基线检测参数 |
| `prefix_profiles` | 逐前缀小时级流量画像，用于基线 |

### 关键字段

**`external_rule_id`**：标识外部缓解制品。
- BGP：`{prefix}|{route_map}`（如 `10.0.0.1/32|DIVERT`）。使用 `|` 作为分隔符以避免与 IPv6 地址中的 `:` 冲突。
- xDrop：xDrop API 返回的规则 ID（如 `rule_abc123`）。

**`scheduled_for`**：延迟撤回/解封的预定执行时间戳。用于 UI 倒计时显示和状态推导。

**`paired_with`**：on_detected 动作上指向自动生成的 on_expired 动作 ID。单向关联。

**`auto_generated`**：自动配对创建的 on_expired 动作上的布尔标记。这些动作不可手动编辑或删除。

**逐规则 `response_id`**：位于 `thresholds` 表。设置后，覆盖该特定规则触发的攻击的模板默认响应。允许在同一模板内为入站和出站检测规则配置不同的响应。

**`bgp_announcements.refcount`**：当前 attach 的攻击数。仅当 `refcount` 降到 0 时，公告才能进入 `delayed`/`withdrawing`。并发 Attach/Detach 通过业务键上的 `SELECT … FOR UPDATE` 序列化——同一公告上 attach 与 detach 的竞态无法撕裂状态。

**`bgp_announcement_attacks.delay_minutes`**：attach 时从源动作 `bgp_withdraw_delay_minutes` 快照的值。用于计算 cycle-sticky MAX 延迟，以及 cycle 后审计（哪个攻击贡献了哪段延迟）。

**`scheduled_actions.announcement_id`**：BGP 撤回行指向被撤回的 `bgp_announcements.id`。调度器可藉此在 vtysh 调用的同时把公告行原子地翻成 `withdrawing`/`withdrawn`。

---

## 9. 前端架构

### 技术栈

| Component | Version | Purpose |
|-----------|---------|---------|
| Vue | 3.5 | 响应式 UI 框架 |
| Element Plus | 2.13 | UI 组件库 |
| Pinia | 3.0 | 状态管理 |
| vue-i18n | 9.14 | 国际化（EN / ZH） |
| ECharts | 6.0 | 流量图表与可视化 |
| vue-router | 4.6 | 客户端路由 |
| Vite | 8.0 | 构建工具 |
| axios | 1.13 | API 请求 HTTP 客户端 |

### 嵌入方式

Vue SPA 构建输出到 `controller/web/dist/`，通过 Go 的 `//go:embed` 指令嵌入 Controller 二进制文件。无需单独的 Web 服务器——Controller 在提供 REST API 的同时直接服务 SPA。

### 主题系统

支持两套主题，可在运行时通过顶栏下拉菜单切换：

- **Classic**：简洁专业的设计风格，灵感来源于 Stripe 的仪表盘美学。
- **Amber**：复古终端美学，数字显示使用 DSEG14 14 段 LCD 字体。

主题通过 CSS 自定义属性（`--xs-*` 变量）实现。切换主题时更新根元素的 `data-theme` 属性，从而切换变量集。

### 国际化

所有 UI 文本外部化在 `i18n/en.js` 和 `i18n/zh.js` 中。语言可在运行时通过顶栏下拉菜单切换。所选语言持久化在本地存储中。

### 主要页面

| Page | Route | Description |
|------|-------|-------------|
| Dashboard | `/` | 统计卡片 + 活跃攻击表 + 流量趋势 |
| Traffic Overview | `/traffic-overview` | 时序图表，支持前缀/Node/方向筛选 |
| Attacks | `/attacks` | 活跃 + 历史攻击列表，支持详情下钻 |
| Attack Detail | `/attacks/:id` | 摘要 + 执行日志（含 BGP Role 列）+ 逐攻击 Force Remove 按钮 + 传感器日志 |
| Active Mitigations | `/mitigations` | BGP Routing + xDrop Filtering 标签页，含详情抽屉。BGP 标签页还会显示 `orphan` 公告 |
| Nodes | `/nodes` | Node 列表，显示状态、配置同步、Flow 配置 |
| Watch Prefixes | `/prefixes` | 前缀管理及模板绑定 |
| Templates | `/templates` | 阈值模板列表 + 含规则的详情弹窗 |
| Responses | `/responses` | 响应详情，含 on_detected / on_expired 动作区域 |
| Dynamic Detection | `/dynamic-detection` | 基线配置与画像状态 |
| Connector Settings | `/settings/*` | Webhook、xDrop、Shell、BGP 连接器管理 |
| Users | `/users` | 用户账户管理 |
| Audit Log | `/audit` | 配置变更历史 |

### 活跃缓解详情抽屉

缓解页面提供**详情抽屉**，点击表格行即可展开，显示内容包括：

1. **头部**：制品类型 + 外部规则 ID + 状态徽标。
2. **摘要**：攻击链接、目标 IP、连接器、创建时间、计时器（已用时 / 倒计时）。
3. **配置**：类型相关字段（BGP：前缀 + route map；xDrop：动作 + 协议 + 标志位）。
4. **执行时间线**：该制品所有执行日志条目的纵向时间线，使用彩色圆点标识：
   - 绿色：成功
   - 黄色：已计划
   - 红色：失败
   - 蓝色：手动覆盖

### API 客户端

前端使用 axios 配合集中式 API 模块。认证通过存储在本地存储中的 JWT 令牌处理。同时支持 API Key 认证以满足编程访问需求。API 模块自动注入 JWT 认证头、统一规范化响应错误，并在收到 401（令牌过期/无效）时重定向到登录页面。
