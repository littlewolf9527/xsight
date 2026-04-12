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
6. [数据模型](#6-数据模型)
7. [前端架构](#7-前端架构)

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
| 4 | fragment | IP 分片 |
| 5-15 | (reserved) | 预留给未来的解码器（数组预分配以避免重建 BPF Map） |

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

1. **阶段匹配**：`on_detected` 动作在攻击确认时触发；`on_expired` 动作在攻击过期时触发。
2. **运行模式**：`once`（每次攻击触发一次）、`periodic`（在攻击存续期间每 N 秒触发一次）、`retry_until_success`（重试直到成功）。
3. **前置条件评估**：每个动作可以设置前置条件，按 12 个属性过滤（decoder、severity、domain、cidr、node、pps、bps、attack_type、dominant ports、unique source IPs）。所有条件使用 AND 逻辑——必须全部满足。
4. **首次匹配 ACL**：对于非 Webhook 类型（xDrop、BGP、Shell），每种类型仅执行第一个匹配的动作。Webhook 动作全部执行（多通道通知）。
5. **执行**：动作分派到对应的处理器（Webhook POST、Shell 执行、xDrop API 调用、vtysh 命令）。

### xDrop 执行

- **on_detected**（filter_l4 / rate_limit）：向 xDrop API 发送 POST 请求，携带规则载荷。响应中返回的 `rule_id` 作为 `external_rule_id` 存储在执行日志中。
- **on_expired**（unblock）：从该攻击的 on_detected 日志中查找所有 `external_rule_id` 条目，逐一向 xDrop API 发送 DELETE 请求。每个成功删除的规则都会生成独立的执行日志条目。
- **tcp_syn 自动注入**：当攻击解码器为 `tcp_syn` 时，引擎自动向 xDrop 规则载荷中添加 `protocol: tcp` 和 `tcp_flags: SYN,!ACK`。
- **自定义载荷**：支持动态变量展开——`{ip}`、`{dominant_src_port}`、`{dominant_dst_port}` 等。变量在执行时根据攻击记录和 Flow 分析数据解析。

### BGP 执行

- **on_detected**（announce）：构造 vtysh 命令：`configure terminal → router bgp {ASN} → address-family {auto} → network {prefix} route-map {name}`。
- **on_expired**（withdraw）：从执行日志中查找之前宣告的路由，逐一执行 `no network ...`。
- **自动 AFI**：地址族在运行时根据前缀 IP 版本通过 `net.ParseCIDR` / `net.ParseIP` 自动判断。IPv4 前缀使用 `ipv4 unicast`，IPv6 前缀使用 `ipv6 unicast`。单个 BGP 连接器同时处理两者。
- **外部规则 ID 格式**：`{prefix}|{route_map}`（使用 `|` 作为分隔符以避免与 IPv6 地址中的 `:` 冲突）。

### 延迟执行

xDrop 和 BGP 均支持攻击过期后的延迟移除：

1. 当 on_expired 事件触发且动作设置了 delay > 0 时，引擎写入一条 `scheduled` 执行日志条目，附带 `scheduled_for` 时间戳。
2. 启动一个可取消的延迟执行。如果延迟期间未被中断，则移除操作正常执行。
3. 如果攻击在延迟期间**再次触发**，所有该攻击的待执行延迟通过追踪器的再次触发回调被取消。
4. 如果运维人员**强制移除**某个特定制品，则仅取消该制品的延迟。
5. 延迟通过完整业务键标识：`(attack_id, action_id, connector_id, external_rule_id)`。

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

## 6. 数据模型

### 核心表

| Table | Purpose |
|-------|---------|
| `attacks` | 攻击记录，含 dst_ip (INET)、方向、解码器、严重程度、峰值 PPS/BPS、response_id、threshold_rule_id |
| `watch_prefixes` | 监控 IP 范围及模板绑定 |
| `threshold_templates` | 命名规则集合，含默认 response_id |
| `thresholds` | 检测规则：domain、direction、decoder、unit、value；可选逐规则 response_id 覆盖 |
| `responses` | 响应定义（动作容器） |
| `response_actions` | 动作：类型、触发阶段、连接器、延迟、paired_with、auto_generated |
| `action_execution_log` | 执行记录：trigger_phase、status、external_rule_id、connector_id、scheduled_for |
| `action_preconditions` | 逐动作过滤条件（attribute、operator、value） |
| `ts_stats` | 时序流量数据（TimescaleDB 超表，支持压缩） |
| `flow_logs` | 采样 Flow 数据，用于攻击指纹识别 |
| `config_audit_log` | 配置变更审计轨迹 |

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

---

## 7. 前端架构

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
| Attack Detail | `/attacks/:id` | 摘要 + 执行日志 + 传感器日志（Flow 数据） |
| Active Mitigations | `/mitigations` | BGP Routing + xDrop Filtering 标签页，含详情抽屉 |
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
