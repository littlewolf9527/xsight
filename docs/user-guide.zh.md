# xSight 用户指南

> xSight 是一个基于 XDP/eBPF 和流量分析的分布式 DDoS 检测与响应平台。
> 本指南涵盖安装、配置与日常运维操作。

---

## 目录

1. [快速开始](#1-快速开始)
2. [节点管理](#2-节点管理)
3. [监控前缀](#3-监控前缀)
4. [检测配置](#4-检测配置)
5. [响应配置](#5-响应配置)
6. [连接器配置](#6-连接器配置)
7. [监控与运维](#7-监控与运维)
8. [常见场景](#8-常见场景)
9. [API 参考](#9-api-参考)
10. [故障排查](#10-故障排查)

---

## 1. 快速开始

> **预估时间**（假设依赖已安装完成）：
> - 基础观测（流量 + 检测）：约 15 分钟
> - 完整缓解流水线（BGP + xDrop）：额外 30-60 分钟

### 1.1 系统要求

| 组件 | 要求 |
|-----------|-------------|
| OS | Debian 12+ / Ubuntu 22.04+（XDP 模式需要 Linux 内核 5.15+） |
| Go | 1.22+ |
| PostgreSQL | 17，需安装 TimescaleDB 扩展 |
| Node.js | 20+（用于构建 Web UI） |
| FRR | 10+（可选，BGP 响应动作需要） |
| xDrop | （可选，xDrop 响应动作需要） |

### 1.2 安装 Controller

**编译：**

```bash
cd controller
go build -o bin/xsight-controller .
```

**配置** — 将 `config.example.yaml` 复制为 `config.yaml` 并编辑：

```yaml
listen:
  grpc: ":50051"      # Node ingestion (gRPC)
  http: ":8080"        # Web UI + REST API

database:
  driver: "postgres"
  dsn: "postgres://xsight:YOUR_PASSWORD@localhost:5432/xsight?sslmode=disable"

auth:
  api_key: "YOUR_API_KEY"

action_engine:
  mode: "auto"         # 重要：默认为 "observe" — xDrop 动作会被跳过
                       # 设为 "auto" 才会启用 xDrop 封锁
                       # （BGP、Webhook、Shell 动作不受 mode 控制，始终执行）
```

> **注意：** 如果 `action_engine.mode` 未配置或设为 `"observe"`，**xDrop 响应动作将不会执行**——引擎记录攻击但跳过所有 xDrop 动作。BGP、Webhook、Shell 动作不受此配置影响，仍然正常执行。必须显式设置 `mode: "auto"` 才能启用自动 xDrop 封锁。

完整参数说明请参阅 `config.example.yaml`。

**以 systemd 服务启动：**

```bash
sudo cp deploy/xsight-controller.service /etc/systemd/system/
sudo systemctl enable --now xsight-controller
```

### 1.3 安装 Node

#### XDP 模式

XDP 模式使用 eBPF 直接在网络接口上抓取数据包，需要 root 权限和 Linux 内核 5.15+。

```bash
cd node
make build
```

**配置**（`config.yaml`）：

```yaml
node_id: "my-node-01"
interfaces:
  - name: "ens3"
    mode: "mirror"
    upstream_sample_rate: 1000
    sample_bytes: 128
bpf:
  max_entries: 1000000
controller:
  address: "controller-ip:50051"
auth:
  node_api_key: "YOUR_NODE_KEY"
```

#### Flow 模式

Flow 模式接收 sFlow / NetFlow v5/v9 / IPFIX，无需 BPF 编译。

**Node config.yaml**（最小配置 — Listener 和 Source 在 Controller Web UI 中配置）：

```yaml
node_id: "flow-node-01"
mode: "flow"              # Required — without this, the node defaults to XDP mode and fails

controller:
  address: "controller-ip:50051"
auth:
  node_api_key: "YOUR_NODE_KEY"
```

> **注意：** 如果 Flow 节点没有配置任何 Listener/Source，它会成功连接但不会采集任何流量。节点连接后，必须在 Controller Web UI 中配置 Flow Listener 和 Flow Source。

**启动：**

```bash
sudo cp deploy/xsight-node.service /etc/systemd/system/
sudo systemctl enable --now xsight-node
```

> Node 服务以 root 运行，因为 XDP 模式需要 `CAP_NET_ADMIN` 权限。systemd 单元文件中设置了 `LimitMEMLOCK=infinity` 以支持 BPF map 内存分配。

### 1.4 首次登录

1. 在浏览器中打开 `http://controller-ip:8080`。
2. 使用默认凭据登录：**admin** / **admin**。
3. **请立即修改默认密码：** 进入 **Settings > Users**，点击 admin 用户的 **Edit** 按钮。
4. 使用右上角标题栏切换主题（Classic / Amber）和语言（EN / ZH）。

### 1.5 基础观测（约 15 分钟）

Controller 和至少一个 Node 运行后：

1. **注册节点：** 进入 **Nodes**（侧边栏 > INFRASTRUCTURE > Nodes）。点击 **Add Node**，输入 Node ID 和 API Key（必须与节点 `config.yaml` 中的一致），选择模式（XDP 或 Flow），点击 **Create**。然后启动节点服务。节点连接成功后状态将显示为 **Online**。

   > **注意：** 必须先在 Controller 中注册节点，再启动节点进程。gRPC 握手会拒绝未注册的节点。

2. **添加监控前缀：** 进入 **Watch Prefixes**（侧边栏 > INFRASTRUCTURE > Watch Prefixes）。点击 **Add Prefix**，输入 CIDR（如 `198.51.100.0/24`），填写名称，点击 **Create**。

3. **创建阈值模板：** 进入 **Templates**（侧边栏 > DETECTION > Templates）。点击 **Create**，输入名称如 "BasicProtection"。点击新模板打开详情页。

4. **添加检测规则：** 在模板详情页中，点击 **+ Add Rule**。设置：
   - Domain: `subnet`
   - Direction: `Receives (Inbound)`
   - Decoder: `ip`
   - Unit: `pps`
   - Comparison: `Over`
   - Value: `100000`
   - Inheritable: 启用
   - 点击 **Create**。

5. **将模板绑定到前缀：** 返回 **Watch Prefixes**，点击你的前缀的 **Edit**，在 **Template** 下拉框中选择 "BasicProtection"，点击 **Save**。

流量数据现在会显示在 **Dashboard** 和 **Traffic Overview** 页面。当流量超过 100K PPS 时，攻击将出现在 **Attacks** 页面。

### 1.6 完整缓解流水线（额外约 30 分钟）

启用自动 BGP + xDrop 响应：

1. **创建连接器** — 进入侧边栏的 **Settings**，配置至少一个 BGP Connector 和/或 xDrop Connector。参见 [第 6 节](#6-连接器配置)。

2. **创建响应：** 进入 **Responses**（侧边栏 > DETECTION > Responses）。点击 **Add Response**，输入名称如 "Production Response"，点击 **Create**。

3. **添加动作：** 点击新响应打开详情页。在 **When Attack Detected** 区域，点击 **+ Add Action**：
   - BGP：Action Type 设为 "BGP"，选择你的连接器，设置 Route Map（如 `DIVERT`），按需设置 Withdraw Delay。点击 **Save**。
   - xDrop：Action Type 设为 "xDrop"，选择 Action "Filter L4"，在 Filter Fields 中勾选 "Dst IP"，按需设置 Unblock Delay。添加前置条件 `Domain = internal_ip` 以限制 xDrop 仅作用于单主机攻击。点击 **Save**。

4. **绑定响应：** 进入 **Templates**，打开你的模板，在 **Default Response** 下拉框中选择你的响应。

当攻击触发时，前往 **Active Mitigations** 页面（侧边栏 > MONITORING > Active Mitigations）查看实时 BGP 路由和 xDrop 规则。

---

## 2. 节点管理

导航路径：**侧边栏 > INFRASTRUCTURE > Nodes**

### 2.1 XDP 模式

XDP 模式将 BPF 程序附加到网络接口上，实现线速数据包检测。

**适用场景：** 直接镜像端口、SPAN 端口或 ERSPAN 隧道，需要逐包精度的场景。当前节点配置模式包括 `mirror` 和 `erspan`。

**Node config.yaml 参数：**

| 参数 | 说明 | 默认值 |
|-----------|-------------|---------|
| `node_id` | 唯一节点标识符 | （必填） |
| `interfaces[].name` | 网络接口名称 | （必填） |
| `interfaces[].mode` | `mirror`（仅接收）或 `erspan` | （必填） |
| `interfaces[].upstream_sample_rate` | 1:N 数据包采样（1 = 不采样） | `1` |
| `interfaces[].sample_bytes` | 每包采集字节数（128-512） | `256` |
| `bpf.max_entries` | BPF map 大小，用于 IP 跟踪 | `1000000` |
| `parse_workers` | 数据包解析线程数 | NumCPU/2 |

### 2.2 Flow 模式

Flow 模式从路由器和交换机接收 sFlow、NetFlow v5/v9 或 IPFIX。

**适用场景：** 已有 Flow 导出基础设施，或不便部署 XDP 的环境。

Flow 模式的节点 `config.yaml` 只需 `node_id`、`mode: flow`、`controller` 和 `auth`。**Flow Listener 和 Flow Source 在 Controller Web UI 中配置**，不在节点本地配置文件中。没有配置 Listener/Source 的 Flow 节点会连接成功但不会采集任何流量。

1. 进入 **Nodes**，在列表中点击 Flow 节点。
2. 点击 **Flow Config** 按钮。
3. **添加 Flow Listener：** 设置监听地址（如 sFlow 使用 `0.0.0.0:6343`）和协议模式（`auto`、`sflow`、`netflow` 或 `ipfix`）。
4. **在 Listener 下添加 Flow Source：** 输入每台导出 Flow 数据的路由器/交换机的设备 IP，可选覆盖采样率。

### 2.3 节点状态

Nodes 页面显示：

| 列名 | 说明 |
|--------|-------------|
| Node ID | 唯一标识符 |
| Mode | XDP 或 Flow |
| Status | Online（绿色）/ Offline（灰色） |
| Config Status | Synced / Pending / Failed |
| Drift | 当前配置版本与已应用版本的差异 |
| Last ACK | 节点最后一次确认配置推送的时间 |

如果节点持续显示 **Pending** 或 **Drift** 值较高，请检查到 gRPC 端口 50051 的网络连通性，并验证节点 API Key 是否正确。

---

## 3. 监控前缀

导航路径：**侧边栏 > INFRASTRUCTURE > Watch Prefixes**

### 3.1 概念

**Watch Prefix** 是 xSight 监控的 IP 范围（IPv4 或 IPv6 CIDR）。每个前缀可以绑定一个 **Threshold Template**（阈值模板）来定义检测规则。

前缀支持父子层级关系。例如，`198.51.100.0/22` 作为父前缀，`198.51.100.0/24` 作为子前缀 — 父模板上标记为 **Inheritable** 的规则会传递给子前缀。

### 3.2 添加前缀

点击 **Add Prefix** 并填写：

| 字段 | 说明 |
|-------|-------------|
| Prefix (CIDR) | IP 范围，如 `198.51.100.0/24` 或 `2001:db8::/32` |
| Name | 显示名称 |
| IP Group | 可选的分组标签 |
| Parent Prefix | 可选的父前缀，用于规则继承 |
| Template | 要绑定的阈值模板 |

### 3.3 全局前缀（0.0.0.0/0）

全局前缀监控所有已注册前缀的聚合流量，作为流量异常的兜底检测。

**限制：**
- 不能绑定包含 xDrop 或 BGP 动作的 Response（防止意外全局黑洞）。
- 仅支持 `subnet` 域规则（不支持 `internal_ip`）。
- 使用 `0.0.0.0/0` 作为全局前缀 — 它同时覆盖 IPv4 和 IPv6 流量。`::/0` 不受支持，API 会拒绝。

---

## 4. 检测配置

导航路径：**侧边栏 > DETECTION > Templates**

### 4.1 阈值模板

**Threshold Template**（阈值模板）是一组命名的检测规则集合。点击列表中的任意模板打开其详情页。

详情页显示：
- **Default Response** — 攻击触发时执行的响应（可从下拉框选择）。
- **Used By** — 哪些前缀引用了此模板。
- **Rules table** — 所有检测规则及其参数。

### 4.2 规则参数

在模板详情页中点击 **+ Add Rule** 创建规则。每条规则定义一个条件，当条件持续满足（默认 3 秒）时，确认攻击。

| 参数 | 选项 | 说明 |
|-----------|---------|-------------|
| Domain | `internal_ip` / `subnet` | `internal_ip`：逐主机检测（攻击报告为 /32 或 /128）。`subnet`：对整个前缀进行聚合检测。 |
| Direction | `Receives (Inbound)` / `Sends (Outbound)` | `Receives` 用于入站 DDoS。`Sends` 用于出站攻击/扫描检测。 |
| Decoder | `ip` / `tcp` / `tcp_syn` / `udp` / `icmp` / `fragment` | 协议过滤器。`ip` 匹配所有协议。`tcp_syn` 仅匹配 SYN TCP 包。 |
| Unit | `pps` / `bps` / `pct (%)` | 每秒包数、每秒比特数或总流量百分比。 |
| Comparison | `Over` / `Under` | 流量超过（Over）或低于（Under）阈值时触发。 |
| Value | 数值 | 阈值。 |
| Inheritable | 开/关 | 启用后，子前缀继承此规则。 |

**生产环境规则示例：**

| Domain | Direction | Decoder | Unit | Value | 用途 |
|--------|-----------|---------|------|-------|---------|
| subnet | Receives | ip | pps | 100,000 | 整体入站 PPS |
| subnet | Receives | ip | bps | 1,000,000,000 | 入站 1 Gbps |
| subnet | Receives | udp | pps | 1,000,000 | UDP 洪水 |
| subnet | Receives | tcp_syn | pps | 1,000,000 | SYN 洪水 |
| internal_ip | Sends | ip | bps | 500,000,000 | 出站单主机 500 Mbps |

### 4.3 规则级响应覆盖

每条规则在规则表中都有独立的 **Response** 下拉列。设置后，该规则触发的攻击会使用指定的 Response，覆盖模板的 Default Response。

**常见用法：** 入站规则使用模板默认响应（BGP + xDrop），而出站（Sends）规则覆盖为仅 Webhook 的 Response。

### 4.4 动态检测（基线）

导航路径：**侧边栏 > DETECTION > Dynamic Detection**

动态检测根据历史数据计算每个前缀的流量基线，当流量显著偏离时发出告警。启用后可配置偏差阈值和最小稳定周数等参数。

### 4.5 检测工作原理

1. **每秒**，检测引擎对所有前缀评估其规则。
2. 当流量超过阈值并持续**确认期**（默认 3 秒）后，攻击被确认。
3. 攻击进入 **Active** 状态，记录到数据库，并触发已配置的 Response。
4. 当流量降至阈值以下，攻击进入 **Expiring** 状态并开始倒计时（默认 300 秒）。
5. 如果在倒计时期间流量再次突破阈值，攻击回到 **Active** 状态（re-breach）。
6. 倒计时结束后，攻击变为 **Expired**，on_expired 动作触发。

**严重等级**自动分类：

| 严重等级 | 条件 |
|----------|-----------|
| Critical | PPS > 1M **或** BPS > 10 Gbps |
| High | PPS > 100K **或** BPS > 1 Gbps |
| Medium | PPS > 10K **或** BPS > 100 Mbps |
| Low | 其他所有情况 |

---

## 5. 响应配置

导航路径：**侧边栏 > DETECTION > Responses**

### 5.1 概念

**Response** 是一组 **Action**（动作）的集合。点击列表中的响应打开其详情页。

详情页分为两个区域：
- **When Attack Detected** — 攻击确认时触发的动作。
- **When Attack Expired** — 攻击结束时触发的动作。

### 5.2 创建动作

在任一区域中点击 **+ Add Action**。Action Editor 对话框包含以下字段：

**通用字段（所有动作类型）：**

| 字段 | 说明 |
|-------|-------------|
| Action Type | `Webhook` / `xDrop` / `Shell` / `BGP` |
| Connector | 使用哪个连接器（下拉选择） |
| Priority | 执行优先级（1-10，数字越小优先级越高） |
| Run Mode | `Once` / `Periodic` / `Retry Until Success` |
| Execution | `Automatic` / `Manual` |
| Enabled | 开/关切换 |

**xDrop 专属字段：**

| 字段 | 说明 |
|-------|-------------|
| xDrop Action | `Filter L4`（阻断）/ `Rate Limit` / `Unblock` |
| Filter Fields | 复选框：Dst IP、Src IP、Dst Port、Src Port、Protocol — 勾选的字段作为规则匹配条件 |
| Rate Limit (PPS) | 限速值（仅限 Rate Limit 动作） |
| Target Nodes | 目标 xDrop 连接器（空 = 全部） |
| Unblock Delay (min) | 攻击过期后，等待多少分钟再移除规则（0-1440） |

> **xDrop decoder 适用范围 (v1.2.1)：** xDrop 动作只对 decoder 为 `tcp`、`tcp_syn`、`udp`、`icmp` 或 `fragment` 的攻击下发。decoder 为 `ip`（L3 聚合）的攻击会被跳过——这类攻击请使用 BGP 动作。跳过在动作日志中记录为 `skip_reason=decoder_not_xdrop_compatible`。

**BGP 专属字段：**

| 字段 | 说明 |
|-------|-------------|
| Route Map | FRR route-map 名称（如 `RTBH`、`DIVERT`） |
| Withdraw Delay (min) | 攻击过期后，等待多少分钟再撤回路由（0-1440） |

**Shell 专属字段：**

| 字段 | 说明 |
|-------|-------------|
| Extra Arguments | 传递给脚本的额外命令行参数 |

**前置条件**（对话框底部）：

点击 **+ Add Condition** 添加过滤条件。只有匹配**所有**条件（AND 逻辑）的攻击才会触发该动作。

| 属性 | 说明 | 示例 |
|-----------|-------------|---------|
| Decoder | 协议类型 | `= udp` — 仅 UDP 攻击 |
| Attack Type | 初始分类 | `= syn_flood` |
| Severity | 严重等级 | `in critical,high` |
| PPS | 峰值包/秒 | `> 100000` |
| BPS | 峰值比特/秒 | `> 1000000000` |
| Domain | 单主机或子网 | `= internal_ip` — 仅 /32 或 /128 攻击 |
| CIDR | 前缀长度 | `= 32` — 仅单 IP |
| Node | 上报节点 | `in sg-mirror-01,hk-mirror-01` |
| Dominant Src Port | 最多源端口 | `= 53` — DNS 反射 |
| Dominant Dst Port | 最多目标端口 | `= 80` — HTTP 攻击 |
| Dominant Src Port % | 源端口集中度 | `>= 80` |
| Unique Src IPs | 不同源 IP 数 | `> 1000` |

### 5.3 自动配对动作

在 "When Attack Detected" 下创建 **xDrop** 或 **BGP** 动作时，系统会**自动生成**一个匹配的 "When Attack Expired" 动作：

- xDrop Filter L4 / Rate Limit → 自动创建 xDrop Unblock
- BGP announce → 自动创建 BGP withdraw

无需手动创建清理动作。自动生成的动作：
- 从父动作复制连接器、延迟和目标设置。
- 修改父动作时自动更新。
- 删除父动作时自动删除。
- 不能直接编辑（通过 on_detected 端的父动作管理）。

> **注意：** 在 "When Attack Expired" 下的 Action Type 下拉框中不会显示 xDrop 和 BGP — 它们通过配对机制自动管理。

### 5.4 延迟

延迟用于防止过早移除缓解措施。攻击者常在防护解除后恢复攻击。

- **Unblock Delay**：设置在 xDrop 动作上。攻击过期后，xDrop 规则继续保持 N 分钟后自动移除。
- **Withdraw Delay**：设置在 BGP 动作上。BGP 路由继续保持 N 分钟后撤回。

延迟期间，**Active Mitigations** 页面会将该条目显示为 **Delayed** 并附带倒计时。如果在延迟期间攻击再次突破阈值，倒计时取消，缓解措施继续保持。

### 5.5 首次匹配 ACL

对于 xDrop、BGP 和 Shell 动作，每种类型仅执行**第一个匹配**的动作（按优先级排序）。这实现了类似 ACL 的规则：

- Priority 1：xDrop filter，前置条件 `Decoder = tcp_syn`
- Priority 2：xDrop filter，无前置条件（兜底）

SYN 洪水攻击匹配 Priority 1 并跳过 Priority 2。UDP 洪水攻击跳过 Priority 1 并匹配 Priority 2。

**例外：** 所有匹配的 Webhook 动作都会执行，不受优先级限制。

---

## 6. 连接器配置

导航路径：**侧边栏 > SETTINGS**

### 6.1 Webhook 连接器

路径：**Settings > Webhook Connectors**

| 字段 | 说明 |
|-------|-------------|
| Name | 显示名称 |
| URL | 接收通知的 HTTP 端点 |
| Headers | 自定义请求头，JSON 格式（如 `{"Authorization": "Bearer xxx"}`） |
| Timeout (ms) | 请求超时时间 |
| Global | 启用后，所有攻击事件自动发送，无需绑定 Response |

点击 **Test** 验证连通性。

### 6.2 xDrop 连接器

路径：**Settings > xDrop Connectors**

| 字段 | 说明 |
|-------|-------------|
| Name | 显示名称 |
| API URL | xDrop REST API 基础 URL（如 `http://10.0.0.1:8000/api/v1`） |
| API Key | 认证密钥 |
| Timeout (ms) | 请求超时时间（如 xDrop 有节点同步，建议 30000） |

点击 **Test** 验证连通性。

### 6.3 Shell 脚本连接器

路径：**Settings > Shell Scripts**

| 字段 | 说明 |
|-------|-------------|
| Name | 显示名称 |
| Command | 可执行文件路径（如 `/usr/local/bin/mitigate.sh`） |
| Default Args | 默认参数 |
| Timeout (ms) | 执行超时时间 |

### 6.4 BGP 连接器

路径：**Settings > BGP Connectors**

| 字段 | 说明 |
|-------|-------------|
| Name | 显示名称 |
| BGP ASN | 你的自治系统号 |
| vtysh Path | vtysh 二进制文件路径（默认：`/usr/bin/vtysh`） |

**自动 AFI：** 连接器自动根据被攻击前缀检测 IPv4 或 IPv6，并在 vtysh 命令中使用正确的 address-family。单个连接器同时处理 IPv4 和 IPv6 — 无需分别配置。

**前置条件：** 需安装 FRR 并启用 `bgpd`。使用连接器前，请先在 FRR 中配置 ASN 和 route-map。

点击 **Test** 验证 FRR 连通性。点击 **Routes** 查看当前 BGP 路由表。

---

## 7. 监控与运维

### 7.1 Dashboard

路径：**侧边栏 > MONITORING > Dashboard**

Dashboard 提供实时概览，包含四个统计卡片：
- **Active Attacks** — 点击跳转到 Attacks 页面。
- **Nodes** — 总数及在线/离线分布。
- **Watch Prefixes** — 监控前缀总数。
- **Thresholds** — 活跃检测规则总数。

卡片下方是 **Active Attacks** 表格，显示当前攻击的目标 IP、Decoder、严重等级、峰值、触发规则和计时器。

### 7.2 Traffic Overview

路径：**侧边栏 > MONITORING > Traffic Overview**

时序流量图表，支持按前缀、节点、方向和时间范围进行筛选。

### 7.3 Attacks

路径：**侧边栏 > MONITORING > Attacks**

**Active Attacks** 标签页显示正在进行的攻击：
- 目标 IP、Direction（Inbound/Outbound）、Decoder、Attack Type、Severity
- **Peak** — 在有峰值 PPS 数据时显示 PPS，否则显示 BPS
- **Trigger Rule** — 检测到攻击的模板和规则
- **Timer** — 显示 "Breaching"（阈值仍被超过）或倒计时（即将过期）
- **Expire** 按钮 — 手动结束攻击

**All Attacks** 标签页提供分页历史记录。

**Attack Detail**（点击任意攻击行）：
- 摘要：IP、Decoder、严重等级、峰值、开始/结束时间、上报节点
- **Actions Log**：该攻击触发的所有动作及其状态、连接器、耗时、错误信息。对 BGP `on_detected` 条目，**BGP Role** 列会标明本攻击是真正触发 vtysh 的那一个（`triggered`），还是加入了别的攻击已建立的共享公告（`attached`）。逐攻击 **Force Remove** 按钮允许在不影响其他 attach 攻击的情况下，把本攻击从共享 BGP 公告解绑，或删除其 xDrop 规则（见 [§ 7.4 Active Mitigations](#74-active-mitigations)）。
- **Sensor Logs**：采样流数据 — Top 源 IP、源端口、目标端口及五元组流量明细

### 7.4 Active Mitigations

路径：**侧边栏 > MONITORING > Active Mitigations**

此页面显示所有当前活跃的 BGP 路由和 xDrop 过滤规则，分为两个标签页。

**BGP Routing 标签页：**
列：Attack ID、Prefix、Route Map、BGP Connector、Announced At、Timer、Status、Actions（Force Withdraw）

**xDrop Filtering 标签页：**
列：Attack ID、Dst IP、Rule ID、Action（drop/rate_limit）、Protocol、TCP Flags、xDrop Connector、Created At、Timer、Status、Actions（Force Unblock）

**状态含义：**

| 状态 | 颜色 | 含义 |
|--------|-------|---------|
| Active | 绿色 | 缓解措施活跃，攻击进行中 |
| Delayed | 黄色 | 攻击已结束，等待延迟计时器后自动移除 |
| Pending | 黄色 | 攻击已结束，移除已排队 |
| Failed | 红色 | 尝试移除但失败 |

**Timer 列：** Active 条目显示已持续时间。Delayed 条目显示剩余倒计时。

**详情抽屉：** 点击任意行打开侧面板，包含：
- **Summary**：攻击链接、目标 IP、连接器、创建时间、计时器
- **Configuration**：BGP（Prefix、Route Map）或 xDrop（Action、Protocol、TCP Flags、Dst IP）
- **Execution Timeline**：该制品所有执行事件的时间线（on_detected、scheduled、on_expired、manual_override），带彩色状态指示点

**强制移除：** 点击 **Force Withdraw**（BGP）或 **Force Unblock**（xDrop）立即移除缓解措施。强制移除后，该特定制品的自动 on_expired 动作将被抑制。

> **共享 BGP 公告 (v1.2)：** 多个攻击触发同一 `(prefix, route_map)` 组合时，它们共享同一条 BGP 公告。公告的 refcount 表示当前 attach 的攻击数量。在 Active Mitigations 页面执行 Force Withdraw 会**把所有 attach 攻击一起解绑**并撤回公告。若只想解绑单个攻击而不影响共享路由，请在 Attack Detail 页面使用逐攻击的 Force Remove 按钮。

**Orphan 公告 (v1.2)：** Controller 启动时会扫 FRR 路由，找出 xSight 里没有对应攻击的条目（v1.2 升级前遗留 或 崩溃残留）。这些条目在 BGP tab 中以 `Orphan` 状态出现。v1.2 首次升级时原有路由会被标为 `Dismissed on Upgrade`——xSight 不会声明所有权。可通过行菜单的 **Force Withdraw** / **Dismiss** 操作处理它们。

### 7.5 可观测性（`/metrics`）

Controller 在 `GET /metrics`（端口 8080，**无需认证**——依赖网络层隔离）暴露 Prometheus 抓取端点。在 Prometheus 中添加抓取配置：

```yaml
scrape_configs:
  - job_name: xsight-controller
    scrape_interval: 15s
    static_configs:
      - targets: ["controller-ip:8080"]
```

适合配告警的关键指标：

| 指标 | 告警思路 |
|------|----------|
| `xsight_attacks_evicted_total` | 非零 → 需要调大 `max_active_attacks` |
| `xsight_scheduled_actions_recovered_total{outcome="executing_retried"}` | 重启后非零 → MarkExecuting / Complete 间崩溃（事故信号） |
| `xsight_action_skip_total{skip_reason="decoder_not_xdrop_compatible"}` | 激增 → 运维把 `ip` decoder 攻击配给了 xDrop（应改用 BGP） |
| `xsight_bgp_announcements{status="orphan"}` | 非零 → FRR 里有 xSight 不认识的路由，需在 UI 中处理 |
| `xsight_vtysh_ops_total{result="failed"}` | 速率告警 → FRR 连通性故障 |

完整指标目录见 [architecture.zh.md § 7 可观测性](architecture.zh.md#7-可观测性-v121)。

### 7.6 审计日志

路径：**侧边栏 > SETTINGS > Audit Log**

记录所有配置变更和手动操作。可按实体类型、时间范围和用户筛选。

---

## 8. 常见场景

### 8.1 UDP 反射攻击

**症状：** 来自知名源端口（53、123、11211）的大量入站 UDP 流量。

**配置：**
1. **模板规则：** Domain `subnet`，Direction `Receives`，Decoder `udp`，Unit `pps`，Value `1000000`。
2. **包含两个动作的 Response：**
   - BGP（on_detected）：Route Map `DIVERT`，Withdraw Delay `5 min`。
   - xDrop（on_detected）：Filter L4，勾选 Dst IP，前置条件 `Domain = internal_ip`，Unblock Delay `5 min`。

**效果：** 攻击检测到 → BGP 路由宣告 + 为每个单主机目标创建 xDrop 丢弃规则。攻击结束 → 5 分钟延迟 → BGP 撤回 + xDrop 规则移除。

### 8.2 SYN 洪水（分层防御）

**症状**：大量 TCP SYN 包打向服务，后端 SYN queue 被撑满，新连接建立失败。

**架构说明**：xSight/xdrop **不**在清洗层做 SYN cookie。scrub-and-return 部署拓扑下（xdrop 只看 ingress，egress 从 ASN 内直接出公网），无状态 SYN cookie 会导致后端收到凭空的 ACK → RST，合法连接被断。分层防御才是正确做法：

| 层 | 职责 | 谁做 |
|---|---|---|
| L1 pps 削峰（防 NIC / 上联被淹）| 把 SYN 速率削到后端能处理的量级 | **xdrop** (`rate_limit` / `drop` / CIDR blacklist) + **xSight** (BGP RTBH 核选项) |
| L4 握手保护（防 SYN queue 耗尽）| Cookie 验证合法连接 | **客户 Linux 内核** (`net.ipv4.tcp_syncookies=1`，Debian/Ubuntu/RHEL 6 以来默认开) |
| L7 应用层 | 应用级防护 | 客户 WAF / 应用 |

**客户侧配置建议**：确认后端 `net.ipv4.tcp_syncookies=1`（执行 `sysctl net.ipv4.tcp_syncookies` 查；值 1 = "SYN queue 满时启用"，生产推荐；值 2 = "始终启用"，会无谓地损 TCP 选项，不推荐）。

**配置（xSight 阶梯响应）**：
1. **模板规则**：Decoder `tcp_syn`，Unit `pps`，Value `1000000`（按后端 SYN 处理能力调）
2. **Response 带阶梯 action**（用 v1.1 auto-pair + delay 机制）：
   - priority 1，on_detected，`xdrop rate_limit` 在阈值 ~50%（轻限速，误伤小）
   - priority 2，on_detected，`action_delay_minutes: 2`，`xdrop drop` + precondition `tcp_flags: SYN,!ACK`（轻限没救就硬丢 SYN）
   - priority 3，on_detected，`action_delay_minutes: 10`，`bgp announce` + RTBH route-map（核选项：上游把 victim IP 整个 blackhole）

**效果**：当攻击 Decoder 为 `tcp_syn` 时，xSight 自动在 xDrop 规则中注入 `protocol: tcp` 和 `tcp_flags: SYN,!ACK`，无需手动配置标志位。阶梯响应让轻度缓解先试，不够再升级。

### 8.2.1 反射攻击（DNS / NTP / Memcached / SSDP / CLDAP / Chargen）

**症状：** 来自特定服务源端口的大量 UDP 流量。源端口模式标识反射类型。

**配置（无专用 decoder — 通过 precondition 组合）：**
反射攻击本质是"UDP + 特定源端口"，xSight 通过 `udp` decoder + `dominant_src_port` precondition 组合识别。不为每种反射引入专用 decoder（v1.3 设计决策：避免消耗稀缺的 BPF decoder 槽位）。

| 攻击 | 模板规则 | 前置条件 |
|---|---|---|
| DNS 放大 | Decoder `udp`，Unit `pps`，Value `10000` | `dominant_src_port = 53` |
| NTP monlist | Decoder `udp`，Unit `pps`，Value `5000` | `dominant_src_port = 123` |
| Memcached | Decoder `udp`，Unit `pps`，Value `1000` | `dominant_src_port = 11211` |
| SSDP | Decoder `udp`，Unit `pps`，Value `5000` | `dominant_src_port = 1900` |
| CLDAP | Decoder `udp`,Unit `pps`，Value `2000` | `dominant_src_port = 389` |
| Chargen | Decoder `udp`，Unit `pps`，Value `1000` | `dominant_src_port = 19` |

**响应动作：** 对可精确识别的反射源（正常不会给你发包的外部服务），用 `drop` 最安全。如果你的服务器可能合法地从这些端口接收流量（例如你自己就在运行 DNS 服务器），改用 `rate_limit`。

**示例 YAML：**
```yaml
threshold_template:
  decoder: udp
  unit: pps
  value: 10000
precondition:
  - { attribute: dominant_src_port, operator: eq, value: "53" }
actions:
  - action_type: xdrop
    xdrop_action: drop
    xdrop_fields: [dst_ip, src_port]
```

### 8.2.2 无状态 ACK / RST / FIN 洪水（v1.3）

**症状：** 不带 SYN 前文的 TCP ACK、RST、FIN 包洪水，能绕过基本的 SYN flood 防御。

**配置：** v1.3 新增专用 decoder —— 不需要 precondition 技巧：

| 攻击 | 模板规则 |
|---|---|
| 无状态 ACK flood | Decoder `tcp_ack`，Unit `pps`，Value `100000` |
| RST flood | Decoder `tcp_rst`，Unit `pps`，Value `50000` |
| FIN flood / 扫描 | Decoder `tcp_fin`，Unit `pps`，Value `10000` |

xSight 独立统计这些（`tcp_syn` 不受影响）—— 一个 `SYN+ACK` 包只会增加 `tcp` 计数，不会增加 `tcp_syn` 或 `tcp_ack`，因此每个 flag 计数器反映真实攻击意图。

### 8.2.3 非 TCP/UDP/ICMP 协议洪水（v1.3）

**症状：** GRE、ESP 或 IGMP 流量异常激增。这些协议有合法用途但可被利用做反射或带宽耗尽攻击。

**配置：**

| 攻击 | 模板规则 |
|---|---|
| GRE 洪水 | Decoder `gre`，Unit `pps`，Value `10000` |
| ESP 洪水 | Decoder `esp`，Unit `pps`，Value `5000` |
| IGMP 洪水 | Decoder `igmp`，Unit `pps`，Value `1000` |
| 其他 IP 协议洪水 | Decoder `ip_other`，Unit `pps`，Value `1000` |

xDrop 的 L4 过滤按 `protocol` 匹配，对这些非标准协议，在 xDrop 侧用 `protocol=all` + precondition 捕获，或直接上 BGP null-route 更直接。

### 8.2.4 畸形 / 异常包（v1.3 — `bad_fragment`, `invalid`）

**症状**：攻击者构造带非法头字段组合或滥用 IP 分片机制的包。例子：Ping of Death（分片重组后超大）、tiny fragment（首个分片太小塞不下 L4 头，用于绕 IDS）、IHL/doff 畸形。

**配置**：v1.3 新增两个**无状态**异常检测 decoder（BPF 级别位操作，不跟 flow state）：

| 攻击 | 模板规则 |
|---|---|
| Ping of Death + tiny fragment | Decoder `bad_fragment`，Unit `pps`，Value `100` |
| IP / TCP 头畸形（IHL<5 / doff<5 / total_length < 头长度）| Decoder `invalid`，Unit `pps`，Value `50` |

**两个 decoder 的精确触发条件（BPF 无状态检测）：**

| Decoder | 触发条件 |
|---|---|
| `bad_fragment` | offset×8 + payload > 65535（PoD）；首片（MF=1, offset=0）payload 小于 20 字节（TCP）或 8 字节（UDP）（tiny frag）|
| `invalid` | IP IHL < 5；IP total_length < IHL×4；TCP data offset < 5 |

**注：flag 异常组合（NULL/XMAS/SYN+FIN/SYN+RST）不归 `invalid`** —— 请在 xdrop 侧通过 `tcp_flags` 匹配写常驻规则（例如规则带 `tcp_flags: "SYN,FIN"` 丢 SYN+FIN 包）。decoder 只数**结构畸形**的包；flag 组合是匹配目标，不是计数目标。

**与已有 `fragment` decoder 的关系：**
- `fragment` = **任何** IP 分片包（baseline，可能是合法 MTU 分片）
- `bad_fragment` = **带攻击特征**的分片（PoD 或 tiny frag）
- 同一个 bad fragment 包会**同时**递增 `fragment` 和 `bad_fragment` —— 用来在同一张图上看攻击/正常比例

Teardrop-style 分片重叠检测需要 stateful 跟踪 per-flow，v1.3 刻意不做。

### 8.3 地毯式轰炸（子网攻击）

**症状：** 整个 /24 被攻击 — 每个 IP 收到中等流量，但聚合流量巨大。

**配置：**
1. **模板规则：** Domain `subnet`（检测聚合前缀流量）。
2. **BGP 动作**，无前置条件（所有攻击）。
3. **xDrop 动作**，前置条件 `Domain = internal_ip`。

**效果：** /24 子网攻击触发整个前缀的 BGP。xDrop **不会**触发（因为 domain 是 `subnet` 而非 `internal_ip`）。如果 /24 内的单个 IP 也超过了 `internal_ip` 阈值，它们会获得各自的 xDrop 规则。

### 8.4 出站攻击检测

**症状：** 被入侵的主机向外发送攻击流量。

**配置：**
1. **模板规则：** Direction `Sends`，Decoder `ip`，Unit `bps`，Value `500000000`。
2. 将规则的 **Response** 下拉框设为仅 Webhook 的 Response（规则级覆盖）。

**效果：** 出站攻击检测到 → 发送 Webhook 通知。不触发 BGP/xDrop（你不会想黑洞自己的 IP）。

### 8.5 误报恢复

**场景：** 合法 IP 被 xDrop 或 BGP 错误阻断。

**步骤：**
1. 进入 **Active Mitigations**。
2. 找到对应条目。
3. 点击 **Force Withdraw**（BGP）或 **Force Unblock**（xDrop），然后确认。

缓解措施立即移除。即使攻击之后自然过期，该制品的自动清理动作也会被抑制 — 不会再次阻断。

### 8.6 IPv6 攻击

**场景：** IPv6 前缀或主机遭受攻击。

无需特殊配置。xSight 原生支持 IPv6：
- 检测支持 IPv6 前缀和地址。
- BGP 动作自动为 IPv6 目标使用 `address-family ipv6 unicast`。
- 同一个 BGP 连接器同时处理 IPv4 和 IPv6（Auto-AFI）。

---

## 9. API 参考

xSight 提供完整的 REST API 用于自动化和集成。

- **Controller API：** 完整端点参考请查阅 [controller/API.md](../controller/API.md)。
- **Node API：** 请查阅 [node/API.md](../node/API.md)。

**认证：** 所有 API 请求需要以下任一方式：
- 请求头：`X-API-Key: YOUR_API_KEY`
- 请求头：`Authorization: Bearer JWT_TOKEN`（通过 `POST /api/login` 获取）

---

## 10. 故障排查

### Controller 无法启动
- 检查 `config.yaml` 是否有语法错误。
- 确认 PostgreSQL 正在运行：`systemctl status postgresql`。
- 检查端口冲突：`ss -tlnp | grep 8080`。
- 查看日志：`journalctl -u xsight-controller -f`。

### 节点未显示为在线
- 检查 gRPC 连通性：`nc -zv controller-ip 50051`。
- 确认 `node_api_key` 与已注册节点匹配。
- 检查节点服务：`systemctl status xsight-node`（Flow 节点使用对应的自定义单元名称）。
- 查看日志：`journalctl -u xsight-node -f`。

### 攻击未触发
- 确认前缀已绑定 Template（在 Watch Prefixes 页面检查）。
- 验证阈值是否与你的流量水平匹配（设置过高 = 永远不会触发）。
- 确认至少有一个 Node 在线且在上报数据。

### 动作未执行
- 确认模板已绑定 Response（检查 Default Response 下拉框）。
- 检查 Response 及其 Action 是否已启用。
- 检查前置条件 — 可能正在过滤该攻击。
- 测试连接器连通性（使用 Connectors 页面的 Test 按钮）。
- 在 Attack Detail 页面查看执行日志。

### BGP 路由未出现
- 确认 FRR 正在运行：`systemctl status frr`。
- 检查 `/etc/frr/daemons` 中是否启用了 `bgpd`。
- 确认 route-map 存在：`vtysh -c "show route-map"`。
- 查看执行日志中的 vtysh 错误。

### xDrop 规则未创建
- 确认 xDrop 服务可从 Controller 访问。
- 检查连接器 API URL 和密钥。
- 如 xDrop 有同步延迟，增大超时时间（建议 30000ms）。
- 查看执行日志中的 HTTP 错误码。
- **v1.2.1：** decoder 为 `ip`（L3 聚合）的攻击会被跳过。检查动作日志是否有 `skip_reason=decoder_not_xdrop_compatible`。请改用 BGP 动作，或在规则上加 decoder 相关前置条件，把合适的攻击引到合适的动作上。
- **v1.2：** `action_engine.mode: observe`（默认）时所有 xDrop 动作也会被跳过。在 `config.yaml` 中改为 `action_engine.mode: auto` 并重启 Controller 才会真正下发。BGP、Webhook、Shell 不受此设置影响。

### 验证 metrics 抓取
- `curl -s http://controller-ip:8080/metrics | grep ^xsight_` — 应该返回 ~15 个 metric family。
- 返回为空：metrics 可能未注册；检查 Controller 启动日志中是否有 `metrics.Register failed`。
- 抓取超时：某个 custom collector 命中了 5s DB 超时 — 检查 PostgreSQL 负载。
