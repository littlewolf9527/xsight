# xSight Controller API 参考手册

基础 URL: `http://<host>:8080/api`

## 认证

除 `/api/login` 外，所有 `/api/*` 端点都需要以下认证方式之一：

- **API Key**: `X-API-Key: <key>` 请求头（在 `config.yaml` 的 `auth.api_key` 中配置）
- **JWT Bearer**: `Authorization: Bearer <token>` 请求头（通过 `/api/login` 获取）

JWT 令牌有效期 24 小时。

---

## 登录

### POST /api/login

用户认证，获取 JWT 令牌。

| 字段 | 类型 | 说明 |
|------|------|------|
| `username` | string | **必填。** |
| `password` | string | **必填。** |

**响应：**

```json
{
  "token": "eyJhbG...",
  "user": { "id": 1, "username": "admin", "role": "admin" }
}
```

---

## 用户管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/users` | 列出所有用户 |
| POST | `/api/users` | 创建用户 |
| PUT | `/api/users/:id` | 更新用户 |
| DELETE | `/api/users/:id` | 删除用户 |

### 创建用户 -- POST /api/users

| 字段 | 类型 | 说明 |
|------|------|------|
| `username` | string | **必填。** |
| `password` | string | **必填。** |
| `role` | string | `admin` 或 `viewer`（默认：`viewer`） |

### 更新用户 -- PUT /api/users/:id

| 字段 | 类型 | 说明 |
|------|------|------|
| `username` | string | 新用户名 |
| `role` | string | `admin` 或 `viewer` |
| `enabled` | bool | 启用/禁用账号 |

---

## 节点管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/nodes` | 列出所有节点（包含 `online` 在线状态） |
| POST | `/api/nodes` | 注册节点 |
| GET | `/api/nodes/:id` | 获取节点详情 |
| PUT | `/api/nodes/:id` | 更新节点 |
| DELETE | `/api/nodes/:id` | 删除节点（级联删除 Flow Listener/Source） |
| GET | `/api/nodes/:id/status` | 节点详细状态（在线、配置漂移、Flow 指标） |

### 创建节点 -- POST /api/nodes

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string | **必填。** 节点标识符（如 `hk-mirror-01`） |
| `api_key` | string | **必填。** gRPC 认证共享密钥 |
| `description` | string | 可读描述 |
| `mode` | string | `xdp`（默认）或 `flow` |

### 更新节点 -- PUT /api/nodes/:id

| 字段 | 类型 | 说明 |
|------|------|------|
| `description` | string | |
| `mode` | string | `xdp` 或 `flow` |
| `enabled` | bool | |

### 节点状态 -- GET /api/nodes/:id/status

**响应**包含：`id`, `mode`, `online`, `config_status`, `delivery_version_current`, `delivery_version_applied`, `drift`, `last_ack_at`, `last_stats_at`, `stats_age_seconds`, `connected_at`, `uptime_seconds`, `flow_metrics`, `source_statuses`, `listener_statuses`。

---

## 前缀管理

监控的 IP 前缀（子网），用于流量监控和阈值检测。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/prefixes` | 列出所有前缀（包含父子层级关系） |
| POST | `/api/prefixes` | 创建监控前缀 |
| GET | `/api/prefixes/:id` | 获取前缀详情 |
| PUT | `/api/prefixes/:id` | 更新前缀 |
| DELETE | `/api/prefixes/:id` | 删除前缀 |

### 创建前缀 -- POST /api/prefixes

| 字段 | 类型 | 说明 |
|------|------|------|
| `prefix` | string | **必填。** CIDR 格式（如 `198.51.100.0/24`）。全局用 `0.0.0.0/0`，不允许 `::/0`。 |
| `parent_id` | int | 父前缀 ID，用于层级结构 |
| `threshold_template_id` | int | 关联阈值模板 |
| `name` | string | 显示名称 |
| `ip_group` | string | IP 分组标签 |

### 更新前缀 -- PUT /api/prefixes/:id

所有字段可选。支持 `prefix`, `name`, `ip_group`, `parent_id`, `threshold_template_id`, `enabled`。将 `parent_id` 或 `threshold_template_id` 设为 `null` 可清除关联。

---

## 阈值模板

可复用的阈值规则集，可分配给多个前缀。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/threshold-templates` | 列出所有模板 |
| POST | `/api/threshold-templates` | 创建模板 |
| GET | `/api/threshold-templates/:id` | 获取模板详情（含规则和关联前缀） |
| PUT | `/api/threshold-templates/:id` | 更新模板 |
| DELETE | `/api/threshold-templates/:id` | 删除模板（若被前缀使用则失败） |
| POST | `/api/threshold-templates/:id/duplicate` | 复制模板（含所有规则） |
| GET | `/api/threshold-templates/:id/rules` | 列出模板中的规则 |
| POST | `/api/threshold-templates/:id/rules` | 在模板中创建规则 |

### 创建模板 -- POST /api/threshold-templates

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | **必填。** |
| `description` | string | |

### 更新模板 -- PUT /api/threshold-templates/:id

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | |
| `description` | string | |
| `response_id` | int/null | 模板默认响应策略。设为 `null` 清除。全局前缀不能使用含 xDrop/BGP 的响应。 |

### 复制模板 -- POST /api/threshold-templates/:id/duplicate

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | 副本名称（默认：原名 + " (Copy)"） |

### 创建模板规则 -- POST /api/threshold-templates/:id/rules

| 字段 | 类型 | 说明 |
|------|------|------|
| `domain` | string | `internal_ip` 或 `subnet`（默认：`internal_ip`） |
| `direction` | string | `receives` 或 `sends`（默认：`receives`） |
| `decoder` | string | 协议过滤：`ip`, `tcp`, `tcp_syn`, `udp`, `icmp`, `frag` 等 |
| `unit` | string | `pps`, `bps` 或 `pct`（占比百分比）。`pct` 需指定具体 decoder。 |
| `comparison` | string | `over`（默认：`over`） |
| `value` | int | 阈值。`pct` 单位时范围 1-100。 |
| `inheritable` | bool | 子前缀是否继承此规则（默认：`true`） |

---

## 阈值规则（逐前缀覆盖）

逐前缀的阈值规则，覆盖或补充模板规则。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/thresholds` | 列出所有阈值规则。过滤：`?prefix_id=N` |
| POST | `/api/thresholds` | 创建逐前缀阈值 |
| GET | `/api/thresholds/:id` | 获取阈值详情 |
| PUT | `/api/thresholds/:id` | 更新阈值 |
| DELETE | `/api/thresholds/:id` | 删除阈值 |
| PUT | `/api/threshold-rules/:id` | 更新模板规则（同一处理器） |
| DELETE | `/api/threshold-rules/:id` | 删除模板规则（同一处理器） |

### 创建阈值 -- POST /api/thresholds

与模板规则相同的字段，外加：

| 字段 | 类型 | 说明 |
|------|------|------|
| `prefix_id` | int | **必填。** 目标前缀 |
| `response_id` | int | 此规则的覆盖响应策略 |

所有模板规则的校验规则同样适用（方向、decoder/unit 组合、全局前缀约束）。

---

## 响应策略

响应策略定义攻击检测或过期时执行的动作。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/responses` | 列出所有响应策略 |
| POST | `/api/responses` | 创建响应策略 |
| GET | `/api/responses/:id` | 获取响应策略（含丰富的动作信息） |
| PUT | `/api/responses/:id` | 更新响应策略 |
| DELETE | `/api/responses/:id` | 删除响应策略（被模板或阈值引用时失败） |

### 创建响应策略 -- POST /api/responses

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | **必填。** |
| `description` | string | |
| `enabled` | bool | 默认：`true` |

---

## 响应动作

响应策略中的动作。每个动作有类型、触发阶段和运行模式。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/responses/:id/actions` | 列出响应策略的动作 |
| POST | `/api/responses/:id/actions` | 创建动作 |
| PUT | `/api/actions/:id` | 更新动作 |
| DELETE | `/api/actions/:id` | 删除动作 |

### 创建/更新动作

| 字段 | 类型 | 说明 |
|------|------|------|
| `action_type` | string | **必填。** `xdrop`, `bgp`, `webhook` 或 `shell` |
| `trigger_phase` | string | `on_detected` 或 `on_expired`。`on_expired` 仅支持 `run_mode=once`。 |
| `run_mode` | string | `once`, `periodic` 或 `retry_until_success` |
| `period_seconds` | int | `periodic` 运行模式的间隔秒数 |
| `execution` | string | 执行顺序控制 |
| `priority` | int | 数值越小优先级越高 |
| `enabled` | bool | 默认：`true` |
| `connector_id` | int | **webhook/shell/bgp 必填。** 使用的连接器 |
| `target_node_ids` | []int | xDrop 连接器 ID 列表（仅 xDrop 类型） |
| `xdrop_action` | string | 仅 xDrop：`filter_l4`, `rate_limit` 或 `unblock` |
| `xdrop_custom_payload` | object | 仅 xDrop：匹配字段（`dst_ip`, `src_ip`, `dst_port`, `src_port`, `protocol`）和 `rate_limit` 值 |
| `shell_extra_args` | string | 仅 Shell：传递给命令的附加参数 |
| `unblock_delay_minutes` | int | 仅 xDrop filter/rate_limit：N 分钟后自动解封（0-1440） |
| `bgp_route_map` | string | 仅 BGP：**on_detected 必填。** 黑洞注入使用的 route-map 名称 |

### xDrop 目标

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/actions/:id/xdrop-targets` | 获取动作的 xDrop 连接器 ID 列表 |
| PUT | `/api/actions/:id/xdrop-targets` | 设置 xDrop 连接器 ID 列表 |

**PUT 请求体：** `{ "connector_ids": [1, 2, 3] }`

### 前置条件

动作的条件执行规则。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/actions/:id/preconditions` | 列出前置条件 |
| PUT | `/api/actions/:id/preconditions` | 替换所有前置条件 |

**PUT 请求体：**

```json
{
  "preconditions": [
    { "attribute": "pps", "operator": "gt", "value": "100000" },
    { "attribute": "decoder", "operator": "eq", "value": "udp" }
  ]
}
```

支持的属性：`cidr`, `decoder`, `attack_type`, `severity`, `pps`, `bps`, `peak_pps`, `peak_bps`, `node`, `domain`, `dominant_src_port`, `dominant_src_port_pct`, `dominant_dst_port`, `dominant_dst_port_pct`, `unique_src_ips`。

支持的操作符：`eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in`, `not_in`。

---

## Webhooks（旧版）

简单 Webhook 通知（Response System v2 之前的旧接口）。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/webhooks` | 列出所有 Webhook |
| POST | `/api/webhooks` | 创建 Webhook |
| PUT | `/api/webhooks/:id` | 更新 Webhook |
| DELETE | `/api/webhooks/:id` | 删除 Webhook |

---

## 设置 -- 连接器

### Webhook 连接器

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/settings/webhook-connectors` | 列出全部 |
| POST | `/api/settings/webhook-connectors` | 创建 |
| GET | `/api/settings/webhook-connectors/:id` | 获取 |
| PUT | `/api/settings/webhook-connectors/:id` | 更新 |
| DELETE | `/api/settings/webhook-connectors/:id` | 删除（被动作引用时失败） |
| POST | `/api/settings/webhook-connectors/:id/test` | 发送测试请求 |

**创建/更新字段：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | **必填。** |
| `url` | string | **必填。** Webhook URL |
| `method` | string | HTTP 方法（默认：`POST`） |
| `headers` | object | 自定义请求头，JSON 格式 `{"Key": "Value"}` |
| `timeout_ms` | int | 请求超时毫秒数（默认：10000） |
| `enabled` | bool | |

### xDrop 连接器

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/settings/xdrop-connectors` | 列出全部（API Key 脱敏） |
| POST | `/api/settings/xdrop-connectors` | 创建 |
| GET | `/api/settings/xdrop-connectors/:id` | 获取（API Key 脱敏） |
| PUT | `/api/settings/xdrop-connectors/:id` | 更新（省略 `api_key` 保留现有值） |
| DELETE | `/api/settings/xdrop-connectors/:id` | 删除（被动作引用时失败） |
| POST | `/api/settings/xdrop-connectors/:id/test` | 测试连通性（GET /health） |

**创建字段：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | **必填。** |
| `api_url` | string | **必填。** xDrop API 基础 URL（如 `http://host:8000/api/v1`） |
| `api_key` | string | **必填。** xDrop API 密钥 |
| `timeout_ms` | int | 请求超时毫秒数（默认：10000） |

### Shell 连接器

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/settings/shell-connectors` | 列出全部 |
| POST | `/api/settings/shell-connectors` | 创建 |
| GET | `/api/settings/shell-connectors/:id` | 获取 |
| PUT | `/api/settings/shell-connectors/:id` | 更新 |
| DELETE | `/api/settings/shell-connectors/:id` | 删除（被动作引用时失败） |

**创建字段：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | **必填。** |
| `command` | string | **必填。** 脚本/二进制的绝对路径（必须以 `/` 开头） |
| `timeout_ms` | int | 执行超时毫秒数（默认：30000） |

### BGP 连接器

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/settings/bgp-connectors` | 列出全部 |
| POST | `/api/settings/bgp-connectors` | 创建 |
| GET | `/api/settings/bgp-connectors/:id` | 获取 |
| PUT | `/api/settings/bgp-connectors/:id` | 更新 |
| DELETE | `/api/settings/bgp-connectors/:id` | 删除（被动作引用时失败） |
| POST | `/api/settings/bgp-connectors/:id/test` | 测试 FRR 连通性（`show bgp summary`） |
| GET | `/api/settings/bgp-connectors/:id/routes` | 显示此连接器地址族的 BGP RIB |

**创建字段：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | **必填。** |
| `bgp_asn` | int | **必填。** 本地 BGP AS 号 |
| `vtysh_path` | string | vtysh 二进制路径（默认：`/usr/bin/vtysh`） |
| `address_family` | string | `ipv4 unicast`（默认）或 `ipv6 unicast` |
| `description` | string | |
| `enabled` | bool | 默认：`true` |

---

## 统计

### GET /api/stats/summary

仪表盘概览计数。

**响应：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `active_attacks` | int | 当前活跃攻击数 |
| `total_nodes` | int | 已注册节点数 |
| `online_nodes` | int | 在线节点数 |
| `total_prefixes` | int | 监控前缀数 |
| `total_thresholds` | int | 阈值规则数 |
| `tracker_count` | int | 内存中跟踪的攻击数 |
| `attacks_created` | int | 启动以来创建的攻击总数 |
| `attacks_suppressed` | int | 被去重抑制的攻击数 |
| `attacks_evicted` | int | 因达到上限被驱逐的攻击数 |

### GET /api/stats/timeseries

逐前缀或逐节点的时序流量数据。

| 参数 | 类型 | 说明 |
|------|------|------|
| `prefix` | string | 按前缀过滤（CIDR） |
| `node_id` | string | 按节点过滤 |
| `direction` | string | `receives`, `sends` 或 `both` |
| `resolution` | string | `5s`, `5min`（默认）或 `1h` |
| `from` | string | RFC3339 开始时间（默认：1 小时前） |
| `to` | string | RFC3339 结束时间 |

### GET /api/stats/overview

从 Ring Buffer 获取的实时流量概览。返回总 PPS/BPS 和 Top 前缀。

| 参数 | 类型 | 说明 |
|------|------|------|
| `direction` | string | `receives`（默认）, `sends` 或 `both` |
| `node_id` | string | 按节点过滤 |
| `limit` | int | 返回最大前缀数（默认：20，最大：200） |

**响应：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `total_pps` | int | 聚合每秒包数 |
| `total_bps` | int | 聚合每秒比特数 |
| `node_count` | int | 贡献数据的节点数 |
| `active_prefixes` | int | 有近期流量的前缀数 |
| `top_prefixes` | array | 按 PPS 排序的 Top 前缀（含逐协议分解：tcp/udp/icmp 的 PPS 和 BPS） |

### GET /api/stats/total-timeseries

聚合（全前缀）时序数据。

| 参数 | 类型 | 说明 |
|------|------|------|
| `direction` | string | `receives`, `sends` 或 `both` |
| `resolution` | string | `5s`, `5min`（默认）或 `1h` |
| `from` | string | RFC3339 开始时间（默认：1 小时前） |
| `to` | string | RFC3339 结束时间 |

---

## 基线

### GET /api/baseline

所有已启用前缀的 P95 基线和推荐阈值。

**响应**（数组）：

| 字段 | 类型 | 说明 |
|------|------|------|
| `prefix` | string | 前缀 CIDR |
| `p95_pps` | int | P95 每秒包数 |
| `p95_bps` | int | P95 每秒比特数 |
| `recommend_pps` | int | 建议手动阈值（P95 x 2） |
| `recommend_bps` | int | 建议手动阈值（P95 x 2） |
| `detect_thresh_pps` | int | 动态检测触发值（P95 x 倍数） |
| `detect_thresh_bps` | int | 动态检测触发值（P95 x 倍数） |
| `data_points` | int | 使用的数据点数 |
| `active` | bool | `false` = 冷启动 / 数据不足 |

---

## 攻击

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/attacks` | 列出攻击（分页、可过滤） |
| GET | `/api/attacks/active` | 列出当前活跃攻击 |
| GET | `/api/attacks/:id` | 获取攻击详情（含动作执行日志） |
| POST | `/api/attacks/:id/expire` | 强制过期一个活跃攻击 |
| GET | `/api/attacks/:id/action-log` | 获取攻击的动作执行日志 |
| GET | `/api/attacks/:id/sensor-logs` | 获取攻击的 Flow 级传感器日志 |

### 列出攻击 -- GET /api/attacks

| 参数 | 类型 | 说明 |
|------|------|------|
| `status` | string | 按状态过滤 |
| `direction` | string | `receives` 或 `sends` |
| `prefix_id` | int | 按前缀过滤 |
| `from` | string | RFC3339 开始时间 |
| `to` | string | RFC3339 结束时间 |
| `limit` | int | 每页大小（默认：50，最大：200） |
| `offset` | int | 分页偏移量 |

**响应：** `{ "attacks": [...], "total": N }`

### 活跃攻击 -- GET /api/attacks/active

| 参数 | 类型 | 说明 |
|------|------|------|
| `limit` | int | 最大返回数（默认：100） |

**响应：** `{ "attacks": [...], "active_count": N, "returned": N, "tracker_count": N }`

### 强制过期 -- POST /api/attacks/:id/expire

手动过期活跃攻击。触发 on_expired 动作（如 xDrop 解封、BGP 路由撤回）。

**响应：** `{ "ok": true, "method": "tracker" }` 或 `{ "ok": true, "method": "db" }`

### 传感器日志 -- GET /api/attacks/:id/sensor-logs

返回攻击目标 IP 在攻击时间窗口内 `flow_logs` 表的逐 Flow 记录。对于活跃攻击，查询窗口限制为最近 1 小时。

| 参数 | 类型 | 说明 |
|------|------|------|
| `limit` | int | 最大 Flow 记录数（默认：1000，最大：10000） |

**响应：** `{ "flows": [...], "total": N, "expired": bool, "window": "full"|"last_1h" }`

---

## 审计日志

### GET /api/audit-log

配置变更历史，含新旧值对比。

| 参数 | 类型 | 说明 |
|------|------|------|
| `entity_type` | string | 按实体类型过滤（如 `watch_prefix`, `threshold`, `response`） |
| `user_id` | int | 按用户过滤 |
| `limit` | int | 每页大小（默认：50） |
| `offset` | int | 分页偏移量 |

---

## 动态检测

基于 EWMA 的动态基线检测配置和状态。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/dynamic-detection/config` | 获取动态检测配置 |
| PUT | `/api/dynamic-detection/config` | 更新配置 |
| GET | `/api/dynamic-detection/status` | 获取各前缀当前检测状态 |

### 更新配置 -- PUT /api/dynamic-detection/config

| 字段 | 类型 | 说明 |
|------|------|------|
| `enabled` | bool | 启用/禁用动态检测 |
| `deviation_min` | float | 最小偏差倍数（必须 >= 0） |
| `deviation_max` | float | 最大偏差倍数（必须 >= deviation_min） |
| `stable_weeks` | int | 激活前需要的数据周数（>= 1） |
| `ewma_alpha` | float | EWMA 平滑系数（0 < alpha < 1） |
| `min_pps` | int | 最小 PPS 地板值（>= 0） |
| `min_bps` | int | 最小 BPS 地板值（>= 0） |

### 检测状态 -- GET /api/dynamic-detection/status

**响应：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `enabled` | bool | 动态检测是否启用 |
| `current_slot` | int | 当前小时槽位（0-167） |
| `current_slot_label` | string | 可读标签（如 "Mon 14:00"） |
| `total_prefixes` | int | 有基线画像的前缀数 |
| `activated_count` | int | 已过学习阶段的前缀数 |
| `learning_count` | int | 仍在学习中的前缀数 |
| `prefixes` | array | 逐前缀详情：`expected_pps`, `expected_bps`, `current_pps`, `current_bps`, `thresh_pps`, `thresh_bps`, `sample_weeks`, `status`（`learning`/`normal`/`exceeded`） |

---

## Flow 配置

管理 Flow 模式节点的 NetFlow/sFlow/IPFIX 监听器和数据源。

### Flow 监听器

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/flow-listeners?node_id=X` | 列出节点的监听器（**node_id 必填**） |
| POST | `/api/flow-listeners` | 创建 Flow 监听器 |
| GET | `/api/flow-listeners/:id` | 获取监听器（含数据源） |
| PUT | `/api/flow-listeners/:id` | 更新监听器（node_id 不可变） |
| DELETE | `/api/flow-listeners/:id` | 删除监听器（级联删除数据源） |

**创建字段：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `node_id` | string | **必填。** 必须是 flow 模式节点 |
| `listen_address` | string | **必填。** `:port` 或 `host:port`（端口 1-65535） |
| `protocol_mode` | string | `auto`（默认）, `sflow`, `netflow` 或 `ipfix` |

### Flow 数据源

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/flow-sources?listener_id=N` | 列出监听器的数据源（**listener_id 必填**） |
| POST | `/api/flow-sources` | 创建 Flow 数据源 |
| GET | `/api/flow-sources/:id` | 获取数据源 |
| PUT | `/api/flow-sources/:id` | 更新数据源（listener_id 不可变） |
| DELETE | `/api/flow-sources/:id` | 删除数据源 |

**创建字段：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `listener_id` | int | **必填。** 父监听器 |
| `name` | string | **必填。** 显示名称 |
| `device_ip` | string | **必填。** 导出器 IP 地址 |
| `sample_mode` | string | `auto`（默认）, `force` 或 `none` |
| `sample_rate` | int | `sample_mode=force` 时必填（必须 > 0） |

---

## 通用响应格式

### 成功

```json
{ "ok": true }
```

### 已创建

HTTP 201，返回：

```json
{ "id": 42 }
```

### 错误

```json
{ "error": "问题描述" }
```

### 冲突（引用保护）

HTTP 409，尝试删除被其他实体引用的对象时返回：

```json
{ "error": "template in use by 3 prefixes: [198.51.100.0/24, 203.0.113.0/24, 10.0.0.0/8]" }
```
