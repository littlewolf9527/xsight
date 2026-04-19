# xSight Node gRPC 接口文档

Node **不**对外暴露 REST API。它是 gRPC **客户端**，主动连接 Controller 的 gRPC 服务（默认端口 50051）。所有通信通过 `xsight.proto` 中定义的 `XSightService` 进行。

## 服务：`xsight.XSightService`

### RPC 列表

| RPC | 类型 | 方向 | 说明 |
|-----|------|------|------|
| `Handshake` | 一元调用 | Node -> Controller | 初始认证与配置交换 |
| `StatsStream` | 客户端流 | Node -> Controller | 周期性聚合流量统计 |
| `SampleStream` | 客户端流 | Node -> Controller | BPF ring buffer 中的包头采样 |
| `CriticalEventStream` | 客户端流 | Node -> Controller | 紧急事件通知 |
| `ControlStream` | 双向流 | Node <-> Controller | 配置下发/确认通道 |

---

## 1. Handshake（一元调用）

TCP 连接建立后的第一个调用。Node 进行身份认证并上报自身信息。Controller 返回接受状态和当前 `WatchConfig`。

**请求：`NodeHandshake`**

| 字段 | 类型 | 说明 |
|------|------|------|
| `node_id` | string | 唯一节点标识（来自 config.yaml） |
| `api_key` | string | 认证密钥（来自 config.yaml `auth.node_api_key`） |
| `interfaces` | string[] | 正在监控的接口名称列表 |
| `agent_version` | string | Node 二进制版本号 |
| `delivery_version_applied` | uint64 | 本地快照中最后应用的配置版本（0 = 无） |
| `mode` | string | `"xdp"` 或 `"flow"` |

**响应：`HandshakeResponse`**

| 字段 | 类型 | 说明 |
|------|------|------|
| `accepted` | bool | Controller 是否接受此节点 |
| `reject_reason` | string | 拒绝原因（接受时为空） |
| `watch_config` | WatchConfig | 初始配置 |
| `delivery_version_current` | uint64 | Controller 上的当前配置版本 |

如果 `delivery_version_applied` 与 `delivery_version_current` 一致，Controller 可能返回空的 `watch_config`（无需更新）。

---

## 2. StatsStream（客户端流）

Node 每秒发送一条 `StatsReport` 消息。Controller 使用这些数据进行 DDoS 检测（基线比较、阈值评估、异常检测）。

**消息：`StatsReport`**

| 字段 | 类型 | 说明 |
|------|------|------|
| `node_id` | string | 节点标识 |
| `interface_name` | string | 来源接口名称 |
| `upstream_sample_rate` | uint32 | 上游设备采样率（1 = 无采样） |
| `local_sample_rate` | uint32 | Node 的 BPF 层采样率 |
| `timestamp` | int64 | Unix 时间戳（秒） |
| `ip_stats` | IPStats[] | 按目的 IP 的入向统计 |
| `prefix_stats` | PrefixStatsMsg[] | 按前缀的入向聚合统计 |
| `global_stats` | GlobalStatsMsg | 全局入向流量计数器 |
| `health` | NodeHealth | 代理健康状态 |
| `sampling_metrics` | SamplingMetrics | Ring buffer 和采样健康信息 |
| `gap_seconds` | uint32 | 重连后的数据间隔时长 |
| `ip_stats_truncated` | bool | ip_stats 是否被截断（IP 数过多） |
| `total_active_ips` | uint32 | 截断前的活跃目的 IP 总数 |
| `top_flows` | FlowSample[] | 本 tick 的 Top-N 流（按包数排序） |
| `src_ip_stats` | IPStats[] | 按源 IP 的出向统计 |
| `src_prefix_stats` | PrefixStatsMsg[] | 按前缀的出向聚合统计 |
| `src_ip_stats_truncated` | bool | src_ip_stats 是否被截断 |
| `total_active_src_ips` | uint32 | 截断前的活跃源 IP 总数 |

流关闭时返回 `google.protobuf.Empty`。

---

## 3. SampleStream（客户端流）

Node 发送 `SampleBatch` 消息，包含从 BPF perf ring buffer 中读取的原始包头采样。Controller 用于流指纹识别和深度检查。仅 XDP 模式使用。

**消息：`SampleBatch`**

| 字段 | 类型 | 说明 |
|------|------|------|
| `node_id` | string | 节点标识 |
| `interface_name` | string | 来源接口名称 |
| `upstream_sample_rate` | uint32 | 上游设备采样率 |
| `local_sample_rate` | uint32 | BPF 层采样率 |
| `timestamp` | int64 | Unix 时间戳（秒） |
| `samples` | PacketSample[] | 采样包头数组 |

流关闭时返回 `google.protobuf.Empty`。

---

## 4. CriticalEventStream（客户端流）

低延迟紧急事件通道。当 Node 检测到需要 Controller 立即关注的情况（如 BPF map 接近满载、接口故障、硬阈值超限）时发送 `CriticalEvent`。

**消息：`CriticalEvent`**

| 字段 | 类型 | 说明 |
|------|------|------|
| `node_id` | string | 节点标识 |
| `interface_name` | string | 来源接口名称 |
| `timestamp` | int64 | Unix 时间戳（秒） |
| `dst_ip` | bytes | 涉及的目的 IP（4 或 16 字节），如适用 |
| `event_type` | string | 事件类别（如 `"hard_threshold_exceeded"`、`"map_full"`、`"interface_down"`） |
| `counters` | map<string, uint64> | 触发时的计数器快照（键值对） |

流关闭时返回 `google.protobuf.Empty`。

---

## 5. ControlStream（双向流）

用于运行时配置更新的双向流。Controller 在监控配置变更时发送 `ConfigPush` 消息（前缀列表、阈值、Flow 监听器配置）。Node 应用配置后回复 `ConfigAck`。

**消息：`ControlMessage`**

使用 `oneof payload` 字段：

| 变体 | 类型 | 发送方 | 说明 |
|------|------|--------|------|
| `config_push` | ConfigPush | Controller | 需要应用的新配置 |
| `config_ack` | ConfigAck | Node | 配置应用确认 |

---

## 共享消息类型

### IPStats

per-IP 流量计数器，出现在 `StatsReport.ip_stats` 和 `StatsReport.src_ip_stats` 中。

| 字段 | 类型 | 说明 |
|------|------|------|
| `dst_ip` | bytes | IP 地址（IPv4 为 4 字节，IPv6 为 16 字节） |
| `pkt_count` | uint64 | 总包数 |
| `byte_count` | uint64 | 总字节数 |
| `decoder_counts` | uint32[] | 按解码器 ID 索引的包计数。槽位 0-4：TCP / TCP_SYN / UDP / ICMP / FRAGMENT。槽位 5-13：TCP_ACK / TCP_RST / TCP_FIN / GRE / ESP / IGMP / IP_OTHER / BAD_FRAGMENT / INVALID。权威注册表见 [`shared/decoder/decoder.go`](../shared/decoder/decoder.go)。 |
| `decoder_byte_counts` | uint64[] | 按解码器 ID 索引的字节计数 |
| `small_pkt` | uint32 | < 128 字节的包数 |
| `medium_pkt` | uint32 | 128-512 字节的包数 |
| `large_pkt` | uint32 | > 512 字节的包数 |

### PrefixStatsMsg

per-prefix 流量计数器，出现在 `StatsReport.prefix_stats` 和 `StatsReport.src_prefix_stats` 中。

| 字段 | 类型 | 说明 |
|------|------|------|
| `prefix` | bytes | 网络地址（4 或 16 字节） |
| `prefix_len` | uint32 | CIDR 前缀长度 |
| `pkt_count` | uint64 | 总包数 |
| `byte_count` | uint64 | 总字节数 |
| `active_ips` | uint32 | 此前缀内的唯一 IP 数 |
| `overflow_count` | uint32 | 超出 per-IP map 容量的 IP 数 |
| `decoder_counts` | uint32[] | 按解码器 ID 索引的包计数 |
| `decoder_byte_counts` | uint64[] | 按解码器 ID 索引的字节计数 |

### GlobalStatsMsg

全局流量计数器，出现在 `StatsReport.global_stats` 中。

| 字段 | 类型 | 说明 |
|------|------|------|
| `total_pkts` | uint64 | 接口上的总包数 |
| `total_bytes` | uint64 | 接口上的总字节数 |
| `matched_pkts` | uint64 | 匹配 watch_prefixes 的入向包数 |
| `matched_bytes` | uint64 | 匹配 watch_prefixes 的入向字节数 |
| `decoder_counts` | uint32[] | 入向按解码器细分的 PPS |
| `decoder_byte_counts` | uint64[] | 入向按解码器细分的 BPS |
| `src_matched_pkts` | uint64 | 匹配 watch_prefixes 的出向包数 |
| `src_matched_bytes` | uint64 | 匹配 watch_prefixes 的出向字节数 |
| `src_decoder_counts` | uint32[] | 出向按解码器细分的 PPS |
| `src_decoder_byte_counts` | uint64[] | 出向按解码器细分的 BPS |

### FlowSample

单个聚合流（五元组），来自一个 tick 内，出现在 `StatsReport.top_flows` 中。

| 字段 | 类型 | 说明 |
|------|------|------|
| `src_ip` | bytes | 源 IP（4 或 16 字节） |
| `dst_ip` | bytes | 目的 IP（4 或 16 字节） |
| `src_port` | uint32 | 源端口 |
| `dst_port` | uint32 | 目的端口 |
| `protocol` | uint32 | IP 协议号（6=TCP, 17=UDP, 1=ICMP） |
| `tcp_flags` | uint32 | 此流中所有 TCP flags 的累积 OR |
| `packets` | uint64 | 包数 |
| `bytes_total` | uint64 | 字节数 |

### PacketSample

单个采样包头，出现在 `SampleBatch.samples` 中。

| 字段 | 类型 | 说明 |
|------|------|------|
| `raw_header` | bytes | 原始捕获的包头字节 |
| `src_ip` | bytes | 解析后的源 IP |
| `dst_ip` | bytes | 解析后的目的 IP |
| `ip_protocol` | uint32 | IP 协议号 |
| `src_port` | uint32 | 源端口（TCP/UDP） |
| `dst_port` | uint32 | 目的端口（TCP/UDP） |
| `packet_length` | uint32 | 原始包在线路上的长度 |
| `tcp_flags` | uint32 | TCP flags（如果是 TCP） |
| `ip_ttl` | uint32 | IP TTL 值 |
| `fragment_offset` | uint32 | IP 分片偏移 |
| `icmp_type` | uint32 | ICMP 类型（如果是 ICMP） |
| `icmp_code` | uint32 | ICMP 代码（如果是 ICMP） |

### NodeHealth

代理健康状态，出现在 `StatsReport.health` 中。

| 字段 | 类型 | 说明 |
|------|------|------|
| `status` | string | `"healthy"`、`"degraded"` 或 `"unhealthy"` |
| `message` | string | 可读的状态描述 |

### SamplingMetrics

Ring buffer 和采样健康信息，出现在 `StatsReport.sampling_metrics` 中。

| 字段 | 类型 | 说明 |
|------|------|------|
| `ring_fill_ratio` | float | 当前 ring buffer 填充率（0.0 - 1.0） |
| `dropped_kernel` | uint64 | 内核侧 ring buffer 丢包数 |
| `dropped_user` | uint64 | 用户态侧丢包数 |
| `decode_error` | uint64 | 包解码错误数 |
| `batch_send_latency_ms` | float | 批量 gRPC 发送的 P50 延迟 |
| `effective_sample_rate` | float | 自适应调整后的实际采样率 |

### WatchConfig

Controller 下发给 Node 的配置（通过 Handshake 响应或 ControlStream ConfigPush）。

| 字段 | 类型 | 说明 |
|------|------|------|
| `prefixes` | WatchPrefix[] | 监控的 IP 前缀列表 |
| `hard_thresholds` | HardThresholds | per-IP 硬阈值（触发 CriticalEvent） |
| `flow_listeners` | FlowListenerConfig[] | Flow 监听器配置（仅 flow 模式，XDP 节点忽略） |

### WatchPrefix

监控列表中的单个 IP 前缀。

| 字段 | 类型 | 说明 |
|------|------|------|
| `prefix` | bytes | 网络地址（4 或 16 字节） |
| `prefix_len` | uint32 | CIDR 前缀长度 |
| `name` | string | 可读标签 |

### HardThresholds

per-IP 硬阈值。超过时 Node 发送 CriticalEvent。

| 字段 | 类型 | 说明 |
|------|------|------|
| `pps` | uint64 | per-IP 包/秒阈值 |
| `bps` | uint64 | per-IP 比特/秒阈值 |

### ConfigPush

Controller 通过 ControlStream 发送给 Node。

| 字段 | 类型 | 说明 |
|------|------|------|
| `watch_config` | WatchConfig | 需要应用的新配置 |
| `delivery_version_current` | uint64 | 配置版本号 |

### ConfigAck

Node 应用 ConfigPush 后通过 ControlStream 发送给 Controller。

| 字段 | 类型 | 说明 |
|------|------|------|
| `delivery_version_applied` | uint64 | 已应用的版本号 |
| `success` | bool | 配置是否成功应用 |
| `error_message` | string | 如果 success=false，错误详情 |

### FlowListenerConfig

下发给 flow 模式 Node 的 Flow 监听器配置。

| 字段 | 类型 | 说明 |
|------|------|------|
| `listen_address` | string | UDP 绑定地址（如 `":6343"`、`":2055"`） |
| `protocol_mode` | string | `"auto"`、`"sflow"`、`"netflow"` 或 `"ipfix"` |
| `sources` | FlowSourceConfig[] | 已注册的导出器设备 |
| `enabled` | bool | 此监听器是否启用 |

### FlowSourceConfig

监听器上的单个流导出器设备。

| 字段 | 类型 | 说明 |
|------|------|------|
| `device_ip` | string | 导出器 IP 地址（与 UDP 源地址匹配） |
| `sample_mode` | string | `"auto"`（使用记录中的采样率）、`"force"`（覆盖）或 `"none"`（rate=1） |
| `sample_rate` | int32 | 覆盖采样率（sample_mode=`"force"` 时使用） |
| `name` | string | 可读显示名称 |
| `enabled` | bool | 此源是否启用 |

---

## 连接生命周期

```
Node 启动
  -> 加载 config.yaml
  -> 加载 WatchConfig 快照（如果存在）
  -> 拨号 Controller gRPC（带重连退避）
  -> Handshake（发送 node_id、api_key、delivery_version_applied）
  -> 如果被接受：
       -> 应用 HandshakeResponse 中的 WatchConfig（如果版本更新）
       -> 打开 StatsStream（每秒发送）
       -> 打开 SampleStream（XDP 模式，批量发送）
       -> 打开 CriticalEventStream（事件触发发送）
       -> 打开 ControlStream（接收 ConfigPush，发送 ConfigAck）
  -> 断连时：退避 + 重连 + 重新 Handshake
```

## 认证

Node 在 `Handshake` 消息中包含 `api_key`。Controller 根据已注册的节点列表验证此密钥。流式 RPC 上没有逐条消息的认证 -- Controller 在 Handshake 成功后信任该 TCP 连接。
