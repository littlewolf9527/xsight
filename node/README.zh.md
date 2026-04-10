# xSight Node

xSight DDoS 检测系统的数据平面代理。Node 通过 XDP/eBPF 从镜像/ERSPAN 端口抓包，或接收 sFlow/NetFlow/IPFIX 流数据，将聚合统计信息通过 gRPC 上报给 Controller。

## 双模式架构

### XDP 模式（默认）

将 XDP/eBPF 程序挂载到镜像或 ERSPAN 接口上，在内核中以线速捕获数据包。BPF 程序解析每个数据包，按解码器类型分类，更新 per-IP 和 per-prefix 统计 map，并将采样包发送到用户态 ring buffer。

**XDP 处理流程：**

```
数据包进入（mirror/ERSPAN）
  -> 解析 Ethernet/IP/Transport 头部
  -> 提取五元组（src_ip, dst_ip, src_port, dst_port, protocol）
  -> 分类解码器（TCP / TCP_SYN / UDP / ICMP / FRAG / ...）
  -> LPM trie 查找：将 dst_ip 与 watch_prefixes 匹配
  -> 更新 ip_stats map（per-IP 计数器）
  -> 更新 prefix_stats map（per-prefix 计数器）
  -> 更新 global_stats map（全局计数器）
  -> 概率采样 -> perf ring buffer (sample_ring)
  -> XDP_DROP（镜像口，不转发）
```

**BPF Maps：**

| Map | 类型 | 说明 |
|-----|------|------|
| `ip_stats` | Per-CPU Hash | 按目的 IP 统计：pkt_count, byte_count, decoder_counts[16], decoder_byte_counts[16], 包大小分桶 |
| `prefix_stats` | Per-CPU Hash | 按前缀聚合统计：pkt_count, byte_count, decoder_counts[16], decoder_byte_counts[16], active_ips, overflow_count |
| `global_stats` | Per-CPU Array | 全局统计：total_pkts, total_bytes, matched_pkts, matched_bytes, sample_drops, 各解码器细分 |
| `watch_prefixes` | LPM Trie | Controller 下发的前缀列表。用于快速路径中 dst_ip 匹配 |
| `sample_ring` | Perf Event Array | 采样包头部的 ring buffer，发送到用户态 |

### Flow 模式

通过 UDP 接收 sFlow、NetFlow v5/v9 或 IPFIX 流记录，使用 [goflow2](https://github.com/netsampler/goflow2) 解码。Node 解码流协议消息，提取五元组 + TCP flags，按解码器类型分类，聚合 per-IP 统计后上报给 Controller。

**Flow 处理流程：**

```
流记录进入（sFlow/NetFlow/IPFIX over UDP）
  -> goflow2 自动检测协议 + 解码
  -> 从 FlowMessage 提取五元组 + TCP flags
  -> 分类解码器（TCP / TCP_SYN / UDP / ICMP / FRAG / ...）
  -> 前缀 trie 查找：将 dst_ip 与 watch_prefixes 匹配
  -> 聚合到 per-IP + per-prefix 统计（RecordTable）
  -> 每 1 秒：刷新统计 -> gRPC StatsReport
```

Flow 监听器和源设备（exporter）通过 Controller Web UI 配置，不在本地配置文件中设置。

## gRPC 数据流

Node 是 **gRPC 客户端**，主动连接 Controller。不对外暴露 REST API 或监听端口（除可选的 pprof）。维护四条数据流：

| 数据流 | 方向 | 频率 | 用途 |
|--------|------|------|------|
| `StatsStream` | Node -> Controller | 1 秒 | 聚合的 per-IP/prefix 统计、健康指标、Top 流 |
| `SampleStream` | Node -> Controller | 批量发送 | BPF ring buffer 中的原始包头采样（仅 XDP 模式） |
| `CriticalEventStream` | Node -> Controller | 事件驱动 | 紧急告警（BPF map 满、接口故障、硬阈值超限） |
| `ControlStream` | 双向 | 按需 | Controller 下发 WatchConfig（前缀列表、阈值、Flow 监听器配置）；Node 以 delivery_version 确认 |

完整 gRPC 消息类型文档见 [API.zh.md](API.zh.md)。

## 编译

### XDP 模式

需要 Linux 环境，安装 `clang`、`llvm-strip` 和内核头文件。不能在 macOS 上编译。

```bash
# 生成 BPF Go 绑定（bpf2go）
go generate ./internal/bpf/

# 编译二进制
go build -o bin/xsight-node .
```

或使用 Makefile：

```bash
make all        # generate + build
make generate   # 仅 bpf2go
make build      # 仅 go build
make clean      # 清理构建产物
```

### Flow 模式

Flow 模式不使用 BPF，只需要 Go 即可编译（可从 macOS 交叉编译）：

```bash
go build -o bin/xsight-node .
```

预生成的 BPF 桩文件（`internal/bpf/stub_notlinux.go`）允许在非 Linux 平台上编译。

## 配置

复制 `config.example.yaml` 并编辑：

```yaml
# XDP 模式（默认）
mode: xdp
node_id: "my-node-01"

interfaces:
  - name: "eth1"
    mode: "mirror"              # mirror | erspan
    upstream_sample_rate: 1     # 1 = 无上游采样
    sample_bytes: 128           # 捕获长度（128-512）

bpf:
  max_entries: 1000000          # ip_stats map 大小

controller:
  address: "controller:50051"

auth:
  node_api_key: "CHANGE_ME"    # openssl rand -hex 32

# 可选调优（仅 xdp 模式）
# parse_workers: 4             # 默认 = NumCPU/2，范围 1-16
# pprof: false                 # pprof 监听 127.0.0.1:6061
```

```yaml
# Flow 模式
mode: flow
node_id: "my-flow-node-01"

controller:
  address: "controller:50051"

auth:
  node_api_key: "CHANGE_ME"
```

Flow 模式下不需要 `interfaces` 和 `bpf` 配置段。Flow 监听器和源设备通过 Controller Web UI 管理，并通过 `ControlStream` 下发到 Node。

## 权限要求

- **XDP 模式**需要 root 或 `CAP_BPF` + `CAP_NET_ADMIN` 权限。BPF 程序需挂载到网络接口。
- **Flow 模式**需要 UDP 端口绑定权限（绑定 < 1024 的特权端口时需额外权限）。

## 目录结构

```
node/
  main.go                     # XDP 模式入口
  flow_main.go                # Flow 模式入口
  config.example.yaml
  Makefile
  bpf/
    xsight.c                  # XDP/eBPF C 程序
    xsight.h                  # BPF 结构体定义
  internal/
    bpf/                      # BPF 加载器、Go 类型映射、bpf2go 生成代码
      gen.go                  # go:generate 指令（bpf2go）
      loader.go               # 加载 + 挂载 XDP 程序，map 操作
      types.go                # 映射 BPF C 结构体的 Go 类型
      stub_notlinux.go        # 非 Linux 平台编译桩
    config/                   # YAML 配置加载 + 校验
      config.go               # Config 结构体、Load()、validate()
      snapshot.go             # WatchConfig 快照持久化（重启恢复）
    collector/                # 定时读取 BPF map（XDP 模式）
      collector.go            # 每秒读取 ip_stats/prefix_stats/global_stats
    sampler/                  # 包采样流水线（XDP 模式）
      sampler.go              # Perf ring buffer 读取器
      batcher.go              # 批量打包样本用于 gRPC SampleStream
      packet.go               # 包头解析器（五元组提取）
      flowtable.go            # 每 tick 的 Top-N 流跟踪
      worker_pool.go          # 并行包解析工作池
    flow/                     # Flow 接收流水线（Flow 模式）
      listener.go             # 使用 goflow2 的 UDP 监听器
      decoder.go              # FlowMessage -> 五元组 + 解码器分类
      aggregator.go           # Per-IP/prefix 统计聚合 + 1 秒刷新
      record.go               # 流记录类型
      recordtable.go          # Per-IP 记录表（聚合用）
      prefixtrie.go           # 内存中的前缀 trie（watch_prefixes 匹配）
    reporter/                 # gRPC 客户端：握手 + 4 条数据流
      reporter.go             # 流生命周期管理、重连、退避
      convert.go              # Collector Report -> protobuf StatsReport 转换
    watchdog/                 # 健康监控
      watchdog.go             # 检测降级状态（ring 溢出、map 满）
    pb/                       # 生成的 protobuf + gRPC 桩代码
      xsight.pb.go
      xsight_grpc.pb.go
```
