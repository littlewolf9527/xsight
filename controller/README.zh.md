# xSight Controller

xSight 的管理平面 -- 基于 XDP/eBPF 的 DDoS 检测与响应系统。

Controller 提供 REST API、gRPC 数据接入、实时检测引擎、自动化响应系统以及内嵌的 Vue 3 Web UI。它从一个或多个 xSight Node（XDP 或 Flow 模式）接收逐 IP 和逐前缀的流量统计，执行阈值检测和动态基线检测，跟踪攻击生命周期，并通过 xDrop、BGP 黑洞、Webhook 或 Shell 脚本触发自动响应。

## 架构

```
                  +-----------+
  xSight Node --- | gRPC :50051 | --- StatsWriter ---> Ring Buffer（内存环形缓冲）
  (XDP/Flow)      +-----------+                              |
                                                  +----------+-----------+
                                                  |                      |
                                              DBWriter               Detector（1秒 tick）
                                                  |                      |
                                              ts_stats              ThresholdExceeded
                                          (PostgreSQL +                  |
                                           TimescaleDB)          AttackTracker（状态机）
                                                                         |
                                                                  ActionEngine
                                                              (xDrop / BGP / Webhook / Shell)
```

### 核心组件

| 包 | 说明 |
|---|------|
| `ingestion` | gRPC 服务端、StatsWriter（Ring Buffer 写入）、DBWriter（ts_stats 持久化）、NodeState（连接状态跟踪）、SampleWorkerPool、FlowWriter |
| `store/ring` | 无锁环形缓冲，用于逐 IP 和逐前缀的流量存储。以 1 秒粒度为实时阈值检测提供数据 |
| `store/postgres` | PostgreSQL + TimescaleDB 存储层。ts_stats 和 flow_logs 使用 hypertable，支持自动压缩和保留策略 |
| `engine/threshold` | 阈值继承树 + 检测器（每 tick 评估硬阈值）。支持 PPS、BPS 和百分比单位 |
| `engine/baseline` | EWMA 动态基线计算器。ProfileEngine 学习每小时流量画像（每周 168 个时间槽），使用渐进偏差检测异常 |
| `engine/classifier` | 攻击类型分类器，基于采样包数据（SYN Flood、UDP 放大等） |
| `engine/dedup` | 告警去重，防止对同一目标产生重复攻击记录 |
| `tracker` | 攻击生命周期状态机 -- 确认窗口、活跃跟踪、动态过期、从数据库崩溃恢复 |
| `action` | 响应执行引擎。支持四种动作类型（xDrop 过滤/限速、BGP 黑洞 via FRR/vtysh、Webhook HTTP 调用、Shell 脚本），带前置条件、触发阶段、运行模式和执行日志 |
| `api` | 基于 Gin 的 REST API，支持 JWT + API Key 认证。所有配置实体的完整 CRUD |
| `configpub` | 配置发布器 -- 通过 gRPC 将前缀/阈值变更推送到已连接的节点，带版本跟踪和漂移检测 |
| `retention` | 自动数据清理。按可配置的周期删除旧的 ts_stats 分区、flow_logs、已结束的攻击记录和审计日志 |
| `watchdog` | systemd watchdog 集成（sd_notify ready + 心跳） |

## Web UI

前端是 Vue 3 + Element Plus 单页应用，编译时嵌入 Go 二进制文件。提供两套主题：

- **Classic** -- 简洁的 Stripe 风格设计，浅色侧边栏加卡片式布局
- **Amber** -- 复古终端风格，使用 DSEG14 LCD 段码字体，深色背景配琥珀色/绿色荧光色

UI 支持中英文切换（页头 i18n 切换按钮）。

## 构建

### 前提条件

- Go 1.25+
- Node.js 18+ 和 npm

### 构建步骤

```bash
# 构建前端
cd web
npm install
npm run build
cd ..

# 构建 Controller 二进制（嵌入 web/dist）
go build -o bin/xsight-controller .
```

或使用 Makefile：

```bash
make build    # 仅编译 Go 二进制（需要 web/dist 已构建）
make proto    # 重新生成 protobuf（需要 protoc + Go gRPC 插件）
make migrate  # 仅运行数据库迁移后退出
```

### 数据库准备

需要 PostgreSQL 15+。强烈建议安装 TimescaleDB 2.x，以获得自动分区压缩和保留策略。

```sql
CREATE DATABASE xsight;
CREATE USER xsight WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE xsight TO xsight;
-- 如果使用 TimescaleDB：
CREATE EXTENSION IF NOT EXISTS timescaledb;
```

迁移在启动时自动执行。使用 `-migrate` 参数可仅运行迁移：

```bash
./bin/xsight-controller -config config.yaml -migrate
```

## 配置

复制 `config.example.yaml` 并编辑：

```yaml
listen:
  grpc: ":50051"           # Node gRPC 数据接入
  http: ":8080"            # Web UI + REST API

database:
  driver: "postgres"
  dsn: "postgres://xsight:PASSWORD@localhost:5432/xsight?sslmode=disable"

log:
  level: "info"            # debug | info | warn | error

auth:
  api_key: "CHANGE_ME"    # REST API 密钥（X-API-Key 请求头）。生成方法：openssl rand -hex 32

detection:
  hard_threshold_confirm_seconds: 3      # 连续超阈值秒数，达到后宣布攻击
  dynamic_threshold_confirm_seconds: 5
  expiry_interval_seconds: 300           # 未超阈值多少秒后攻击过期
  expiry_function: "static"              # "static" | "dynamic"（按攻击持续时间缩放）
  max_active_attacks: 10000
  dry_run: false                         # 仅检测，不创建攻击记录

ring:
  max_points_per_ip: 120      # 每 IP 历史深度（默认 120 = 2 分钟 @ 1秒/点）
  max_ips_per_prefix: 10000   # 每前缀最大跟踪 IP 数
  max_global_keys: 100000     # 全局最大跟踪 IP 总数

retention:
  ts_stats_days: 7             # 原始 5 秒统计
  ts_stats_compress_days: 1    # 超过 N 天的分区自动压缩（TimescaleDB）
  ts_stats_cagg_days: 90       # 5 分钟聚合
  flow_logs_days: 7            # flow_logs（已压缩）
  attacks_days: 90             # 已结束的攻击记录
  audit_log_days: 180          # 配置变更审计日志
  interval_hours: 24           # 清理频率
```

完整配置项参见 `config.example.yaml`，内含详细注释。

## 运行

```bash
./bin/xsight-controller -config config.yaml
```

Controller 启动后将：
1. 连接 PostgreSQL 并执行迁移
2. 在 `:50051` 启动 gRPC 服务端，等待 Node 连接
3. 在 `:8080` 启动 HTTP 服务端，提供 Web UI 和 REST API
4. 开始 1 秒粒度的检测 tick 循环
5. 按配置周期启动数据保留清理器
6. 向 systemd 发送就绪信号（如在 systemd 下运行）

pprof 调试端点运行在 `127.0.0.1:6060`（仅本地访问）。

## 目录结构

```
controller/
  main.go                  # 入口，组件装配
  embed.go                 # go:embed 嵌入 web/dist
  config.example.yaml
  Makefile
  web/                     # Vue 3 前端源码
    src/
    dist/                  # 构建后的前端（嵌入二进制）
  internal/
    config/                # YAML 配置加载
    pb/                    # 生成的 protobuf（gRPC 服务定义）
    ingestion/             # gRPC 处理器、StatsWriter、DBWriter、NodeState、FlowWriter
    store/                 # Store 接口定义
      postgres/            # PostgreSQL 实现（迁移、查询）
      ring/                # 内存环形缓冲（逐 IP、逐前缀）
    engine/
      threshold/           # 阈值继承树 + 检测器
      baseline/            # EWMA 计算器 + ProfileEngine（168 时间槽/周）
      classifier/          # 攻击类型分类
      dedup/               # 告警去重
    tracker/               # 攻击生命周期状态机
    action/                # 响应执行（xDrop、BGP、Webhook、Shell）
    api/                   # REST API 处理器 + 路由
    configpub/             # 通过 gRPC 推送配置到节点
    retention/             # 数据保留清理
    netutil/               # IP/前缀格式化工具
    watchdog/              # systemd sd_notify 集成
```
