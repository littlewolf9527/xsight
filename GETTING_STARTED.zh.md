# xSight 快速上手指南

本文档介绍如何从源码构建、配置和运行 xSight。

xSight 由两个组件构成：

- **Controller（控制器）** -- 中心服务器，包含 Web UI、REST API、gRPC 数据接收、检测引擎和 PostgreSQL 存储。
- **Node（节点）** -- 部署在各观测点的轻量 Agent，支持两种模式：
  - **XDP 模式** -- 通过 BPF/XDP 从镜像口/ERSPAN 抓包。需要 Linux + 较新内核。
  - **Flow 模式** -- sFlow/NetFlow/IPFIX 接收器。任意 Linux 即可运行。

---

## 1. 环境要求

### Controller

| 依赖 | 版本 |
|---|---|
| Go | 1.25+ |
| Node.js | 18+（仅前端编译需要） |
| PostgreSQL | 15+，需安装 TimescaleDB 2.x 扩展 |
| 操作系统 | Linux / macOS / Windows |

### Node（XDP 模式）

| 依赖 | 版本 |
|---|---|
| Linux 内核 | 5.4+（推荐 5.15+） |
| clang / llvm | 11+ |
| Linux 内核头文件 | 与运行内核版本一致 |
| Go | 1.25+ |
| 权限 | root（需要 CAP_BPF + CAP_NET_ADMIN） |

### Node（Flow 模式）

| 依赖 | 版本 |
|---|---|
| Go | 1.25+ |
| 操作系统 | 任意 Linux（无内核特殊要求） |

Flow 模式的接收器（sFlow/NetFlow/IPFIX 监听）在节点启动后通过 Web UI 配置，无编译时依赖。

---

## 2. 数据库配置

xSight 使用 PostgreSQL + TimescaleDB 扩展来存储时序数据，并支持自动数据保留策略。

```bash
# 安装 PostgreSQL（Ubuntu/Debian）
sudo apt install -y postgresql postgresql-client

# 安装 TimescaleDB 扩展（参考 https://docs.timescale.com 选择对应发行版）
# Ubuntu 示例：
# sudo add-apt-repository ppa:timescale/timescaledb-ppa
# sudo apt install -y timescaledb-2-postgresql-15
# sudo timescaledb-tune

# 创建数据库
sudo -u postgres createdb xsight
sudo -u postgres psql -d xsight -c "CREATE EXTENSION IF NOT EXISTS timescaledb;"
```

创建专用数据库用户：

```bash
sudo -u postgres psql -c "CREATE USER xsight WITH PASSWORD 'YOUR_DB_PASSWORD';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE xsight TO xsight;"
sudo -u postgres psql -d xsight -c "GRANT ALL ON SCHEMA public TO xsight;"
```

> Controller 首次启动时会自动创建所有表和 hypertable。

### PostgreSQL 性能调优（推荐）

xSight 会写入大量时序数据（ts_stats）。PostgreSQL 默认配置较为保守，可能导致高磁盘 I/O 和系统负载。生产环境建议在 `postgresql.conf` 中应用以下配置：

```ini
# /etc/postgresql/17/main/postgresql.conf

# 异步提交 — 减少 fsync 阻塞，崩溃时最多丢失 <1 秒数据（对统计数据可接受）
synchronous_commit = off

# 内存 — 根据可用 RAM 调整
#   8 GB 服务器（最低配置）：shared_buffers = 2GB,  effective_cache_size = 6GB
#  16 GB 服务器（推荐配置）：shared_buffers = 4GB, effective_cache_size = 12GB
shared_buffers = 4GB              # 约 25% RAM
effective_cache_size = 12GB       # 约 75% RAM

# WAL 调优 — 减少写入放大
wal_buffers = 64MB
max_wal_size = 4GB
min_wal_size = 1GB
wal_compression = on

# 如无主从复制需求，minimal WAL 可显著减少 I/O
wal_level = minimal
max_wal_senders = 0
```

修改后重启 PostgreSQL：

```bash
sudo systemctl restart postgresql
```

> **性能提升参考**：在我们的基准测试中（8 核 / 16GB 服务器，~5000 万 PPS 入库），应用上述配置后系统负载从 **6-7 降至 0.19**，磁盘写入从 **3.8 MB/s 降至 608 KB/s**。

---

## 3. 编译

### Controller

```bash
# 1. 编译前端（Vue 3 + Element Plus）
cd controller/web
npm install
npm run build
cd ../..

# 2. 编译 Controller 二进制（前端通过 Go embed 嵌入）
cd controller
go build -o bin/xsight-controller .
cd ..
```

### Node -- XDP 模式

```bash
cd node

# 1. 生成 BPF Go 绑定（需要 clang/llvm + 内核头文件）
go generate ./internal/bpf/

# 2. 编译节点二进制
go build -o bin/xsight-node .
cd ..
```

### Node -- Flow 模式

Flow 模式不使用 BPF，因此不需要 `go generate`。

```bash
cd node
go build -o bin/xsight-node .
cd ..
```

---

## 4. 配置

### Controller

```bash
cp controller/config.example.yaml controller/config.yaml
```

编辑 `controller/config.yaml`，关键字段：

```yaml
database:
  driver: "postgres"
  dsn: "postgres://xsight:YOUR_DB_PASSWORD@localhost:5432/xsight?sslmode=disable"

auth:
  api_key: "CHANGE_ME"   # 生成方式: openssl rand -hex 32
```

完整配置选项（检测阈值、环形缓冲区大小、数据保留策略等）请参考 `controller/config.example.yaml`。

### Node

```bash
cp node/config.example.yaml node/config.yaml
```

编辑 `node/config.yaml`，关键字段：

```yaml
node_id: "my-node-01"            # 节点唯一名称

interfaces:                       # 仅 XDP 模式
  - name: "eth1"
    mode: "mirror"

controller:
  address: "controller-ip:50051"  # Controller 的 gRPC 地址

auth:
  node_api_key: "CHANGE_ME"      # 需与 Controller 的 api_key 一致
```

如需使用 Flow 模式，设置 `mode: flow` 并移除 `interfaces` 配置块。Flow 监听器通过 Web UI 配置。

---

## 5. 运行

### Controller

```bash
./controller/bin/xsight-controller -config controller/config.yaml
```

### Node

```bash
# XDP 模式需要 root 权限
sudo ./node/bin/xsight-node -config node/config.yaml

# Flow 模式（如需绑定特权端口同样需要 root）
sudo ./node/bin/xsight-node -config node/config.yaml
```

### systemd（生产环境）

模板 service 文件位于 `deploy/` 目录。安装方法：

```bash
# Controller
sudo cp deploy/xsight-controller.service /etc/systemd/system/
sudo vim /etc/systemd/system/xsight-controller.service   # 修改路径
sudo systemctl daemon-reload
sudo systemctl enable --now xsight-controller

# Node
sudo cp deploy/xsight-node.service /etc/systemd/system/
sudo vim /etc/systemd/system/xsight-node.service          # 修改路径
sudo systemctl daemon-reload
sudo systemctl enable --now xsight-node
```

---

## 6. 验证

**Web UI** -- 浏览器访问 `http://<controller-ip>:8080`。
默认账号：`admin` / `admin`。首次登录后请立即修改密码。

**API 健康检查：**

```bash
curl -H "X-API-Key: YOUR_KEY" http://localhost:8080/api/stats/summary
```

正常返回包含节点和流量统计的 JSON 数据。

---

## 7. 一键部署 -- Ubuntu 22.04 / 24.04

以下脚本在单台机器上安装 Controller + XDP Node 的全部依赖并完成编译。请根据实际情况修改密码和路径。

```bash
#!/usr/bin/env bash
set -euo pipefail

# --- 安装依赖 ---
sudo apt update
sudo apt install -y build-essential clang llvm gcc-multilib \
    linux-headers-$(uname -r) \
    postgresql postgresql-client \
    curl git

# 安装 Go 1.25
GO_VERSION=1.25.0
curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | sudo tar -C /usr/local -xz
export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"

# 安装 Node.js 18（通过 NodeSource）
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# 安装 TimescaleDB（请参考官方文档选择对应的 PG 版本）
# https://docs.timescale.com/self-hosted/latest/install/
# 安装完成后：
sudo -u postgres psql -c "CREATE USER xsight WITH PASSWORD 'changeme';"
sudo -u postgres createdb -O xsight xsight
sudo -u postgres psql -d xsight -c "CREATE EXTENSION IF NOT EXISTS timescaledb;"

# --- 编译 ---
cd /opt/xsight

# Controller
cd controller/web && npm install && npm run build && cd ../..
cd controller && go build -o bin/xsight-controller . && cd ..

# Node（XDP 模式）
cd node && go generate ./internal/bpf/ && go build -o bin/xsight-node . && cd ..

# --- 配置 ---
cp controller/config.example.yaml controller/config.yaml
cp node/config.example.yaml node/config.yaml
# 编辑两个配置文件：设置数据库 DSN、API Key、node_id、接口名、Controller 地址

# --- 启动 ---
./controller/bin/xsight-controller -config controller/config.yaml &
sudo ./node/bin/xsight-node -config node/config.yaml &

echo "Controller Web UI: http://localhost:8080  (admin / admin)"
```

---

## 常见问题排查

| 现象 | 可能原因 |
|---|---|
| `go generate` 报 "clang not found" | 需安装 `clang` 和 `llvm` 包 |
| `go generate` 报缺少头文件 | 需安装 `linux-headers-$(uname -r)` |
| Node 无法 attach XDP 程序 | 检查是否以 root 运行；确认配置中的接口名正确 |
| Node 无法连接 Controller | 检查 `controller.address` 配置和防火墙是否放行 50051 端口 |
| BPF 系统调用 "permission denied" | 内核版本过低或缺少 CAP_BPF，需要 5.4+ 内核 |
| TimescaleDB 扩展未找到 | 确认已安装 `timescaledb` 包并在数据库中执行了 `CREATE EXTENSION` |
