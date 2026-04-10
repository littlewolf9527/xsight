<div align="center">
  <img src=".github/assets/xsight_logo_amber_hd.png" alt="xSight" height="120">

  <h1>xSight</h1>

  <p>基于 XDP/eBPF 的分布式 DDoS 检测与响应平台 — 线速流量分析，自动化缓解。</p>

  [![Go](https://img.shields.io/badge/Go-1.24%2B-00ADD8?logo=go)](https://go.dev)
  [![Vue](https://img.shields.io/badge/Vue-3-4FC08D?logo=vuedotjs)](https://vuejs.org)
  [![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
  [![Built with Claude Code](https://img.shields.io/badge/Built%20with-Claude%20Code-orange?logo=anthropic)](https://claude.com/product/claude-code)

  [English](README.md)
</div>

---

## 项目简介

xSight 是一套分布式 DDoS 检测与响应平台，融合了 XDP/eBPF 线速抓包计数与 Flow 分析（sFlow、NetFlow、IPFIX）两种采集模式。它通过监控镜像/ERSPAN 端口的流量或接收路由器/交换机的 Flow 数据，利用硬阈值与动态基线双重检测机制识别容量型攻击，并触发自动响应 — 从 BPF 防火墙规则到 BGP 黑洞路由。

系统由两个组件构成：

- **Node（节点）** — 部署在每个观测点，通过 XDP 抓包或接收 Flow 数据，按 IP/协议维度统计流量，通过 gRPC 流式上报至 Controller
- **Controller（控制器）** — 集中管控平面，运行检测引擎，使用 TimescaleDB 存储时序数据，触发响应动作，并提供 Web UI

| Classic 主题 | Amber 主题 |
|:---:|:---:|
| ![Classic](.github/assets/traffic_overview_classic.png) | ![Amber](.github/assets/traffic_overview_amber.png) |

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        Controller（检测与管控平面）                        │
│                                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐ │
│  │  Web UI  │  │ HTTP API │  │  检测    │  │  响应    │  │TimescaleDB│ │
│  │ (Vue 3 + │  │  (Gin)   │  │  引擎    │  │  动作    │  │    (PG)   │ │
│  │  EPlus)  │  │          │  │          │  │          │  │           │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └───────────┘ │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │  gRPC（统计上报 + 配置下发）
             ┌───────────────────┼───────────────────┐
             ▼                   ▼                   ▼
      ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
      │  节点 1     │    │  节点 2     │    │  节点 N     │
      │ （XDP 模式）│    │（Flow 模式）│    │ （XDP 模式）│
      │ ┌─────────┐ │    │ ┌─────────┐ │    │ ┌─────────┐ │
      │ │ BPF/XDP │ │    │ │  sFlow  │ │    │ │ BPF/XDP │ │
      │ │  计数器  │ │    │ │ NetFlow │ │    │ │  计数器  │ │
      │ └─────────┘ │    │ └─────────┘ │    │ └─────────┘ │
      └─────────────┘    └─────────────┘    └─────────────┘
       镜像/ERSPAN        路由器/交换机       镜像/ERSPAN
```

---

## 核心特性

### 双模采集

| 模式 | 工作原理 | 适用场景 |
|------|---------|---------|
| **XDP** | BPF 程序挂载在镜像/ERSPAN 端口，线速逐包计数 | 高精度、逐包可见性 |
| **Flow** | sFlow、NetFlow v5/v9、IPFIX 接收器，支持多源 | 路由器/交换机集成，无内核依赖 |

### 检测引擎
- **硬阈值检测** — 按协议解码器（TCP、TCP SYN、UDP、ICMP、IP）独立设置 PPS 和 BPS 阈值
- **动态基线检测** — EWMA 算法，168 槽位周循环画像（每小时一个槽位），基于学习到的基线百分比偏差告警
- **双向检测** — 独立监控入向和出向流量
- **全局地毯式轰炸检测** — 0.0.0.0/0 聚合阈值，捕获分散在大量 IP 上的分布式攻击
- **解码器级粒度** — 每种协议解码器可独立配置阈值和基线

### 响应系统
| 动作 | 说明 |
|------|------|
| **xDrop** | 向 xDrop 节点推送 BPF 防火墙规则，实现线速封堵 |
| **BGP RTBH** | 通过 BGP 宣告 /32 黑洞路由，由上游进行 null-route |
| **Webhook** | HTTP 回调至外部系统（SIEM、Slack、PagerDuty 等） |
| **Shell** | 执行本地脚本，用于自定义自动化 |

- **自动 `tcp_flags` 注入** — SYN Flood 事件自动为 xDrop 规则添加 `tcp_flags=SYN`，精准封堵而不误伤正常流量
- **动态过期** — 响应规则自动过期，每个检测周期重新评估

### 流量分析
- **Flow 指纹** — 攻击期间进行五元组采样，捕获 Top Talker 和协议分布
- **传感器日志** — 每事件结构化日志，包含完整的解码器维度拆分
- **逐 IP 跟踪** — 实时按目的 IP 统计 PPS/BPS，可配置聚合窗口

### Web UI
- **双主题** — Classic（Stripe 风格简洁）和 Amber（DSEG14 LCD 复古风格）
- **国际化** — 完整的中英文支持（ZH/EN 切换）
- **实时仪表盘** — 流量概览、逐 IP 下钻、告警时间线、响应历史
- **配置管理** — 在浏览器中管理检测配置、响应动作和节点配置

### 数据管线
- **TimescaleDB** — 连续聚合实现高效时间范围查询，自动压缩，可配置数据保留策略
- **配置下发管线** — Controller 通过 gRPC `ControlStream` 将检测/响应配置推送至节点，无需轮询即可保持所有节点同步

---

## 项目结构

```
xsight/
├── controller/          # 管控平面（Go + Vue 3）
│   ├── internal/        # API、检测引擎、跟踪器、响应动作、存储
│   └── web/             # Vue 3 + Element Plus 前端
├── node/                # 数据平面（Go + BPF/XDP）
│   ├── internal/        # BPF 加载器、上报器、采样器、Flow 解码器
│   └── bpf/             # XDP 内核程序（C）
├── shared/              # 共享解码器包
├── proto/               # gRPC 服务定义
├── scripts/             # 编译与服务管理脚本
├── deploy/              # systemd 服务文件
└── .github/assets/      # Logo、截图、赞助商
```

---

## 环境要求

| 组件 | 要求 |
|------|------|
| Controller | Go 1.25+、Node.js 18+（仅编译前端需要）、PostgreSQL 15+ with TimescaleDB |
| Node（XDP 模式） | Linux 内核 5.4+、clang/llvm 11+、Go 1.25+、root / CAP_NET_ADMIN |
| Node（Flow 模式） | Go 1.25+，无需特殊内核或 root 权限 |

**硬件配置（Controller — 包含 PostgreSQL + TimescaleDB）：**

| | CPU | 内存 | 磁盘 | 适用场景 |
|--|-----|------|------|----------|
| **最低配置** | 4 核 | 8 GB | 40 GB SSD | 小型网络，前缀数较少 |
| **推荐配置** | 8 核 | 16 GB | 80 GB SSD | 生产环境，大流量场景 |

**硬件配置（Node）：**

| | CPU | 内存 | 磁盘 | 备注 |
|--|-----|------|------|------|
| XDP 模式 | 2 核+ | 2 GB+ | 10 GB | 开销极低 — 大部分工作在 BPF 内核空间完成 |
| Flow 模式 | 2 核+ | 2 GB+ | 10 GB | 随 Flow exporter 数量线性增长 |

> **XDP 模式**需要 Linux — BPF 程序挂载在内核的 XDP hook 上。**Flow 模式**和 **Controller** 可运行于任意操作系统。

详细的环境准备步骤请参见**[准备工作](GETTING_STARTED.md)**。

---

## 快速开始

### 1. 编译

```bash
# 编译 controller（前端 + Go 二进制）
./scripts/build-controller.sh

# 编译 node（BPF 程序 + Go 二进制）——需在 Linux 主机上执行
./scripts/build-node.sh
```

### 2. 配置

```bash
# Controller
cp controller/config.example.yaml controller/config.yaml
# 编辑：设置数据库 DSN、gRPC 监听地址、检测配置

# Node
cp node/config.example.yaml node/config.yaml
# 编辑：设置采集模式（xdp/flow）、网卡、Controller gRPC 地址
```

### 3. 启动

```bash
# 启动 controller（无需 root）
./scripts/controller.sh start

# 启动 node — XDP 模式（需要 root）
sudo ./scripts/node.sh start

# 启动 node — Flow 模式（无需 root）
./scripts/node.sh start

# 查看状态
./scripts/controller.sh status
./scripts/node.sh status
```

Web UI 默认访问地址：`http://<controller-host>:8080`，默认登录账号：**admin / admin** — 首次登录后请立即修改密码。

---

## 许可证

MIT — 详见 [LICENSE](LICENSE)。

BPF/C 内核程序（`node/bpf/`）遵循 GPL-2.0 协议，这是 Linux 内核 BPF 子系统的要求。

---

## 赞助商

本项目由 [Hytron](https://www.hytron.io/) 赞助开发工具支持。

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/sponsor-hytron-dark.png">
  <img src=".github/assets/sponsor-hytron.png" alt="Hytron" height="60">
</picture>

---

<sub>本项目完全通过 <a href="https://claude.com/product/claude-code">Claude Code</a> vibe coding 构建 — 包括 XDP/BPF 内核程序、gRPC 流式通信、检测引擎和 Vue 前端。</sub>
