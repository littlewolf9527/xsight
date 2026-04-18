# xSight Getting Started Guide

This guide covers building, configuring, and running xSight from source.

xSight has two components:

- **Controller** -- central server with Web UI, REST API, gRPC ingestion, detection engine, and PostgreSQL storage.
- **Node** -- lightweight agent deployed at each observation point. Two modes:
  - **XDP mode** -- BPF/XDP packet capture from a mirror/ERSPAN port. Requires Linux with modern kernel.
  - **Flow mode** -- sFlow/NetFlow/IPFIX receiver. Runs on any Linux.

---

## 1. Prerequisites

### Controller

| Requirement | Version |
|---|---|
| Go | 1.25+ |
| Node.js | 18+ (frontend build only) |
| PostgreSQL | 15+ with TimescaleDB 2.x extension |
| OS | Linux / macOS / Windows |

### Node (XDP mode)

| Requirement | Version |
|---|---|
| Linux kernel | 5.4+ (5.15+ recommended) |
| clang / llvm | 11+ |
| Linux kernel headers | matching running kernel |
| Go | 1.25+ |
| Privileges | root (CAP_BPF + CAP_NET_ADMIN) |

### Node (Flow mode)

| Requirement | Version |
|---|---|
| Go | 1.25+ |
| OS | Any Linux (no special kernel needed) |

Flow receivers (sFlow/NetFlow/IPFIX listeners) are configured via the Web UI after the node starts -- no compile-time dependencies.

---

## 2. Database Setup

xSight requires PostgreSQL with the TimescaleDB extension for time-series storage and automatic data retention.

```bash
# Install PostgreSQL (Ubuntu/Debian)
sudo apt install -y postgresql postgresql-client

# Install TimescaleDB extension (see https://docs.timescale.com for your distro)
# Ubuntu example:
# sudo add-apt-repository ppa:timescale/timescaledb-ppa
# sudo apt install -y timescaledb-2-postgresql-15
# sudo timescaledb-tune

# Create database
sudo -u postgres createdb xsight
sudo -u postgres psql -d xsight -c "CREATE EXTENSION IF NOT EXISTS timescaledb;"
```

Create a dedicated database user:

```bash
sudo -u postgres psql -c "CREATE USER xsight WITH PASSWORD 'YOUR_DB_PASSWORD';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE xsight TO xsight;"
sudo -u postgres psql -d xsight -c "GRANT ALL ON SCHEMA public TO xsight;"
```

> Tables and hypertables are created automatically on first controller startup.

### PostgreSQL Performance Tuning (Recommended)

xSight writes high-volume time-series data (ts_stats). The default PostgreSQL configuration is conservative and may cause high disk I/O and load. For production deployments, apply these settings in `postgresql.conf`:

```ini
# /etc/postgresql/17/main/postgresql.conf

# Async commit — reduces fsync blocking. <1s data loss on crash (acceptable for stats).
synchronous_commit = off

# Memory — adjust based on available RAM
#   8 GB server (minimum):  shared_buffers = 2GB,  effective_cache_size = 6GB
#  16 GB server (recommended): shared_buffers = 4GB, effective_cache_size = 12GB
shared_buffers = 4GB              # ~25% of RAM
effective_cache_size = 12GB       # ~75% of RAM

# WAL tuning — reduces write amplification
wal_buffers = 64MB
max_wal_size = 4GB
min_wal_size = 1GB
wal_compression = on

# If no replication is needed, minimal WAL reduces I/O significantly
wal_level = minimal
max_wal_senders = 0
```

After editing, restart PostgreSQL:

```bash
sudo systemctl restart postgresql
```

> **Impact**: In our benchmarks (8-core / 16GB server, ~50M PPS ingest), these settings reduced system load from **6-7 down to 0.19** and disk write from **3.8 MB/s to 608 KB/s**.

---

## 3. Build

### Controller

```bash
# 1. Build the frontend (Vue 3 + Element Plus)
cd controller/web
npm install
npm run build
cd ../..

# 2. Build the controller binary (frontend is embedded via Go embed)
cd controller
go build -o bin/xsight-controller .
cd ..
```

### Node -- XDP mode

```bash
cd node

# 1. Generate BPF Go bindings (requires clang/llvm + kernel headers)
go generate ./internal/bpf/

# 2. Build the node binary
go build -o bin/xsight-node .
cd ..
```

### Node -- Flow mode

Flow mode does not use BPF, so `go generate` is not needed.

```bash
cd node
go build -o bin/xsight-node .
cd ..
```

---

## 4. Configuration

### Controller

```bash
cp controller/config.example.yaml controller/config.yaml
```

Edit `controller/config.yaml`. The critical fields:

```yaml
database:
  driver: "postgres"
  dsn: "postgres://xsight:YOUR_DB_PASSWORD@localhost:5432/xsight?sslmode=disable"

auth:
  api_key: "CHANGE_ME"   # generate with: openssl rand -hex 32

action_engine:
  mode: "observe"        # IMPORTANT: set to "auto" to enable xDrop blocking.
                         # "observe" (default) skips all xDrop actions with
                         # skip_reason=mode_observe. BGP, webhook, shell
                         # actions are NOT gated by this setting.
```

See `controller/config.example.yaml` for the full list of options (detection thresholds, ring buffer sizing, data retention).

> **Safety default:** `action_engine.mode` starts as `observe` so a fresh install cannot accidentally push xDrop rules. After validating detection against real traffic, switch to `auto` to enable automated xDrop blocking. You can also manage xDrop/BGP from the Web UI before flipping this switch — manual Force Remove operations always run regardless of mode.

### Node

```bash
cp node/config.example.yaml node/config.yaml
```

Edit `node/config.yaml`. The critical fields:

```yaml
node_id: "my-node-01"            # unique name for this node

interfaces:                       # XDP mode only
  - name: "eth1"
    mode: "mirror"

controller:
  address: "controller-ip:50051"  # gRPC address of the controller

auth:
  node_api_key: "CHANGE_ME"      # must match controller's api_key
```

For Flow mode, set `mode: flow` and remove the `interfaces` block. Flow listeners are configured through the Web UI.

---

## 5. Running

### Controller

```bash
./controller/bin/xsight-controller -config controller/config.yaml
```

### Node

```bash
# XDP mode requires root
sudo ./node/bin/xsight-node -config node/config.yaml

# Flow mode (also needs root for binding to privileged ports, if any)
sudo ./node/bin/xsight-node -config node/config.yaml
```

### systemd (production)

Template service files are in the `deploy/` directory. To install:

```bash
# Controller
sudo cp deploy/xsight-controller.service /etc/systemd/system/
sudo vim /etc/systemd/system/xsight-controller.service   # adjust paths
sudo systemctl daemon-reload
sudo systemctl enable --now xsight-controller

# Node
sudo cp deploy/xsight-node.service /etc/systemd/system/
sudo vim /etc/systemd/system/xsight-node.service          # adjust paths
sudo systemctl daemon-reload
sudo systemctl enable --now xsight-node
```

---

## 6. Verification

**Web UI** -- open `http://<controller-ip>:8080` in your browser.
Default credentials: `admin` / `admin`. Change the password immediately after first login.

**API health check:**

```bash
curl -H "X-API-Key: YOUR_KEY" http://localhost:8080/api/stats/summary
```

A successful response returns JSON with node and traffic statistics.

**Prometheus scrape (optional):**

```bash
curl -s http://localhost:8080/metrics | grep ^xsight_ | head
```

`/metrics` is **unauthenticated by convention** — the endpoint relies on network-level isolation (same as kube-apiserver / etcd / Prometheus itself). If the controller is internet-reachable, firewall port 8080 or expose `/metrics` through a reverse proxy with its own auth.

To scrape from Prometheus:

```yaml
scrape_configs:
  - job_name: xsight-controller
    scrape_interval: 15s
    static_configs:
      - targets: ["controller-ip:8080"]
```

---

## 7. Quick Setup -- Ubuntu 22.04 / 24.04

Condensed script that installs everything on a single machine (controller + XDP node). Adjust passwords and paths as needed.

```bash
#!/usr/bin/env bash
set -euo pipefail

# --- Dependencies ---
sudo apt update
sudo apt install -y build-essential clang llvm gcc-multilib \
    linux-headers-$(uname -r) \
    postgresql postgresql-client \
    curl git

# Install Go 1.25
GO_VERSION=1.25.0
curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | sudo tar -C /usr/local -xz
export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"

# Install Node.js 18 (via NodeSource)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Install TimescaleDB (follow official docs for your exact PG version)
# https://docs.timescale.com/self-hosted/latest/install/
# After install:
sudo -u postgres psql -c "CREATE USER xsight WITH PASSWORD 'changeme';"
sudo -u postgres createdb -O xsight xsight
sudo -u postgres psql -d xsight -c "CREATE EXTENSION IF NOT EXISTS timescaledb;"

# --- Build ---
cd /opt/xsight

# Controller
cd controller/web && npm install && npm run build && cd ../..
cd controller && go build -o bin/xsight-controller . && cd ..

# Node (XDP mode)
cd node && go generate ./internal/bpf/ && go build -o bin/xsight-node . && cd ..

# --- Configure ---
cp controller/config.example.yaml controller/config.yaml
cp node/config.example.yaml node/config.yaml
# Edit both config files: set database DSN, API keys, node_id, interface, controller address

# --- Run ---
./controller/bin/xsight-controller -config controller/config.yaml &
sudo ./node/bin/xsight-node -config node/config.yaml &

echo "Controller Web UI: http://localhost:8080  (admin / admin)"
```

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `go generate` fails with "clang not found" | Install `clang` and `llvm` packages |
| `go generate` fails with missing headers | Install `linux-headers-$(uname -r)` |
| Node can't attach XDP program | Run as root; check interface name in config |
| Node can't connect to controller | Verify `controller.address` and firewall allows port 50051 |
| "permission denied" on BPF syscall | Kernel too old or missing CAP_BPF; use kernel 5.4+ |
| TimescaleDB extension not found | Ensure `timescaledb` package is installed and the extension is created in the database |
