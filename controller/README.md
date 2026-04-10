# xSight Controller

Management plane for xSight -- the XDP/eBPF-based DDoS detection and response system.

The Controller provides a REST API, gRPC ingestion endpoint, real-time detection engine, automated response system, and an embedded Vue 3 Web UI. It receives per-IP and per-prefix traffic statistics from one or more xSight Nodes (XDP or flow mode), performs threshold and dynamic baseline detection, tracks attack lifecycles, and triggers automated responses via xDrop, BGP blackhole, webhooks, or shell scripts.

## Architecture

```
                  +-----------+
  xSight Node --- | gRPC :50051 | --- StatsWriter ---> Ring Buffer (in-memory)
  (XDP/Flow)      +-----------+                              |
                                                  +----------+-----------+
                                                  |                      |
                                              DBWriter               Detector (1s tick)
                                                  |                      |
                                              ts_stats              ThresholdExceeded
                                          (PostgreSQL +                  |
                                           TimescaleDB)          AttackTracker (state machine)
                                                                         |
                                                                  ActionEngine
                                                              (xDrop / BGP / Webhook / Shell)
```

### Core Components

| Package | Description |
|---------|-------------|
| `ingestion` | gRPC server, StatsWriter (ring buffer feeder), DBWriter (ts_stats persistence), NodeState (connection tracking), SampleWorkerPool, FlowWriter |
| `store/ring` | Lock-free ring buffer for per-IP and per-prefix traffic. Serves real-time threshold detection at 1-second granularity |
| `store/postgres` | PostgreSQL + TimescaleDB store. Hypertables for ts_stats and flow_logs with automatic compression and retention |
| `engine/threshold` | Threshold Tree (template inheritance) + Detector (hard threshold evaluation per tick). Supports PPS, BPS, and percentage-of-total units |
| `engine/baseline` | EWMA dynamic baseline calculator. ProfileEngine learns hourly traffic profiles (168 weekly slots) and detects anomalies using progressive deviation |
| `engine/classifier` | Attack type classifier using sampled packet data (SYN flood, UDP amplification, etc.) |
| `engine/dedup` | Alert deduplication to prevent duplicate attack records for the same target |
| `tracker` | Attack lifecycle state machine -- confirmation window, active tracking, dynamic expiry, crash recovery from DB |
| `action` | Response execution engine. Supports four action types (xDrop filter/rate-limit, BGP blackhole via FRR/vtysh, webhook HTTP calls, shell scripts) with preconditions, trigger phases, run modes, and execution logging |
| `api` | Gin-based REST API with JWT + API key authentication. Full CRUD for all configuration entities |
| `configpub` | Config Publisher -- pushes prefix/threshold changes to connected nodes via gRPC, with version tracking and drift detection |
| `retention` | Automatic data cleanup. Drops old ts_stats chunks, flow_logs, expired attacks, and audit log entries on a configurable schedule |
| `watchdog` | systemd watchdog integration (sd_notify ready + heartbeat) |

## Web UI

The frontend is a Vue 3 + Element Plus SPA, embedded into the Go binary at compile time. It ships with two themes:

- **Classic** -- Clean, Stripe-inspired design with a light sidebar and card-based layout
- **Amber** -- Retro terminal aesthetic using DSEG14 LCD segment font, dark background with amber/green phosphor colors

The UI supports English and Chinese (i18n toggle in the header).

## Build

### Prerequisites

- Go 1.25+
- Node.js 18+ and npm

### Steps

```bash
# Build frontend
cd web
npm install
npm run build
cd ..

# Build controller binary (embeds web/dist)
go build -o bin/xsight-controller .
```

Or use the Makefile:

```bash
make build    # Go binary only (assumes web/dist already built)
make proto    # Regenerate protobuf (requires protoc + Go gRPC plugins)
make migrate  # Run database migrations and exit
```

### Database Setup

PostgreSQL 15+ is required. TimescaleDB 2.x is strongly recommended for automatic chunk compression and retention policies.

```sql
CREATE DATABASE xsight;
CREATE USER xsight WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE xsight TO xsight;
-- If using TimescaleDB:
CREATE EXTENSION IF NOT EXISTS timescaledb;
```

Migrations run automatically on startup. Use `-migrate` flag to run migrations only:

```bash
./bin/xsight-controller -config config.yaml -migrate
```

## Configuration

Copy `config.example.yaml` and edit:

```yaml
listen:
  grpc: ":50051"           # Node gRPC ingestion
  http: ":8080"            # Web UI + REST API

database:
  driver: "postgres"
  dsn: "postgres://xsight:PASSWORD@localhost:5432/xsight?sslmode=disable"

log:
  level: "info"            # debug | info | warn | error

auth:
  api_key: "CHANGE_ME"    # REST API key (X-API-Key header). Generate: openssl rand -hex 32

detection:
  hard_threshold_confirm_seconds: 3      # consecutive breach seconds before attack declared
  dynamic_threshold_confirm_seconds: 5
  expiry_interval_seconds: 300           # seconds of no breach before attack expires
  expiry_function: "static"              # "static" | "dynamic" (scales by attack duration)
  max_active_attacks: 10000
  dry_run: false                         # detect but don't create attack records

ring:
  max_points_per_ip: 120      # per-IP history depth (default 120 = 2 min at 1s)
  max_ips_per_prefix: 10000   # max tracked IPs per prefix
  max_global_keys: 100000     # total tracked IPs globally

retention:
  ts_stats_days: 7             # raw 5s stats
  ts_stats_compress_days: 1    # compress chunks older than N days (TimescaleDB)
  ts_stats_cagg_days: 90       # 5min aggregation
  flow_logs_days: 7            # flow_logs (compressed)
  attacks_days: 90             # ended attack records
  audit_log_days: 180          # config change audit trail
  interval_hours: 24           # cleanup frequency
```

See `config.example.yaml` for the full reference with inline comments.

## Running

```bash
./bin/xsight-controller -config config.yaml
```

The controller will:
1. Connect to PostgreSQL and run migrations
2. Start the gRPC server on `:50051` for node connections
3. Start the HTTP server on `:8080` for the Web UI and REST API
4. Begin the 1-second detection tick loop
5. Start the retention cleaner on the configured schedule
6. Signal systemd readiness (if running under systemd)

A pprof debug endpoint runs on `127.0.0.1:6060` (localhost only).

## Directory Structure

```
controller/
  main.go                  # Entry point, wiring
  embed.go                 # go:embed for web/dist
  config.example.yaml
  Makefile
  web/                     # Vue 3 frontend source
    src/
    dist/                  # Built frontend (embedded)
  internal/
    config/                # YAML config loader
    pb/                    # Generated protobuf (gRPC service)
    ingestion/             # gRPC handler, StatsWriter, DBWriter, NodeState, FlowWriter
    store/                 # Store interfaces
      postgres/            # PostgreSQL implementation (migrations, queries)
      ring/                # In-memory ring buffer (per-IP, per-prefix)
    engine/
      threshold/           # Threshold tree + detector
      baseline/            # EWMA calculator + ProfileEngine (168-slot weekly)
      classifier/          # Attack type classification
      dedup/               # Alert deduplication
    tracker/               # Attack lifecycle state machine
    action/                # Response execution (xDrop, BGP, webhook, shell)
    api/                   # REST API handlers + router
    configpub/             # Config push to nodes via gRPC
    retention/             # Data retention cleaner
    netutil/               # IP/prefix formatting utilities
    watchdog/              # systemd sd_notify integration
```
