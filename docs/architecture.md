# xSight Architecture Guide

> This document describes the architecture of xSight for developers, contributors, and advanced operators.
> It covers the system design, data flow, and key subsystem contracts.
> For user-facing configuration and operation, see the [User Guide](user-guide.md).

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Node Data Plane](#2-node-data-plane)
3. [Controller Control Plane](#3-controller-control-plane)
4. [Action Execution Engine](#4-action-execution-engine)
5. [Auto-Paired Action Lifecycle](#5-auto-paired-action-lifecycle)
6. [Data Model](#6-data-model)
7. [Frontend Architecture](#7-frontend-architecture)

---

## 1. System Overview

xSight is a distributed DDoS detection and response platform with two main components:

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

**Node** — deployed at traffic observation points. Captures packets (XDP mode) or receives flow exports (Flow mode). Reports per-second aggregated statistics to the Controller via gRPC streaming.

**Controller** — central brain. Receives traffic data, runs detection, tracks attacks, executes response actions, serves the Web UI and REST API, pushes configuration to nodes.

### Communication Protocol

Nodes communicate with the Controller via gRPC (default port 50051). The protocol defines five RPC methods:

| Method | Type | Purpose |
|--------|------|---------|
| `Handshake` | Unary | Node authentication + initial config exchange |
| `StatsStream` | Client streaming | 1-second aggregated traffic statistics (primary detection path) |
| `SampleStream` | Client streaming | Packet sample delivery for attack classification (best-effort) |
| `CriticalEventStream` | Client streaming | Low-latency event-driven alerts |
| `ControlStream` | Bidirectional | Configuration push (Controller → Node) and acknowledgment (Node → Controller) |

The primary detection path uses `StatsReport` messages containing per-destination-IP statistics, per-prefix aggregates, global counters, and optional top-flow summaries.

### Module Map

**Controller packages (`controller/internal/`):**

| Package | Purpose |
|---------|---------|
| `ingestion` | gRPC server, receives Node traffic reports, feeds ring buffers and DB writer |
| `store/ring` | In-memory ring buffers for real-time per-second traffic snapshots |
| `store/postgres` | PostgreSQL data access layer with schema migrations |
| `engine/threshold` | Threshold inheritance tree and per-second detection tick |
| `engine/baseline` | Dynamic baseline profiling and anomaly detection |
| `engine/classifier` | Attack type classification from packet samples |
| `engine/dedup` | Alert deduplication based on decoder hierarchy |
| `tracker` | Attack state machine (confirm, active, expiring, expired) |
| `action` | Action execution engine (BGP, xDrop, webhook, shell) |
| `configpub` | Configuration push to nodes via gRPC ControlStream |
| `api` | REST API and embedded Vue SPA serving |
| `config` | Configuration loading and validation |
| `retention` | Background cleanup of expired data |
| `netutil` | IP/CIDR utility functions |
| `watchdog` | Systemd watchdog integration |

**Node packages (`node/internal/`):**

| Package | Purpose |
|---------|---------|
| `bpf` | BPF program bindings (generated from C source) |
| `config` | Node configuration and snapshot management |
| `collector` | Reads BPF maps every second, computes deltas, exports stats |
| `flow` | Flow aggregation and sFlow/NetFlow/IPFIX listener |
| `reporter` | gRPC client connection to Controller with three reporting streams |
| `sampler` | Parallel packet parsing pipeline (Reader → Workers → Aggregator) |
| `watchdog` | Systemd watchdog integration |

---

## 2. Node Data Plane

### XDP Mode

The BPF/XDP program (`node/bpf/xsight.c`) attaches to a network interface and processes every packet at the earliest possible point in the kernel network stack.

**Packet parsing pipeline:**

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

**Decoder array:** Each IP destination has a fixed-size array of counters (`decoder_counts[16]`) indexed by decoder type. The canonical index registry is defined in `shared/decoder/decoder.go` — the table below is a mirror, not an independent definition.

| Index | Decoder | Description |
|-------|---------|-------------|
| 0 | tcp | All TCP packets |
| 1 | tcp_syn | TCP packets with SYN flag set and ACK cleared |
| 2 | udp | All UDP packets |
| 3 | icmp | ICMP and ICMPv6 |
| 4 | fragment | IP fragments |
| 5-15 | (reserved) | Future decoders (array is pre-allocated to avoid BPF map rebuilds) |

> **Note:** There is no separate `ip` decoder slot. Aggregate IP-level statistics (total packets/bytes) are tracked in the parent `pkt_count` / `byte_count` fields, not via a decoder index. The `ip` decoder name used in threshold rules maps to the aggregate counters, not to a decoder_counts slot.

Counters track both packet count and byte count per decoder. Additionally, packets are classified into size buckets (small / medium / large) for traffic characterization.

**Prefix matching:** The BPF program uses an LPM (Longest Prefix Match) trie to determine which watch prefix an IP belongs to. Only IPs matching a registered prefix are counted in per-IP statistics. Unmatched packets still contribute to global counters.

**Bidirectional support (v2.11+):** The BPF program maintains separate stats maps for inbound (destination-based) and outbound (source-based) traffic. This enables detection of both DDoS attacks (inbound) and compromised host behavior (outbound).

### Flow Mode

In Flow mode, the Node receives flow export packets from routers and switches instead of capturing raw packets. The flow parser supports:

| Protocol | Port (default) | Notes |
|----------|----------------|-------|
| sFlow v5 | 6343 | Counter + flow samples |
| NetFlow v5 | 2055 | Fixed format, simple |
| NetFlow v9 | 2055 | Template-based |
| IPFIX | 4739 | Template-based (NetFlow v10) |

Flow listeners and sources are configured from the Controller (not in the node config file). The node receives the listener configuration via the `ControlStream` gRPC channel as part of `WatchConfig` delivery.

The flow parser extracts per-IP and per-prefix statistics similar to XDP mode, applying sample rate correction to produce accurate PPS/BPS values.

**Capability differences between modes:**

| Capability | XDP Mode | Flow Mode |
|-----------|----------|-----------|
| `StatsStream` (per-second stats) | Yes | Yes |
| `SampleStream` (raw packet samples) | Yes | No |
| Attack classifier (sample-driven type identification) | Yes | No |
| Top flows / flow_logs | Yes (from BPF ring buffer samples) | Yes (from flow records) |
| Sensor Logs (5-tuple breakdown in attack detail) | Yes | Yes |
| Per-packet TCP flags inspection | Yes | Depends on flow export fields |

Flow mode does not produce raw `SampleBatch` messages. The attack classifier (which upgrades attack types based on packet-level inspection) is only available in XDP mode. Flow mode attacks retain their initial classification from the decoder-based detection.

### Node → Controller Reporting

Every second, the node sends a `StatsReport` message to the Controller containing:

- **Per-destination-IP stats**: packet/byte counts with per-decoder breakdown
- **Per-prefix aggregated stats**: prefix-level totals with active IP count
- **Per-source-IP stats**: outbound traffic tracking (for sends detection)
- **Global stats**: total packets/bytes, matched packets (within watch prefixes)
- **Top flows**: Top-N 5-tuple flow aggregations (for flow fingerprinting)
- **Sampling metrics**: ring fill ratio, kernel drops, decode errors (in Flow mode, these fields are reused for flow-ingestion health metrics such as unknown exporter count and template misses)
- **Node health**: healthy / degraded / unhealthy

---

## 3. Controller Control Plane

### Data Ingestion

The ingestion pipeline processes incoming `StatsReport` messages:

1. **gRPC handler** receives the streamed message and validates the node identity.
2. **Ring buffer writer** stores per-IP and per-prefix data points in in-memory sliding windows (one data point per second per IP per node).
3. **DB writer** batches data points and flushes to the `ts_stats` table every 5 seconds for long-term storage and historical charting.
4. **Flow writer** stores top-flow samples in the `flow_logs` table for attack fingerprinting (sensor logs).

Ring buffers are the primary data source for real-time detection. The DB is used for dashboards, traffic overview charts, and baseline calculations.

### Detection Engine

The detection engine runs a **tick loop every second**:

1. **Threshold tree** maps each registered prefix to its resolved set of threshold rules (including inherited rules from parent prefixes).
2. For each connected node and each prefix, the engine reads the latest data point from the ring buffer.
3. **Subnet rules** are evaluated against the prefix-level aggregate (total PPS/BPS for the prefix).
4. **Internal-IP rules** are evaluated per individual IP within the prefix.
5. When a rule is breached, the event is passed through **alert deduplication** (suppresses redundant alerts from decoder hierarchy — e.g., a `tcp` alert suppresses a simultaneous `ip` alert for the same IP).
6. Deduplicated events are fed to the **attack tracker**.

### Dynamic Baseline

The baseline system calculates normal traffic profiles from historical data:

1. **Hourly P95 calculation**: Computes the 95th percentile PPS and BPS for each (node, prefix) pair from `ts_stats`.
2. **EWMA smoothing**: Applies Exponential Weighted Moving Average to produce a stable baseline that adapts gradually to traffic changes.
3. **Deviation detection**: When current traffic exceeds `baseline * deviation_multiplier`, a dynamic threshold breach is generated.
4. **Recommendation**: The baseline engine provides recommended static threshold values based on historical profiles.

### Attack Tracker

The attack tracker manages the lifecycle of each attack through a state machine:

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

State transitions trigger callbacks:
- **Confirming → Active**: `on_detected` event → Action Engine fires on_detected actions.
- **Expiring → Active** (re-breach): Cancels pending delayed withdrawals/unblocks.
- **Expiring → Expired**: `on_expired` event → Action Engine fires on_expired actions.

The tracker supports two expiry modes:
- **Static**: Fixed expiry interval (configurable, default 300 seconds).
- **Dynamic**: Expiry interval scales with attack duration (longer attacks get longer expiry timers, up to a configurable maximum multiplier).

### Configuration Delivery

The Controller pushes configuration to nodes via the bidirectional `ControlStream`:

1. When prefixes, thresholds, or flow listeners change, the Controller increments a **delivery version**.
2. The new `WatchConfig` (prefix list + threshold values + flow listener config) is sent to all connected nodes.
3. Each node applies the config and sends a `ConfigAck` with the applied version.
4. The Controller tracks `config_status` per node (`synced` / `pending` / `failed`) and separately exposes **delivery drift** as the version gap between current and applied versions.

---

## 4. Action Execution Engine

When the tracker fires an attack event, the Action Engine determines what to execute.

### Response Resolution

The resolution path depends on the attack direction:

**Inbound attacks (`receives`):**
1. Check the attack's `threshold_rule_id` — if the triggering rule has a per-rule `response_id`, use that.
2. Otherwise, fall back to the prefix's threshold template `response_id`.
3. If no response is found, only global webhook connectors are notified.

**Outbound attacks (`sends`):**
1. Check the triggering rule's per-rule `response_id` — if set, use that.
2. **No template-level fallback.** Outbound attacks do not inherit the template's default response. This is intentional — the template default is typically configured for inbound mitigation (BGP/xDrop), which should not be applied to outbound traffic.
3. If no per-rule response is set, only global webhook connectors are notified.

### Action Dispatch

The engine iterates over the response's actions, sorted by `(trigger_phase, priority)`:

1. **Phase matching**: `on_detected` actions fire on attack confirmation; `on_expired` actions fire on expiry.
2. **Run mode**: `once` (fire once per attack), `periodic` (fire every N seconds while active), `retry_until_success`.
3. **Precondition evaluation**: Each action can have preconditions that filter by 12 attributes (decoder, severity, domain, cidr, node, pps, bps, attack_type, dominant ports, unique source IPs). All conditions use AND logic — every condition must be satisfied.
4. **First-match ACL**: For non-webhook types (xDrop, BGP, Shell), only the first matching action per type executes. Webhook actions all execute (multi-channel notification).
5. **Execution**: The action is dispatched to the appropriate handler (webhook POST, shell exec, xDrop API call, vtysh command).

### xDrop Execution

- **on_detected** (filter_l4 / rate_limit): POST to xDrop API with the rule payload. The response's `rule_id` is stored as `external_rule_id` in the execution log.
- **on_expired** (unblock): Looks up all `external_rule_id` entries from on_detected logs for this attack and DELETEs each rule from the xDrop API. Each successfully deleted rule gets its own execution log entry.
- **tcp_syn auto-injection**: When the attack decoder is `tcp_syn`, the engine automatically adds `protocol: tcp` and `tcp_flags: SYN,!ACK` to the xDrop rule payload.
- **Custom payload**: Supports dynamic variable expansion — `{ip}`, `{dominant_src_port}`, `{dominant_dst_port}`, etc. Variables are resolved at execution time from the attack record and flow analysis data.

### BGP Execution

- **on_detected** (announce): Constructs a vtysh command: `configure terminal → router bgp {ASN} → address-family {auto} → network {prefix} route-map {name}`.
- **on_expired** (withdraw): Looks up previously announced routes from execution logs and runs `no network ...` for each.
- **Auto-AFI**: The address-family is determined at runtime from the prefix IP version using `net.ParseCIDR` / `net.ParseIP`. IPv4 prefixes use `ipv4 unicast`, IPv6 prefixes use `ipv6 unicast`. A single BGP connector handles both.
- **External rule ID format**: `{prefix}|{route_map}` (the `|` separator avoids collision with `:` in IPv6 addresses).

### Delayed Execution

Both xDrop and BGP support delayed removal after attack expiry:

1. When the on_expired event fires and the action has a delay > 0, the engine writes a `scheduled` execution log entry with a `scheduled_for` timestamp.
2. A cancelable delayed execution is started. If the delay period elapses without interruption, the removal executes.
3. If the attack **re-breaches** during the delay, all pending delays for that attack are cancelled via the tracker's re-breach callback.
4. If the operator **force-removes** a specific artifact, only that artifact's delay is cancelled.
5. Delays are identified by a full business key: `(attack_id, action_id, connector_id, external_rule_id)`.

### Manual Override (Force Remove)

Operators can force-remove a BGP route or xDrop rule from the Active Mitigations page:

1. The actual removal is executed first (vtysh withdraw or xDrop DELETE).
2. A `manual_override` execution log entry is written with the artifact's business key.
3. When the attack later expires naturally, the on_expired handler checks for manual_override logs **per-artifact** — if found, that specific artifact is skipped.
4. Other artifacts under the same action or attack are not affected.

---

## 5. Auto-Paired Action Lifecycle

When an xDrop or BGP action is created with `trigger_phase: on_detected`, the system automatically creates a matching `on_expired` child action.

### Data Model

- The parent (on_detected) action stores `paired_with = child.id`.
- The child (on_expired) action has `auto_generated = true`.
- The link is single-direction: parent → child. The child does not reference the parent.

### CRUD Synchronization

| Operation on parent | Effect on child |
|--------------------|-----------------| 
| Create (xDrop/BGP on_detected) | Auto-create matching on_expired (unblock/withdraw) |
| Update (connector, delay, targets, enabled) | Propagate changes to child |
| Disable | Child also disabled |
| Enable | Child also enabled |
| Delete | Child deleted first, then parent |

Parent/child CRUD includes compensating rollback on failure — if the child operation fails, the parent operation is reverted via application-level compensation (not a single DB transaction).

### Execution Log and Status Derivation

The Active Mitigations page derives artifact status from `action_execution_log` entries:

| Log State | Derived Status |
|-----------|---------------|
| on_detected success + attack active + no on_expired | **Active** |
| on_detected success + attack expired + scheduled_for in future | **Delayed** |
| on_detected success + attack expired + no on_expired | **Pending** |
| on_expired success (matching external_rule_id) | **Removed** (filtered from view) |
| on_expired failed | **Failed** |
| manual_override success | **Removed** |

Each successful withdrawal/unblock writes a **per-artifact** execution log entry with the matching `external_rule_id`, ensuring the status derivation correctly identifies removed items.

---

## 6. Data Model

### Core Tables

| Table | Purpose |
|-------|---------|
| `attacks` | Attack records with dst_ip (INET), direction, decoder, severity, peak PPS/BPS, response_id, threshold_rule_id |
| `watch_prefixes` | Monitored IP ranges with template binding |
| `threshold_templates` | Named rule collections with default response_id |
| `thresholds` | Detection rules: domain, direction, decoder, unit, value; optional per-rule response_id override |
| `responses` | Response definitions (containers for actions) |
| `response_actions` | Actions: type, trigger_phase, connector, delay, paired_with, auto_generated |
| `action_execution_log` | Execution records: trigger_phase, status, external_rule_id, connector_id, scheduled_for |
| `action_preconditions` | Per-action filter conditions (attribute, operator, value) |
| `ts_stats` | Time-series traffic data (TimescaleDB hypertable with compression) |
| `flow_logs` | Sampled flow data for attack fingerprinting |
| `config_audit_log` | Configuration change audit trail |

### Additional Tables

| Table | Purpose |
|-------|---------|
| `nodes` | Registered node agents with mode, delivery version, config status |
| `users` | User accounts with bcrypt-hashed passwords and roles (admin/operator/viewer) |
| `webhook_connectors` | Webhook integration endpoints |
| `xdrop_connectors` | xDrop API endpoints |
| `shell_connectors` | Shell command configurations |
| `bgp_connectors` | BGP connector config (ASN, vtysh path) |
| `flow_listeners` | Flow mode listener configuration per node |
| `flow_sources` | Flow exporter devices per listener |
| `response_action_xdrop_targets` | Many-to-many mapping of actions to xDrop connectors |
| `dynamic_detection_config` | Baseline detection parameters |
| `prefix_profiles` | Per-prefix hourly traffic profiles for baseline |

### Key Fields

**`external_rule_id`**: Identifies an external mitigation artifact.
- BGP: `{prefix}|{route_map}` (e.g., `10.0.0.1/32|DIVERT`). The `|` separator avoids collision with `:` in IPv6 addresses.
- xDrop: The rule ID returned by the xDrop API (e.g., `rule_abc123`).

**`scheduled_for`**: Timestamp when a delayed withdrawal/unblock will execute. Used for UI countdown display and status derivation.

**`paired_with`**: On the on_detected action, points to the auto-generated on_expired action ID. Single-direction link.

**`auto_generated`**: Boolean flag on on_expired actions created by auto-pairing. These actions cannot be manually edited or deleted.

**Per-rule `response_id`**: On `thresholds` table. When set, overrides the template's default response for attacks triggered by that specific rule. Enables different responses for inbound vs outbound detection rules within the same template.

---

## 7. Frontend Architecture

### Stack

| Component | Version | Purpose |
|-----------|---------|---------|
| Vue | 3.5 | Reactive UI framework |
| Element Plus | 2.13 | UI component library |
| Pinia | 3.0 | State management |
| vue-i18n | 9.14 | Internationalization (EN / ZH) |
| ECharts | 6.0 | Traffic charts and visualizations |
| vue-router | 4.6 | Client-side routing |
| Vite | 8.0 | Build tool |
| axios | 1.13 | HTTP client for API calls |

### Embedding

The Vue SPA is built into `controller/web/dist/` and embedded into the Controller binary using Go's `//go:embed` directive. No separate web server is needed — the Controller serves the SPA alongside the REST API.

### Theme System

Two themes are supported, selectable at runtime via the header dropdown:

- **Classic**: Clean, professional design inspired by Stripe's dashboard aesthetic.
- **Amber**: Retro terminal aesthetic using the DSEG14 14-segment LCD font for numeric displays.

Themes are implemented via CSS custom properties (`--xs-*` variables). Switching themes updates the `data-theme` attribute on the root element, which toggles the variable set.

### Internationalization

All UI text is externalized in `i18n/en.js` and `i18n/zh.js`. Language is switched at runtime via the header dropdown. The selected language persists in local storage.

### Key Pages

| Page | Route | Description |
|------|-------|-------------|
| Dashboard | `/` | Stats cards + active attacks table + traffic trend |
| Traffic Overview | `/traffic-overview` | Time-series charts with prefix/node/direction filters |
| Attacks | `/attacks` | Active + historical attacks with detail drill-down |
| Attack Detail | `/attacks/:id` | Summary + execution log + sensor logs (flow data) |
| Active Mitigations | `/mitigations` | BGP Routing + xDrop Filtering tabs with detail drawer |
| Nodes | `/nodes` | Node list with status, config sync, flow config |
| Watch Prefixes | `/prefixes` | Prefix management with template binding |
| Templates | `/templates` | Threshold template list + detail modal with rules |
| Responses | `/responses` | Response detail with on_detected / on_expired action sections |
| Dynamic Detection | `/dynamic-detection` | Baseline config and profile status |
| Connector Settings | `/settings/*` | Webhook, xDrop, Shell, BGP connector management |
| Users | `/users` | User account management |
| Audit Log | `/audit` | Configuration change history |

### Active Mitigations Detail Drawer

The Mitigations page features a **detail drawer** that opens when clicking a table row. It displays:

1. **Header**: Artifact type + external rule ID + status badge.
2. **Summary**: Attack link, target IP, connector, creation time, timer (elapsed / countdown).
3. **Configuration**: Type-specific fields (BGP: prefix + route map; xDrop: action + protocol + flags).
4. **Execution Timeline**: Vertical timeline of all execution log entries for this artifact, with colored dots:
   - Green: success
   - Yellow: scheduled
   - Red: failed
   - Blue: manual_override

### API Client

The frontend uses axios with a centralized API module. Authentication is handled via JWT tokens stored in local storage. API key authentication is also supported for programmatic access. The API module automatically injects JWT auth headers, normalizes response errors, and redirects to the login page on 401 (expired/invalid token).
