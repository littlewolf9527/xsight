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
6. [Action State Layer (v1.2)](#6-action-state-layer-v12)
7. [Observability (v1.2.1)](#7-observability-v121)
8. [Data Model](#8-data-model)
9. [Frontend Architecture](#9-frontend-architecture)

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
| 4 | fragment | IP fragments (any `MF=1` or `offset≠0`) |
| 5 | tcp_ack | TCP packets with ACK bit and no SYN — stateless ACK flood identification |
| 6 | tcp_rst | TCP packets with RST bit — RST flood |
| 7 | tcp_fin | TCP packets with FIN bit — FIN flood / scan |
| 8 | gre | IP protocol 47 |
| 9 | esp | IP protocol 50 |
| 10 | igmp | IP protocol 2 |
| 11 | ip_other | Catch-all for IP protocols not otherwise counted |
| 12 | bad_fragment | Ping-of-Death signature (`offset×8 + payload > 65535`) or tiny first-fragment (too small to hold L4 header) |
| 13 | invalid | `IHL < 5` / `IP total_length < IHL×4` / TCP `doff < 5` |
| 14-15 | (reserved) | Future decoders — array is pre-allocated to avoid BPF map rebuilds |

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

1. **`action_engine.mode` gate** — the global `action_engine.mode` config value (`observe` | `auto`, default `observe`) gates xDrop actions only. In `observe` mode all xDrop actions are skipped with `skip_reason=mode_observe`; BGP / webhook / shell are never gated by this setting. Set `mode: auto` in `config.yaml` to enable xDrop blocking.
2. **Phase matching**: `on_detected` actions fire on attack confirmation; `on_expired` actions fire on expiry.
3. **Run mode**: `once` (fire once per attack), `periodic` (fire every N seconds while active), `retry_until_success`.
4. **Precondition evaluation**: Each action can have preconditions that filter by attributes such as `decoder`, `severity`, `domain`, `carpet_bomb` (alias for `domain eq subnet`), `cidr`, `node`, `pps`, `bps`, `attack_type`, dominant ports, unique source IPs. All conditions use AND logic — every condition must be satisfied.
5. **First-match ACL**: For non-webhook types (xDrop, BGP, Shell), only the first matching action per type executes. Webhook actions all execute (multi-channel notification).
6. **xDrop decoder gate (v1.2.1)**: After the first-match mark, if `action_type=xdrop` and the attack's `decoder_family` is not in the xDrop-compatible whitelist (`tcp`, `tcp_syn`, `udp`, `icmp`, `fragment`), the action is skipped with `skip_reason=decoder_not_xdrop_compatible`. The `ip` decoder is intentionally excluded — it is an L3 aggregate and would degrade to a full-prefix blackhole. Operators should use BGP null-route for L3-aggregate attacks.
7. **Execution**: The action is dispatched to the appropriate handler (webhook POST, shell exec, xDrop API call, vtysh command).

All skip outcomes are recorded in `action_execution_log` with `status=skipped` and a structured `skip_reason` column. The `xsight_action_skip_total{skip_reason}` Prometheus counter mirrors each log entry so operators can rate-monitor skips without pulling log rows.

### xDrop Execution

- **on_detected** (filter_l4 / rate_limit): POST to xDrop API with the rule payload. The response's `rule_id` is stored as `external_rule_id` in the execution log.
- **on_expired** (unblock): Looks up all `external_rule_id` entries from on_detected logs for this attack and DELETEs each rule from the xDrop API. Each successfully deleted rule gets its own execution log entry.
- **tcp_syn auto-injection**: When the attack decoder is `tcp_syn`, the engine automatically adds `protocol: tcp` and `tcp_flags: SYN,!ACK` to the xDrop rule payload.
- **Custom payload**: Supports dynamic variable expansion — `{ip}`, `{dominant_src_port}`, `{dominant_dst_port}`, etc. Variables are resolved at execution time from the attack record and flow analysis data.

### BGP Execution (Wanguard-Style Shared Announcement)

v1.2 treats a BGP announcement as a **refcounted resource keyed on `(prefix, route_map, connector_id)`**, not a per-attack side effect. Multiple attacks that resolve to the same prefix + route-map share a single FRR route; the route is only withdrawn when the last attack detaches.

**Attach path (on_detected)**:
1. `Attach(prefix, route_map, connector_id, attack_id, action_id, delay_minutes)` runs inside a `SELECT … FOR UPDATE` transaction on the business key.
2. If no row exists, it INSERTs a `bgp_announcements` row with `status=announcing`, `refcount=1`, inserts into `bgp_announcement_attacks`, and returns `NeedAnnounce=true`.
3. If a row exists, it increments `refcount`, inserts into `bgp_announcement_attacks`, and returns `NeedAnnounce=false` — the caller does **not** re-run vtysh.
4. Only `NeedAnnounce=true` triggers `configure terminal → router bgp {ASN} → address-family {auto} → network {prefix} route-map {name}`. On success the row transitions to `active`.

**Detach path (on_expired)**:
1. `Detach(announcement_id, attack_id)` decrements `refcount` and stamps `detached_at` on the `bgp_announcement_attacks` row.
2. If `refcount > 0` after decrement, the announcement stays active — other attached attacks still need the route.
3. If `refcount == 0`, the announcement transitions to `delayed` (if the effective delay > 0) or `withdrawing` (delay = 0). The **effective delay is MAX(delay_minutes across all attacks attached in this cycle)** — see Cycle-Sticky MAX Delay below.
4. When the delay elapses without a re-attach, vtysh `no network …` runs and the row transitions to `withdrawn`.

**Auto-AFI**: The address-family is resolved at runtime from the prefix IP version using `net.ParseCIDR` / `net.ParseIP`. IPv4 prefixes use `ipv4 unicast`, IPv6 prefixes use `ipv6 unicast`. A single BGP connector handles both.

**Business key in execution log**: `external_rule_id = {prefix}|{route_map}` (the `|` separator avoids collision with `:` in IPv6 addresses). The announcement's DB `id` is carried on each `action_execution_log` row via `announcement_id`.

**Cycle-Sticky MAX Delay**: When multiple attacks share an announcement, the effective withdraw delay is `MAX(delay_minutes)` across all attacks attached during the current announce cycle (from `announced_at` to the final `Detach` that drops refcount to 0). An attack that attaches mid-cycle with a shorter delay cannot shorten an already-locked-in longer delay; likewise attaching with a longer delay extends the MAX. This is recorded on `bgp_announcement_attacks.delay_minutes` so the post-cycle audit shows each attack's contribution.

### xDrop Execution

- **on_detected** (filter_l4 / rate_limit): POST to xDrop API. The returned `rule_id` is stored as `external_rule_id` in `action_execution_log` and in a new row in `xdrop_active_rules` (v1.2 authoritative state table, see Section 6).
- **on_expired** (unblock): Looks up all `xdrop_active_rules` rows for this attack and DELETEs each rule via the xDrop API. Each successful removal stamps `withdrawn_at` on the rule row and writes a per-artifact log entry.
- **tcp_syn auto-injection**: When the attack decoder is `tcp_syn`, the engine automatically adds `protocol: tcp` and `tcp_flags: SYN,!ACK` to the xDrop rule payload.
- **Protocol normalization (v1.2.1)**: xDrop accepts the enum `{all, tcp, udp, icmp, icmpv6}` for its `protocol` field. xSight normalizes `tcp_syn → tcp` and `fragment → all` at payload-emit time. The `ip` decoder is filtered out earlier by the decoder compatibility gate (see Action Dispatch step 6).
- **Custom payload**: Supports dynamic variable expansion — `{ip}`, `{dominant_src_port}`, `{dominant_dst_port}`, etc. Variables are resolved at execution time from the attack record and flow analysis data.

### Delayed Execution (Persisted)

Both xDrop and BGP support delayed removal after attack expiry. In v1.2, delayed tasks are **persisted** in the `scheduled_actions` table so they survive controller restarts:

1. When the on_expired event fires and the action has a delay > 0, the engine writes a row into `scheduled_actions` with `status=pending`, `scheduled_for={now + delay}`, and the full business key `(attack_id, action_id, connector_id, external_rule_id)`. For BGP, the row also carries `announcement_id`.
2. A cancelable in-memory timer is started. When it fires, the row flips to `status=executing` (`MarkExecuting`), runs the removal, then transitions to `completed` / `failed` via `Complete` / `Fail`.
3. If the attack **re-breaches** during the delay, all pending rows for that attack are cancelled with `status=cancelled` and `cancel_reason=rebreach`.
4. If the operator **force-removes** a specific artifact, only that artifact's row is cancelled (`cancel_reason=force_remove`).
5. On startup, `RecoverScheduledActions` scans pending rows and re-arms timers for future `scheduled_for`, fires overdue tasks immediately, and `reconcileExecutingSchedules` retries rows stuck in `executing` (crashed between `MarkExecuting` and `Complete`). Outcomes are counted in the `xsight_scheduled_actions_recovered_total{outcome}` Prometheus counter (`armed`, `overdue_fired`, `executing_retried`).

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

## 6. Action State Layer (v1.2)

Prior to v1.2, the Active Mitigations page derived artifact status from `action_execution_log` — a log-scanning query that was fragile under concurrent attach/detach and lost state across controller restarts. v1.2 introduces an explicit **Action State Layer** with dedicated state tables. The log is retained as an append-only audit trail, but UI and API queries now read state directly from the state tables.

### State Tables

| Table | Purpose | Key columns |
|-------|---------|-------------|
| `bgp_announcements` | Per-announcement lifecycle, refcounted | `prefix`, `route_map`, `connector_id`, `status`, `refcount`, `delay_minutes`, `announced_at`, `withdrawn_at` |
| `bgp_announcement_attacks` | Which attacks are attached to which announcement | `announcement_id`, `attack_id`, `action_id`, `delay_minutes`, `attached_at`, `detached_at` |
| `bgp_announcement_events` | Append-only audit (announce/attach/detach/delay_started/withdrawn/orphan_detected) | `announcement_id`, `event_type`, `attack_id`, `detail`, `created_at` |
| `xdrop_active_rules` | Per-xDrop-rule lifecycle | `attack_id`, `action_id`, `connector_id`, `external_rule_id`, `status`, `delay_started_at`, `delay_minutes`, `withdrawn_at` |
| `scheduled_actions` | Persisted delayed tasks (xdrop_unblock, bgp_withdraw) | `action_type`, `attack_id`, `action_id`, `external_rule_id`, `announcement_id`, `scheduled_for`, `status`, `cancel_reason` |
| `action_manual_overrides` | Operator force-remove audit (for on_expired suppression) | `attack_id`, `action_id`, `connector_id`, `external_rule_id`, `created_by` |

`bgp_announcements.status` enum: `announcing` → `active` → (`delayed`|`withdrawing`) → `withdrawn` | `failed` | `orphan` | `dismissed` | `dismissed_on_upgrade`.

`xdrop_active_rules.status` enum: `active` → (`delayed`|`withdrawing`) → `withdrawn` | `failed`.

`scheduled_actions.status` enum: `pending` → `executing` → `completed` | `cancelled` | `failed`.

### FRR Orphan Detection (Bootstrap Scan)

On controller startup, `BootstrapBGPOrphans` runs once:

1. Queries FRR via vtysh for the current BGP RIB on each registered connector (`show bgp ipv4/ipv6 unicast`).
2. For each FRR prefix that has **no matching active `bgp_announcements` row with refcount > 0**, inserts an orphan marker row into `bgp_announcements`.
3. On the very first v1.2 boot (no prior announcement history), orphans are inserted with `status=dismissed_on_upgrade` — this represents pre-v1.2 routes that xSight did not create and should not claim ownership of. Operators can review them in the UI and choose to adopt, withdraw, or leave dismissed.
4. On subsequent boots, new orphans (routes in FRR with no backing xSight attack) are inserted with `status=orphan`. Operators use `POST /api/active-actions/bgp/orphan-force-withdraw` or `/orphan-dismiss` to resolve them.
5. Rows that the operator has already dismissed are never re-pestered — the bootstrap only overwrites rows in `withdrawn` status.

This closes the pre-v1.2 blind spot where FRR routes could outlive xSight (e.g., crash between announce and DB write) with no visibility.

### UI Status Derivation

The Active Mitigations page queries the state tables directly rather than log-scanning:

- **BGP tab**: `SELECT FROM bgp_announcements WHERE status IN ('active', 'delayed', 'withdrawing', 'orphan')`.
- **xDrop tab**: `SELECT FROM xdrop_active_rules WHERE status IN ('active', 'delayed', 'withdrawing')`.
- **Detail drawer Execution Timeline**: merges `bgp_announcement_events` (BGP) or synthesized entries from `action_execution_log` (xDrop) plus `action_manual_overrides` rows.

### bgp_role on Action-Execution-Log

Because a single BGP announcement can serve multiple attacks, the `GET /api/attacks/:id/action-log` response enriches each BGP on_detected log row with a `bgp_role` field:

| bgp_role | Meaning |
|----------|---------|
| `triggered` | This attack was first to attach in the current cycle — the vtysh announce actually fired for this attack. |
| `attached_shared` | This attack joined an existing `active` announcement (refcount was already ≥1). No vtysh side effect. |
| (empty) | Not a BGP on_detected row, or the announcement lookup failed. |

The `triggered` attack is determined by sorting `bgp_announcement_attacks` on `(attached_at ASC, attack_id ASC)` and picking the first. A cycle filter (`attached_at >= announced_at`) is applied first so prior-cycle ghost attachments are ignored. The enrichment also returns `announcement_id` and `announcement_refcount` so the UI can render "shared with N attacks" tooltips.

---

## 7. Observability (v1.2.1)

### Prometheus `/metrics` Endpoint

The Controller exposes a Prometheus scrape endpoint at `GET /metrics`. It is **unauthenticated by convention** (matching kube-apiserver / etcd / Prometheus itself) — network-level isolation is expected to gate it.

The registry is populated at startup by `metrics.Register()`. The default `promhttp.Handler()` also exposes Go runtime and process metrics for free.

**Counters (inline, bumped at call sites):**

| Metric | Labels | Semantics |
|--------|--------|-----------|
| `xsight_vtysh_ops_total` | `operation`, `result` | vtysh announce/withdraw outcomes. `operation ∈ {announce, withdraw}`, `result ∈ {success, failed, idempotent}`. `idempotent` = FRR reported route-absent on withdraw, xSight absorbed as success. |
| `xsight_action_executions_total` | `action_type`, `status` | Action dispatch outcomes. `action_type ∈ {bgp, xdrop, webhook, shell}`, `status ∈ {success, failed, timeout, skipped, scheduled}`. |
| `xsight_action_skip_total` | `skip_reason` | Broken-out view of `status=skipped`. `skip_reason ∈ {mode_observe, precondition_not_matched, first_match_suppressed, decoder_not_xdrop_compatible, manual_override_suppressed, force_removed}`. |
| `xsight_scheduled_actions_recovered_total` | `outcome` | Startup recovery of `scheduled_actions`. `outcome ∈ {armed, overdue_fired, executing_retried}`. Non-zero `executing_retried` is an incident signal (crash between MarkExecuting and Complete). |

**Custom collectors (scrape-time DB reads, fresh gauges):**

| Metric | Labels | Source |
|--------|--------|--------|
| `xsight_bgp_announcements` | `status` | `SELECT status, count(*) FROM bgp_announcements GROUP BY status` |
| `xsight_xdrop_rules` | `status` | `SELECT status, count(*) FROM xdrop_active_rules GROUP BY status` |
| `xsight_scheduled_actions` | `status` | `SELECT status, count(*) FROM scheduled_actions GROUP BY status` |

Each collector has a 5-second context timeout. If the query errors, the collector emits zero samples for that scrape (standard "collector error" signal in Prometheus) rather than returning HTTP 500.

**Attack tracker gauges (wrap atomic counters in `tracker.Tracker`):**

| Metric | Type | Source |
|--------|------|--------|
| `xsight_attacks_active` | Gauge | `tracker.ActiveCount()` |
| `xsight_attacks_created_total` | Counter | `tracker.CreatedTotal` |
| `xsight_attacks_suppressed_total` | Counter | `tracker.SuppressedTotal` (dedup) |
| `xsight_attacks_evicted_total` | Counter | `tracker.EvictedTotal` (capacity cap reached — non-zero means raise `max_active_attacks`) |

### Instrumentation Pattern

The engine instruments its `store.Store` via a thin decorator (`metrics.InstrumentStore`) installed once in `main.go`. Only the `ActionExecLog().Create()` path is wrapped — it bumps `xsight_action_executions_total{action_type, status}` from the log row's own fields. All other call sites pass through without modification. This keeps the metric as a side effect of a durable DB write (single source of truth), so the log row and the counter can never disagree.

### xDrop Decoder Compatibility Gate

xDrop operates at L4 (protocol + 5-tuple). Decoders that are L3 aggregates (`ip`) cannot be safely translated to an xDrop rule — the resulting `protocol=all` with a `dst_ip` match would degrade into a full-prefix blackhole once flow analysis for `dominant_src_port` / `dominant_dst_port` fails to narrow it. v1.2.1 therefore enforces a compatibility whitelist:

| Decoder | xDrop-compatible | Rationale |
|---------|------------------|-----------|
| `tcp` | yes | Maps to `protocol=tcp` |
| `tcp_syn` | yes | Maps to `protocol=tcp` + `tcp_flags=SYN,!ACK` |
| `udp` | yes | Maps to `protocol=udp` |
| `icmp` | yes | Maps to `protocol=icmp` (or `icmpv6`) |
| `fragment` | yes | Normalized to `protocol=all`; fragmented traffic is a clear attack signal |
| `ip` | **no** | L3 aggregate — use BGP null-route instead |

Attacks whose `decoder_family` is not in the whitelist have their xDrop actions skipped with `skip_reason=decoder_not_xdrop_compatible`. BGP / webhook / shell are unaffected.

---

## 8. Data Model

### Core Tables

| Table | Purpose |
|-------|---------|
| `attacks` | Attack records with dst_ip (INET), direction, decoder, severity, peak PPS/BPS, response_id, threshold_rule_id |
| `watch_prefixes` | Monitored IP ranges with template binding |
| `threshold_templates` | Named rule collections with default response_id |
| `thresholds` | Detection rules: domain, direction, decoder, unit, value; optional per-rule response_id override |
| `responses` | Response definitions (containers for actions) |
| `response_actions` | Actions: type, trigger_phase, connector, delay, paired_with, auto_generated |
| `action_execution_log` | Append-only audit of every dispatch: trigger_phase, status, skip_reason, external_rule_id, connector_id, scheduled_for |
| `action_preconditions` | Per-action filter conditions (attribute, operator, value) |
| `ts_stats` | Time-series traffic data (TimescaleDB hypertable with compression) |
| `flow_logs` | Sampled flow data for attack fingerprinting |
| `config_audit_log` | Configuration change audit trail |

### Action State Tables (v1.2)

See [Section 6](#6-action-state-layer-v12) for lifecycle semantics.

| Table | Purpose |
|-------|---------|
| `bgp_announcements` | Per-announcement state (shared, refcounted). Unique on `(prefix, route_map, connector_id)` |
| `bgp_announcement_attacks` | N:1 mapping of attacks → announcement. PK `(announcement_id, attack_id)` |
| `bgp_announcement_events` | Append-only audit trail for Mitigations detail drawer |
| `xdrop_active_rules` | Per-xDrop-rule state. Unique on `(attack_id, action_id, connector_id, external_rule_id)` |
| `scheduled_actions` | Persisted delayed withdraw/unblock tasks (survives restart) |
| `action_manual_overrides` | Operator force-remove audit, used for per-artifact on_expired suppression |

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

**`bgp_announcements.refcount`**: Number of currently-attached attacks. The announcement can only transition to `delayed`/`withdrawing` when `refcount` drops to 0. Concurrent Attach/Detach are serialized via `SELECT … FOR UPDATE` on the business key — races between attach and detach on the same announcement cannot produce a torn state.

**`bgp_announcement_attacks.delay_minutes`**: Snapshot of the originating action's `bgp_withdraw_delay_minutes` at attach time. Used to compute the cycle-sticky MAX delay and for the post-cycle audit (which attack contributed which delay).

**`scheduled_actions.announcement_id`**: On BGP withdraw rows, points at the `bgp_announcements.id` being withdrawn. Lets the scheduler flip the announcement row to `withdrawing`/`withdrawn` atomically with the vtysh call.

---

## 9. Frontend Architecture

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
| Attack Detail | `/attacks/:id` | Summary + execution log (with BGP Role column) + per-attack Force Remove + sensor logs |
| Active Mitigations | `/mitigations` | BGP Routing + xDrop Filtering tabs with detail drawer. BGP tab also surfaces `orphan` announcements |
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
