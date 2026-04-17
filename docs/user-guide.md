# xSight User Guide

> xSight is a distributed DDoS detection and response platform powered by XDP/eBPF and flow analysis.
> This guide covers installation, configuration, and daily operation.

---

## Table of Contents

1. [Quick Start](#1-quick-start)
2. [Node Management](#2-node-management)
3. [Watch Prefixes](#3-watch-prefixes)
4. [Detection Configuration](#4-detection-configuration)
5. [Response Configuration](#5-response-configuration)
6. [Connector Configuration](#6-connector-configuration)
7. [Monitoring & Operations](#7-monitoring--operations)
8. [Common Scenarios](#8-common-scenarios)
9. [API Reference](#9-api-reference)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Quick Start

> **Time estimates** (assuming dependencies are already installed):
> - Basic observation (traffic + detection): ~15 minutes
> - Full mitigation pipeline (BGP + xDrop): +30-60 minutes

### 1.1 System Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Debian 12+ / Ubuntu 22.04+ (Linux kernel 5.15+ for XDP mode) |
| Go | 1.22+ |
| PostgreSQL | 17 with TimescaleDB extension |
| Node.js | 20+ (for building the Web UI) |
| FRR | 10+ (optional, required for BGP response actions) |
| xDrop | (optional, required for xDrop response actions) |

### 1.2 Install Controller

**Build:**

```bash
cd controller
go build -o bin/xsight-controller .
```

**Configure** — copy `config.example.yaml` to `config.yaml` and edit:

```yaml
listen:
  grpc: ":50051"      # Node ingestion (gRPC)
  http: ":8080"        # Web UI + REST API

database:
  driver: "postgres"
  dsn: "postgres://xsight:YOUR_PASSWORD@localhost:5432/xsight?sslmode=disable"

auth:
  api_key: "YOUR_API_KEY"

action_engine:
  mode: "auto"         # IMPORTANT: default is "observe" — xDrop actions will be SKIPPED
                       # Set to "auto" to enable xDrop blocking
                       # (BGP, webhook, shell actions are NOT gated by mode — they always run)
```

> **Warning:** If `action_engine.mode` is omitted or set to `"observe"`, **xDrop response actions will NOT execute** — the engine logs the attack and skips all xDrop actions. BGP, webhook, and shell actions are not gated by this setting and continue to execute normally. Set `mode: "auto"` to enable automated xDrop blocking.

See `config.example.yaml` for the full parameter reference.

**Start as a systemd service:**

```bash
sudo cp deploy/xsight-controller.service /etc/systemd/system/
sudo systemctl enable --now xsight-controller
```

### 1.3 Install Node

#### XDP Mode

XDP mode captures packets directly on a network interface using eBPF. Requires root and Linux kernel 5.15+.

```bash
cd node
make build
```

**Configure** (`config.yaml`):

```yaml
node_id: "my-node-01"
interfaces:
  - name: "ens3"
    mode: "mirror"
    upstream_sample_rate: 1000
    sample_bytes: 128
bpf:
  max_entries: 1000000
controller:
  address: "controller-ip:50051"
auth:
  node_api_key: "YOUR_NODE_KEY"
```

#### Flow Mode

Flow mode receives sFlow / NetFlow v5/v9 / IPFIX. No BPF compilation required.

**Node config.yaml** (minimal — listeners and sources are configured in the Controller Web UI):

```yaml
node_id: "flow-node-01"
mode: "flow"              # Required — without this, the node defaults to XDP mode and fails

controller:
  address: "controller-ip:50051"
auth:
  node_api_key: "YOUR_NODE_KEY"
```

> **Important:** A flow node with no configured listeners/sources will connect successfully but will not ingest any traffic. You must configure Flow Listeners and Flow Sources in the Controller Web UI after the node connects.

**Start:**

```bash
sudo cp deploy/xsight-node.service /etc/systemd/system/
sudo systemctl enable --now xsight-node
```

> The node service runs as root because XDP mode requires `CAP_NET_ADMIN`. The systemd unit sets `LimitMEMLOCK=infinity` for BPF map allocation.

### 1.4 First Login

1. Open `http://controller-ip:8080` in your browser.
2. Sign in with the default credentials: **admin** / **admin**.
3. **Change the default password immediately:** go to **Settings > Users**, click **Edit** on the admin user.
4. Use the top-right header to switch theme (Classic / Amber) and language (EN / ZH).

### 1.5 Basic Observation (~15 minutes)

Once the Controller and at least one Node are running:

1. **Register the Node:** Go to **Nodes** (sidebar > INFRASTRUCTURE > Nodes). Click **Add Node**, enter the Node ID and API Key (must match the node's `config.yaml`), select the mode (XDP or Flow), and click **Create**. Then start the node service. The node will appear as **Online** once it connects.

   > **Important:** The node must be registered in the Controller **before** starting the node process. The gRPC handshake rejects unknown nodes.

2. **Add a Watch Prefix:** Go to **Watch Prefixes** (sidebar > INFRASTRUCTURE > Watch Prefixes). Click **Add Prefix**, enter a CIDR (e.g., `198.51.100.0/24`), give it a name, and click **Create**.

3. **Create a Threshold Template:** Go to **Templates** (sidebar > DETECTION > Templates). Click **Create**, enter a name like "BasicProtection". Click the new template to open its detail view.

4. **Add a detection rule:** In the template detail, click **+ Add Rule**. Set:
   - Domain: `subnet`
   - Direction: `Receives (Inbound)`
   - Decoder: `ip`
   - Unit: `pps`
   - Comparison: `Over`
   - Value: `100000`
   - Inheritable: enabled
   - Click **Create**.

5. **Bind the template to your prefix:** Go back to **Watch Prefixes**, click **Edit** on your prefix, select "BasicProtection" from the **Template** dropdown, and click **Save**.

Traffic data will now appear on the **Dashboard** and **Traffic Overview** pages. When traffic exceeds 100K PPS, an attack will appear on the **Attacks** page.

### 1.6 Full Mitigation Pipeline (+30 minutes)

To enable automatic BGP + xDrop response:

1. **Create Connectors** — Go to **Settings** in the sidebar and configure at least one BGP Connector and/or xDrop Connector. See [Section 6](#6-connector-configuration).

2. **Create a Response:** Go to **Responses** (sidebar > DETECTION > Responses). Click **Add Response**, give it a name like "Production Response", and click **Create**.

3. **Add Actions:** Click the new response to open its detail page. In the **When Attack Detected** section, click **+ Add Action**:
   - For BGP: Set Action Type to "BGP", select your connector, set Route Map (e.g., `DIVERT`), set Withdraw Delay if desired. Click **Save**.
   - For xDrop: Set Action Type to "xDrop", select Action "Filter L4", check "Dst IP" in Filter Fields, set Unblock Delay if desired. Add a precondition `Domain = internal_ip` to limit xDrop to single-host attacks. Click **Save**.

4. **Bind the Response:** Go to **Templates**, open your template, and select your Response from the **Default Response** dropdown.

When an attack triggers, check the **Active Mitigations** page (sidebar > MONITORING > Active Mitigations) to see live BGP routes and xDrop rules.

---

## 2. Node Management

Navigate to: **Sidebar > INFRASTRUCTURE > Nodes**

### 2.1 XDP Mode

XDP mode attaches a BPF program to a network interface for line-rate packet inspection.

**When to use:** Direct mirror port, SPAN port, or ERSPAN tunnel where per-packet accuracy is needed. Current node config modes are `mirror` and `erspan`.

**Node config.yaml parameters:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `node_id` | Unique node identifier | (required) |
| `interfaces[].name` | Network interface name | (required) |
| `interfaces[].mode` | `mirror` (receive-only) or `erspan` | (required) |
| `interfaces[].upstream_sample_rate` | 1:N packet sampling (1 = no sampling) | `1` |
| `interfaces[].sample_bytes` | Bytes to capture per packet (128-512) | `256` |
| `bpf.max_entries` | BPF map size for IP tracking | `1000000` |
| `parse_workers` | Packet parse threads | NumCPU/2 |

### 2.2 Flow Mode

Flow mode receives sFlow, NetFlow v5/v9, or IPFIX from routers and switches.

**When to use:** Existing flow export infrastructure, or environments where XDP deployment is not feasible.

The node `config.yaml` for Flow mode needs `node_id`, `mode: flow`, `controller`, and `auth`. **Flow Listeners and Flow Sources are configured in the Controller Web UI**, not in the node's local config file. A flow node without configured listeners/sources will connect but will not ingest any traffic.

1. Go to **Nodes**, click the Flow node in the list.
2. Click the **Flow Config** button.
3. **Add a Flow Listener:** Set the listen address (e.g., `0.0.0.0:6343` for sFlow) and protocol mode (`auto`, `sflow`, `netflow`, or `ipfix`).
4. **Add Flow Sources** under the listener: Enter the device IP of each router/switch exporting flow data, and optionally override the sample rate.

### 2.3 Node Status

The Nodes page shows:

| Column | Description |
|--------|-------------|
| Node ID | Unique identifier |
| Mode | XDP or Flow |
| Status | Online (green) / Offline (grey) |
| Config Status | Synced / Pending / Failed |
| Drift | Difference between current and applied config version |
| Last ACK | When the node last acknowledged a config push |

If a node shows persistent **Pending** or high **Drift**, check network connectivity to gRPC port 50051 and verify the node API key.

---

## 3. Watch Prefixes

Navigate to: **Sidebar > INFRASTRUCTURE > Watch Prefixes**

### 3.1 Concept

A **Watch Prefix** is an IP range (IPv4 or IPv6 CIDR) that xSight monitors. Each prefix can be bound to a **Threshold Template** that defines detection rules.

Prefixes support a parent-child hierarchy. For example, `198.51.100.0/22` as parent and `198.51.100.0/24` as child — rules marked **Inheritable** on the parent template propagate to children.

### 3.2 Adding a Prefix

Click **Add Prefix** and fill in:

| Field | Description |
|-------|-------------|
| Prefix (CIDR) | IP range, e.g., `198.51.100.0/24` or `2001:db8::/32` |
| Name | Display name |
| IP Group | Optional grouping label |
| Parent Prefix | Optional parent for rule inheritance |
| Template | Threshold Template to bind |

### 3.3 Global Prefix (0.0.0.0/0)

The global prefix monitors aggregate traffic across all registered prefixes. It acts as a catch-all for volume anomalies.

**Limitations:**
- Cannot bind a Response containing xDrop or BGP actions (prevents accidental global blackhole).
- Only `subnet` domain rules are supported (not `internal_ip`).
- Use `0.0.0.0/0` for the global prefix — it covers both IPv4 and IPv6 traffic. `::/0` is not supported and will be rejected by the API.

---

## 4. Detection Configuration

Navigate to: **Sidebar > DETECTION > Templates**

### 4.1 Threshold Templates

A **Threshold Template** is a named collection of detection rules. Click any template in the list to open its detail view.

The detail view shows:
- **Default Response** — the Response executed when an attack triggers (selectable from dropdown).
- **Used By** — which prefixes reference this template.
- **Rules table** — all detection rules with their parameters.

### 4.2 Rule Parameters

Click **+ Add Rule** in the template detail to create a rule. Each rule defines a condition that, when sustained (default 3 seconds), confirms an attack.

| Parameter | Options | Description |
|-----------|---------|-------------|
| Domain | `internal_ip` / `subnet` | `internal_ip`: per-host detection (attack reported as /32 or /128). `subnet`: aggregate detection for the entire prefix. |
| Direction | `Receives (Inbound)` / `Sends (Outbound)` | `Receives` for inbound DDoS. `Sends` for outbound attack/scan detection. |
| Decoder | `ip` / `tcp` / `tcp_syn` / `udp` / `icmp` / `fragment` | Protocol filter. `ip` matches all. `tcp_syn` matches SYN-only TCP packets. |
| Unit | `pps` / `bps` / `pct (%)` | Packets per second, bits per second, or percentage of total. |
| Comparison | `Over` / `Under` | Trigger when traffic exceeds (Over) or drops below (Under) the threshold. |
| Value | number | Threshold value. |
| Inheritable | on/off | When enabled, child prefixes inherit this rule. |

**Example rules for production:**

| Domain | Direction | Decoder | Unit | Value | Purpose |
|--------|-----------|---------|------|-------|---------|
| subnet | Receives | ip | pps | 100,000 | Overall inbound PPS |
| subnet | Receives | ip | bps | 1,000,000,000 | Inbound 1 Gbps |
| subnet | Receives | udp | pps | 1,000,000 | UDP flood |
| subnet | Receives | tcp_syn | pps | 1,000,000 | SYN flood |
| internal_ip | Sends | ip | bps | 500,000,000 | Outbound per-host 500 Mbps |

### 4.3 Rule-Level Response Override

Each rule has its own **Response** dropdown column in the rules table. When set, it overrides the template's Default Response for attacks triggered by that specific rule.

**Common use case:** Inbound rules use the template default (BGP + xDrop), while the outbound (sends) rule overrides with a webhook-only Response.

### 4.4 Dynamic Detection (Baseline)

Navigate to: **Sidebar > DETECTION > Dynamic Detection**

Dynamic detection calculates a traffic baseline for each prefix from historical data and alerts when traffic deviates significantly. Enable it and configure parameters like deviation thresholds and minimum stable weeks.

### 4.5 How Detection Works

1. **Every second**, the detection engine evaluates all prefixes against their rules.
2. When traffic exceeds a threshold for the **confirmation period** (default 3 seconds), the attack is confirmed.
3. The attack enters **Active** state, is recorded in the database, and triggers the configured Response.
4. When traffic drops below the threshold, the attack enters **Expiring** with a countdown (default 300 seconds).
5. If traffic re-breaches during the countdown, the attack returns to **Active** (re-breach).
6. When the countdown finishes, the attack is **Expired** and on_expired actions fire.

**Severity** is auto-classified:

| Severity | Condition |
|----------|-----------|
| Critical | PPS > 1M **or** BPS > 10 Gbps |
| High | PPS > 100K **or** BPS > 1 Gbps |
| Medium | PPS > 10K **or** BPS > 100 Mbps |
| Low | All other |

---

## 5. Response Configuration

Navigate to: **Sidebar > DETECTION > Responses**

### 5.1 Concept

A **Response** is a collection of **Actions**. Click a response in the list to open its detail page.

The detail page is divided into two sections:
- **When Attack Detected** — actions that fire when an attack is confirmed.
- **When Attack Expired** — actions that fire when the attack ends.

### 5.2 Creating an Action

Click **+ Add Action** in either section. The Action Editor dialog has these fields:

**Common fields (all action types):**

| Field | Description |
|-------|-------------|
| Action Type | `Webhook` / `xDrop` / `Shell` / `BGP` |
| Connector | Which connector to use (dropdown) |
| Priority | Execution priority (1-10, lower = higher priority) |
| Run Mode | `Once` / `Periodic` / `Retry Until Success` |
| Execution | `Automatic` / `Manual` |
| Enabled | On/Off toggle |

**xDrop-specific fields:**

| Field | Description |
|-------|-------------|
| xDrop Action | `Filter L4` (block) / `Rate Limit` / `Unblock` |
| Filter Fields | Checkboxes: Dst IP, Src IP, Dst Port, Src Port, Protocol — checked fields become rule match conditions |
| Rate Limit (PPS) | Rate limit value (only for Rate Limit action) |
| Target Nodes | Which xDrop connectors to target (empty = all) |
| Unblock Delay (min) | Minutes to wait before removing the rule after attack expires (0-1440) |

**BGP-specific fields:**

| Field | Description |
|-------|-------------|
| Route Map | FRR route-map name (e.g., `RTBH`, `DIVERT`) |
| Withdraw Delay (min) | Minutes to wait before withdrawing the route after attack expires (0-1440) |

**Shell-specific fields:**

| Field | Description |
|-------|-------------|
| Extra Arguments | Additional command-line arguments passed to the script |

**Preconditions** (bottom of the dialog):

Click **+ Add Condition** to add filters. Only attacks matching **all** conditions (AND logic) will trigger the action.

| Attribute | Description | Example |
|-----------|-------------|---------|
| Decoder | Protocol type | `= udp` — only UDP attacks |
| Attack Type | Initial classification | `= syn_flood` |
| Severity | Severity level | `in critical,high` |
| PPS | Peak packets/sec | `> 100000` |
| BPS | Peak bits/sec | `> 1000000000` |
| Domain | Single host or subnet | `= internal_ip` — only /32 or /128 attacks |
| CIDR | Prefix length | `= 32` — only single IP |
| Node | Reporting node | `in sg-mirror-01,hk-mirror-01` |
| Dominant Src Port | Top source port | `= 53` — DNS reflection |
| Dominant Dst Port | Top destination port | `= 80` — HTTP attacks |
| Dominant Src Port % | Source port concentration | `>= 80` |
| Unique Src IPs | Distinct source IPs | `> 1000` |

### 5.3 Auto-Paired Actions

When you create an **xDrop** or **BGP** action under "When Attack Detected", the system **automatically generates** a matching action under "When Attack Expired":

- xDrop Filter L4 / Rate Limit → auto-creates xDrop Unblock
- BGP announce → auto-creates BGP withdraw

You do not need to manually create cleanup actions. The auto-generated action:
- Copies the connector, delay, and target settings from the parent.
- Updates automatically when you modify the parent.
- Is deleted automatically when you delete the parent.
- Cannot be edited directly (manage it through the parent on_detected action).

> **Note:** xDrop and BGP are not available in the Action Type dropdown under "When Attack Expired" — they are managed automatically via pairing.

### 5.4 Delay

Delay prevents premature removal of mitigation. Attackers often resume once protection is lifted.

- **Unblock Delay**: Set on xDrop actions. The xDrop rule stays active for N minutes after the attack expires before being automatically removed.
- **Withdraw Delay**: Set on BGP actions. The BGP route stays active for N minutes before being withdrawn.

During the delay, the **Active Mitigations** page shows the item as **Delayed** with a countdown. If the attack re-breaches during the delay, the countdown is cancelled and mitigation stays active.

### 5.5 First-Match ACL

For xDrop, BGP, and Shell actions, only the **first matching** action per type executes (sorted by priority). This enables ACL-style rules:

- Priority 1: xDrop filter with precondition `Decoder = tcp_syn`
- Priority 2: xDrop filter with no precondition (catch-all)

A SYN flood matches Priority 1 and skips Priority 2. A UDP flood skips Priority 1 and matches Priority 2.

**Exception:** All matching Webhook actions execute regardless of priority.

---

## 6. Connector Configuration

Navigate to: **Sidebar > SETTINGS**

### 6.1 Webhook Connectors

Path: **Settings > Webhook Connectors**

| Field | Description |
|-------|-------------|
| Name | Display name |
| URL | HTTP endpoint to receive notifications |
| Headers | Custom headers as JSON (e.g., `{"Authorization": "Bearer xxx"}`) |
| Timeout (ms) | Request timeout |
| Global | When enabled, all attack events are sent automatically without needing a Response binding |

Click **Test** to verify connectivity.

### 6.2 xDrop Connectors

Path: **Settings > xDrop Connectors**

| Field | Description |
|-------|-------------|
| Name | Display name |
| API URL | xDrop REST API base URL (e.g., `http://10.0.0.1:8000/api/v1`) |
| API Key | Authentication key |
| Timeout (ms) | Request timeout (recommend 30000 if xDrop has node sync) |

Click **Test** to verify connectivity.

### 6.3 Shell Script Connectors

Path: **Settings > Shell Scripts**

| Field | Description |
|-------|-------------|
| Name | Display name |
| Command | Executable path (e.g., `/usr/local/bin/mitigate.sh`) |
| Default Args | Default arguments |
| Timeout (ms) | Execution timeout |

### 6.4 BGP Connectors

Path: **Settings > BGP Connectors**

| Field | Description |
|-------|-------------|
| Name | Display name |
| BGP ASN | Your Autonomous System Number |
| vtysh Path | Path to vtysh binary (default: `/usr/bin/vtysh`) |

**Auto-AFI:** The connector automatically detects IPv4 vs IPv6 from the attacked prefix and uses the correct address-family in vtysh commands. A single connector handles both IPv4 and IPv6 — no separate configuration needed.

**Prerequisites:** FRR must be installed with `bgpd` enabled. Configure your ASN and route-maps in FRR before using the connector.

Click **Test** to verify FRR connectivity. Click **Routes** to view the current BGP routing table.

---

## 7. Monitoring & Operations

### 7.1 Dashboard

Path: **Sidebar > MONITORING > Dashboard**

The Dashboard provides a real-time overview with four stat cards:
- **Active Attacks** — click to jump to the Attacks page.
- **Nodes** — total count with online/offline breakdown.
- **Watch Prefixes** — total monitored prefixes.
- **Thresholds** — total active detection rules.

Below the cards is an **Active Attacks** table showing current attacks with target IP, decoder, severity, peak values, trigger rule, and timer.

### 7.2 Traffic Overview

Path: **Sidebar > MONITORING > Traffic Overview**

Time-series traffic charts with filtering by prefix, node, direction, and time range.

### 7.3 Attacks

Path: **Sidebar > MONITORING > Attacks**

**Active Attacks** tab shows ongoing attacks with:
- Target IP, Direction (Inbound/Outbound), Decoder, Attack Type, Severity
- **Peak** — shows PPS when peak PPS data is available, otherwise shows BPS
- **Trigger Rule** — the template and rule that detected the attack
- **Timer** — shows "Breaching" (threshold still exceeded) or a countdown (expiring)
- **Expire** button — manually end an attack

**All Attacks** tab provides paginated history.

**Attack Detail** (click any attack row):
- Summary: IP, decoder, severity, peak values, start/end times, node sources
- **Actions Log**: All actions that fired for this attack with status, connector, duration, error message
- **Sensor Logs**: Sampled flow data — top source IPs, source ports, destination ports, and 5-tuple flow breakdown

### 7.4 Active Mitigations

Path: **Sidebar > MONITORING > Active Mitigations**

This page shows all currently active BGP routes and xDrop filtering rules across two tabs.

**BGP Routing tab:**
Columns: Attack ID, Prefix, Route Map, BGP Connector, Announced At, Timer, Status, Actions (Force Withdraw)

**xDrop Filtering tab:**
Columns: Attack ID, Dst IP, Rule ID, Action (drop/rate_limit), Protocol, TCP Flags, xDrop Connector, Created At, Timer, Status, Actions (Force Unblock)

**Status meanings:**

| Status | Color | Meaning |
|--------|-------|---------|
| Active | Green | Mitigation is active, attack ongoing |
| Delayed | Yellow | Attack ended, waiting for delay timer before automatic removal |
| Pending | Yellow | Attack ended, removal is queued |
| Failed | Red | Removal attempted but failed |

**Timer column:** Active items show elapsed duration. Delayed items show remaining countdown.

**Detail Drawer:** Click any row to open a side panel with:
- **Summary**: Attack link, target IP, connector, creation time, timer
- **Configuration**: BGP (Prefix, Route Map) or xDrop (Action, Protocol, TCP Flags, Dst IP)
- **Execution Timeline**: Chronological list of all execution events for this artifact (on_detected, scheduled, on_expired, manual_override) with colored status dots

**Force Remove:** Click **Force Withdraw** (BGP) or **Force Unblock** (xDrop) to immediately remove a mitigation. After force removal, the automatic on_expired action is suppressed for that specific artifact.

### 7.5 Audit Log

Path: **Sidebar > SETTINGS > Audit Log**

Records all configuration changes and manual operations. Filter by entity type, time range, and user.

---

## 8. Common Scenarios

### 8.1 UDP Reflection Attack

**Symptoms:** High inbound UDP traffic from well-known source ports (53, 123, 11211).

**Setup:**
1. **Template rule:** Domain `subnet`, Direction `Receives`, Decoder `udp`, Unit `pps`, Value `1000000`.
2. **Response with two actions:**
   - BGP (on_detected): Route Map `DIVERT`, Withdraw Delay `5 min`.
   - xDrop (on_detected): Filter L4, Dst IP checked, Precondition `Domain = internal_ip`, Unblock Delay `5 min`.

**Result:** Attack detected → BGP route announced + xDrop drop rule created for each single-host target. Attack ends → 5-minute delay → BGP withdrawn + xDrop rules removed.

### 8.2 SYN Flood

**Symptoms:** High volume of TCP SYN packets.

**Setup:**
1. **Template rule:** Decoder `tcp_syn`, Unit `pps`, Value `1000000`.
2. **xDrop action** with Dst IP filter field checked.

**Result:** When the attack decoder is `tcp_syn`, xSight automatically injects `protocol: tcp` and `tcp_flags: SYN,!ACK` into the xDrop rule. No manual flag configuration needed.

### 8.3 Carpet Bombing (Subnet Attack)

**Symptoms:** An entire /24 is attacked — each IP receives moderate traffic but the aggregate is massive.

**Setup:**
1. **Template rule:** Domain `subnet` (detects aggregate prefix traffic).
2. **BGP action** with no precondition (all attacks).
3. **xDrop action** with precondition `Domain = internal_ip`.

**Result:** The /24 subnet attack triggers BGP for the whole prefix. xDrop does **not** fire (because domain is `subnet`, not `internal_ip`). If individual IPs within the /24 also exceed the `internal_ip` threshold, they get their own xDrop rules.

### 8.4 Outbound Attack Detection

**Symptoms:** A compromised host sends attack traffic outward.

**Setup:**
1. **Template rule:** Direction `Sends`, Decoder `ip`, Unit `bps`, Value `500000000`.
2. Set the rule's **Response** dropdown to a webhook-only Response (rule-level override).

**Result:** Outbound attack detected → webhook notification sent. No BGP/xDrop triggered (you don't want to blackhole your own IP).

### 8.5 False Positive Recovery

**Situation:** A legitimate IP is incorrectly blocked by xDrop or BGP.

**Steps:**
1. Go to **Active Mitigations**.
2. Find the entry.
3. Click **Force Withdraw** (BGP) or **Force Unblock** (xDrop), then confirm.

The mitigation is removed immediately. Even if the attack later expires naturally, the automatic cleanup action is suppressed for this artifact — no re-blocking occurs.

### 8.6 IPv6 Attack

**Situation:** An IPv6 prefix or host is under attack.

No special configuration needed. xSight natively supports IPv6:
- Detection works with IPv6 prefixes and addresses.
- BGP actions automatically use `address-family ipv6 unicast` for IPv6 targets.
- The same BGP connector handles both IPv4 and IPv6 (Auto-AFI).

---

## 9. API Reference

xSight provides a full REST API for automation and integration.

- **Controller API:** See [controller/API.md](../controller/API.md) for the complete endpoint reference.
- **Node API:** See [node/API.md](../node/API.md).

**Authentication:** All API requests require either:
- Header: `X-API-Key: YOUR_API_KEY`
- Header: `Authorization: Bearer JWT_TOKEN` (obtained via `POST /api/login`)

---

## 10. Troubleshooting

### Controller won't start
- Check `config.yaml` for syntax errors.
- Verify PostgreSQL is running: `systemctl status postgresql`.
- Check port conflicts: `ss -tlnp | grep 8080`.
- Review logs: `journalctl -u xsight-controller -f`.

### Node not showing as online
- Check gRPC connectivity: `nc -zv controller-ip 50051`.
- Verify `node_api_key` matches a registered node.
- Check the node service: `systemctl status xsight-node` (or your custom unit name for Flow nodes).
- Review logs: `journalctl -u xsight-node -f`.

### Attacks not triggering
- Confirm the prefix has a Template bound (check in Watch Prefixes page).
- Verify thresholds match your traffic levels (too high = never triggers).
- Check that at least one Node is online and reporting data.

### Actions not executing
- Verify the template has a Response bound (check Default Response dropdown).
- Check that the Response and its Actions are enabled.
- Review Preconditions — they may be filtering the attack.
- Test connector connectivity (use the Test button on the Connectors page).
- Check execution logs on the Attack Detail page.

### BGP routes not appearing
- Verify FRR is running: `systemctl status frr`.
- Check `bgpd` is enabled in `/etc/frr/daemons`.
- Verify route-map exists: `vtysh -c "show route-map"`.
- Review execution logs for vtysh errors.

### xDrop rules not being created
- Verify xDrop service is reachable from the Controller.
- Check connector API URL and key.
- Increase timeout if xDrop has sync delays (30000ms recommended).
- Review execution logs for HTTP error codes.
