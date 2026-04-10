# xSight Controller API Reference

Base URL: `http://<host>:8080/api`

## Authentication

All `/api/*` endpoints (except `/api/login`) require one of:

- **API Key**: `X-API-Key: <key>` header (configured in `config.yaml` under `auth.api_key`)
- **JWT Bearer**: `Authorization: Bearer <token>` header (obtained from `/api/login`)

JWT tokens expire after 24 hours.

---

## Login

### POST /api/login

Authenticate a user and receive a JWT token.

| Field | Type | Description |
|-------|------|-------------|
| `username` | string | **Required.** |
| `password` | string | **Required.** |

**Response:**

```json
{
  "token": "eyJhbG...",
  "user": { "id": 1, "username": "admin", "role": "admin" }
}
```

---

## Users

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/users` | List all users |
| POST | `/api/users` | Create a user |
| PUT | `/api/users/:id` | Update a user |
| DELETE | `/api/users/:id` | Delete a user |

### Create User -- POST /api/users

| Field | Type | Description |
|-------|------|-------------|
| `username` | string | **Required.** |
| `password` | string | **Required.** |
| `role` | string | `admin` or `viewer` (default: `viewer`) |

### Update User -- PUT /api/users/:id

| Field | Type | Description |
|-------|------|-------------|
| `username` | string | New username |
| `role` | string | `admin` or `viewer` |
| `enabled` | bool | Enable/disable account |

---

## Nodes

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/nodes` | List all nodes (enriched with `online` status) |
| POST | `/api/nodes` | Register a node |
| GET | `/api/nodes/:id` | Get node details |
| PUT | `/api/nodes/:id` | Update node |
| DELETE | `/api/nodes/:id` | Delete node (cascades to flow listeners/sources) |
| GET | `/api/nodes/:id/status` | Detailed node status (online, config drift, flow metrics) |

### Create Node -- POST /api/nodes

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | **Required.** Node identifier (e.g. `hk-mirror-01`) |
| `api_key` | string | **Required.** Shared secret for gRPC authentication |
| `description` | string | Human-readable label |
| `mode` | string | `xdp` (default) or `flow` |

### Update Node -- PUT /api/nodes/:id

| Field | Type | Description |
|-------|------|-------------|
| `description` | string | |
| `mode` | string | `xdp` or `flow` |
| `enabled` | bool | |

### Node Status -- GET /api/nodes/:id/status

**Response** includes: `id`, `mode`, `online`, `config_status`, `delivery_version_current`, `delivery_version_applied`, `drift`, `last_ack_at`, `last_stats_at`, `stats_age_seconds`, `connected_at`, `uptime_seconds`, `flow_metrics`, `source_statuses`, `listener_statuses`.

---

## Prefixes

Watched IP prefixes (subnets) for traffic monitoring and threshold detection.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/prefixes` | List all prefixes (tree structure with parent/child) |
| POST | `/api/prefixes` | Create a watched prefix |
| GET | `/api/prefixes/:id` | Get prefix details |
| PUT | `/api/prefixes/:id` | Update prefix |
| DELETE | `/api/prefixes/:id` | Delete prefix |

### Create Prefix -- POST /api/prefixes

| Field | Type | Description |
|-------|------|-------------|
| `prefix` | string | **Required.** CIDR notation (e.g. `198.51.100.0/24`). Use `0.0.0.0/0` for global. `::/0` is not allowed. |
| `parent_id` | int | Parent prefix ID for hierarchy |
| `threshold_template_id` | int | Assign a threshold template |
| `name` | string | Display name |
| `ip_group` | string | IP group label |

### Update Prefix -- PUT /api/prefixes/:id

All fields optional. Supports `prefix`, `name`, `ip_group`, `parent_id`, `threshold_template_id`, `enabled`. Set `parent_id` or `threshold_template_id` to `null` to clear.

---

## Threshold Templates

Reusable threshold rule sets that can be assigned to multiple prefixes.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/threshold-templates` | List all templates |
| POST | `/api/threshold-templates` | Create a template |
| GET | `/api/threshold-templates/:id` | Get template with rules and assigned prefixes |
| PUT | `/api/threshold-templates/:id` | Update template |
| DELETE | `/api/threshold-templates/:id` | Delete template (fails if in use by prefixes) |
| POST | `/api/threshold-templates/:id/duplicate` | Duplicate template with all rules |
| GET | `/api/threshold-templates/:id/rules` | List rules in this template |
| POST | `/api/threshold-templates/:id/rules` | Create a rule in this template |

### Create Template -- POST /api/threshold-templates

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | **Required.** |
| `description` | string | |

### Update Template -- PUT /api/threshold-templates/:id

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | |
| `description` | string | |
| `response_id` | int/null | Default response for this template. Set `null` to clear. Cannot be xDrop/BGP if assigned to global prefix. |

### Duplicate Template -- POST /api/threshold-templates/:id/duplicate

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Name for the copy (default: original name + " (Copy)") |

### Create Template Rule -- POST /api/threshold-templates/:id/rules

| Field | Type | Description |
|-------|------|-------------|
| `domain` | string | `internal_ip` or `subnet` (default: `internal_ip`) |
| `direction` | string | `receives` or `sends` (default: `receives`) |
| `decoder` | string | Protocol filter: `ip`, `tcp`, `tcp_syn`, `udp`, `icmp`, `frag`, etc. |
| `unit` | string | `pps`, `bps`, or `pct` (percentage of total). `pct` requires a specific decoder. |
| `comparison` | string | `over` (default: `over`) |
| `value` | int | Threshold value. For `pct` unit: 1-100. |
| `inheritable` | bool | Whether child prefixes inherit this rule (default: `true`) |

---

## Thresholds (Per-Prefix Overrides)

Per-prefix threshold rules that override or supplement template rules.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/thresholds` | List all thresholds. Filter: `?prefix_id=N` |
| POST | `/api/thresholds` | Create a per-prefix threshold |
| GET | `/api/thresholds/:id` | Get threshold details |
| PUT | `/api/thresholds/:id` | Update threshold |
| DELETE | `/api/thresholds/:id` | Delete threshold |
| PUT | `/api/threshold-rules/:id` | Update a template rule (same handler) |
| DELETE | `/api/threshold-rules/:id` | Delete a template rule (same handler) |

### Create Threshold -- POST /api/thresholds

Same fields as template rules, plus:

| Field | Type | Description |
|-------|------|-------------|
| `prefix_id` | int | **Required.** Target prefix |
| `response_id` | int | Override response for this rule |

All validation from template rules applies (direction, decoder/unit combos, global prefix constraints).

---

## Responses

Response policies that define what actions to execute when an attack is detected or expires.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/responses` | List all responses |
| POST | `/api/responses` | Create a response |
| GET | `/api/responses/:id` | Get response with enriched actions |
| PUT | `/api/responses/:id` | Update response |
| DELETE | `/api/responses/:id` | Delete response (fails if referenced by templates or thresholds) |

### Create Response -- POST /api/responses

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | **Required.** |
| `description` | string | |
| `enabled` | bool | Default: `true` |

---

## Response Actions

Actions within a response policy. Each action has a type, trigger phase, and run mode.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/responses/:id/actions` | List actions for a response |
| POST | `/api/responses/:id/actions` | Create an action |
| PUT | `/api/actions/:id` | Update an action |
| DELETE | `/api/actions/:id` | Delete an action |

### Create/Update Action

| Field | Type | Description |
|-------|------|-------------|
| `action_type` | string | **Required.** `xdrop`, `bgp`, `webhook`, or `shell` |
| `trigger_phase` | string | `on_detected` or `on_expired`. `on_expired` only supports `run_mode=once`. |
| `run_mode` | string | `once`, `periodic`, or `retry_until_success` |
| `period_seconds` | int | Interval for `periodic` run mode |
| `execution` | string | Execution order control |
| `priority` | int | Lower = higher priority |
| `enabled` | bool | Default: `true` |
| `connector_id` | int | **Required for webhook/shell/bgp.** Connector to use |
| `target_node_ids` | []int | xDrop connector IDs to target (xDrop type only) |
| `xdrop_action` | string | xDrop only: `filter_l4`, `rate_limit`, or `unblock` |
| `xdrop_custom_payload` | object | xDrop only: match fields (`dst_ip`, `src_ip`, `dst_port`, `src_port`, `protocol`) and `rate_limit` value |
| `shell_extra_args` | string | Shell only: additional arguments passed to the command |
| `unblock_delay_minutes` | int | xDrop filter/rate_limit only: auto-unblock after N minutes (0-1440) |
| `bgp_route_map` | string | BGP only: **Required for on_detected.** Route-map name for blackhole injection |

### xDrop Targets

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/actions/:id/xdrop-targets` | Get xDrop connector IDs for an action |
| PUT | `/api/actions/:id/xdrop-targets` | Set xDrop connector IDs |

**PUT body:** `{ "connector_ids": [1, 2, 3] }`

### Preconditions

Conditional execution rules for actions.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/actions/:id/preconditions` | List preconditions |
| PUT | `/api/actions/:id/preconditions` | Replace all preconditions |

**PUT body:**

```json
{
  "preconditions": [
    { "attribute": "pps", "operator": "gt", "value": "100000" },
    { "attribute": "decoder", "operator": "eq", "value": "udp" }
  ]
}
```

Supported attributes: `cidr`, `decoder`, `attack_type`, `severity`, `pps`, `bps`, `peak_pps`, `peak_bps`, `node`, `domain`, `dominant_src_port`, `dominant_src_port_pct`, `dominant_dst_port`, `dominant_dst_port_pct`, `unique_src_ips`.

Supported operators: `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in`, `not_in`.

---

## Webhooks (Legacy)

Simple webhook notifications (pre-Response System v2).

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/webhooks` | List all webhooks |
| POST | `/api/webhooks` | Create a webhook |
| PUT | `/api/webhooks/:id` | Update a webhook |
| DELETE | `/api/webhooks/:id` | Delete a webhook |

---

## Settings -- Connectors

### Webhook Connectors

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/settings/webhook-connectors` | List all |
| POST | `/api/settings/webhook-connectors` | Create |
| GET | `/api/settings/webhook-connectors/:id` | Get |
| PUT | `/api/settings/webhook-connectors/:id` | Update |
| DELETE | `/api/settings/webhook-connectors/:id` | Delete (fails if in use by actions) |
| POST | `/api/settings/webhook-connectors/:id/test` | Send test payload |

**Create/Update fields:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | **Required.** |
| `url` | string | **Required.** Webhook URL |
| `method` | string | HTTP method (default: `POST`) |
| `headers` | object | Custom headers as JSON `{"Key": "Value"}` |
| `timeout_ms` | int | Request timeout in ms (default: 10000) |
| `enabled` | bool | |

### xDrop Connectors

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/settings/xdrop-connectors` | List all (API key masked) |
| POST | `/api/settings/xdrop-connectors` | Create |
| GET | `/api/settings/xdrop-connectors/:id` | Get (API key masked) |
| PUT | `/api/settings/xdrop-connectors/:id` | Update (omit `api_key` to keep existing) |
| DELETE | `/api/settings/xdrop-connectors/:id` | Delete (fails if in use by actions) |
| POST | `/api/settings/xdrop-connectors/:id/test` | Test connectivity (GET /health) |

**Create fields:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | **Required.** |
| `api_url` | string | **Required.** xDrop API base URL (e.g. `http://host:8000/api/v1`) |
| `api_key` | string | **Required.** xDrop API key |
| `timeout_ms` | int | Request timeout in ms (default: 10000) |

### Shell Connectors

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/settings/shell-connectors` | List all |
| POST | `/api/settings/shell-connectors` | Create |
| GET | `/api/settings/shell-connectors/:id` | Get |
| PUT | `/api/settings/shell-connectors/:id` | Update |
| DELETE | `/api/settings/shell-connectors/:id` | Delete (fails if in use by actions) |

**Create fields:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | **Required.** |
| `command` | string | **Required.** Absolute path to script/binary (must start with `/`) |
| `timeout_ms` | int | Execution timeout in ms (default: 30000) |

### BGP Connectors

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/settings/bgp-connectors` | List all |
| POST | `/api/settings/bgp-connectors` | Create |
| GET | `/api/settings/bgp-connectors/:id` | Get |
| PUT | `/api/settings/bgp-connectors/:id` | Update |
| DELETE | `/api/settings/bgp-connectors/:id` | Delete (fails if in use by actions) |
| POST | `/api/settings/bgp-connectors/:id/test` | Test FRR connectivity (`show bgp summary`) |
| GET | `/api/settings/bgp-connectors/:id/routes` | Show BGP RIB for this connector's address family |

**Create fields:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | **Required.** |
| `bgp_asn` | int | **Required.** Local BGP AS number |
| `vtysh_path` | string | Path to vtysh binary (default: `/usr/bin/vtysh`) |
| `address_family` | string | `ipv4 unicast` (default) or `ipv6 unicast` |
| `description` | string | |
| `enabled` | bool | Default: `true` |

---

## Stats

### GET /api/stats/summary

Dashboard summary counters.

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `active_attacks` | int | Currently active attacks |
| `total_nodes` | int | Registered nodes |
| `online_nodes` | int | Connected nodes |
| `total_prefixes` | int | Watched prefixes |
| `total_thresholds` | int | Threshold rules |
| `tracker_count` | int | Attacks tracked in memory |
| `attacks_created` | int | Total attacks created since startup |
| `attacks_suppressed` | int | Attacks suppressed by dedup |
| `attacks_evicted` | int | Attacks evicted (max limit) |

### GET /api/stats/timeseries

Per-prefix or per-node time-series traffic data.

| Param | Type | Description |
|-------|------|-------------|
| `prefix` | string | Filter by prefix (CIDR) |
| `node_id` | string | Filter by node |
| `direction` | string | `receives`, `sends`, or `both` |
| `resolution` | string | `5s`, `5min` (default), or `1h` |
| `from` | string | RFC3339 start time (default: 1 hour ago) |
| `to` | string | RFC3339 end time |

### GET /api/stats/overview

Real-time traffic overview from ring buffer. Returns total PPS/BPS and top prefixes.

| Param | Type | Description |
|-------|------|-------------|
| `direction` | string | `receives` (default), `sends`, or `both` |
| `node_id` | string | Filter by node |
| `limit` | int | Max prefixes returned (default: 20, max: 200) |

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `total_pps` | int | Aggregate packets per second |
| `total_bps` | int | Aggregate bits per second |
| `node_count` | int | Nodes contributing data |
| `active_prefixes` | int | Prefixes with recent traffic |
| `top_prefixes` | array | Top prefixes by PPS (with per-protocol breakdown: tcp/udp/icmp PPS and BPS) |

### GET /api/stats/total-timeseries

Aggregate (all-prefix) time-series data.

| Param | Type | Description |
|-------|------|-------------|
| `direction` | string | `receives`, `sends`, or `both` |
| `resolution` | string | `5s`, `5min` (default), or `1h` |
| `from` | string | RFC3339 start time (default: 1 hour ago) |
| `to` | string | RFC3339 end time |

---

## Baseline

### GET /api/baseline

P95 baseline and recommended thresholds for all enabled prefixes.

**Response** (array):

| Field | Type | Description |
|-------|------|-------------|
| `prefix` | string | Prefix CIDR |
| `p95_pps` | int | P95 packets per second |
| `p95_bps` | int | P95 bits per second |
| `recommend_pps` | int | Suggested manual threshold (P95 x 2) |
| `recommend_bps` | int | Suggested manual threshold (P95 x 2) |
| `detect_thresh_pps` | int | Dynamic detection trigger (P95 x multiplier) |
| `detect_thresh_bps` | int | Dynamic detection trigger (P95 x multiplier) |
| `data_points` | int | Number of data points used |
| `active` | bool | `false` = cold start / insufficient data |

---

## Attacks

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/attacks` | List attacks (paginated, filterable) |
| GET | `/api/attacks/active` | List currently active attacks |
| GET | `/api/attacks/:id` | Get attack details with action execution log |
| POST | `/api/attacks/:id/expire` | Force-expire an active attack |
| GET | `/api/attacks/:id/action-log` | Get action execution log for an attack |
| GET | `/api/attacks/:id/sensor-logs` | Get flow-level sensor logs for an attack |

### List Attacks -- GET /api/attacks

| Param | Type | Description |
|-------|------|-------------|
| `status` | string | Filter by status |
| `direction` | string | `receives` or `sends` |
| `prefix_id` | int | Filter by prefix |
| `from` | string | RFC3339 start time |
| `to` | string | RFC3339 end time |
| `limit` | int | Page size (default: 50, max: 200) |
| `offset` | int | Pagination offset |

**Response:** `{ "attacks": [...], "total": N }`

### Active Attacks -- GET /api/attacks/active

| Param | Type | Description |
|-------|------|-------------|
| `limit` | int | Max results (default: 100) |

**Response:** `{ "attacks": [...], "active_count": N, "returned": N, "tracker_count": N }`

### Force Expire -- POST /api/attacks/:id/expire

Manually expires an active attack. Triggers on_expired actions (e.g., xDrop unblock, BGP route withdrawal).

**Response:** `{ "ok": true, "method": "tracker" }` or `{ "ok": true, "method": "db" }`

### Sensor Logs -- GET /api/attacks/:id/sensor-logs

Returns per-flow records from the `flow_logs` table for the attack's target IP and time window. For active attacks, the query window is capped to the last 1 hour.

| Param | Type | Description |
|-------|------|-------------|
| `limit` | int | Max flow records (default: 1000, max: 10000) |

**Response:** `{ "flows": [...], "total": N, "expired": bool, "window": "full"|"last_1h" }`

---

## Audit Log

### GET /api/audit-log

Configuration change history with old/new diffs.

| Param | Type | Description |
|-------|------|-------------|
| `entity_type` | string | Filter by entity type (e.g. `watch_prefix`, `threshold`, `response`) |
| `user_id` | int | Filter by user |
| `limit` | int | Page size (default: 50) |
| `offset` | int | Pagination offset |

---

## Dynamic Detection

EWMA-based dynamic baseline detection configuration and status.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/dynamic-detection/config` | Get dynamic detection configuration |
| PUT | `/api/dynamic-detection/config` | Update configuration |
| GET | `/api/dynamic-detection/status` | Get current detection status per prefix |

### Update Config -- PUT /api/dynamic-detection/config

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable/disable dynamic detection |
| `deviation_min` | float | Minimum deviation multiplier (must be >= 0) |
| `deviation_max` | float | Maximum deviation multiplier (must be >= deviation_min) |
| `stable_weeks` | int | Weeks of data before activation (>= 1) |
| `ewma_alpha` | float | EWMA smoothing factor (0 < alpha < 1) |
| `min_pps` | int | Minimum PPS floor (>= 0) |
| `min_bps` | int | Minimum BPS floor (>= 0) |

### Detection Status -- GET /api/dynamic-detection/status

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Whether dynamic detection is enabled |
| `current_slot` | int | Current hourly slot (0-167) |
| `current_slot_label` | string | Human-readable label (e.g. "Mon 14:00") |
| `total_prefixes` | int | Prefixes with baseline profiles |
| `activated_count` | int | Prefixes past the learning phase |
| `learning_count` | int | Prefixes still learning |
| `prefixes` | array | Per-prefix detail: `expected_pps`, `expected_bps`, `current_pps`, `current_bps`, `thresh_pps`, `thresh_bps`, `sample_weeks`, `status` (`learning`/`normal`/`exceeded`) |

---

## Flow Configuration

Manage NetFlow/sFlow/IPFIX listeners and sources for flow-mode nodes.

### Flow Listeners

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/flow-listeners?node_id=X` | List listeners for a node (**node_id required**) |
| POST | `/api/flow-listeners` | Create a flow listener |
| GET | `/api/flow-listeners/:id` | Get listener with its sources |
| PUT | `/api/flow-listeners/:id` | Update listener (node_id immutable) |
| DELETE | `/api/flow-listeners/:id` | Delete listener (cascades to sources) |

**Create fields:**

| Field | Type | Description |
|-------|------|-------------|
| `node_id` | string | **Required.** Must be a flow-mode node |
| `listen_address` | string | **Required.** `:port` or `host:port` (1-65535) |
| `protocol_mode` | string | `auto` (default), `sflow`, `netflow`, or `ipfix` |

### Flow Sources

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/flow-sources?listener_id=N` | List sources for a listener (**listener_id required**) |
| POST | `/api/flow-sources` | Create a flow source |
| GET | `/api/flow-sources/:id` | Get source |
| PUT | `/api/flow-sources/:id` | Update source (listener_id immutable) |
| DELETE | `/api/flow-sources/:id` | Delete source |

**Create fields:**

| Field | Type | Description |
|-------|------|-------------|
| `listener_id` | int | **Required.** Parent listener |
| `name` | string | **Required.** Display name |
| `device_ip` | string | **Required.** Exporter IP address |
| `sample_mode` | string | `auto` (default), `force`, or `none` |
| `sample_rate` | int | Required when `sample_mode=force` (must be > 0) |

---

## Common Response Patterns

### Success

```json
{ "ok": true }
```

### Created

HTTP 201 with:

```json
{ "id": 42 }
```

### Error

```json
{ "error": "description of the problem" }
```

### Conflict (in-use guard)

HTTP 409 when trying to delete an entity that is referenced by other entities:

```json
{ "error": "template in use by 3 prefixes: [198.51.100.0/24, 203.0.113.0/24, 10.0.0.0/8]" }
```
