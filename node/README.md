# xSight Node

Data plane agent for the xSight DDoS detection system. The Node captures network traffic -- either via XDP/eBPF packet capture from mirror/ERSPAN ports, or by receiving flow data (sFlow/NetFlow/IPFIX) -- and reports aggregated statistics to the Controller over gRPC.

## Dual Mode Architecture

### XDP Mode (default)

Attaches an XDP/eBPF program to mirror or ERSPAN interfaces to capture packets at line rate in the kernel. The BPF program parses each packet, classifies it by decoder type, updates per-IP and per-prefix statistics maps, and samples selected packets to a userspace ring buffer.

**XDP Pipeline:**

```
Packet in (mirror/ERSPAN)
  -> Parse Ethernet/IP/Transport headers
  -> Extract 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
  -> Classify decoder (TCP / TCP_SYN / UDP / ICMP / FRAG / ...)
  -> LPM trie lookup: match dst_ip against watch_prefixes
  -> Update ip_stats map (per-IP counters)
  -> Update prefix_stats map (per-prefix counters)
  -> Update global_stats map (total counters)
  -> Probabilistic sample -> perf ring buffer (sample_ring)
  -> XDP_DROP (mirror port, no forwarding)
```

**BPF Maps:**

| Map | Type | Description |
|-----|------|-------------|
| `ip_stats` | Per-CPU Hash | Per-destination-IP counters: pkt_count, byte_count, decoder_counts[16], decoder_byte_counts[16], size buckets |
| `prefix_stats` | Per-CPU Hash | Per-prefix aggregate counters: pkt_count, byte_count, decoder_counts[16], decoder_byte_counts[16], active_ips, overflow_count |
| `global_stats` | Per-CPU Array | Total counters: total_pkts, total_bytes, matched_pkts, matched_bytes, sample_drops, per-decoder breakdown |
| `watch_prefixes` | LPM Trie | Prefix list pushed from Controller. Used for dst_ip match in the fast path |
| `sample_ring` | Perf Event Array | Ring buffer for sampled packet headers sent to userspace |

### Flow Mode

Receives sFlow, NetFlow v5/v9, or IPFIX flow records via UDP using [goflow2](https://github.com/netsampler/goflow2). The Node decodes flow protocol messages, extracts 5-tuple + TCP flags, classifies each record by decoder type, and aggregates per-IP statistics before reporting to the Controller.

**Flow Pipeline:**

```
Flow record in (sFlow/NetFlow/IPFIX over UDP)
  -> goflow2 auto-detect protocol + decode
  -> Extract 5-tuple + TCP flags from FlowMessage
  -> Classify decoder (TCP / TCP_SYN / UDP / ICMP / FRAG / ...)
  -> Prefix trie lookup: match dst_ip against watch_prefixes
  -> Aggregate into per-IP + per-prefix stats (RecordTable)
  -> Every 1s: flush stats -> gRPC StatsReport
```

Flow listeners and sources (exporter devices) are configured via the Controller Web UI, not the local config file.

## gRPC Streams

The Node is a **gRPC client** that connects to the Controller. It does not expose any REST API or listening port (except optional pprof). Four streams are maintained:

| Stream | Direction | Interval | Purpose |
|--------|-----------|----------|---------|
| `StatsStream` | Node -> Controller | 1s | Aggregated per-IP/prefix stats, health metrics, top flows |
| `SampleStream` | Node -> Controller | Batched | Raw packet header samples from BPF ring buffer (XDP mode only) |
| `CriticalEventStream` | Node -> Controller | Event-driven | Urgent alerts (BPF map full, interface down, hard threshold exceeded) |
| `ControlStream` | Bidirectional | On change | Controller pushes WatchConfig (prefixes, thresholds, flow listeners); Node ACKs with delivery_version |

See [API.md](API.md) for full gRPC message type documentation.

## Build

### XDP Mode

Requires Linux with `clang`, `llvm-strip`, and kernel headers. Cannot be built on macOS.

```bash
# Generate BPF Go bindings (bpf2go)
go generate ./internal/bpf/

# Build the binary
go build -o bin/xsight-node .
```

Or use the Makefile:

```bash
make all        # generate + build
make generate   # bpf2go only
make build      # go build only
make clean      # remove artifacts
```

### Flow Mode

Flow mode does not use BPF, so it can be built with just Go (cross-compile from macOS is fine):

```bash
go build -o bin/xsight-node .
```

The pre-generated BPF stubs (`internal/bpf/stub_notlinux.go`) allow building on non-Linux platforms.

## Configuration

Copy `config.example.yaml` and edit:

```yaml
# XDP mode (default)
mode: xdp
node_id: "my-node-01"

interfaces:
  - name: "eth1"
    mode: "mirror"              # mirror | erspan
    upstream_sample_rate: 1     # 1 = no upstream sampling
    sample_bytes: 128           # capture length (128-512)

bpf:
  max_entries: 1000000          # ip_stats map size

controller:
  address: "controller:50051"

auth:
  node_api_key: "CHANGE_ME"    # openssl rand -hex 32

# Optional tuning (xdp mode only)
# parse_workers: 4             # default = NumCPU/2, range 1-16
# pprof: false                 # pprof on 127.0.0.1:6061
```

```yaml
# Flow mode
mode: flow
node_id: "my-flow-node-01"

controller:
  address: "controller:50051"

auth:
  node_api_key: "CHANGE_ME"
```

In flow mode, `interfaces` and `bpf` sections are not needed. Flow listeners and sources are managed through the Controller Web UI and pushed to the Node via `ControlStream`.

## Permissions

- **XDP mode** requires root or `CAP_BPF` + `CAP_NET_ADMIN` capabilities. The BPF program is attached to the network interface.
- **Flow mode** needs permission to bind UDP ports (typically no special capabilities unless binding to privileged ports < 1024).

## Directory Structure

```
node/
  main.go                     # XDP mode entrypoint
  flow_main.go                # Flow mode entrypoint
  config.example.yaml
  Makefile
  bpf/
    xsight.c                  # XDP/eBPF C program
    xsight.h                  # BPF struct definitions
  internal/
    bpf/                      # BPF loader, Go type mirrors, bpf2go generated code
      gen.go                  # go:generate directive for bpf2go
      loader.go               # Load + attach XDP program, map operations
      types.go                # Go structs mirroring BPF C structs
      stub_notlinux.go        # Build stub for non-Linux platforms
    config/                   # YAML config loader + validation
      config.go               # Config struct, Load(), validate()
      snapshot.go             # WatchConfig snapshot persistence (survive restarts)
    collector/                # Periodic BPF map reader (XDP mode)
      collector.go            # Reads ip_stats/prefix_stats/global_stats every 1s
    sampler/                  # Packet sample pipeline (XDP mode)
      sampler.go              # Perf ring buffer reader
      batcher.go              # Batch samples for gRPC SampleStream
      packet.go               # Packet header parser (5-tuple extraction)
      flowtable.go            # Top-N flow tracking per tick
      worker_pool.go          # Parallel packet parse workers
    flow/                     # Flow receiver pipeline (Flow mode)
      listener.go             # UDP listener using goflow2
      decoder.go              # FlowMessage -> 5-tuple + decoder classification
      aggregator.go           # Per-IP/prefix stats aggregation + 1s flush
      record.go               # Flow record types
      recordtable.go          # Per-IP record table for aggregation
      prefixtrie.go           # In-memory prefix trie for watch_prefixes matching
    reporter/                 # gRPC client: handshake + 4 streams
      reporter.go             # Stream lifecycle, reconnect, backoff
      convert.go              # Collector Report -> protobuf StatsReport conversion
    watchdog/                 # Health monitoring
      watchdog.go             # Detects degraded state (ring overflow, map full)
    pb/                       # Generated protobuf + gRPC stubs
      xsight.pb.go
      xsight_grpc.pb.go
```
