// SPDX-License-Identifier: GPL-2.0
// xSight Node — BPF shared definitions

#ifndef __XSIGHT_H__
#define __XSIGHT_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Config map indices
#define CFG_SAMPLE_RATE      0  // dynamic sample rate (written by Agent)
#define CFG_SAMPLE_BYTES     1  // per-packet capture length (128-512)
#define CFG_MODE             2  // 0=mirror, 1=erspan
#define CFG_UPSTREAM_RATE    3  // upstream_sample_rate (from config.yaml)

// Default values
#define DEFAULT_SAMPLE_RATE  1
#define DEFAULT_SAMPLE_BYTES 256
#define MAX_SAMPLE_BYTES     512

// Protocol numbers (not always in vmlinux.h)
#define IPPROTO_ICMPV6       58
#define IPPROTO_GRE          47

// GRE protocol IDs for ERSPAN
#define GRE_PROTO_ERSPAN_II  0x88BE
#define GRE_PROTO_ERSPAN_III 0x22EB

// GRE header flags
#define GRE_FLAG_SEQ         0x1000  // Sequence number present

// Ethernet types
#define ETH_P_ARP            0x0806
#define ETH_P_IP             0x0800
#define ETH_P_IPV6           0x86DD
#define ETH_P_8021Q          0x8100

// Packet size thresholds
#define PKT_SMALL_THRESHOLD  128
#define PKT_LARGE_THRESHOLD  512

// ---------------------------------------------------------------------------
// Decoder Index — append-only, never reorder.
// IMPORTANT: keep in sync with shared/decoder/decoder.go
// ---------------------------------------------------------------------------
#define DECODER_TCP       0
#define DECODER_TCP_SYN   1
#define DECODER_UDP       2
#define DECODER_ICMP      3
#define DECODER_FRAG      4
// v1.3 Phase 1b — TCP flag subdivisions
#define DECODER_TCP_ACK   5
#define DECODER_TCP_RST   6
#define DECODER_TCP_FIN   7
// v1.3 Phase 1b — Non-TCP/UDP/ICMP protocols
#define DECODER_GRE       8
#define DECODER_ESP       9
#define DECODER_IGMP      10
#define DECODER_IP_OTHER  11
// v1.3 Phase 1b (追加) — Packet-level anomalies (stateless detection)
#define DECODER_BAD_FRAGMENT 12  // Ping of Death / tiny fragment
#define DECODER_INVALID      13  // IP IHL<5, TCP doff<5, header length anomalies
// Slots 14-15 reserved for future decoders (explicit additions only).
#define MAX_DECODERS      16

// IP protocol numbers used by v1.3 Phase 1b dispatch (not all present in vmlinux.h)
#ifndef IPPROTO_ESP
#define IPPROTO_ESP       50
#endif
#ifndef IPPROTO_IGMP
#define IPPROTO_IGMP      2
#endif
// IPPROTO_GRE already defined above (line 28)

// ---------------------------------------------------------------------------
// Data Structures — must match Go-side definitions exactly
// ---------------------------------------------------------------------------

// Per-destination-IP statistics
// Reference: brainstorm-node.md "per dst_ip aggregated stats structure"
struct dst_ip_stats {
    __u64 pkt_count;
    __u64 byte_count;

    // Protocol distribution (array indexed by DECODER_* constants)
    __u32 decoder_counts[MAX_DECODERS];
    // Per-decoder byte counts (for per-decoder BPS thresholds)
    __u64 decoder_byte_counts[MAX_DECODERS];

    // Packet size distribution
    __u32 small_pkt;       // <128B (small-packet flood indicator)
    __u32 medium_pkt;      // 128-512B
    __u32 large_pkt;       // >512B (bandwidth attack indicator)
};

// LPM trie key for watch_prefix matching (IPv4 + IPv6 unified)
struct lpm_key {
    __u32 prefixlen;
    __u8  addr[16];        // IPv4 uses first 4 bytes, IPv6 uses all 16
};

// Prefix stats key — matches watch_prefix entry
struct prefix_key {
    __u8  addr[16];
    __u32 prefixlen;
};

// Per-prefix aggregated statistics (for carpet bombing detection + chart decoder breakdown)
struct prefix_stats {
    __u64 pkt_count;
    __u64 byte_count;
    __u32 overflow_count;  // ip_stats map full → this prefix's IPs couldn't be tracked
    __u32 _pad;            // alignment padding (keeps struct size stable)
    __u32 decoder_counts[MAX_DECODERS];  // indexed by DECODER_* constants
    __u64 decoder_byte_counts[MAX_DECODERS];  // per-decoder byte counts for BPS thresholds
};

// Sample header — prefixed to each ring buffer record
// Enables userspace to distinguish valid data from zero-padded tail.
struct sample_hdr {
    __u32 cap_len;   // actual captured bytes (≤ MAX_SAMPLE_BYTES)
    __u32 pkt_len;   // original packet length on wire
};

// Global stats — single entry, every packet increments unconditionally
// v2.11: added matched_bytes + per-decoder breakdown for 0.0.0.0/0 global threshold detection
struct global_stats {
    __u64 total_pkts;
    __u64 total_bytes;
    __u64 matched_pkts;    // packets matching watch_prefix
    __u64 matched_bytes;   // bytes matching watch_prefix (authoritative source for global ip+bps)
    __u64 sample_drops;    // ring buffer reserve failures (backpressure signal)

    // Per-decoder breakdown (inbound, matched traffic only)
    __u32 decoder_counts[MAX_DECODERS];
    __u64 decoder_byte_counts[MAX_DECODERS];

    // v2.11 Phase 2: outbound global counters (src_ip matched traffic)
    __u64 src_matched_pkts;
    __u64 src_matched_bytes;
    __u32 src_decoder_counts[MAX_DECODERS];
    __u64 src_decoder_byte_counts[MAX_DECODERS];
};

// ---------------------------------------------------------------------------
// BPF Maps — SEC(".maps") style for bpf2go compatibility
// Reference: brainstorm-node.md "BPF Maps inventory"
// ---------------------------------------------------------------------------

// Global packet counter — health check (Array, 1 entry)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_stats);
} global_stats SEC(".maps");

// Watch prefix trie A — active side (LPM Trie, 50K)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 50000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u32);  // prefix index
} watch_trie_a SEC(".maps");

// Watch prefix trie B — shadow side (LPM Trie, 50K)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 50000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u32);
} watch_trie_b SEC(".maps");

// Per-prefix aggregated stats (Hash, 50K)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 50000);
    __type(key, struct prefix_key);
    __type(value, struct prefix_stats);
} prefix_stats_map SEC(".maps");

// Per-destination-IP stats A — active side (Hash, configurable max_entries)
// Note: max_entries set via bpf2go or runtime rewrite; 1M default, prealloc
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, struct lpm_key);  // full IP as /32 or /128
    __type(value, struct dst_ip_stats);
} ip_stats_a SEC(".maps");

// Per-destination-IP stats B — shadow side (Hash, same as A)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, struct lpm_key);
    __type(value, struct dst_ip_stats);
} ip_stats_b SEC(".maps");

// v2.11 Phase 2: Per-source-IP stats (outbound tracking, reuses dst_ip_stats struct)
// max_entries intentionally smaller — outbound cardinality typically lower than inbound
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200000);
    __type(key, struct lpm_key);
    __type(value, struct dst_ip_stats);
} src_stats_a SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200000);
    __type(key, struct lpm_key);
    __type(value, struct dst_ip_stats);
} src_stats_b SEC(".maps");

// v2.11 Phase 2: Per-prefix outbound aggregated stats
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 50000);
    __type(key, struct prefix_key);
    __type(value, struct prefix_stats);
} src_prefix_stats_map SEC(".maps");

// Double-buffer slot selector (Array, 1 entry: 0=A active, 1=B active)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} active_slot SEC(".maps");

// Runtime config (Array, 8 entries)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} xsight_config SEC(".maps");

// Sampling ring buffer — raw packet headers to userspace (16MB)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} samples SEC(".maps");

#endif // __XSIGHT_H__
