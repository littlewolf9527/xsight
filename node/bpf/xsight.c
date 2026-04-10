// SPDX-License-Identifier: GPL-2.0
// xSight Node — XDP program (pure counting + sampling, all XDP_DROP)
//            docs/node-development-plan.md P1/P2
//
// P0: Minimal skeleton ✓
// P1: L2/L3 parsing → trie lookup → per-IP/prefix counting ✓
// P2: ERSPAN decap (Type I/II/III) + ring buffer sampling

#include "xsight.h"

// ---------------------------------------------------------------------------
// DECODER_SWITCH — single source of truth for protocol → decoder index mapping.
// To add a new decoder: add one case here + one constant in xsight.h + one in shared/decoder/decoder.go.
// All 4 call sites (ip_stats, prefix_stats, global inbound, global outbound) use this macro.
// ---------------------------------------------------------------------------
#define DECODER_SWITCH(counts, byte_counts, pkt_len, l4_proto, is_syn, is_frag) \
do {                                                                            \
    switch (l4_proto) {                                                         \
    case IPPROTO_TCP:                                                           \
        __sync_fetch_and_add(&(counts)[DECODER_TCP], 1);                        \
        __sync_fetch_and_add(&(byte_counts)[DECODER_TCP], pkt_len);             \
        if (is_syn) {                                                           \
            __sync_fetch_and_add(&(counts)[DECODER_TCP_SYN], 1);                \
            __sync_fetch_and_add(&(byte_counts)[DECODER_TCP_SYN], pkt_len);     \
        }                                                                       \
        break;                                                                  \
    case IPPROTO_UDP:                                                           \
        __sync_fetch_and_add(&(counts)[DECODER_UDP], 1);                        \
        __sync_fetch_and_add(&(byte_counts)[DECODER_UDP], pkt_len);             \
        break;                                                                  \
    case IPPROTO_ICMP:                                                          \
    case IPPROTO_ICMPV6:                                                        \
        __sync_fetch_and_add(&(counts)[DECODER_ICMP], 1);                       \
        __sync_fetch_and_add(&(byte_counts)[DECODER_ICMP], pkt_len);            \
        break;                                                                  \
    }                                                                           \
    if (is_frag) {                                                              \
        __sync_fetch_and_add(&(counts)[DECODER_FRAG], 1);                       \
        __sync_fetch_and_add(&(byte_counts)[DECODER_FRAG], pkt_len);            \
    }                                                                           \
} while (0)

// Helper: update per-IP stats (protocol distribution + packet size)
// ---------------------------------------------------------------------------
static __always_inline void update_ip_stats(
    struct dst_ip_stats *st,
    __u32 pkt_len,
    __u8  l4_proto,
    bool  is_syn,
    bool  is_frag)
{
    __sync_fetch_and_add(&st->pkt_count, 1);
    __sync_fetch_and_add(&st->byte_count, pkt_len);

    DECODER_SWITCH(st->decoder_counts, st->decoder_byte_counts,
                   pkt_len, l4_proto, is_syn, is_frag);

    if (pkt_len < PKT_SMALL_THRESHOLD)
        __sync_fetch_and_add(&st->small_pkt, 1);
    else if (pkt_len > PKT_LARGE_THRESHOLD)
        __sync_fetch_and_add(&st->large_pkt, 1);
    else
        __sync_fetch_and_add(&st->medium_pkt, 1);
}

// ---------------------------------------------------------------------------
// Helper: update per-decoder counters on prefix_stats (shared by inbound + outbound)
// ---------------------------------------------------------------------------
static __always_inline void update_prefix_decoders(
    struct prefix_stats *ps,
    __u32 pkt_len,
    __u8  l4_proto,
    bool  is_syn,
    bool  is_frag)
{
    DECODER_SWITCH(ps->decoder_counts, ps->decoder_byte_counts,
                   pkt_len, l4_proto, is_syn, is_frag);
}

// MACRO: build prefix_key, mask host bits, lookup in map.
// Must be a macro because BPF map references must be compile-time constants.
// Result is stored in variable named _ps_##suffix.
#define LOOKUP_PREFIX_STATS(result_var, map, ip_key, matched_prefixlen)       \
do {                                                                          \
    struct prefix_key _lpk = {};                                              \
    __builtin_memcpy(_lpk.addr, (ip_key)->addr, 16);                         \
    _lpk.prefixlen = (matched_prefixlen);                                     \
    __u32 _fb = (matched_prefixlen) / 8;                                      \
    __u32 _rm = (matched_prefixlen) % 8;                                      \
    if (_fb < 16) {                                                           \
        if (_rm)                                                              \
            _lpk.addr[_fb] &= (0xFF << (8 - _rm));                           \
        _Pragma("unroll")                                                     \
        for (int _i = 0; _i < 16; _i++) {                                    \
            if (_i > _fb || (_i == _fb && _rm == 0))                          \
                _lpk.addr[_i] = 0;                                            \
        }                                                                     \
    }                                                                         \
    (result_var) = bpf_map_lookup_elem(&(map), &_lpk);                        \
} while (0)

// ---------------------------------------------------------------------------
// MACRO: process one direction — prefix_stats + ip_stats update
// Must be a macro (not function) because BPF map references must be
// compile-time constants — cannot pass maps through void* parameters.
// ---------------------------------------------------------------------------
#define PROCESS_DIRECTION(prefix_map, ip_map_a, ip_map_b, active_slot,     \
                          ip_key, matched_prefixlen, pkt_len,               \
                          l4_proto, is_syn, is_frag)                        \
do {                                                                        \
    struct prefix_stats *_ps;                                               \
    LOOKUP_PREFIX_STATS(_ps, prefix_map, ip_key, matched_prefixlen);        \
    if (_ps) {                                                              \
        __sync_fetch_and_add(&_ps->pkt_count, 1);                          \
        __sync_fetch_and_add(&_ps->byte_count, pkt_len);                   \
        update_prefix_decoders(_ps, pkt_len, l4_proto, is_syn, is_frag);   \
    }                                                                       \
    struct dst_ip_stats *_ist;                                              \
    if (active_slot == 0)                                                   \
        _ist = bpf_map_lookup_elem(&ip_map_a, ip_key);                     \
    else                                                                    \
        _ist = bpf_map_lookup_elem(&ip_map_b, ip_key);                     \
    if (_ist) {                                                             \
        update_ip_stats(_ist, pkt_len, l4_proto, is_syn, is_frag);         \
    } else {                                                                \
        struct dst_ip_stats _new = {};                                      \
        update_ip_stats(&_new, pkt_len, l4_proto, is_syn, is_frag);        \
        int _ret;                                                           \
        if (active_slot == 0)                                               \
            _ret = bpf_map_update_elem(&ip_map_a, ip_key, &_new,           \
                                       BPF_NOEXIST);                        \
        else                                                                \
            _ret = bpf_map_update_elem(&ip_map_b, ip_key, &_new,           \
                                       BPF_NOEXIST);                        \
        if (_ret != 0 && _ps)                                               \
            __sync_fetch_and_add(&_ps->overflow_count, 1);                  \
    }                                                                       \
} while (0)

// UPDATE_GLOBAL_DECODERS — thin wrapper around DECODER_SWITCH for global_stats arrays.
// Kept as a named macro for readability at call sites.
#define UPDATE_GLOBAL_DECODERS(dec_counts, dec_byte_counts,                 \
                               pkt_len, l4_proto, is_syn, is_frag)          \
    DECODER_SWITCH(dec_counts, dec_byte_counts, pkt_len, l4_proto, is_syn, is_frag)

// ---------------------------------------------------------------------------
// Helper: read __u64 from config map with default
// ---------------------------------------------------------------------------
static __always_inline __u64 cfg_read(__u32 index, __u64 def)
{
    __u64 *val = bpf_map_lookup_elem(&xsight_config, &index);
    return val ? *val : def;
}

// ---------------------------------------------------------------------------
// Helper: emit sample to ring buffer
// Sends raw packet bytes (from data to data_end), capped at sample_bytes.
// Called only when pkt_count % sample_rate == 0 after trie match.
// ---------------------------------------------------------------------------
static __always_inline void emit_sample(struct xdp_md *ctx, struct global_stats *gs)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 pkt_len  = (__u32)(data_end - data);

    // Reserve fixed-size slot: sample_hdr(8B) + MAX_SAMPLE_BYTES(512B) = 520B
    // Verifier needs constant size for bpf_ringbuf_reserve.
    void *buf = bpf_ringbuf_reserve(&samples, sizeof(struct sample_hdr) + MAX_SAMPLE_BYTES, 0);
    if (!buf) {
        // Ring buffer full — count the drop for backpressure signaling
        if (gs)
            __sync_fetch_and_add(&gs->sample_drops, 1);
        return;
    }

    __u64 sample_bytes = cfg_read(CFG_SAMPLE_BYTES, DEFAULT_SAMPLE_BYTES);

    // Clamp to [1, MAX_SAMPLE_BYTES-1] with bitmask — verifier-friendly.
    // MAX_SAMPLE_BYTES=512 is power-of-2, so &511 gives [0,511].
    // Cap at 511 (not 512) to keep verifier provably bounded for all paths.
    __u32 cap_len = (__u32)sample_bytes & (MAX_SAMPLE_BYTES - 1);
    if (cap_len == 0)
        cap_len = MAX_SAMPLE_BYTES - 1;  // 511

    // Don't read past packet end
    if (cap_len > pkt_len)
        cap_len = pkt_len;

    // Final verifier-friendly bound: re-apply bitmask so verifier can prove
    // cap_len is in [0, 511] regardless of control flow.
    cap_len &= (MAX_SAMPLE_BYTES - 1);
    if (cap_len == 0) {
        bpf_ringbuf_discard(buf, 0);
        return;
    }

    // Write sample header (first 8 bytes of reserved slot)
    struct sample_hdr *hdr = buf;
    hdr->cap_len = cap_len;
    hdr->pkt_len = pkt_len;

    // Packet data follows header. cap_len is provably in [1, 511].
    if (bpf_xdp_load_bytes(ctx, 0, (void *)hdr + sizeof(struct sample_hdr), cap_len) < 0) {
        bpf_ringbuf_discard(buf, 0);
        return;
    }

    bpf_ringbuf_submit(buf, 0);
}

// ---------------------------------------------------------------------------
// Helper: parse inner IP header, extract dst_ip + l4 info
// Returns 0 on success, -1 if packet is too short / not IP.
// All results written to out-params (scalars only, no pkt_end passing).
// ---------------------------------------------------------------------------
// parse_ip extracts dst_ip key + L4 protocol info from IP header.
// src_key is extracted separately in xsight_main to avoid verifier pointer issues.
static __always_inline int parse_ip(
    void *l3_hdr, void *data_end,
    struct lpm_key *key, __u8 *l4_proto,
    bool *is_frag, bool *is_syn, __u16 eth_type)
{
    if (eth_type == ETH_P_IP) {
        struct iphdr *iph = l3_hdr;
        if ((void *)(iph + 1) > data_end)
            return -1;

        key->prefixlen = 32;
        __builtin_memcpy(key->addr, &iph->daddr, 4);

        *l4_proto = iph->protocol;

        __u16 frag_off = bpf_ntohs(iph->frag_off);
        *is_frag = (frag_off & 0x2000) || (frag_off & 0x1FFF);

        if (*l4_proto == IPPROTO_TCP && !(*is_frag)) {
            void *l4_hdr = l3_hdr + (iph->ihl * 4);
            if (l4_hdr + 14 <= data_end) {
                __u8 flags = *((__u8 *)l4_hdr + 13);
                *is_syn = (flags & 0x02) && !(flags & 0x10);
            }
        }
        return 0;

    } else if (eth_type == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = l3_hdr;
        if ((void *)(ip6h + 1) > data_end)
            return -1;

        key->prefixlen = 128;
        __builtin_memcpy(key->addr, &ip6h->daddr, 16);

        *l4_proto = ip6h->nexthdr;

        if (*l4_proto == IPPROTO_TCP) {
            void *l4_hdr = (void *)(ip6h + 1);
            if (l4_hdr + 14 <= data_end) {
                __u8 flags = *((__u8 *)l4_hdr + 13);
                *is_syn = (flags & 0x02) && !(flags & 0x10);
            }
        }
        return 0;
    }

    return -1;  // Not IP
}

// extract_src_key extracts source IP into an LPM key for outbound trie lookup.
// Separate function to avoid verifier pointer arithmetic issues with multi-output parse_ip.
static __always_inline void extract_src_key(
    void *l3_hdr, void *data_end,
    struct lpm_key *src_key, __u16 eth_type)
{
    if (eth_type == ETH_P_IP) {
        struct iphdr *iph = l3_hdr;
        if ((void *)(iph + 1) > data_end)
            return;
        src_key->prefixlen = 32;
        __builtin_memcpy(src_key->addr, &iph->saddr, 4);
    } else if (eth_type == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = l3_hdr;
        if ((void *)(ip6h + 1) > data_end)
            return;
        src_key->prefixlen = 128;
        __builtin_memcpy(src_key->addr, &ip6h->saddr, 16);
    }
}

SEC("xdp")
int xsight_main(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 pkt_len  = (__u32)(ctx->data_end - ctx->data);

    // ① global_stats — every packet, unconditionally
    __u32 gs_key = 0;
    struct global_stats *gs = bpf_map_lookup_elem(&global_stats, &gs_key);
    if (gs) {
        __sync_fetch_and_add(&gs->total_pkts, 1);
        __sync_fetch_and_add(&gs->total_bytes, pkt_len);
    }

    // ② Parse outer L2
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    __u16 eth_type = bpf_ntohs(eth->h_proto);

    // ARP pass-through
    if (eth_type == ETH_P_ARP)
        return XDP_PASS;

    void *l3_hdr = (void *)(eth + 1);

    // Handle 802.1Q VLAN (single tag)
    if (eth_type == ETH_P_8021Q) {
        struct vlan_hdr *vhdr = l3_hdr;
        if ((void *)(vhdr + 1) > data_end)
            return XDP_DROP;
        eth_type = bpf_ntohs(vhdr->h_vlan_encapsulated_proto);
        l3_hdr   = (void *)(vhdr + 1);
    }

    // ② ERSPAN mode: detect GRE encapsulation → decap to inner frame
    // Read mode from config map: 0=mirror (default), 1=erspan
    __u64 mode = cfg_read(CFG_MODE, 0);

    if (mode == 1) {
        // ERSPAN path: outer must be IPv4 with protocol=GRE
        // (IPv6 GRE tunnels are theoretically possible but extremely rare)
        if (eth_type != ETH_P_IP)
            return XDP_DROP;

        struct iphdr *outer_iph = l3_hdr;
        if ((void *)(outer_iph + 1) > data_end)
            return XDP_DROP;

        if (outer_iph->protocol != IPPROTO_GRE)
            return XDP_DROP;

        // GRE header: flags(2B) + protocol(2B) = 4 bytes minimum
        void *gre_hdr = l3_hdr + (outer_iph->ihl * 4);
        if (gre_hdr + 4 > data_end)
            return XDP_DROP;

        __u16 gre_flags = bpf_ntohs(*(__u16 *)gre_hdr);
        __u16 gre_proto = bpf_ntohs(*((__u16 *)gre_hdr + 1));

        // Determine inner frame offset based on ERSPAN type
        // Reference: brainstorm-node.md "ERSPAN auto-detection"
        void *inner_eth;

        if (gre_proto == GRE_PROTO_ERSPAN_III) {
            // Type III: GRE(4B) + sequence(4B if SEQ set) + ERSPAN-III header(12B)
            __u32 gre_len = 4;
            if (gre_flags & GRE_FLAG_SEQ)
                gre_len += 4;  // sequence number
            inner_eth = gre_hdr + gre_len + 12;
            // Note: optional 8B subheader not handled (PoC — record if needed)

        } else if (gre_proto == GRE_PROTO_ERSPAN_II) {
            if (gre_flags & GRE_FLAG_SEQ) {
                // Type II: GRE(4B) + sequence(4B) + ERSPAN-II header(8B)
                inner_eth = gre_hdr + 4 + 4 + 8;
            } else {
                // Type I: GRE(4B) only, no ERSPAN header
                inner_eth = gre_hdr + 4;
            }

        } else {
            // Unknown GRE protocol — drop
            return XDP_DROP;
        }

        // Parse inner Ethernet
        struct ethhdr *inner_eth_hdr = inner_eth;
        if ((void *)(inner_eth_hdr + 1) > data_end)
            return XDP_DROP;

        eth_type = bpf_ntohs(inner_eth_hdr->h_proto);
        l3_hdr   = (void *)(inner_eth_hdr + 1);

        // Handle inner VLAN
        if (eth_type == ETH_P_8021Q) {
            struct vlan_hdr *ivhdr = l3_hdr;
            if ((void *)(ivhdr + 1) > data_end)
                return XDP_DROP;
            eth_type = bpf_ntohs(ivhdr->h_vlan_encapsulated_proto);
            l3_hdr   = (void *)(ivhdr + 1);
        }
    }

    // ③ Parse IP — dst_key via parse_ip, src_key via separate extract (avoids verifier pointer issues)
    struct lpm_key dst_key = {};
    struct lpm_key src_key = {};
    __u8  l4_proto = 0;
    bool  is_frag  = false;
    bool  is_syn   = false;

    if (parse_ip(l3_hdr, data_end, &dst_key, &l4_proto, &is_frag, &is_syn, eth_type) != 0)
        return XDP_DROP;

    // Extract src_ip for outbound detection (separate call to avoid verifier issues)
    extract_src_key(l3_hdr, data_end, &src_key, eth_type);

    // ④ Read active_slot → choose trie + maps
    __u32 slot_key = 0;
    __u32 *slot = bpf_map_lookup_elem(&active_slot, &slot_key);
    __u32 active = slot ? *slot : 0;

    // ⑤ LPM trie lookup — dst_ip (inbound)
    __u32 *dst_prefix_idx;
    if (active == 0)
        dst_prefix_idx = bpf_map_lookup_elem(&watch_trie_a, &dst_key);
    else
        dst_prefix_idx = bpf_map_lookup_elem(&watch_trie_b, &dst_key);

    // ⑤b LPM trie lookup — src_ip (outbound)
    __u32 *src_prefix_idx;
    if (active == 0)
        src_prefix_idx = bpf_map_lookup_elem(&watch_trie_a, &src_key);
    else
        src_prefix_idx = bpf_map_lookup_elem(&watch_trie_b, &src_key);

    // Both miss → done.
    // Compiler barrier prevents clang from merging these two pointer null-checks
    // into a single "r1 |= r0" which the BPF verifier rejects as "pointer |= pointer".
    if (!dst_prefix_idx) {
        asm volatile("" ::: "memory");
        if (!src_prefix_idx)
            return XDP_DROP;
    }

    // ====== INBOUND (dst_ip matched) ======
    if (dst_prefix_idx) {
        if (gs) {
            __sync_fetch_and_add(&gs->matched_pkts, 1);
            __sync_fetch_and_add(&gs->matched_bytes, pkt_len);
            UPDATE_GLOBAL_DECODERS(gs->decoder_counts, gs->decoder_byte_counts,
                                   pkt_len, l4_proto, is_syn, is_frag);
        }
        PROCESS_DIRECTION(prefix_stats_map, ip_stats_a, ip_stats_b,
                          active, &dst_key, *dst_prefix_idx,
                          pkt_len, l4_proto, is_syn, is_frag);
    }

    // ====== OUTBOUND (src_ip matched) — same macro, different maps ======
    if (src_prefix_idx) {
        if (gs) {
            __sync_fetch_and_add(&gs->src_matched_pkts, 1);
            __sync_fetch_and_add(&gs->src_matched_bytes, pkt_len);
            UPDATE_GLOBAL_DECODERS(gs->src_decoder_counts, gs->src_decoder_byte_counts,
                                   pkt_len, l4_proto, is_syn, is_frag);
        }
        PROCESS_DIRECTION(src_prefix_stats_map, src_stats_a, src_stats_b,
                          active, &src_key, *src_prefix_idx,
                          pkt_len, l4_proto, is_syn, is_frag);
    }

    // ⑧ Ring buffer sampling — after trie match (either direction)
    // Use total matched packets (inbound + outbound) for sampling decision
    __u64 current_pkt_count = gs ? (gs->matched_pkts + gs->src_matched_pkts) : 1;

    __u64 sample_rate = cfg_read(CFG_SAMPLE_RATE, DEFAULT_SAMPLE_RATE);
    if (sample_rate == 0)
        sample_rate = 1;

    if (current_pkt_count % sample_rate == 0)
        emit_sample(ctx, gs);

    // ⑨ Drop — mirror/ERSPAN packets are copies
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
