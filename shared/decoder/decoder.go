// Package decoder defines the canonical decoder index registry shared between
// xSight Node (BPF + Go agent) and Controller.
//
// IMPORTANT: Decoder indices are append-only and must never be reordered.
// The BPF C enums in xsight.h MUST be kept in sync with these constants.
// Violating this invariant causes new/old binaries to misinterpret decoder_counts[i].
//
package decoder

// MaxDecoders is the fixed array size for decoder_counts in BPF maps and protobuf.
// Pre-allocated to avoid BPF map rebuilds when adding new decoders.
const MaxDecoders = 16

// StandardCount is the number of decoders with dedicated ts_stats columns
// (tcp_pps, tcp_syn_pps, udp_pps, icmp_pps, frag_pps).
// Indices 0..StandardCount-1 are written to fixed columns.
// Indices >= StandardCount are written to extra_decoder_pps JSONB.
const StandardCount = 5

// Decoder index constants — append-only, never reorder.
// Keep in sync with xsight.h DECODER_* defines.
const (
	TCP    = 0
	TCPSyn = 1
	UDP    = 2
	ICMP   = 3
	Frag   = 4
	// v1.3 Phase 1b — TCP flag subdivisions (DDoS detection):
	TCPAck = 5 // stateless ACK flood identification
	TCPRst = 6 // RST flood
	TCPFin = 7 // FIN flood
	// v1.3 Phase 1b — Non-TCP/UDP/ICMP protocols:
	GRE     = 8  // IP proto 47
	ESP     = 9  // IP proto 50
	IGMP    = 10 // IP proto 2
	IPOther = 11 // catch-all for other IP protocols
	// v1.3 Phase 1b (追加) — Packet-level anomalies (detected stateless in BPF):
	BadFragment = 12 // Ping of Death-style (frag_end > 65535) + tiny fragment (first frag too small for L4 header)
	Invalid     = 13 // IP IHL < 5 / TCP doff < 5 / IP total_length < header size
	// Reflection sub-categories (dns_reflect, ntp_reflect, memcached_reflect, etc.)
	// are intentionally NOT decoders — they are identified via precondition
	// `decoder=udp + dominant_src_port=<port>` at detection time. See
	// v1.3-scope.md §A for rationale (pure syntactic sugar, consumes scarce slots).
	// TCP flag anomalies (NULL / XMAS / SYN+FIN / SYN+RST) are intentionally NOT
	// in `Invalid` — users express these as xdrop rules via `tcp_flags` match field.
	// Slots 14-15 reserved for future decoders (explicit additions only).
)

// Names maps decoder index to human-readable name.
// Used for logging, API responses, threshold decoder field matching.
// Empty string means the slot is unused.
var Names = [MaxDecoders]string{
	"tcp", "tcp_syn", "udp", "icmp", "fragment",
	"tcp_ack", "tcp_rst", "tcp_fin",
	"gre", "esp", "igmp", "ip_other",
	"bad_fragment", "invalid",
	"", "",
}

// Index returns the decoder index for a given name, or -1 if unknown.
func Index(name string) int {
	for i, n := range Names {
		if n != "" && n == name {
			return i
		}
	}
	return -1
}

// DispatchClass categorizes decoders by which xDrop payload fields are legal.
// Used by the xDrop dispatch-boundary sanitizer to strip illegal fields
// before the HTTP POST — single source of truth so new decoders never need
// a separate "strip list" update.
//
// See fix-plan-xdrop-port-bgp-schedule-2026-05-02.md §Bug 1.
type DispatchClass int

const (
	// Ported — L4 protocols: src_port/dst_port allowed; tcp_flags allowed
	// for the TCP-flag subfamily.
	Ported DispatchClass = iota
	// PortlessProto — IP protocols without ports (icmp, fragment, gre, esp, igmp):
	// delete src_port, dst_port, tcp_flags before dispatch.
	PortlessProto
	// Anomaly — packet-level anomalies (bad_fragment, invalid):
	// uses decoder= field; delete protocol, src_port, dst_port, tcp_flags.
	Anomaly
	// Unsupported — not dispatched to xDrop (ip, ip_other, empty/unknown).
	// The engine.go gate blocks these before xdrop.go is reached; the class
	// exists so the registry is complete and the sanitizer can no-op.
	Unsupported
)

// decoderDispatchClass maps decoder name → DispatchClass.
// ip/ip_other are Unsupported: the controller already excludes them from
// xDrop dispatch (xDropCompatibleDecoders gate in engine.go) to avoid
// broad L3-aggregate wildcard drops. Moving ip to PortlessProto would
// accidentally make it xDrop-eligible through the registry path.
var decoderDispatchClass = map[string]DispatchClass{
	"tcp":          Ported,
	"tcp_syn":      Ported,
	"tcp_ack":      Ported,
	"tcp_rst":      Ported,
	"tcp_fin":      Ported,
	"udp":          Ported,
	"icmp":         PortlessProto,
	"fragment":     PortlessProto,
	"gre":          PortlessProto,
	"esp":          PortlessProto,
	"igmp":         PortlessProto,
	"bad_fragment": Anomaly,
	"invalid":      Anomaly,
	"ip":           Unsupported,
	"ip_other":     Unsupported,
}

// GetDispatchClass returns the DispatchClass for the given decoder name.
// Unknown/empty decoders return Unsupported.
func GetDispatchClass(decoder string) DispatchClass {
	if dc, ok := decoderDispatchClass[decoder]; ok {
		return dc
	}
	return Unsupported
}
