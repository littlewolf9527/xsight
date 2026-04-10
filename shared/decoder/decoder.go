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
	// Future decoders start at index 5:
	// GRE  = 5
	// DNS  = 6
	// NTP  = 7
)

// Names maps decoder index to human-readable name.
// Used for logging, API responses, threshold decoder field matching.
// Empty string means the slot is unused.
var Names = [MaxDecoders]string{
	"tcp", "tcp_syn", "udp", "icmp", "fragment",
	"", "", "", "", "", "", "", "", "", "", "",
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
