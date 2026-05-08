package flow

import (
	"github.com/littlewolf9527/xsight/shared/decoder"
)

// MaxDecoderHits is the maximum number of decoder indices a single packet
// can match (TCP base + up to 3 flag sub-decoders: one of SYN/ACK + RST + FIN).
const MaxDecoderHits = 4

// ProtocolToDecoders returns all decoder indices that should be incremented
// for a packet with the given IP protocol number and TCP flags.
//
// Returns a fixed-size array and count to avoid heap allocation on the hot path.
//
// Mirrors the BPF DECODER_SWITCH macro (node/bpf/xsight.c) exactly:
//
//   - TCP: always increments decoder.TCP, then independently checks each
//     flag bit (SYN+!ACK, ACK+!SYN, RST, FIN). A single packet may
//     match multiple sub-decoders (additive semantics). For example,
//     ACK+RST (0x14) → {TCP, TCPAck, TCPRst}, n=3.
//   - Non-TCP: returns a single decoder index.
//
// Fragment / bad_fragment / invalid are not detectable from flow records
// (no IP-header flags or anomaly bits in sFlow/NetFlow) and are omitted.
func ProtocolToDecoders(protocol uint8, tcpFlags uint8) (indices [MaxDecoderHits]int, n int) {
	switch protocol {
	case 6: // TCP — additive sub-decoder checks, matching DECODER_SWITCH
		indices[0] = decoder.TCP
		n = 1
		if tcpFlags&0x02 != 0 && tcpFlags&0x10 == 0 { // SYN+!ACK
			indices[n] = decoder.TCPSyn
			n++
		}
		if tcpFlags&0x10 != 0 && tcpFlags&0x02 == 0 { // ACK+!SYN
			indices[n] = decoder.TCPAck
			n++
		}
		if tcpFlags&0x04 != 0 { // RST
			indices[n] = decoder.TCPRst
			n++
		}
		if tcpFlags&0x01 != 0 { // FIN
			indices[n] = decoder.TCPFin
			n++
		}
	case 17: // UDP
		indices[0] = decoder.UDP
		n = 1
	case 1, 58: // ICMP (v4=1, v6=58)
		indices[0] = decoder.ICMP
		n = 1
	case 2: // IGMP
		indices[0] = decoder.IGMP
		n = 1
	case 47: // GRE
		indices[0] = decoder.GRE
		n = 1
	case 50: // ESP
		indices[0] = decoder.ESP
		n = 1
	default: // catch-all — matches BPF DECODER_IP_OTHER
		indices[0] = decoder.IPOther
		n = 1
	}
	return
}
