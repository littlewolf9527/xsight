package flow

import (
	"github.com/littlewolf9527/xsight/shared/decoder"
)

// ProtocolToDecoder maps IP protocol number + TCP flags to a decoder index.
// Returns -1 for protocols without a specific decoder (counted in total pps/bps only).
// Mirrors the BPF DECODER_SWITCH macro logic.
func ProtocolToDecoder(protocol uint8, tcpFlags uint8) int {
	switch protocol {
	case 6: // TCP
		if tcpFlags&0x02 != 0 && tcpFlags&0x10 == 0 {
			// SYN set, ACK not set → SYN flood
			return decoder.TCPSyn
		}
		return decoder.TCP
	case 17: // UDP
		return decoder.UDP
	case 1, 58: // ICMP (v4=1, v6=58)
		return decoder.ICMP
	default:
		return -1 // no specific decoder, contributes to total only
	}
}
