package flow

import (
	"testing"

	"github.com/littlewolf9527/xsight/shared/decoder"
)

func TestProtocolToDecoderTCP(t *testing.T) {
	idx := ProtocolToDecoder(6, 0x10) // TCP ACK
	if idx != decoder.TCP {
		t.Errorf("TCP ACK: expected %d, got %d", decoder.TCP, idx)
	}
}

func TestProtocolToDecoderTCPSyn(t *testing.T) {
	idx := ProtocolToDecoder(6, 0x02) // SYN only
	if idx != decoder.TCPSyn {
		t.Errorf("TCP SYN: expected %d, got %d", decoder.TCPSyn, idx)
	}
}

func TestProtocolToDecoderTCPSynAck(t *testing.T) {
	// SYN+ACK should be TCP (not TCPSyn, because ACK is set)
	idx := ProtocolToDecoder(6, 0x12) // SYN+ACK
	if idx != decoder.TCP {
		t.Errorf("TCP SYN+ACK: expected %d (TCP), got %d", decoder.TCP, idx)
	}
}

func TestProtocolToDecoderUDP(t *testing.T) {
	idx := ProtocolToDecoder(17, 0)
	if idx != decoder.UDP {
		t.Errorf("UDP: expected %d, got %d", decoder.UDP, idx)
	}
}

func TestProtocolToDecoderICMPv4(t *testing.T) {
	idx := ProtocolToDecoder(1, 0)
	if idx != decoder.ICMP {
		t.Errorf("ICMPv4: expected %d, got %d", decoder.ICMP, idx)
	}
}

func TestProtocolToDecoderICMPv6(t *testing.T) {
	idx := ProtocolToDecoder(58, 0)
	if idx != decoder.ICMP {
		t.Errorf("ICMPv6: expected %d, got %d", decoder.ICMP, idx)
	}
}

func TestProtocolToDecoderUnknown(t *testing.T) {
	idx := ProtocolToDecoder(47, 0) // GRE
	if idx != -1 {
		t.Errorf("unknown protocol: expected -1, got %d", idx)
	}
}
