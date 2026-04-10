package sampler

import (
	"encoding/binary"
	"net"
	"testing"
)

// buildEthIPv4TCP constructs a minimal Ethernet + IPv4 + TCP frame.
func buildEthIPv4TCP(srcIP, dstIP net.IP, srcPort, dstPort uint16, syn bool) []byte {
	buf := make([]byte, 14+20+20) // Eth(14) + IPv4(20) + TCP(20)

	// Ethernet header: dst(6) + src(6) + type(2)
	buf[12] = 0x08
	buf[13] = 0x00 // EtherType IPv4

	// IPv4 header
	ip := buf[14:]
	ip[0] = 0x45                                             // version=4, ihl=5
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+20))       // total length
	ip[8] = 64                                               // TTL
	ip[9] = 6                                                // protocol = TCP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())

	// TCP header
	tcp := buf[34:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 0x50 // data offset = 5
	if syn {
		tcp[13] = 0x02 // SYN flag
	} else {
		tcp[13] = 0x10 // ACK flag
	}

	return buf
}

// buildEthIPv4UDP constructs a minimal Ethernet + IPv4 + UDP frame.
func buildEthIPv4UDP(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	buf := make([]byte, 14+20+8) // Eth(14) + IPv4(20) + UDP(8)

	buf[12] = 0x08
	buf[13] = 0x00

	ip := buf[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8))
	ip[8] = 128
	ip[9] = 17 // UDP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())

	udp := buf[34:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], 8) // length

	return buf
}

// buildEthDot1QIPv4TCP constructs Ethernet + 802.1Q VLAN + IPv4 + TCP.
func buildEthDot1QIPv4TCP(srcIP, dstIP net.IP, srcPort, dstPort uint16, vlanID uint16) []byte {
	buf := make([]byte, 14+4+20+20) // Eth(14) + Dot1Q(4) + IPv4(20) + TCP(20)

	// Ethernet: type = 0x8100 (VLAN)
	buf[12] = 0x81
	buf[13] = 0x00

	// Dot1Q: VLAN ID + inner EtherType IPv4
	binary.BigEndian.PutUint16(buf[14:16], vlanID)
	buf[16] = 0x08
	buf[17] = 0x00 // inner EtherType = IPv4

	// IPv4
	ip := buf[18:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+20))
	ip[8] = 64
	ip[9] = 6 // TCP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())

	// TCP
	tcp := buf[38:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 0x50
	tcp[13] = 0x02 // SYN

	return buf
}

func TestParseTCPPacket(t *testing.T) {
	raw := buildEthIPv4TCP(
		net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"),
		12345, 80, true,
	)
	ps := ParsePacket(raw, uint32(len(raw)))

	if !ps.SrcIP.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("SrcIP = %v, want 10.0.0.1", ps.SrcIP)
	}
	if !ps.DstIP.Equal(net.ParseIP("10.0.0.2")) {
		t.Errorf("DstIP = %v, want 10.0.0.2", ps.DstIP)
	}
	if ps.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6 (TCP)", ps.Protocol)
	}
	if ps.SrcPort != 12345 {
		t.Errorf("SrcPort = %d, want 12345", ps.SrcPort)
	}
	if ps.DstPort != 80 {
		t.Errorf("DstPort = %d, want 80", ps.DstPort)
	}
	if ps.TCPFlags&0x02 == 0 {
		t.Error("SYN flag not set")
	}
	if ps.TTL != 64 {
		t.Errorf("TTL = %d, want 64", ps.TTL)
	}
}

func TestParseUDPPacket(t *testing.T) {
	raw := buildEthIPv4UDP(
		net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2"),
		53, 1024,
	)
	ps := ParsePacket(raw, uint32(len(raw)))

	if !ps.SrcIP.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("SrcIP = %v, want 192.168.1.1", ps.SrcIP)
	}
	if ps.Protocol != 17 {
		t.Errorf("Protocol = %d, want 17 (UDP)", ps.Protocol)
	}
	if ps.SrcPort != 53 {
		t.Errorf("SrcPort = %d, want 53", ps.SrcPort)
	}
	if ps.DstPort != 1024 {
		t.Errorf("DstPort = %d, want 1024", ps.DstPort)
	}
	if ps.TTL != 128 {
		t.Errorf("TTL = %d, want 128", ps.TTL)
	}
}

func TestParseVLANTaggedPacket(t *testing.T) {
	raw := buildEthDot1QIPv4TCP(
		net.ParseIP("172.16.0.1"), net.ParseIP("172.16.0.2"),
		443, 55000, 100,
	)
	ps := ParsePacket(raw, uint32(len(raw)))

	if ps.SrcIP == nil {
		t.Fatal("SrcIP is nil — VLAN-tagged packet not decoded")
	}
	if !ps.SrcIP.Equal(net.ParseIP("172.16.0.1")) {
		t.Errorf("SrcIP = %v, want 172.16.0.1", ps.SrcIP)
	}
	if !ps.DstIP.Equal(net.ParseIP("172.16.0.2")) {
		t.Errorf("DstIP = %v, want 172.16.0.2", ps.DstIP)
	}
	if ps.SrcPort != 443 {
		t.Errorf("SrcPort = %d, want 443", ps.SrcPort)
	}
	if ps.DstPort != 55000 {
		t.Errorf("DstPort = %d, want 55000", ps.DstPort)
	}
	if ps.TCPFlags&0x02 == 0 {
		t.Error("SYN flag not set on VLAN-tagged packet")
	}
}

func TestParseEmptyPacket(t *testing.T) {
	ps := ParsePacket([]byte{}, 0)
	if ps.SrcIP != nil || ps.DstIP != nil {
		t.Error("expected nil IPs for empty packet")
	}
}

func TestPacketParserReuse(t *testing.T) {
	p := NewPacketParser()

	// Parse TCP, then UDP — verify no state leakage
	raw1 := buildEthIPv4TCP(net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2"), 80, 443, true)
	ps1 := p.Parse(raw1, uint32(len(raw1)))
	if ps1.TCPFlags&0x02 == 0 {
		t.Error("first parse: SYN not set")
	}

	raw2 := buildEthIPv4UDP(net.ParseIP("3.3.3.3"), net.ParseIP("4.4.4.4"), 53, 1234)
	ps2 := p.Parse(raw2, uint32(len(raw2)))
	if ps2.Protocol != 17 {
		t.Errorf("second parse: Protocol = %d, want 17", ps2.Protocol)
	}
	if ps2.TCPFlags != 0 {
		t.Errorf("second parse: TCPFlags = %d, want 0 (no leakage from previous TCP)", ps2.TCPFlags)
	}
	if !ps2.SrcIP.Equal(net.ParseIP("3.3.3.3")) {
		t.Errorf("second parse: SrcIP = %v, want 3.3.3.3", ps2.SrcIP)
	}
}
