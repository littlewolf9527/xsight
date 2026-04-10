// Package sampler — packet.go provides gopacket-based parsing of raw samples
// into structured PacketSample fields.
//
// Uses DecodingLayerParser for zero-allocation decoding on the hot path.
package sampler

import (
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// PacketSample is a parsed packet sample with both raw bytes and structured fields.
// Mirrors the protobuf PacketSample message from brainstorm-node.md.
type PacketSample struct {
	RawHeader      []byte // original captured bytes
	SrcIP          net.IP
	DstIP          net.IP
	Protocol       uint32 // IP protocol (TCP=6, UDP=17, ICMP=1)
	SrcPort        uint32
	DstPort        uint32
	PacketLength   uint32 // original packet length on wire
	TCPFlags       uint32 // FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10 URG=0x20
	TTL            uint32
	FragmentOffset uint32
	ICMPType       uint32
	ICMPCode       uint32
}

// PacketParser is a reusable, zero-allocation packet decoder.
// It pre-allocates all layer structs and reuses them across calls.
// Handles both direct (mirror) and ERSPAN-encapsulated packets:
//   - Mirror: Ethernet → IP → TCP/UDP/ICMP
//   - ERSPAN Type II: Ethernet → IP → GRE → ERSPAN → inner Ethernet → inner IP → L4
//     For ERSPAN, the layer structs are overwritten by the inner layers,
//     so the final state naturally reflects the innermost (real) traffic.
type PacketParser struct {
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType

	// Pre-allocated layer structs (reused across all calls)
	eth     layers.Ethernet
	dot1q   layers.Dot1Q
	ipv4    layers.IPv4
	ipv6    layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	icmpv4  layers.ICMPv4
	icmpv6  layers.ICMPv6
	gre     layers.GRE
	erspan2 layers.ERSPANII
}

// NewPacketParser creates a reusable PacketParser with all required layers
// pre-registered for zero-allocation decoding.
//
// Adding a new decoder/layer:
//  1. Add a field to PacketParser struct (e.g. `dns layers.DNS`)
//  2. Register it here in NewDecodingLayerParser (e.g. `&p.dns`)
//  3. Add a case in Parse() switch on decoded LayerTypes to extract fields
//  4. Add the extracted fields to PacketSample struct if needed
//  5. IgnoreUnsupported=true means unregistered layers are silently skipped
func NewPacketParser() *PacketParser {
	p := &PacketParser{
		decoded: make([]gopacket.LayerType, 0, 10),
	}
	p.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&p.eth,
		&p.dot1q,
		&p.ipv4,
		&p.ipv6,
		&p.tcp,
		&p.udp,
		&p.icmpv4,
		&p.icmpv6,
		&p.gre,
		&p.erspan2,
	)
	// Ignore unsupported layer types (e.g. VLAN, ARP) instead of returning errors.
	p.parser.IgnoreUnsupported = true
	return p
}

// Parse decodes raw Ethernet frame bytes into a PacketSample.
// This method is NOT goroutine-safe — use one PacketParser per goroutine.
func (p *PacketParser) Parse(raw []byte, pktLen uint32) PacketSample {
	ps := PacketSample{
		RawHeader:    raw,
		PacketLength: pktLen,
	}

	p.decoded = p.decoded[:0]
	_ = p.parser.DecodeLayers(raw, &p.decoded)

	// Track which layers were decoded to populate the sample.
	// For ERSPAN, DecodingLayerParser overwrites the same layer struct
	// when it encounters the inner Ethernet/IP/L4, so the final state
	// of ipv4/tcp/udp etc. already reflects the innermost layer.
	var hasIPv4, hasIPv6 bool
	for _, lt := range p.decoded {
		switch lt {
		case layers.LayerTypeIPv4:
			hasIPv4 = true
		case layers.LayerTypeIPv6:
			hasIPv6 = true

		case layers.LayerTypeTCP:
			ps.SrcPort = uint32(p.tcp.SrcPort)
			ps.DstPort = uint32(p.tcp.DstPort)
			var flags uint32
			if p.tcp.FIN {
				flags |= 0x01
			}
			if p.tcp.SYN {
				flags |= 0x02
			}
			if p.tcp.RST {
				flags |= 0x04
			}
			if p.tcp.PSH {
				flags |= 0x08
			}
			if p.tcp.ACK {
				flags |= 0x10
			}
			if p.tcp.URG {
				flags |= 0x20
			}
			ps.TCPFlags = flags

		case layers.LayerTypeUDP:
			ps.SrcPort = uint32(p.udp.SrcPort)
			ps.DstPort = uint32(p.udp.DstPort)

		case layers.LayerTypeICMPv4:
			ps.ICMPType = uint32(p.icmpv4.TypeCode.Type())
			ps.ICMPCode = uint32(p.icmpv4.TypeCode.Code())

		case layers.LayerTypeICMPv6:
			ps.ICMPType = uint32(p.icmpv6.TypeCode.Type())
			ps.ICMPCode = uint32(p.icmpv6.TypeCode.Code())
		}
	}

	if hasIPv4 {
		ps.SrcIP = p.ipv4.SrcIP
		ps.DstIP = p.ipv4.DstIP
		ps.Protocol = uint32(p.ipv4.Protocol)
		ps.TTL = uint32(p.ipv4.TTL)
		ps.FragmentOffset = uint32(p.ipv4.FragOffset)
	} else if hasIPv6 {
		ps.SrcIP = p.ipv6.SrcIP
		ps.DstIP = p.ipv6.DstIP
		ps.Protocol = uint32(p.ipv6.NextHeader)
		ps.TTL = uint32(p.ipv6.HopLimit)
	}

	return ps
}

// ParsePacket decodes raw Ethernet frame bytes into a PacketSample.
// It uses a package-level PacketParser for zero-allocation decoding.
// NOT goroutine-safe — the caller must ensure single-threaded access
// (which is the case for the ring buffer reader callback).
func ParsePacket(raw []byte, pktLen uint32) PacketSample {
	return defaultParser.Parse(raw, pktLen)
}

var defaultParser = NewPacketParser()
