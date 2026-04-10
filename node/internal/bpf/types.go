package bpf

import (
	"fmt"
	"net"

	"github.com/littlewolf9527/xsight/shared/decoder"
)

// SampleHdr mirrors struct sample_hdr in xsight.h.
// Prefixed to each ring buffer record to carry effective length.
type SampleHdr struct {
	CapLen uint32 // actual captured bytes
	PktLen uint32 // original packet length on wire
}

// SampleHdrSize is the byte size of SampleHdr (used by sampler).
const SampleHdrSize = 8

// GlobalStats mirrors struct global_stats in xsight.h.
// v2.11: added MatchedBytes + per-decoder breakdown for global threshold detection.
// v2.11 Phase 2: added outbound (src_ip matched) counters.
type GlobalStats struct {
	TotalPkts         uint64
	TotalBytes        uint64
	MatchedPkts       uint64
	MatchedBytes      uint64                     // bytes within watch scope (for global ip+bps)
	SampleDrops       uint64                     // ring buffer reserve failures (backpressure signal)
	DecoderCounts     [decoder.MaxDecoders]uint32 // per-decoder PPS (inbound matched only)
	DecoderByteCounts [decoder.MaxDecoders]uint64 // per-decoder BPS (inbound matched only)
	// Outbound (src_ip matched) global counters
	SrcMatchedPkts       uint64
	SrcMatchedBytes      uint64
	SrcDecoderCounts     [decoder.MaxDecoders]uint32
	SrcDecoderByteCounts [decoder.MaxDecoders]uint64
}

// DstIPStats mirrors struct dst_ip_stats in xsight.h.
// DecoderCounts is indexed by shared/decoder constants.
type DstIPStats struct {
	PktCount          uint64
	ByteCount         uint64
	DecoderCounts     [decoder.MaxDecoders]uint32 // indexed by decoder.TCP, decoder.UDP, etc.
	DecoderByteCounts [decoder.MaxDecoders]uint64 // per-decoder byte counts for BPS thresholds
	SmallPkt          uint32
	MediumPkt         uint32
	LargePkt          uint32
	_                 [4]byte // padding to match BPF struct alignment (bpf2go generated)
}

// PrefixStats mirrors struct prefix_stats in xsight.h.
// DecoderCounts is indexed by shared/decoder constants.
type PrefixStats struct {
	PktCount          uint64
	ByteCount         uint64
	OverflowCount     uint32
	Pad               uint32                     // alignment padding, matches BPF struct
	DecoderCounts     [decoder.MaxDecoders]uint32 // indexed by decoder.TCP, decoder.UDP, etc.
	DecoderByteCounts [decoder.MaxDecoders]uint64 // per-decoder byte counts for BPS thresholds
}

// LPMKey mirrors struct lpm_key in xsight.h.
type LPMKey struct {
	Prefixlen uint32
	Addr      [16]byte
}

// PrefixKey mirrors struct prefix_key in xsight.h.
type PrefixKeyGo struct {
	Addr      [16]byte
	Prefixlen uint32
}

// PrefixEntry is a convenience type for specifying watch prefixes.
type PrefixEntry struct {
	Net       net.IPNet
	Prefixlen uint32
}

// ParsePrefix parses a CIDR string into a PrefixEntry.
func ParsePrefix(cidr string) (PrefixEntry, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return PrefixEntry{}, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	ones, _ := ipnet.Mask.Size()
	return PrefixEntry{Net: *ipnet, Prefixlen: uint32(ones)}, nil
}

// LPMKey returns the BPF LPM trie key for this prefix.
func (p PrefixEntry) LPMKey() LPMKey {
	key := LPMKey{Prefixlen: p.Prefixlen}
	ip := p.Net.IP
	if ip4 := ip.To4(); ip4 != nil {
		copy(key.Addr[:4], ip4)
	} else {
		copy(key.Addr[:], ip.To16())
	}
	return key
}

// PrefixKey returns the BPF prefix_stats map key for this prefix.
func (p PrefixEntry) PrefixKey() PrefixKeyGo {
	pkey := PrefixKeyGo{Prefixlen: p.Prefixlen}
	ip := p.Net.IP
	if ip4 := ip.To4(); ip4 != nil {
		copy(pkey.Addr[:4], ip4)
	} else {
		copy(pkey.Addr[:], ip.To16())
	}
	return pkey
}

// String returns the CIDR notation.
func (p PrefixEntry) String() string {
	return p.Net.String()
}
