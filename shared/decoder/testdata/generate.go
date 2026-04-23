//go:build ignore
// +build ignore

// generate.go — xSight v1.3 packet fixture generator.
//
// Run via: go run generate.go
// Produces: packet-fixtures.json (cross-repo byte-compat contract ground truth).
//
// Deliberately stdlib-only so xsight/shared remains dep-free.
// Do NOT edit packet-fixtures.json by hand — re-run this generator and commit
// the regenerated JSON. xsight.c semantics change => generator changes => fixture
// changes => downstream (xSight contract_test.go + xdrop decoder_contract_test.go)
// flag the change.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// Fixture is the on-disk record for one synthetic packet.
type Fixture struct {
	Name                  string   `json:"name"`
	Hex                   string   `json:"hex"`
	FrameType             string   `json:"frame_type"`
	ExpectedDecoders      []string `json:"expected_decoders"`
	ExpectedIsInvalid     bool     `json:"expected_is_invalid"`
	ExpectedIsBadFragment bool     `json:"expected_is_bad_fragment"`
	Notes                 string   `json:"notes"`
}

// FixtureFile is the JSON envelope.
type FixtureFile struct {
	Comment     string    `json:"_comment"`
	Version     int       `json:"version"`
	GeneratedBy string    `json:"generated_by"`
	Fixtures    []Fixture `json:"fixtures"`
}

// ---------------------------------------------------------------------------
// Packet synthesis primitives
// ---------------------------------------------------------------------------

const (
	srcIPv4A = 0x0a000001 // 10.0.0.1
	dstIPv4A = 0x0a000002 // 10.0.0.2
)

var (
	srcIPv6A = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	dstIPv6A = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
)

// ipv4 holds the knobs for building an IPv4 header.
type ipv4 struct {
	ihl      uint8  // default 5
	totalLen uint16 // default computed from payload
	mf       bool
	offset8  uint16 // 13-bit fragment offset in 8-byte units
	proto    uint8
	payload  []byte
}

func buildIPv4(p ipv4) []byte {
	ihl := p.ihl
	if ihl == 0 {
		ihl = 5
	}
	hdrLen := int(ihl) * 4
	// xsight.c parse_ip requires pkt >= sizeof(struct iphdr) = 20 bytes
	// BEFORE it reads IHL to classify the packet. An "IHL=4 invalid" fixture
	// is a 20+-byte frame whose header claims IHL=4 (buf[0] low nibble = 4),
	// NOT a genuinely truncated frame — xsight.c would early-return on the
	// bounds check for the latter. Allocate max(hdrLen, 20) so the parser
	// reaches the IHL classification branch, and src/dst IP writes at
	// buf[12:20] stay in bounds. Mirrors the same-named helper in
	// shared/decoder/contract_test.go (keep the two in sync — codex v1.3.x
	// audit P1 caught the drift after only the test was fixed).
	bufLen := hdrLen + len(p.payload)
	if bufLen < 20 {
		bufLen = 20
	}
	buf := make([]byte, bufLen)
	buf[0] = 0x40 | (ihl & 0x0f) // Version=4, IHL
	buf[1] = 0x00                // TOS
	tot := p.totalLen
	if tot == 0 {
		tot = uint16(hdrLen + len(p.payload))
	}
	binary.BigEndian.PutUint16(buf[2:4], tot)
	binary.BigEndian.PutUint16(buf[4:6], 0) // ID
	var fragOff uint16
	if p.mf {
		fragOff |= 0x2000
	}
	fragOff |= p.offset8 & 0x1fff
	binary.BigEndian.PutUint16(buf[6:8], fragOff)
	buf[8] = 0x40    // TTL
	buf[9] = p.proto // Protocol
	// checksum left zero — tests ignore checksum
	binary.BigEndian.PutUint32(buf[12:16], srcIPv4A)
	binary.BigEndian.PutUint32(buf[16:20], dstIPv4A)
	// IHL>5 options bytes left zero (header extended but empty)
	copy(buf[hdrLen:], p.payload)
	return buf
}

// tcpHdr builds a 20-byte TCP header with given flags. doffWords sets the data-offset
// field; pass 5 for a minimum-length header. If doffWords>5 but no options are appended,
// the parser will read garbage options — only use doff>5 with a matching payload or when
// deliberately testing undersized / oversized cases.
func tcpHdr(srcPort, dstPort uint16, flags uint8, doffWords uint8) []byte {
	if doffWords == 0 {
		doffWords = 5
	}
	buf := make([]byte, 20)
	binary.BigEndian.PutUint16(buf[0:2], srcPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	// seq + ack left zero
	buf[12] = (doffWords & 0x0f) << 4 // data offset in upper nibble
	buf[13] = flags
	binary.BigEndian.PutUint16(buf[14:16], 0xffff) // window
	// checksum + urgent zero
	return buf
}

// udpHdr builds a minimum UDP header (no checksum validation).
func udpHdr(srcPort, dstPort uint16, payloadLen int) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint16(buf[0:2], srcPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	binary.BigEndian.PutUint16(buf[4:6], uint16(8+payloadLen))
	// checksum zero
	return buf
}

// ipv6 holds the knobs for building an IPv6 header.
type ipv6Hdr struct {
	nextHdr uint8
	payload []byte
}

func buildIPv6(p ipv6Hdr) []byte {
	buf := make([]byte, 40+len(p.payload))
	buf[0] = 0x60 // Version=6
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(p.payload)))
	buf[6] = p.nextHdr
	buf[7] = 0x40 // Hop Limit
	copy(buf[8:24], srcIPv6A[:])
	copy(buf[24:40], dstIPv6A[:])
	copy(buf[40:], p.payload)
	return buf
}

// ipv6Extension builds an 8-byte Hop-by-Hop extension header stub: 0 options, pad-to-8.
// Only used for the "ipv6 ext header blindspot" fixture.
func ipv6ExtHopByHop(nextHdr uint8) []byte {
	buf := make([]byte, 8)
	buf[0] = nextHdr // NH of the thing after this ext
	buf[1] = 0x00    // HdrExtLen = 0 means 8 bytes total
	// remaining 6 bytes PadN options (type 1, len 4, 4 zero bytes)
	buf[2] = 0x01
	buf[3] = 0x04
	return buf
}

// tcpFlags alphabet for readability.
const (
	FIN uint8 = 0x01
	SYN uint8 = 0x02
	RST uint8 = 0x04
	PSH uint8 = 0x08
	ACK uint8 = 0x10
	URG uint8 = 0x20
)

// ---------------------------------------------------------------------------
// Fixture definitions
// ---------------------------------------------------------------------------

func mustHex(b []byte) string { return hex.EncodeToString(b) }

// baselineTCP composes an IPv4 + TCP packet with the given flags and returns hex.
func baselineTCP(flags uint8) string {
	tcp := tcpHdr(12345, 80, flags, 5)
	return mustHex(buildIPv4(ipv4{proto: 6, payload: tcp}))
}

// baselineTCPWithDoff composes an IPv4 + TCP with the given doff (in 32-bit words).
func baselineTCPWithDoff(flags uint8, doff uint8) string {
	tcp := tcpHdr(12345, 80, flags, doff)
	return mustHex(buildIPv4(ipv4{proto: 6, payload: tcp}))
}

// baselineUDP composes an IPv4 + UDP with given payload length.
func baselineUDP(payloadLen int) string {
	payload := make([]byte, payloadLen)
	udp := udpHdr(12345, 53, payloadLen)
	return mustHex(buildIPv4(ipv4{proto: 17, payload: append(udp, payload...)}))
}

// baselineICMP composes an IPv4 + minimal ICMP Echo Request.
func baselineICMP() string {
	icmp := make([]byte, 8)
	icmp[0] = 8 // Type = Echo Request
	return mustHex(buildIPv4(ipv4{proto: 1, payload: icmp}))
}

// baselineICMPv6 composes an IPv6 + minimal ICMPv6 Echo Request.
func baselineICMPv6() string {
	icmp := make([]byte, 8)
	icmp[0] = 128 // Type = Echo Request
	return mustHex(buildIPv6(ipv6Hdr{nextHdr: 58, payload: icmp}))
}

// baselineProto composes an IPv4 packet with proto+opaque payload (for gre/esp/igmp).
func baselineProto(proto uint8, payloadLen int) string {
	return mustHex(buildIPv4(ipv4{proto: proto, payload: make([]byte, payloadLen)}))
}

// fragPacket constructs an IPv4 fragment with knobs.
// firstFrag: MF=1 offset=0; middleFrag: MF=1 offset>0; lastFrag: MF=0 offset>0;
// plain packet: MF=0 offset=0.
// totalLenOverride ≠ 0 forces IP total_length (for invalid packet testing).
func fragPacket(proto uint8, mf bool, offset8 uint16, payload []byte, totalLenOverride uint16) string {
	return mustHex(buildIPv4(ipv4{
		proto:    proto,
		mf:       mf,
		offset8:  offset8,
		payload:  payload,
		totalLen: totalLenOverride,
	}))
}

// tcpPayload32 returns 32 bytes of TCP-shaped payload for fragment tests where the
// fragment needs to carry >=20 bytes of "TCP header".
func tcpPayload(n int) []byte {
	if n < 20 {
		return make([]byte, n)
	}
	b := make([]byte, n)
	binary.BigEndian.PutUint16(b[0:2], 12345)
	binary.BigEndian.PutUint16(b[2:4], 80)
	b[12] = 0x50 // doff=5
	b[13] = SYN
	binary.BigEndian.PutUint16(b[14:16], 0xffff)
	return b
}

// udpPayload returns n bytes with a plausible UDP-ish header if n>=8.
func udpPayload(n int) []byte {
	if n < 8 {
		return make([]byte, n)
	}
	b := make([]byte, n)
	binary.BigEndian.PutUint16(b[0:2], 12345)
	binary.BigEndian.PutUint16(b[2:4], 53)
	binary.BigEndian.PutUint16(b[4:6], uint16(n))
	return b
}

// allFixtures returns the complete Phase 0 fixture set.
// Order: within each group, positives first then negatives/boundaries.
// Keep fixture names stable — downstream tests grep them by name.
func allFixtures() []Fixture {
	var f []Fixture

	// ---- tcp ----
	f = append(f,
		Fixture{
			Name: "tcp_syn_only", Hex: baselineTCP(SYN), FrameType: "ip",
			ExpectedDecoders: []string{"tcp", "tcp_syn"},
			Notes:            "IPv4 TCP SYN=1 ACK=0 — handshake step 1",
		},
		Fixture{
			Name: "tcp_ack_pure", Hex: baselineTCP(ACK), FrameType: "ip",
			ExpectedDecoders: []string{"tcp", "tcp_ack"},
			Notes:            "IPv4 TCP ACK=1 SYN=0 — keepalive / bare ack",
		},
		Fixture{
			Name: "tcp_ack_with_psh", Hex: baselineTCP(ACK | PSH), FrameType: "ip",
			ExpectedDecoders: []string{"tcp", "tcp_ack"},
			Notes:            "IPv4 TCP ACK+PSH — established data; ACK flood main surface",
		},
		Fixture{
			Name: "tcp_ack_with_fin", Hex: baselineTCP(ACK | FIN), FrameType: "ip",
			ExpectedDecoders: []string{"tcp", "tcp_ack", "tcp_fin"},
			Notes:            "IPv4 TCP ACK+FIN — normal close; tcp_ack (ACK,!SYN) AND tcp_fin (FIN) both match",
		},
		Fixture{
			Name: "tcp_syn_ack", Hex: baselineTCP(SYN | ACK), FrameType: "ip",
			ExpectedDecoders: []string{"tcp"},
			Notes:            "IPv4 TCP SYN+ACK handshake step 2 — NOT tcp_syn (ACK set) NOT tcp_ack (SYN set); only tcp fires",
		},
		Fixture{
			Name: "tcp_rst_only", Hex: baselineTCP(RST), FrameType: "ip",
			ExpectedDecoders: []string{"tcp", "tcp_rst"},
			Notes:            "IPv4 TCP RST — tcp_rst positive",
		},
		Fixture{
			Name: "tcp_rst_ack", Hex: baselineTCP(RST | ACK), FrameType: "ip",
			ExpectedDecoders: []string{"tcp", "tcp_ack", "tcp_rst"},
			Notes:            "IPv4 TCP RST+ACK — common RST form (also matches tcp_ack = ACK && !SYN)",
		},
		Fixture{
			Name: "tcp_fin_only", Hex: baselineTCP(FIN), FrameType: "ip",
			ExpectedDecoders: []string{"tcp", "tcp_fin"},
			Notes:            "IPv4 TCP FIN — tcp_fin positive",
		},
		Fixture{
			Name: "tcp_urg", Hex: baselineTCP(URG | ACK), FrameType: "ip",
			ExpectedDecoders: []string{"tcp", "tcp_ack"},
			Notes:            "IPv4 TCP URG+ACK — URG is not a decoder; tcp_ack still matches",
		},
	)

	// ---- udp / icmp / icmpv6 ----
	f = append(f,
		Fixture{
			Name: "udp_basic", Hex: baselineUDP(32), FrameType: "ip",
			ExpectedDecoders: []string{"udp"},
			Notes:            "IPv4 UDP with 32B payload",
		},
		Fixture{
			Name: "icmp_echo", Hex: baselineICMP(), FrameType: "ip",
			ExpectedDecoders: []string{"icmp"},
			Notes:            "IPv4 ICMP Echo Request",
		},
		Fixture{
			Name: "icmpv6_echo", Hex: baselineICMPv6(), FrameType: "ip",
			ExpectedDecoders: []string{"icmp"},
			Notes:            "IPv6 ICMPv6 Echo Request — xsight reports as icmp decoder (v4 + v6 merged)",
		},
	)

	// ---- gre / esp / igmp (Phase 1) ----
	f = append(f,
		Fixture{
			Name: "gre_basic", Hex: baselineProto(47, 8), FrameType: "ip",
			ExpectedDecoders: []string{"gre"},
			Notes:            "IPv4 GRE (proto=47) — IANA",
		},
		Fixture{
			Name: "esp_basic", Hex: baselineProto(50, 16), FrameType: "ip",
			ExpectedDecoders: []string{"esp"},
			Notes:            "IPv4 ESP (proto=50) — IANA",
		},
		Fixture{
			Name: "igmp_basic", Hex: baselineProto(2, 8), FrameType: "ip",
			ExpectedDecoders: []string{"igmp"},
			Notes:            "IPv4 IGMP (proto=2) — IANA",
		},
		Fixture{
			Name: "ip_other_sctp", Hex: baselineProto(132, 16), FrameType: "ip",
			ExpectedDecoders: []string{"ip_other"},
			Notes:            "IPv4 SCTP (proto=132) — falls into ip_other bucket",
		},
	)

	// ---- bad_fragment (Phase 4) ----
	// PoD boundary: frag_end = offset*8 + payload.
	// frag_end=65535 → legal; frag_end=65536 → bad.
	// offset=8191 is the max 13-bit value. 8191*8 = 65528. payload=7 → 65535 (legal);
	// payload=8 → 65536 (bad).
	f = append(f,
		Fixture{
			Name: "pod_frag_end_65535",
			Hex: fragPacket(17, false, 8191, make([]byte, 7) /* payload */, 0),
			FrameType: "ip",
			ExpectedDecoders:      []string{"udp", "fragment"},
			ExpectedIsBadFragment: false,
			Notes:                 "IPv4 frag: offset=8191 payload=7 → frag_end=65535 (legal boundary, NOT bad)",
		},
		Fixture{
			Name: "pod_frag_end_65536",
			Hex: fragPacket(17, false, 8191, make([]byte, 8), 0),
			FrameType: "ip",
			ExpectedDecoders:      []string{"udp", "fragment"},
			ExpectedIsBadFragment: true,
			Notes:                 "IPv4 frag: offset=8191 payload=8 → frag_end=65536 (bad per RFC 791 / PoD)",
		},
		Fixture{
			Name: "tiny_first_frag_tcp_19",
			Hex: fragPacket(6, true, 0, tcpPayload(19), 0),
			FrameType: "ip",
			ExpectedDecoders:      []string{"tcp", "fragment"},
			ExpectedIsBadFragment: true,
			Notes:                 "First TCP fragment payload=19 < 20 → tiny_first_frag positive",
		},
		Fixture{
			Name: "tiny_first_frag_tcp_20",
			Hex: fragPacket(6, true, 0, tcpPayload(20), 0),
			FrameType: "ip",
			ExpectedDecoders:      []string{"tcp", "fragment"},
			ExpectedIsBadFragment: false,
			Notes:                 "First TCP fragment payload=20 — boundary legal",
		},
		Fixture{
			Name: "tiny_first_frag_udp_7",
			Hex: fragPacket(17, true, 0, udpPayload(7), 0),
			FrameType: "ip",
			ExpectedDecoders:      []string{"udp", "fragment"},
			ExpectedIsBadFragment: true,
			Notes:                 "First UDP fragment payload=7 < 8 → tiny_first_frag positive",
		},
		Fixture{
			Name: "tiny_first_frag_udp_8",
			Hex: fragPacket(17, true, 0, udpPayload(8), 0),
			FrameType: "ip",
			ExpectedDecoders:      []string{"udp", "fragment"},
			ExpectedIsBadFragment: false,
			Notes:                 "First UDP fragment payload=8 — boundary legal",
		},
		Fixture{
			Name: "tiny_frag_middle",
			Hex: fragPacket(6, true, 185, make([]byte, 10), 0),
			FrameType: "ip",
			ExpectedDecoders:      []string{"tcp", "fragment"},
			ExpectedIsBadFragment: false,
			Notes:                 "Middle fragment (MF=1 offset>0) with small payload — tiny check is first-frag only",
		},
		Fixture{
			Name: "tiny_frag_last",
			Hex: fragPacket(6, false, 185, make([]byte, 10), 0),
			FrameType: "ip",
			ExpectedDecoders:      []string{"tcp", "fragment"},
			ExpectedIsBadFragment: false,
			Notes:                 "Last fragment (MF=0 offset>0) with small payload — MF gate excludes",
		},
	)

	// ---- invalid (Phase 4) ----
	// IHL < 5, total_length < header bytes, TCP doff < 5
	f = append(f,
		Fixture{
			Name: "invalid_ihl_4",
			Hex: mustHex(buildIPv4(ipv4{ihl: 4, proto: 6, totalLen: 20, payload: tcpPayload(0)})),
			FrameType:         "ip",
			ExpectedDecoders:  []string{"tcp"},
			ExpectedIsInvalid: true,
			Notes:             "IPv4 IHL=4 → invalid + early-return; xsight.c sets l4_proto BEFORE early-return (line 311) so tcp decoder still fires — but l4 header offset undefined so no sub-flags",
		},
		Fixture{
			Name: "invalid_ihl_5",
			Hex: mustHex(buildIPv4(ipv4{ihl: 5, proto: 6, payload: tcpPayload(20)})),
			FrameType:         "ip",
			ExpectedDecoders:  []string{"tcp", "tcp_syn"},
			ExpectedIsInvalid: false,
			Notes:             "IPv4 IHL=5 → valid boundary; full 20B TCP payload with SYN triggers tcp + tcp_syn sub-flag",
		},
		Fixture{
			Name: "invalid_tot_len_short",
			Hex: mustHex(buildIPv4(ipv4{ihl: 5, proto: 6, totalLen: 19, payload: []byte{}})),
			FrameType:         "ip",
			ExpectedDecoders:  []string{"tcp"},
			ExpectedIsInvalid: true,
			Notes:             "IPv4 total_length=19 < 20 (hdr) → invalid; parser continues; packet too short for L4 sub-flag parse → only tcp decoder",
		},
		Fixture{
			Name: "invalid_tot_len_equal",
			Hex: mustHex(buildIPv4(ipv4{ihl: 5, proto: 6, totalLen: 20, payload: []byte{}})),
			FrameType:         "ip",
			ExpectedDecoders:  []string{"tcp"},
			ExpectedIsInvalid: false,
			Notes:             "IPv4 total_length=20 == hdr → valid boundary; packet too short for L4 sub-flag parse",
		},
		Fixture{
			Name: "invalid_tcp_doff_4",
			Hex: baselineTCPWithDoff(SYN, 4),
			FrameType:         "ip",
			ExpectedDecoders:  []string{"tcp", "tcp_syn"},
			ExpectedIsInvalid: true,
			Notes:             "IPv4 TCP doff=4 → invalid; other decoders still fire per xsight.c",
		},
		Fixture{
			Name: "invalid_tcp_doff_5",
			Hex: baselineTCPWithDoff(SYN, 5),
			FrameType:         "ip",
			ExpectedDecoders:  []string{"tcp", "tcp_syn"},
			ExpectedIsInvalid: false,
			Notes:             "IPv4 TCP doff=5 → valid boundary",
		},
	)

	// ---- IPv6 contract boundaries ----
	f = append(f,
		Fixture{
			Name: "ipv6_tcp_doff_4",
			Hex: mustHex(buildIPv6(ipv6Hdr{nextHdr: 6, payload: tcpHdr(12345, 80, SYN, 4)})),
			FrameType:         "ip",
			ExpectedDecoders:  []string{"tcp", "tcp_syn"},
			ExpectedIsInvalid: true,
			Notes:             "IPv6 (nexthdr=TCP direct) + doff=4 → invalid",
		},
		Fixture{
			Name: "ipv6_tcp_doff_5",
			Hex: mustHex(buildIPv6(ipv6Hdr{nextHdr: 6, payload: tcpHdr(12345, 80, SYN, 5)})),
			FrameType:         "ip",
			ExpectedDecoders:  []string{"tcp", "tcp_syn"},
			ExpectedIsInvalid: false,
			Notes:             "IPv6 + doff=5 → valid",
		},
		Fixture{
			Name: "ipv6_ext_hbh_tcp_doff_4",
			// HBH(nexthdr=6) then TCP
			Hex: mustHex(buildIPv6(ipv6Hdr{
				nextHdr: 0, // Hop-by-Hop
				payload: append(ipv6ExtHopByHop(6), tcpHdr(12345, 80, SYN, 4)...),
			})),
			FrameType:         "ip",
			ExpectedDecoders:  []string{}, // v1.3 doesn't walk ext headers; nexthdr != TCP → tcp decoder skipped
			ExpectedIsInvalid: false,       // v1.3 silent skip contract — see P4-UT-15b in xdrop proposal
			Notes:             "IPv6 HopByHop ext header + TCP doff=4 — xsight v1.3 BLIND SPOT: no ext walker, so tcp decoder and doff check are silently skipped; locking this contract so future ext walker implementation flips this intentionally",
		},
	)

	// stable order for deterministic output
	sort.SliceStable(f, func(i, j int) bool { return f[i].Name < f[j].Name })
	return f
}

func main() {
	fixtures := allFixtures()

	out := FixtureFile{
		Comment: "xSight v1.3 byte-compat contract fixtures. " +
			"Generated by testdata/generate.go (stdlib only). " +
			"Consumed by xsight/shared/decoder/contract_test.go and " +
			"xdrop/node/agent/bpf/decoder_contract_test.go. " +
			"Edit the generator, not this file.",
		Version:     1,
		GeneratedBy: "xsight/shared/decoder/testdata/generate.go",
		Fixtures:    fixtures,
	}

	buf, err := json.MarshalIndent(&out, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal:", err)
		os.Exit(1)
	}

	if err := os.WriteFile("packet-fixtures.json", append(buf, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}

	fmt.Printf("wrote packet-fixtures.json with %d fixtures\n", len(fixtures))
}
