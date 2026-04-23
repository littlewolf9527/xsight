// contract_test.go — xSight v1.3 byte-compat contract tests.
//
// Cross-repo contract fixture framework (Phase 0 of xdrop v2.6 adaptation).
//
// Each fixture asserts three things about a synthetic packet:
//   - expected_decoders: which DECODER_SWITCH slots must fire
//   - expected_is_invalid: xsight.c parse_ip *is_invalid output
//   - expected_is_bad_fragment: xsight.c parse_ip *is_bad_fragment output
//
// The tests run a Go-parity reimplementation of xsight.c parse_ip +
// DECODER_SWITCH against each fixture. A drift between Go parity and xsight.c
// — or between this test and the on-disk packet-fixtures.json — fails the
// test, flagging the contract.
//
// On-disk JSON sync is tested separately via TestFixtureJSONInSync. If the
// JSON is missing or scaffold (version 0), that test SKIPS with a pointer to
// go generate. Scaffold + missing are both tolerated so fresh checkouts never
// block a first build — regeneration cadence is a commit-time concern.
package decoder

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// ---------------------------------------------------------------------------
// Fixture builder (mirrors testdata/generate.go exactly — drift caught by tests)
// ---------------------------------------------------------------------------

type testFixture struct {
	Name             string
	Hex              string
	FrameType        string
	ExpectedDecoders []string
	ExpectedInvalid  bool
	ExpectedBadFrag  bool
	Notes            string
}

const (
	fin = 0x01
	syn = 0x02
	rst = 0x04
	psh = 0x08
	ack = 0x10
	urg = 0x20
)

type ipv4Spec struct {
	ihl      uint8
	totalLen uint16
	mf       bool
	offset8  uint16
	proto    uint8
	payload  []byte
}

func buildIPv4(s ipv4Spec) []byte {
	ihl := s.ihl
	if ihl == 0 {
		ihl = 5
	}
	hdrLen := int(ihl) * 4
	// xsight.c parse_ip requires pkt >= sizeof(struct iphdr) = 20 bytes
	// BEFORE it reads IHL to classify the packet. An "IHL=4 invalid" attack
	// in practice is a 20+-byte frame where the header *claims* IHL=4 (buf[0]
	// low nibble = 4) — not a genuinely truncated frame, which xsight.c would
	// early-return on at the bounds check. Allocate max(hdrLen, 20) so the
	// parser reaches the IHL classification branch. src/dst IP bytes at
	// 12-19 are then always valid to write.
	bufLen := hdrLen + len(s.payload)
	if bufLen < 20 {
		bufLen = 20
	}
	buf := make([]byte, bufLen)
	buf[0] = 0x40 | (ihl & 0x0f)
	tot := s.totalLen
	if tot == 0 {
		tot = uint16(hdrLen + len(s.payload))
	}
	binary.BigEndian.PutUint16(buf[2:4], tot)
	var fragOff uint16
	if s.mf {
		fragOff |= 0x2000
	}
	fragOff |= s.offset8 & 0x1fff
	binary.BigEndian.PutUint16(buf[6:8], fragOff)
	buf[8] = 0x40
	buf[9] = s.proto
	binary.BigEndian.PutUint32(buf[12:16], 0x0a000001)
	binary.BigEndian.PutUint32(buf[16:20], 0x0a000002)
	copy(buf[hdrLen:], s.payload)
	return buf
}

func tcpHdrBytes(srcPort, dstPort uint16, flags, doff uint8) []byte {
	if doff == 0 {
		doff = 5
	}
	buf := make([]byte, 20)
	binary.BigEndian.PutUint16(buf[0:2], srcPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	buf[12] = (doff & 0x0f) << 4
	buf[13] = flags
	binary.BigEndian.PutUint16(buf[14:16], 0xffff)
	return buf
}

func udpHdrBytes(srcPort, dstPort uint16, payloadLen int) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint16(buf[0:2], srcPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	binary.BigEndian.PutUint16(buf[4:6], uint16(8+payloadLen))
	return buf
}

type ipv6Spec struct {
	nextHdr uint8
	payload []byte
}

func buildIPv6(s ipv6Spec) []byte {
	buf := make([]byte, 40+len(s.payload))
	buf[0] = 0x60
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(s.payload)))
	buf[6] = s.nextHdr
	buf[7] = 0x40
	buf[8] = 0x20
	buf[9] = 0x01
	buf[10] = 0x0d
	buf[11] = 0xb8
	buf[23] = 0x01
	buf[24] = 0x20
	buf[25] = 0x01
	buf[26] = 0x0d
	buf[27] = 0xb8
	buf[39] = 0x02
	copy(buf[40:], s.payload)
	return buf
}

func ipv6ExtHBH(nh uint8) []byte {
	buf := make([]byte, 8)
	buf[0] = nh
	buf[2] = 0x01
	buf[3] = 0x04
	return buf
}

func tcpPayloadN(n int) []byte {
	if n < 20 {
		return make([]byte, n)
	}
	b := make([]byte, n)
	binary.BigEndian.PutUint16(b[0:2], 12345)
	binary.BigEndian.PutUint16(b[2:4], 80)
	b[12] = 0x50
	b[13] = syn
	binary.BigEndian.PutUint16(b[14:16], 0xffff)
	return b
}

func udpPayloadN(n int) []byte {
	if n < 8 {
		return make([]byte, n)
	}
	b := make([]byte, n)
	binary.BigEndian.PutUint16(b[0:2], 12345)
	binary.BigEndian.PutUint16(b[2:4], 53)
	binary.BigEndian.PutUint16(b[4:6], uint16(n))
	return b
}

func hx(b []byte) string { return hex.EncodeToString(b) }

// allTestFixtures — mirrors testdata/generate.go. Keep synchronized.
//
// Decoder expectations derived by tracing xsight.c (DECODER_SWITCH lines
// 24-90 + parse_ip lines 296-392). Key rules to remember:
//   - tcp_syn requires SYN=1 AND ACK=0 (SYN+ACK hits only `tcp`)
//   - tcp_ack requires ACK=1 AND SYN=0 (xsight.c line 34)
//   - tcp_rst / tcp_fin just check their bit (independent of ACK/SYN)
//   - IHL<5 sets is_invalid + early-return, but l4_proto IS set before return,
//     so DECODER_SWITCH still fires the proto case (no sub-flags since
//     l4 header not parsed).
//   - tot_len<hdr_bytes sets is_invalid but parse CONTINUES; downstream
//     fragment / doff checks still run (guarded).
//   - TCP doff check is gated on !is_frag.
//   - ICMPv4 (proto=1) and ICMPv6 (proto=58 over IPv6) are merged into the
//     single "icmp" decoder (xsight.c lines 51-54).
//   - IPv6 xsight.c DOES NOT walk extension headers — any nexthdr != direct
//     TCP/UDP/ICMP/GRE/ESP is silent no-op (contract).
func allTestFixtures() []testFixture {
	var f []testFixture

	tcpFix := func(name string, flags uint8, decoders []string, note string) {
		f = append(f, testFixture{
			Name: name, Hex: hx(buildIPv4(ipv4Spec{proto: 6, payload: tcpHdrBytes(12345, 80, flags, 5)})),
			FrameType: "ip", ExpectedDecoders: decoders, Notes: note,
		})
	}
	tcpFix("tcp_syn_only", syn, []string{"tcp", "tcp_syn"}, "SYN=1 ACK=0")
	tcpFix("tcp_ack_pure", ack, []string{"tcp", "tcp_ack"}, "ACK=1 SYN=0 keepalive")
	tcpFix("tcp_ack_with_psh", ack|psh, []string{"tcp", "tcp_ack"}, "ACK+PSH — ACK flood main surface")
	tcpFix("tcp_ack_with_fin", ack|fin, []string{"tcp", "tcp_ack", "tcp_fin"}, "ACK+FIN normal close")
	tcpFix("tcp_syn_ack", syn|ack, []string{"tcp"}, "SYN+ACK: not tcp_syn (ACK set) not tcp_ack (SYN set)")
	tcpFix("tcp_rst_only", rst, []string{"tcp", "tcp_rst"}, "RST")
	tcpFix("tcp_rst_ack", rst|ack, []string{"tcp", "tcp_ack", "tcp_rst"}, "RST+ACK")
	tcpFix("tcp_fin_only", fin, []string{"tcp", "tcp_fin"}, "FIN")
	tcpFix("tcp_urg", urg|ack, []string{"tcp", "tcp_ack"}, "URG+ACK — URG is not a decoder; tcp_ack still matches")

	f = append(f,
		testFixture{
			Name: "udp_basic",
			Hex: hx(buildIPv4(ipv4Spec{proto: 17, payload: append(udpHdrBytes(12345, 53, 32), make([]byte, 32)...)})),
			FrameType: "ip", ExpectedDecoders: []string{"udp"}, Notes: "UDP 32B payload",
		},
		testFixture{
			Name: "icmp_echo",
			Hex: hx(buildIPv4(ipv4Spec{proto: 1, payload: []byte{8, 0, 0, 0, 0, 0, 0, 0}})),
			FrameType: "ip", ExpectedDecoders: []string{"icmp"}, Notes: "IPv4 ICMP Echo",
		},
		testFixture{
			Name: "icmpv6_echo",
			Hex: hx(buildIPv6(ipv6Spec{nextHdr: 58, payload: []byte{128, 0, 0, 0, 0, 0, 0, 0}})),
			FrameType: "ip", ExpectedDecoders: []string{"icmp"}, Notes: "IPv6 ICMPv6 Echo → merged icmp decoder",
		},
		testFixture{
			Name: "gre_basic",
			Hex: hx(buildIPv4(ipv4Spec{proto: 47, payload: make([]byte, 8)})), FrameType: "ip",
			ExpectedDecoders: []string{"gre"}, Notes: "IPv4 GRE proto=47",
		},
		testFixture{
			Name: "esp_basic",
			Hex: hx(buildIPv4(ipv4Spec{proto: 50, payload: make([]byte, 16)})), FrameType: "ip",
			ExpectedDecoders: []string{"esp"}, Notes: "IPv4 ESP proto=50",
		},
		testFixture{
			Name: "igmp_basic",
			Hex: hx(buildIPv4(ipv4Spec{proto: 2, payload: make([]byte, 8)})), FrameType: "ip",
			ExpectedDecoders: []string{"igmp"}, Notes: "IPv4 IGMP proto=2",
		},
		testFixture{
			Name: "ip_other_sctp",
			Hex: hx(buildIPv4(ipv4Spec{proto: 132, payload: make([]byte, 16)})), FrameType: "ip",
			ExpectedDecoders: []string{"ip_other"}, Notes: "IPv4 SCTP proto=132 catch-all bucket",
		},
	)

	// bad_fragment
	f = append(f,
		testFixture{
			Name: "pod_frag_end_65535",
			Hex: hx(buildIPv4(ipv4Spec{proto: 17, mf: false, offset8: 8191, payload: make([]byte, 7)})),
			FrameType: "ip", ExpectedDecoders: []string{"udp", "fragment"},
			ExpectedBadFrag: false,
			Notes:           "frag_end=65535 legal boundary",
		},
		testFixture{
			Name: "pod_frag_end_65536",
			Hex: hx(buildIPv4(ipv4Spec{proto: 17, mf: false, offset8: 8191, payload: make([]byte, 8)})),
			FrameType: "ip", ExpectedDecoders: []string{"udp", "fragment"},
			ExpectedBadFrag: true,
			Notes:           "frag_end=65536 PoD",
		},
		testFixture{
			Name: "tiny_first_frag_tcp_19",
			Hex: hx(buildIPv4(ipv4Spec{proto: 6, mf: true, offset8: 0, payload: tcpPayloadN(19)})),
			FrameType: "ip", ExpectedDecoders: []string{"tcp", "fragment"},
			ExpectedBadFrag: true,
			Notes:           "first TCP frag 19B < 20",
		},
		testFixture{
			Name: "tiny_first_frag_tcp_20",
			Hex: hx(buildIPv4(ipv4Spec{proto: 6, mf: true, offset8: 0, payload: tcpPayloadN(20)})),
			FrameType: "ip", ExpectedDecoders: []string{"tcp", "fragment"},
			ExpectedBadFrag: false,
			Notes:           "first TCP frag 20B legal",
		},
		testFixture{
			Name: "tiny_first_frag_udp_7",
			Hex: hx(buildIPv4(ipv4Spec{proto: 17, mf: true, offset8: 0, payload: udpPayloadN(7)})),
			FrameType: "ip", ExpectedDecoders: []string{"udp", "fragment"},
			ExpectedBadFrag: true,
			Notes:           "first UDP frag 7B < 8",
		},
		testFixture{
			Name: "tiny_first_frag_udp_8",
			Hex: hx(buildIPv4(ipv4Spec{proto: 17, mf: true, offset8: 0, payload: udpPayloadN(8)})),
			FrameType: "ip", ExpectedDecoders: []string{"udp", "fragment"},
			ExpectedBadFrag: false,
			Notes:           "first UDP frag 8B legal",
		},
		testFixture{
			Name: "tiny_frag_middle",
			Hex: hx(buildIPv4(ipv4Spec{proto: 6, mf: true, offset8: 185, payload: make([]byte, 10)})),
			FrameType: "ip", ExpectedDecoders: []string{"tcp", "fragment"},
			ExpectedBadFrag: false,
			Notes:           "middle frag — tiny check is first-frag only (MF && offset==0)",
		},
		testFixture{
			Name: "tiny_frag_last",
			Hex: hx(buildIPv4(ipv4Spec{proto: 6, mf: false, offset8: 185, payload: make([]byte, 10)})),
			FrameType: "ip", ExpectedDecoders: []string{"tcp", "fragment"},
			ExpectedBadFrag: false,
			Notes:           "last frag — MF=0 gate excludes tiny check",
		},
	)

	// invalid
	f = append(f,
		testFixture{
			Name: "invalid_ihl_4",
			Hex: hx(buildIPv4(ipv4Spec{ihl: 4, proto: 6, totalLen: 20, payload: make([]byte, 0)})),
			FrameType: "ip", ExpectedDecoders: []string{"tcp"}, ExpectedInvalid: true,
			Notes: "IHL=4 invalid + early-return; proto was set pre-return so tcp decoder still fires (no sub-flags, l4 hdr offset undefined)",
		},
		testFixture{
			Name: "invalid_ihl_5",
			Hex: hx(buildIPv4(ipv4Spec{ihl: 5, proto: 6, payload: tcpPayloadN(20)})),
			FrameType: "ip", ExpectedDecoders: []string{"tcp", "tcp_syn"}, ExpectedInvalid: false,
			Notes: "IHL=5 legal boundary",
		},
		testFixture{
			Name: "invalid_tot_len_short",
			Hex: hx(buildIPv4(ipv4Spec{ihl: 5, proto: 6, totalLen: 19, payload: make([]byte, 0)})),
			FrameType: "ip", ExpectedDecoders: []string{"tcp"}, ExpectedInvalid: true,
			Notes: "tot_len=19 < hdr 20 → invalid, continues; packet too short for TCP sub-flag parse so only tcp decoder",
		},
		testFixture{
			Name: "invalid_tot_len_equal",
			Hex: hx(buildIPv4(ipv4Spec{ihl: 5, proto: 6, totalLen: 20, payload: make([]byte, 0)})),
			FrameType: "ip", ExpectedDecoders: []string{"tcp"}, ExpectedInvalid: false,
			Notes: "tot_len=20 == hdr legal boundary; packet too short for TCP sub-flag parse",
		},
		testFixture{
			Name: "invalid_tcp_doff_4",
			Hex: hx(buildIPv4(ipv4Spec{proto: 6, payload: tcpHdrBytes(12345, 80, syn, 4)})),
			FrameType: "ip", ExpectedDecoders: []string{"tcp", "tcp_syn"}, ExpectedInvalid: true,
			Notes: "TCP doff=4 invalid; SYN flag still fires sub-decoder",
		},
		testFixture{
			Name: "invalid_tcp_doff_5",
			Hex: hx(buildIPv4(ipv4Spec{proto: 6, payload: tcpHdrBytes(12345, 80, syn, 5)})),
			FrameType: "ip", ExpectedDecoders: []string{"tcp", "tcp_syn"}, ExpectedInvalid: false,
			Notes: "TCP doff=5 legal",
		},
	)

	// IPv6
	f = append(f,
		testFixture{
			Name: "ipv6_tcp_doff_4",
			Hex: hx(buildIPv6(ipv6Spec{nextHdr: 6, payload: tcpHdrBytes(12345, 80, syn, 4)})),
			FrameType: "ip", ExpectedDecoders: []string{"tcp", "tcp_syn"}, ExpectedInvalid: true,
			Notes: "IPv6 nexthdr=TCP direct, doff=4",
		},
		testFixture{
			Name: "ipv6_tcp_doff_5",
			Hex: hx(buildIPv6(ipv6Spec{nextHdr: 6, payload: tcpHdrBytes(12345, 80, syn, 5)})),
			FrameType: "ip", ExpectedDecoders: []string{"tcp", "tcp_syn"}, ExpectedInvalid: false,
			Notes: "IPv6 nexthdr=TCP direct, doff=5 legal",
		},
		testFixture{
			Name: "ipv6_ext_hbh_tcp_doff_4",
			Hex: hx(buildIPv6(ipv6Spec{nextHdr: 0,
				payload: append(ipv6ExtHBH(6), tcpHdrBytes(12345, 80, syn, 4)...)})),
			FrameType: "ip", ExpectedDecoders: []string{}, ExpectedInvalid: false,
			Notes: "IPv6 HBH ext + TCP — v1.3 does NOT walk ext headers; tcp decoder AND doff check silently skipped (contract blindspot)",
		},
	)

	sort.SliceStable(f, func(i, j int) bool { return f[i].Name < f[j].Name })
	return f
}

// ---------------------------------------------------------------------------
// Go-parity parser for xsight.c parse_ip + DECODER_SWITCH
// ---------------------------------------------------------------------------

type parseResult struct {
	decoders      map[string]bool
	isBadFragment bool
	isInvalid     bool
}

func (p *parseResult) hit(name string) { p.decoders[name] = true }

func goParityParse(pkt []byte) parseResult {
	res := parseResult{decoders: map[string]bool{}}
	if len(pkt) < 1 {
		return res
	}
	ver := pkt[0] >> 4
	switch ver {
	case 4:
		parseIPv4(pkt, &res)
	case 6:
		parseIPv6(pkt, &res)
	}
	return res
}

// parseIPv4 mirrors xsight.c parse_ip (IPv4 branch) + DECODER_SWITCH dispatch.
// Call order matches xsight.c exactly so that test failures pinpoint semantic
// drift.
func parseIPv4(pkt []byte, r *parseResult) {
	if len(pkt) < 20 {
		return
	}
	ihl := pkt[0] & 0x0f
	proto := pkt[9] // xsight.c line 311: set before any early return
	totLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	fragOff := binary.BigEndian.Uint16(pkt[6:8])
	mf := fragOff&0x2000 != 0
	offset13 := fragOff & 0x1fff
	isFrag := mf || offset13 != 0

	var tcpFlags uint8

	// xsight.c lines 316-319: ihl<5 → invalid + early return.
	// DECODER_SWITCH still fires (proto already set, tcp_flags=0 gates out all
	// sub-flag counters naturally).
	if ihl < 5 {
		r.isInvalid = true
		dispatchDecoder(r, proto, tcpFlags, isFrag)
		return
	}

	hdrBytes := int(ihl) * 4

	// xsight.c lines 324-326: tot_len<hdr_bytes → invalid + CONTINUE.
	if totLen < hdrBytes {
		r.isInvalid = true
	}

	if isFrag {
		// xsight.c line 336: guarded payload.
		payload := 0
		if totLen > hdrBytes {
			payload = totLen - hdrBytes
		}
		fragEnd := uint32(offset13)*8 + uint32(payload)
		if fragEnd > 65535 {
			r.isBadFragment = true
		}
		if mf && offset13 == 0 {
			if proto == 6 && payload < 20 {
				r.isBadFragment = true
			}
			if proto == 17 && payload < 8 {
				r.isBadFragment = true
			}
		}
	}

	// xsight.c lines 353-362: TCP doff check gated on !is_frag.
	if proto == 6 && !isFrag {
		l4Off := hdrBytes
		if len(pkt) >= l4Off+14 {
			doff := pkt[l4Off+12] >> 4
			if doff < 5 {
				r.isInvalid = true
			}
			tcpFlags = pkt[l4Off+13]
		}
	}

	dispatchDecoder(r, proto, tcpFlags, isFrag)
}

// parseIPv6 mirrors xsight.c parse_ip (IPv6 branch). Does NOT walk extension
// headers (v1.3 design).
func parseIPv6(pkt []byte, r *parseResult) {
	if len(pkt) < 40 {
		return
	}
	next := pkt[6]
	l4Off := 40
	var tcpFlags uint8

	if next == 6 && len(pkt) >= l4Off+14 {
		doff := pkt[l4Off+12] >> 4
		if doff < 5 {
			r.isInvalid = true
		}
		tcpFlags = pkt[l4Off+13]
	}

	switch next {
	case 1, 58:
		r.hit("icmp")
	case 6:
		r.hit("tcp")
		if tcpFlags&syn != 0 && tcpFlags&ack == 0 {
			r.hit("tcp_syn")
		}
		if tcpFlags&ack != 0 && tcpFlags&syn == 0 {
			r.hit("tcp_ack")
		}
		if tcpFlags&rst != 0 {
			r.hit("tcp_rst")
		}
		if tcpFlags&fin != 0 {
			r.hit("tcp_fin")
		}
	case 17:
		r.hit("udp")
	case 47:
		r.hit("gre")
	case 50:
		r.hit("esp")
	}
	// HBH / Routing / Fragment / Destination / AH → silent skip (contract).
}

// dispatchDecoder mirrors xsight.c DECODER_SWITCH macro (lines 24-90).
func dispatchDecoder(r *parseResult, proto uint8, tcpFlags uint8, isFrag bool) {
	switch proto {
	case 6:
		r.hit("tcp")
		if tcpFlags&syn != 0 && tcpFlags&ack == 0 {
			r.hit("tcp_syn")
		}
		if tcpFlags&ack != 0 && tcpFlags&syn == 0 {
			r.hit("tcp_ack")
		}
		if tcpFlags&rst != 0 {
			r.hit("tcp_rst")
		}
		if tcpFlags&fin != 0 {
			r.hit("tcp_fin")
		}
	case 17:
		r.hit("udp")
	case 1, 58:
		// xsight.c lines 51-54 merge ICMP and ICMPV6. IPv4 path only hits
		// proto=1 here; IPv6 parsing path handled in parseIPv6 switch.
		r.hit("icmp")
	case 47:
		r.hit("gre")
	case 50:
		r.hit("esp")
	case 2:
		r.hit("igmp")
	default:
		r.hit("ip_other")
	}
	if isFrag {
		r.hit("fragment")
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestGoParityMatchesFixtures(t *testing.T) {
	fixtures := allTestFixtures()
	if len(fixtures) == 0 {
		t.Fatal("no fixtures — builder returned empty slice")
	}

	for _, fx := range fixtures {
		fx := fx
		t.Run(fx.Name, func(t *testing.T) {
			pkt, err := hex.DecodeString(fx.Hex)
			if err != nil {
				t.Fatalf("hex decode: %v", err)
			}
			got := goParityParse(pkt)

			want := map[string]bool{}
			for _, d := range fx.ExpectedDecoders {
				want[d] = true
			}

			if !reflect.DeepEqual(got.decoders, want) {
				t.Errorf("decoder mismatch\n want: %v\n  got: %v\n notes: %s",
					sortKeys(want), sortKeys(got.decoders), fx.Notes)
			}
			if got.isBadFragment != fx.ExpectedBadFrag {
				t.Errorf("is_bad_fragment mismatch: want=%v got=%v notes=%s",
					fx.ExpectedBadFrag, got.isBadFragment, fx.Notes)
			}
			if got.isInvalid != fx.ExpectedInvalid {
				t.Errorf("is_invalid mismatch: want=%v got=%v notes=%s",
					fx.ExpectedInvalid, got.isInvalid, fx.Notes)
			}
		})
	}
}

func TestFixtureNoDuplicateName(t *testing.T) {
	seen := map[string]bool{}
	for _, fx := range allTestFixtures() {
		if seen[fx.Name] {
			t.Errorf("duplicate fixture name: %s", fx.Name)
		}
		seen[fx.Name] = true
	}
}

func TestFixtureCoverageMatrix(t *testing.T) {
	required := []string{
		"tcp", "tcp_syn", "udp", "icmp", "fragment",
		"tcp_ack", "tcp_rst", "tcp_fin",
		"gre", "esp", "igmp", "ip_other",
	}
	positives := map[string]int{}
	for _, fx := range allTestFixtures() {
		for _, d := range fx.ExpectedDecoders {
			positives[d]++
		}
	}
	for _, d := range required {
		if positives[d] == 0 {
			t.Errorf("decoder %q has no positive fixture", d)
		}
	}
}

func TestFixtureJSONInSync(t *testing.T) {
	path := filepath.Join("testdata", "packet-fixtures.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("packet-fixtures.json missing (%v) — run: cd testdata && go run generate.go", err)
	}

	var on struct {
		Version  int `json:"version"`
		Fixtures []struct {
			Name                  string   `json:"name"`
			Hex                   string   `json:"hex"`
			ExpectedDecoders      []string `json:"expected_decoders"`
			ExpectedIsInvalid     bool     `json:"expected_is_invalid"`
			ExpectedIsBadFragment bool     `json:"expected_is_bad_fragment"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal(data, &on); err != nil {
		t.Fatalf("malformed JSON: %v", err)
	}

	if on.Version == 0 {
		t.Skip("packet-fixtures.json is still scaffold (version 0); run go generate")
	}

	got := allTestFixtures()
	if len(got) != len(on.Fixtures) {
		t.Fatalf("fixture count drift: in-memory=%d on-disk=%d — run go generate",
			len(got), len(on.Fixtures))
	}
	for i := range got {
		if got[i].Name != on.Fixtures[i].Name {
			t.Errorf("fixture[%d] name drift: in=%q disk=%q",
				i, got[i].Name, on.Fixtures[i].Name)
		}
		if got[i].Hex != on.Fixtures[i].Hex {
			t.Errorf("fixture %q hex drift — run go generate", got[i].Name)
		}
		wantD := map[string]bool{}
		for _, d := range got[i].ExpectedDecoders {
			wantD[d] = true
		}
		gotD := map[string]bool{}
		for _, d := range on.Fixtures[i].ExpectedDecoders {
			gotD[d] = true
		}
		if !reflect.DeepEqual(wantD, gotD) {
			t.Errorf("fixture %q decoder drift: want=%v disk=%v",
				got[i].Name, wantD, gotD)
		}
		if got[i].ExpectedInvalid != on.Fixtures[i].ExpectedIsInvalid {
			t.Errorf("fixture %q invalid flag drift", got[i].Name)
		}
		if got[i].ExpectedBadFrag != on.Fixtures[i].ExpectedIsBadFragment {
			t.Errorf("fixture %q bad_fragment flag drift", got[i].Name)
		}
	}
}

func sortKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
