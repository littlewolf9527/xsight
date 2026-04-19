package threshold

import (
	"net"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/engine"
	"github.com/littlewolf9527/xsight/controller/internal/store/ring"
	"github.com/littlewolf9527/xsight/shared/decoder"
)

// TestCheckRuleParity verifies checkRule and checkRuleStr produce identical
// breach decisions and actual values for the same inputs.
func TestCheckRuleParity(t *testing.T) {
	dp := ring.DataPoint{
		Time: time.Now(),
		PPS:  50000,
		BPS:  400000000,
		DecoderPPS: [decoder.MaxDecoders]int32{
			30000, // TCP
			5000,  // TCPSyn
			15000, // UDP
			2000,  // ICMP
			100,   // Frag
		},
		DecoderBPS: [decoder.MaxDecoders]int64{
			240000000, // TCP BPS
			40000000,  // TCPSyn BPS
			120000000, // UDP BPS
			16000000,  // ICMP BPS
			800000,    // Frag BPS
		},
	}

	rules := []engine.ResolvedThreshold{
		{ThresholdID: 1, PrefixID: 10, Decoder: "ip", Unit: "pps", Comparison: "over", Value: 40000, Domain: "internal_ip"},
		{ThresholdID: 2, PrefixID: 10, Decoder: "ip", Unit: "pps", Comparison: "over", Value: 60000, Domain: "internal_ip"},
		{ThresholdID: 3, PrefixID: 10, Decoder: "tcp", Unit: "pps", Comparison: "over", Value: 25000, Domain: "internal_ip"},
		{ThresholdID: 4, PrefixID: 10, Decoder: "tcp", Unit: "pps", Comparison: "under", Value: 50000, Domain: "internal_ip"},
		{ThresholdID: 5, PrefixID: 10, Decoder: "udp", Unit: "pps", Comparison: "over", Value: 20000, Domain: "internal_ip"},
		{ThresholdID: 6, PrefixID: 10, Decoder: "ip", Unit: "bps", Comparison: "over", Value: 300000000, Domain: "internal_ip"},
		{ThresholdID: 7, PrefixID: 10, Decoder: "tcp", Unit: "bps", Comparison: "over", Value: 100, Domain: "internal_ip"}, // now supported: per-decoder bps
		{ThresholdID: 8, PrefixID: 10, Decoder: "icmp", Unit: "pps", Comparison: "over", Value: 1000, Domain: "internal_ip"},
		{ThresholdID: 9, PrefixID: 10, Decoder: "fragment", Unit: "pps", Comparison: "over", Value: 200, Domain: "internal_ip"},
		{ThresholdID: 10, PrefixID: 10, Decoder: "unknown", Unit: "pps", Comparison: "over", Value: 0, Domain: "internal_ip"},
		{ThresholdID: 11, PrefixID: 10, Decoder: "tcp", Unit: "pct", Comparison: "over", Value: 50, Domain: "internal_ip"},    // 30000/50000*100=60% > 50%
		{ThresholdID: 12, PrefixID: 10, Decoder: "udp", Unit: "pct", Comparison: "over", Value: 40, Domain: "internal_ip"},    // 15000/50000*100=30% < 40%
	}

	ip := net.ParseIP("10.0.0.1")
	ipStr := "10.0.0.1"
	prefix := "10.0.0.0/24"
	nodeID := "test-node"

	for _, r := range rules {
		got1 := checkRule(r, dp, prefix, ip, nodeID)
		got2 := checkRuleStr(r, dp, prefix, ipStr, nodeID)

		if (got1 == nil) != (got2 == nil) {
			t.Errorf("rule %d (%s/%s/%s): checkRule breached=%v, checkRuleStr breached=%v",
				r.ThresholdID, r.Decoder, r.Unit, r.Comparison, got1 != nil, got2 != nil)
			continue
		}
		if got1 == nil {
			continue
		}
		if got1.Actual != got2.Actual {
			t.Errorf("rule %d: actual mismatch: checkRule=%d, checkRuleStr=%d",
				r.ThresholdID, got1.Actual, got2.Actual)
		}
		if got1.ThresholdID != got2.ThresholdID {
			t.Errorf("rule %d: ThresholdID mismatch", r.ThresholdID)
		}
		if got1.Decoder != got2.Decoder {
			t.Errorf("rule %d: Decoder mismatch", r.ThresholdID)
		}
	}
}

// TestEvaluateRule verifies the shared evaluation logic directly.
func TestEvaluateRule(t *testing.T) {
	dp := ring.DataPoint{
		PPS:        1000,
		BPS:        8000,
		DecoderPPS: [decoder.MaxDecoders]int32{500, 0, 300},  // TCP=500, UDP=300
		DecoderBPS: [decoder.MaxDecoders]int64{4000, 0, 2400}, // TCP=4000, UDP=2400
	}

	tests := []struct {
		name     string
		rule     engine.ResolvedThreshold
		wantVal  int64
		wantHit  bool
	}{
		{"ip pps over hit", engine.ResolvedThreshold{Decoder: "ip", Unit: "pps", Comparison: "over", Value: 500}, 1000, true},
		{"ip pps over miss", engine.ResolvedThreshold{Decoder: "ip", Unit: "pps", Comparison: "over", Value: 2000}, 1000, false},
		{"ip bps over hit", engine.ResolvedThreshold{Decoder: "ip", Unit: "bps", Comparison: "over", Value: 5000}, 8000, true},
		{"tcp pps under hit", engine.ResolvedThreshold{Decoder: "tcp", Unit: "pps", Comparison: "under", Value: 600}, 500, true},
		{"udp pps over miss", engine.ResolvedThreshold{Decoder: "udp", Unit: "pps", Comparison: "over", Value: 500}, 300, false},
		{"tcp bps over hit", engine.ResolvedThreshold{Decoder: "tcp", Unit: "bps", Comparison: "over", Value: 3000}, 4000, true},   // DecoderBPS[TCP]=4000
		{"tcp bps over miss", engine.ResolvedThreshold{Decoder: "tcp", Unit: "bps", Comparison: "over", Value: 5000}, 4000, false}, // 4000 < 5000
		{"unknown decoder skip", engine.ResolvedThreshold{Decoder: "xyz", Unit: "pps", Comparison: "over", Value: 0}, -1, false},
		// Percentage threshold tests
		{"tcp pct over hit", engine.ResolvedThreshold{Decoder: "tcp", Unit: "pct", Comparison: "over", Value: 40}, 50, true},   // 500/1000*100 = 50% > 40%
		{"tcp pct over miss", engine.ResolvedThreshold{Decoder: "tcp", Unit: "pct", Comparison: "over", Value: 60}, 50, false},  // 50% < 60%
		{"udp pct over hit", engine.ResolvedThreshold{Decoder: "udp", Unit: "pct", Comparison: "over", Value: 20}, 30, true},    // 300/1000*100 = 30% > 20%
		{"udp pct under hit", engine.ResolvedThreshold{Decoder: "udp", Unit: "pct", Comparison: "under", Value: 50}, 30, true},  // 30% < 50%
		{"ip pct always 100", engine.ResolvedThreshold{Decoder: "ip", Unit: "pct", Comparison: "over", Value: 99}, 100, true},   // ip pct = 1000/1000*100 = 100%
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, hit := evaluateRule(tt.rule, dp)
			if val != tt.wantVal {
				t.Errorf("actual = %d, want %d", val, tt.wantVal)
			}
			if hit != tt.wantHit {
				t.Errorf("breached = %v, want %v", hit, tt.wantHit)
			}
		})
	}
}

// TestEvaluateRule_V13Decoders asserts the new v1.3 Phase 1b decoders (TCP ACK/RST/FIN
// and GRE/ESP/IGMP/ip_other) route through evaluateRule correctly via decoder.Index().
// No detector-side changes were needed for v1.3 Phase 1b thanks to the v2.9.0 array
// refactor — this test confirms that invariant still holds.
func TestEvaluateRule_V13Decoders(t *testing.T) {
	// Populate DecoderPPS / DecoderBPS at the exact v1.3 slot indices.
	var dp ring.DataPoint
	dp.DecoderPPS[decoder.TCPAck] = 11000
	dp.DecoderPPS[decoder.TCPRst] = 7000
	dp.DecoderPPS[decoder.TCPFin] = 3000
	dp.DecoderPPS[decoder.GRE] = 1500
	dp.DecoderPPS[decoder.ESP] = 200
	dp.DecoderPPS[decoder.IGMP] = 50
	dp.DecoderPPS[decoder.IPOther] = 900
	dp.DecoderPPS[decoder.BadFragment] = 400
	dp.DecoderPPS[decoder.Invalid] = 250
	dp.DecoderBPS[decoder.TCPAck] = 11_000_000
	dp.DecoderBPS[decoder.GRE] = 12_000_000
	dp.DecoderBPS[decoder.BadFragment] = 320_000
	dp.DecoderBPS[decoder.Invalid] = 10_000

	tests := []struct {
		name    string
		rule    engine.ResolvedThreshold
		wantVal int64
		wantHit bool
	}{
		// ACK flood: TCP ACK pps > threshold
		{"tcp_ack pps over hit", engine.ResolvedThreshold{Decoder: "tcp_ack", Unit: "pps", Comparison: "over", Value: 10000}, 11000, true},
		{"tcp_ack pps over miss", engine.ResolvedThreshold{Decoder: "tcp_ack", Unit: "pps", Comparison: "over", Value: 20000}, 11000, false},
		{"tcp_ack bps over hit", engine.ResolvedThreshold{Decoder: "tcp_ack", Unit: "bps", Comparison: "over", Value: 10_000_000}, 11_000_000, true},
		// RST flood
		{"tcp_rst pps over hit", engine.ResolvedThreshold{Decoder: "tcp_rst", Unit: "pps", Comparison: "over", Value: 5000}, 7000, true},
		// FIN flood / scan
		{"tcp_fin pps over hit", engine.ResolvedThreshold{Decoder: "tcp_fin", Unit: "pps", Comparison: "over", Value: 1000}, 3000, true},
		{"tcp_fin pps over miss", engine.ResolvedThreshold{Decoder: "tcp_fin", Unit: "pps", Comparison: "over", Value: 5000}, 3000, false},
		// Non-TCP/UDP/ICMP protocols
		{"gre pps over hit", engine.ResolvedThreshold{Decoder: "gre", Unit: "pps", Comparison: "over", Value: 1000}, 1500, true},
		{"gre bps over hit", engine.ResolvedThreshold{Decoder: "gre", Unit: "bps", Comparison: "over", Value: 10_000_000}, 12_000_000, true},
		{"esp pps over miss", engine.ResolvedThreshold{Decoder: "esp", Unit: "pps", Comparison: "over", Value: 300}, 200, false},
		{"igmp pps under hit", engine.ResolvedThreshold{Decoder: "igmp", Unit: "pps", Comparison: "under", Value: 100}, 50, true},
		{"ip_other pps over hit", engine.ResolvedThreshold{Decoder: "ip_other", Unit: "pps", Comparison: "over", Value: 500}, 900, true},
		// v1.3 Phase 1b (追加): bad_fragment + invalid decoder threshold matches
		{"bad_fragment pps over hit", engine.ResolvedThreshold{Decoder: "bad_fragment", Unit: "pps", Comparison: "over", Value: 100}, 400, true},
		{"bad_fragment pps over miss", engine.ResolvedThreshold{Decoder: "bad_fragment", Unit: "pps", Comparison: "over", Value: 500}, 400, false},
		{"bad_fragment bps over hit", engine.ResolvedThreshold{Decoder: "bad_fragment", Unit: "bps", Comparison: "over", Value: 300_000}, 320_000, true},
		{"invalid pps over hit", engine.ResolvedThreshold{Decoder: "invalid", Unit: "pps", Comparison: "over", Value: 100}, 250, true},
		{"invalid pps under hit", engine.ResolvedThreshold{Decoder: "invalid", Unit: "pps", Comparison: "under", Value: 300}, 250, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, hit := evaluateRule(tt.rule, dp)
			if val != tt.wantVal {
				t.Errorf("actual = %d, want %d", val, tt.wantVal)
			}
			if hit != tt.wantHit {
				t.Errorf("breached = %v, want %v", hit, tt.wantHit)
			}
		})
	}
}
