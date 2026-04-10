package flow

import (
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/node/internal/pb"
)

func newTestAggregator(prefixes []string) *FlowAggregator {
	trie := NewPrefixTrie()
	trie.Rebuild(prefixes)
	return NewFlowAggregator(trie)
}

// flushNow is a test helper that flushes the current-second bucket.
// Duration=0 records (sFlow) are placed in the current-second bucket,
// so tests without time spreading should use this.
func flushNow(agg *FlowAggregator, nodeID, iface string) *pb.StatsReport {
	return agg.FlushAt(time.Now().Unix(), nodeID, iface, 1)
}

func TestAggregatorInboundMatch(t *testing.T) {
	agg := newTestAggregator([]string{"10.0.0.0/24"})
	source := &Source{SampleMode: "none"} // rate=1

	rec := FlowRecord{
		SrcIP:    net.ParseIP("1.2.3.4"),
		DstIP:    net.ParseIP("10.0.0.50"),
		Protocol: 6,
		Packets:  100,
		Bytes:    5000,
	}
	agg.Add(rec, source)

	msg := flushNow(agg, "test", "flow")
	if msg == nil {
		t.Fatal("expected non-nil report")
	}
	if len(msg.IpStats) != 1 {
		t.Errorf("expected 1 IP stat, got %d", len(msg.IpStats))
	}
	if len(msg.PrefixStats) != 1 {
		t.Errorf("expected 1 prefix stat, got %d", len(msg.PrefixStats))
	}
	if msg.GlobalStats.MatchedPkts != 100 {
		t.Errorf("expected matched_pkts=100, got %d", msg.GlobalStats.MatchedPkts)
	}
}

func TestAggregatorOutboundMatch(t *testing.T) {
	agg := newTestAggregator([]string{"10.0.0.0/24"})
	source := &Source{SampleMode: "none"}

	rec := FlowRecord{
		SrcIP:    net.ParseIP("10.0.0.50"), // src matches → outbound
		DstIP:    net.ParseIP("8.8.8.8"),   // dst doesn't match
		Protocol: 17,
		Packets:  50,
		Bytes:    2500,
	}
	agg.Add(rec, source)

	msg := flushNow(agg, "test", "flow")
	if msg == nil {
		t.Fatal("expected non-nil report")
	}
	if len(msg.SrcIpStats) != 1 {
		t.Errorf("expected 1 src IP stat, got %d", len(msg.SrcIpStats))
	}
	if msg.GlobalStats.SrcMatchedPkts != 50 {
		t.Errorf("expected src_matched_pkts=50, got %d", msg.GlobalStats.SrcMatchedPkts)
	}
	// Inbound should be empty
	if len(msg.IpStats) != 0 {
		t.Errorf("expected 0 inbound IP stats, got %d", len(msg.IpStats))
	}
}

func TestAggregatorInternalToInternalDualCount(t *testing.T) {
	agg := newTestAggregator([]string{"10.0.0.0/24", "10.0.1.0/24"})
	source := &Source{SampleMode: "none"}

	rec := FlowRecord{
		SrcIP:    net.ParseIP("10.0.0.50"), // src matches → outbound
		DstIP:    net.ParseIP("10.0.1.50"), // dst matches → inbound
		Protocol: 6,
		Packets:  100,
		Bytes:    5000,
	}
	agg.Add(rec, source)

	msg := flushNow(agg, "test", "flow")
	if msg == nil {
		t.Fatal("expected non-nil report")
	}
	// Both directions should have data
	if len(msg.IpStats) != 1 {
		t.Errorf("expected 1 inbound IP, got %d", len(msg.IpStats))
	}
	if len(msg.SrcIpStats) != 1 {
		t.Errorf("expected 1 outbound IP, got %d", len(msg.SrcIpStats))
	}
	if msg.GlobalStats.MatchedPkts != 100 {
		t.Errorf("expected inbound matched=100, got %d", msg.GlobalStats.MatchedPkts)
	}
	if msg.GlobalStats.SrcMatchedPkts != 100 {
		t.Errorf("expected outbound matched=100, got %d", msg.GlobalStats.SrcMatchedPkts)
	}
}

func TestAggregatorSampleRateExpansion(t *testing.T) {
	agg := newTestAggregator([]string{"10.0.0.0/24"})
	source := &Source{SampleMode: "force", SampleRate: 1000}

	rec := FlowRecord{
		SrcIP:    net.ParseIP("1.2.3.4"),
		DstIP:    net.ParseIP("10.0.0.50"),
		Protocol: 17,
		Packets:  5,
		Bytes:    500,
	}
	agg.Add(rec, source)

	msg := flushNow(agg, "test", "flow")
	if msg == nil {
		t.Fatal("expected non-nil report")
	}
	// 5 packets × 1000 rate = 5000
	if msg.GlobalStats.MatchedPkts != 5000 {
		t.Errorf("expected 5000 (5×1000), got %d", msg.GlobalStats.MatchedPkts)
	}
}

func TestAggregatorNoMatchNoFlush(t *testing.T) {
	agg := newTestAggregator([]string{"10.0.0.0/24"})
	source := &Source{SampleMode: "none"}

	rec := FlowRecord{
		SrcIP:    net.ParseIP("1.2.3.4"),
		DstIP:    net.ParseIP("8.8.8.8"), // no match
		Protocol: 6,
		Packets:  100,
		Bytes:    5000,
	}
	agg.Add(rec, source)

	msg := flushNow(agg, "test", "flow")
	if msg != nil {
		t.Error("expected nil report when no prefix matches")
	}
}

func TestAggregatorTopFlowsOnlyMatched(t *testing.T) {
	agg := newTestAggregator([]string{"10.0.0.0/24"})
	source := &Source{SampleMode: "none"}

	// Matched flow
	agg.Add(FlowRecord{
		SrcIP: net.ParseIP("1.1.1.1"), DstIP: net.ParseIP("10.0.0.1"),
		Protocol: 6, Packets: 100, Bytes: 5000,
	}, source)
	// Unmatched flow
	agg.Add(FlowRecord{
		SrcIP: net.ParseIP("2.2.2.2"), DstIP: net.ParseIP("8.8.8.8"),
		Protocol: 17, Packets: 999, Bytes: 99999,
	}, source)

	msg := flushNow(agg, "test", "flow")
	if msg == nil {
		t.Fatal("expected non-nil report")
	}
	// Only matched flow should be in top_flows
	if len(msg.TopFlows) != 1 {
		t.Errorf("expected 1 top flow (matched only), got %d", len(msg.TopFlows))
	}
}

func TestBytesToIPv4(t *testing.T) {
	b := [16]byte{}
	b[12] = 10
	b[13] = 0
	b[14] = 0
	b[15] = 1
	ip := bytesToIP(b)
	if ip.String() != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", ip.String())
	}
}

func TestBytesToIPv6(t *testing.T) {
	b := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	ip := bytesToIP(b)
	if ip.String() != "2001:db8::1" {
		t.Errorf("expected 2001:db8::1, got %s", ip.String())
	}
}

// ============================================================
// Time spreading tests
// ============================================================

func TestAggregatorTimeSpreadEven(t *testing.T) {
	agg := newTestAggregator([]string{"10.0.0.0/24"})
	source := &Source{SampleMode: "none"}

	duration := 30

	rec := FlowRecord{
		SrcIP:    net.ParseIP("1.2.3.4"),
		DstIP:    net.ParseIP("10.0.0.50"),
		Protocol: 6,
		Packets:  3000,
		Bytes:    150000,
		Duration: duration,
	}
	agg.Add(rec, source)

	// Buckets spread into future: [now, now+duration-1]
	now := time.Now().Unix()
	expectedPerSec := uint64(3000) / uint64(duration)
	totalPkts := uint64(0)

	for i := 0; i < duration; i++ {
		ts := now + int64(i)
		msg := agg.FlushAt(ts, "test", "flow", 1)
		if msg != nil {
			totalPkts += msg.GlobalStats.MatchedPkts
			if msg.GlobalStats.MatchedPkts < expectedPerSec || msg.GlobalStats.MatchedPkts > expectedPerSec+1 {
				t.Errorf("ts=%d: expected ~%d pkts, got %d", ts, expectedPerSec, msg.GlobalStats.MatchedPkts)
			}
		}
	}

	if totalPkts != 3000 {
		t.Errorf("total across all buckets: expected 3000, got %d", totalPkts)
	}
}

func TestAggregatorTimeSpreadRemainder(t *testing.T) {
	agg := newTestAggregator([]string{"10.0.0.0/24"})
	source := &Source{SampleMode: "none"}

	rec := FlowRecord{
		SrcIP:    net.ParseIP("1.2.3.4"),
		DstIP:    net.ParseIP("10.0.0.50"),
		Protocol: 17,
		Packets:  33, // 33 / 10 = 3 base, 3 remainder → first 3 buckets get 4, rest get 3
		Bytes:    1000,
		Duration: 10,
	}
	agg.Add(rec, source)

	now := time.Now().Unix()
	totalPkts := uint64(0)
	got4 := 0
	got3 := 0

	for i := 0; i < 10; i++ {
		ts := now + int64(i) // [now, now+9]
		msg := agg.FlushAt(ts, "test", "flow", 1)
		if msg != nil {
			p := msg.GlobalStats.MatchedPkts
			totalPkts += p
			if p == 4 {
				got4++
			} else if p == 3 {
				got3++
			} else {
				t.Errorf("bucket %d: unexpected pkts=%d", i, p)
			}
		}
	}

	if totalPkts != 33 {
		t.Errorf("total: expected 33, got %d", totalPkts)
	}
	if got4 != 3 {
		t.Errorf("expected 3 buckets with 4 pkts, got %d", got4)
	}
	if got3 != 7 {
		t.Errorf("expected 7 buckets with 3 pkts, got %d", got3)
	}
}

func TestAggregatorTimeSpreadClampMaxDuration(t *testing.T) {
	agg := newTestAggregator([]string{"10.0.0.0/24"})
	source := &Source{SampleMode: "none"}

	rec := FlowRecord{
		SrcIP:    net.ParseIP("1.2.3.4"),
		DstIP:    net.ParseIP("10.0.0.50"),
		Protocol: 6,
		Packets:  600,
		Bytes:    60000,
		Duration: 600, // > maxSpreadDuration(300), will be clamped
	}
	agg.Add(rec, source)

	// Clamped to 300 buckets at [now, now+299]
	now := time.Now().Unix()
	totalPkts := uint64(0)
	for i := 0; i < 300; i++ {
		ts := now + int64(i)
		msg := agg.FlushAt(ts, "test", "flow", 1)
		if msg != nil {
			totalPkts += msg.GlobalStats.MatchedPkts
		}
	}

	if totalPkts != 600 {
		t.Errorf("total: expected 600, got %d", totalPkts)
	}
}

func TestAggregatorTimeSpreadZeroDurationFallback(t *testing.T) {
	agg := newTestAggregator([]string{"10.0.0.0/24"})
	source := &Source{SampleMode: "none"}

	// sFlow: no time fields
	rec := FlowRecord{
		SrcIP:    net.ParseIP("1.2.3.4"),
		DstIP:    net.ParseIP("10.0.0.50"),
		Protocol: 6,
		Packets:  100,
		Bytes:    5000,
	}
	agg.Add(rec, source)

	// Should be in current-second bucket
	msg := flushNow(agg, "test", "flow")
	if msg == nil {
		t.Fatal("expected non-nil report for sFlow (Duration=0)")
	}
	if msg.GlobalStats.MatchedPkts != 100 {
		t.Errorf("expected 100 pkts in current bucket, got %d", msg.GlobalStats.MatchedPkts)
	}
}

func TestAggregatorTimeSpreadDurationZeroOrNegative(t *testing.T) {
	agg := newTestAggregator([]string{"10.0.0.0/24"})
	source := &Source{SampleMode: "none"}

	// Duration=0 (listener sets this when end < start) → arrival-time bucket
	rec := FlowRecord{
		SrcIP:    net.ParseIP("1.2.3.4"),
		DstIP:    net.ParseIP("10.0.0.50"),
		Protocol: 6,
		Packets:  100,
		Bytes:    5000,
		Duration: 0,
	}
	agg.Add(rec, source)

	msg := flushNow(agg, "test", "flow")
	if msg == nil {
		t.Fatal("expected non-nil report")
	}
	if msg.GlobalStats.MatchedPkts != 100 {
		t.Errorf("expected 100 in arrival bucket, got %d", msg.GlobalStats.MatchedPkts)
	}
}

func TestAggregatorTimeSpreadBothDirections(t *testing.T) {
	agg := newTestAggregator([]string{"10.0.0.0/24", "10.0.1.0/24"})
	source := &Source{SampleMode: "none"}

	rec := FlowRecord{
		SrcIP:    net.ParseIP("10.0.0.50"), // outbound
		DstIP:    net.ParseIP("10.0.1.50"), // inbound
		Protocol: 6,
		Packets:  500,
		Bytes:    25000,
		Duration: 5,
	}
	agg.Add(rec, source)

	now := time.Now().Unix()
	totalIn := uint64(0)
	totalOut := uint64(0)
	for i := 0; i < 5; i++ {
		ts := now + int64(i) // [now, now+4]
		msg := agg.FlushAt(ts, "test", "flow", 1)
		if msg != nil {
			totalIn += msg.GlobalStats.MatchedPkts
			totalOut += msg.GlobalStats.SrcMatchedPkts
		}
	}

	if totalIn != 500 {
		t.Errorf("inbound total: expected 500, got %d", totalIn)
	}
	if totalOut != 500 {
		t.Errorf("outbound total: expected 500, got %d", totalOut)
	}
}

// ============================================================
// collectHealth / source online-offline tests
// ============================================================

func makeTestListener(sources map[string]*Source) *Listener {
	return &Listener{
		ListenAddr:   ":2055",
		ProtocolMode: "auto",
		sources:      sources,
	}
}

func TestCollectHealthSourceActive(t *testing.T) {
	agg := newTestAggregator([]string{"10.0.0.0/24"})
	s := &Source{
		DeviceIP:   netip.MustParseAddr("10.0.0.1"),
		SampleMode: "auto",
	}
	s.LastSeenAt.Store(time.Now().Unix()) // just seen
	s.RecordsReceived.Store(100)

	l := makeTestListener(map[string]*Source{"10.0.0.1": s})
	agg.SetListeners([]*Listener{l})

	health := agg.collectHealth()
	if health == nil {
		t.Fatal("expected non-nil health")
	}

	var parsed struct {
		Sources []struct {
			DeviceIP string `json:"device_ip"`
			Active   bool   `json:"active"`
		} `json:"sources"`
	}
	if err := json.Unmarshal([]byte(health.Message), &parsed); err != nil {
		t.Fatalf("failed to parse health message JSON: %v", err)
	}
	if len(parsed.Sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(parsed.Sources))
	}
	if !parsed.Sources[0].Active {
		t.Error("expected source to be active (just seen)")
	}
}

func TestCollectHealthSourceOffline(t *testing.T) {
	agg := newTestAggregator([]string{"10.0.0.0/24"})
	s := &Source{
		DeviceIP:   netip.MustParseAddr("10.0.0.1"),
		SampleMode: "auto",
	}
	s.LastSeenAt.Store(time.Now().Unix() - 120) // 120s ago > 60s timeout
	s.RecordsReceived.Store(50)

	l := makeTestListener(map[string]*Source{"10.0.0.1": s})
	agg.SetListeners([]*Listener{l})

	health := agg.collectHealth()
	var parsed struct {
		Sources []struct {
			Active bool `json:"active"`
		} `json:"sources"`
	}
	if err := json.Unmarshal([]byte(health.Message), &parsed); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if parsed.Sources[0].Active {
		t.Error("expected source to be offline (>60s since last seen)")
	}
}

func TestCollectHealthSourceNeverSeen(t *testing.T) {
	agg := newTestAggregator([]string{"10.0.0.0/24"})
	s := &Source{
		DeviceIP:   netip.MustParseAddr("10.0.0.1"),
		SampleMode: "auto",
	}
	// LastSeenAt = 0 (never seen)

	l := makeTestListener(map[string]*Source{"10.0.0.1": s})
	agg.SetListeners([]*Listener{l})

	health := agg.collectHealth()
	var parsed struct {
		Sources []struct {
			Active bool `json:"active"`
		} `json:"sources"`
	}
	if err := json.Unmarshal([]byte(health.Message), &parsed); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if parsed.Sources[0].Active {
		t.Error("expected source to be offline (never seen)")
	}
}

func TestCollectHealthNoListeners(t *testing.T) {
	agg := newTestAggregator([]string{"10.0.0.0/24"})
	// No listeners set — should still emit JSON with empty sources
	health := agg.collectHealth()
	var parsed struct {
		Sources []interface{} `json:"sources"`
	}
	if err := json.Unmarshal([]byte(health.Message), &parsed); err != nil {
		t.Fatalf("expected valid JSON, got %q: %v", health.Message, err)
	}
	if len(parsed.Sources) != 0 {
		t.Errorf("expected 0 sources, got %d", len(parsed.Sources))
	}
}

// ============================================================
// TemplateMisses + collectMetrics mapping tests
// ============================================================

func TestCollectMetricsTemplateMisses(t *testing.T) {
	agg := newTestAggregator([]string{"10.0.0.0/24"})
	l := makeTestListener(map[string]*Source{})
	l.TemplateMisses.Store(42)
	l.DecodeErrors.Store(3)
	l.UnknownExporter.Store(7)

	agg.SetListeners([]*Listener{l})

	// Flush to get metrics (need at least one record so Flush isn't nil)
	source := &Source{SampleMode: "none"}
	agg.Add(FlowRecord{
		SrcIP: net.ParseIP("1.2.3.4"), DstIP: net.ParseIP("10.0.0.1"),
		Protocol: 6, Packets: 1, Bytes: 100,
	}, source)

	msg := flushNow(agg, "test", "flow")
	if msg == nil {
		t.Fatal("expected non-nil report")
	}
	sm := msg.SamplingMetrics
	if sm == nil {
		t.Fatal("expected non-nil SamplingMetrics")
	}
	// Proto mapping: DroppedKernel = TemplateMisses
	if sm.DroppedKernel != 42 {
		t.Errorf("DroppedKernel (template_misses): expected 42, got %d", sm.DroppedKernel)
	}
	if sm.DecodeError != 3 {
		t.Errorf("DecodeError: expected 3, got %d", sm.DecodeError)
	}
	// DroppedUser = UnknownExporter
	if sm.DroppedUser != 7 {
		t.Errorf("DroppedUser (unknown_exporter): expected 7, got %d", sm.DroppedUser)
	}
}
