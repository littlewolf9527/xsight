package ingestion

import (
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store/ring"
	"github.com/littlewolf9527/xsight/shared/decoder"
	pb "github.com/littlewolf9527/xsight/controller/internal/pb"
)

// TestOldNodeFixedFields verifies that a StatsReport using deprecated fixed fields
// (old node format) produces the same ring DataPoint as the new decoder_counts format.
func TestOldNodeFixedFields(t *testing.T) {
	rings := ring.New(ring.DefaultLimits())
	w := NewStatsWriter(rings)

	// Old node format: fixed fields 7-11, no decoder_counts
	oldReport := &pb.StatsReport{
		NodeId:             "test-node",
		UpstreamSampleRate: 1,
		Timestamp:          time.Now().Unix(),
		PrefixStats: []*pb.PrefixStatsMsg{
			{
				Prefix:      []byte{10, 0, 0, 0},
				PrefixLen:   24,
				PktCount:    1000,
				ByteCount:   100000,
				ActiveIps:   5,
				TcpCount:    500,
				TcpSynCount: 100,
				UdpCount:    300,
				IcmpCount:   50,
				FragCount:   10,
				// DecoderCounts is nil (old node)
			},
		},
	}

	w.HandleStats("test-node", oldReport)

	pr := rings.GetPrefixRing("test-node", "10.0.0.0/24")
	if pr == nil {
		t.Fatal("expected prefix ring for 10.0.0.0/24")
	}
	dp, ok := pr.LatestOne(5 * time.Second)
	if !ok {
		t.Fatal("expected data point")
	}

	// Verify fallback correctly populated DecoderPPS from old fixed fields
	if dp.DecoderPPS[decoder.TCP] != 500 {
		t.Errorf("TCP PPS = %d, want 500", dp.DecoderPPS[decoder.TCP])
	}
	if dp.DecoderPPS[decoder.TCPSyn] != 100 {
		t.Errorf("TCPSyn PPS = %d, want 100", dp.DecoderPPS[decoder.TCPSyn])
	}
	if dp.DecoderPPS[decoder.UDP] != 300 {
		t.Errorf("UDP PPS = %d, want 300", dp.DecoderPPS[decoder.UDP])
	}
	if dp.DecoderPPS[decoder.ICMP] != 50 {
		t.Errorf("ICMP PPS = %d, want 50", dp.DecoderPPS[decoder.ICMP])
	}
	if dp.DecoderPPS[decoder.Frag] != 10 {
		t.Errorf("Frag PPS = %d, want 10", dp.DecoderPPS[decoder.Frag])
	}
}

// TestNewNodeDecoderCounts verifies that a StatsReport using decoder_counts (field 20)
// produces the correct ring DataPoint.
func TestNewNodeDecoderCounts(t *testing.T) {
	rings := ring.New(ring.DefaultLimits())
	w := NewStatsWriter(rings)

	// New node format: decoder_counts field 20
	newReport := &pb.StatsReport{
		NodeId:             "test-node",
		UpstreamSampleRate: 1,
		Timestamp:          time.Now().Unix(),
		PrefixStats: []*pb.PrefixStatsMsg{
			{
				Prefix:        []byte{10, 0, 0, 0},
				PrefixLen:     24,
				PktCount:      1000,
				ByteCount:     100000,
				ActiveIps:     5,
				DecoderCounts: []uint32{500, 100, 300, 50, 10}, // trimmed (no trailing zeroes)
			},
		},
	}

	w.HandleStats("test-node", newReport)

	pr := rings.GetPrefixRing("test-node", "10.0.0.0/24")
	if pr == nil {
		t.Fatal("expected prefix ring for 10.0.0.0/24")
	}
	dp, ok := pr.LatestOne(5 * time.Second)
	if !ok {
		t.Fatal("expected data point")
	}

	if dp.DecoderPPS[decoder.TCP] != 500 {
		t.Errorf("TCP PPS = %d, want 500", dp.DecoderPPS[decoder.TCP])
	}
	if dp.DecoderPPS[decoder.TCPSyn] != 100 {
		t.Errorf("TCPSyn PPS = %d, want 100", dp.DecoderPPS[decoder.TCPSyn])
	}
	if dp.DecoderPPS[decoder.UDP] != 300 {
		t.Errorf("UDP PPS = %d, want 300", dp.DecoderPPS[decoder.UDP])
	}
	if dp.DecoderPPS[decoder.ICMP] != 50 {
		t.Errorf("ICMP PPS = %d, want 50", dp.DecoderPPS[decoder.ICMP])
	}
	if dp.DecoderPPS[decoder.Frag] != 10 {
		t.Errorf("Frag PPS = %d, want 10", dp.DecoderPPS[decoder.Frag])
	}
}

// TestBothFormatsProduceSameResult verifies old and new formats yield identical ring data.
func TestBothFormatsProduceSameResult(t *testing.T) {
	ringsOld := ring.New(ring.DefaultLimits())
	ringsNew := ring.New(ring.DefaultLimits())
	wOld := NewStatsWriter(ringsOld)
	wNew := NewStatsWriter(ringsNew)

	ts := time.Now().Unix()

	// Old format
	wOld.HandleStats("n1", &pb.StatsReport{
		NodeId: "n1", UpstreamSampleRate: 1, Timestamp: ts,
		PrefixStats: []*pb.PrefixStatsMsg{{
			Prefix: []byte{192, 168, 1, 0}, PrefixLen: 24,
			PktCount: 2000, ByteCount: 200000,
			TcpCount: 800, TcpSynCount: 200, UdpCount: 600, IcmpCount: 100, FragCount: 20,
		}},
	})

	// New format (same values)
	wNew.HandleStats("n1", &pb.StatsReport{
		NodeId: "n1", UpstreamSampleRate: 1, Timestamp: ts,
		PrefixStats: []*pb.PrefixStatsMsg{{
			Prefix: []byte{192, 168, 1, 0}, PrefixLen: 24,
			PktCount: 2000, ByteCount: 200000,
			DecoderCounts: []uint32{800, 200, 600, 100, 20},
		}},
	})

	prOld := ringsOld.GetPrefixRing("n1", "192.168.1.0/24")
	prNew := ringsNew.GetPrefixRing("n1", "192.168.1.0/24")
	if prOld == nil || prNew == nil {
		t.Fatal("missing prefix ring")
	}

	dpOld, okOld := prOld.LatestOne(5 * time.Second)
	dpNew, okNew := prNew.LatestOne(5 * time.Second)
	if !okOld || !okNew {
		t.Fatal("missing data point")
	}

	for i := 0; i < decoder.MaxDecoders; i++ {
		if dpOld.DecoderPPS[i] != dpNew.DecoderPPS[i] {
			t.Errorf("decoder[%d] (%s): old=%d new=%d", i, decoder.Names[i], dpOld.DecoderPPS[i], dpNew.DecoderPPS[i])
		}
	}
	if dpOld.PPS != dpNew.PPS {
		t.Errorf("PPS: old=%d new=%d", dpOld.PPS, dpNew.PPS)
	}
	if dpOld.BPS != dpNew.BPS {
		t.Errorf("BPS: old=%d new=%d", dpOld.BPS, dpNew.BPS)
	}
}
