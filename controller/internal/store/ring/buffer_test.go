package ring

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestDefaultLimits(t *testing.T) {
	lim := DefaultLimits()
	if lim.MaxPointsPerIP != 120 {
		t.Errorf("MaxPointsPerIP = %d, want 120", lim.MaxPointsPerIP)
	}
	if lim.MaxIPsPerPrefix != 10_000 {
		t.Errorf("MaxIPsPerPrefix = %d, want 10000", lim.MaxIPsPerPrefix)
	}
	if lim.MaxGlobalKeys != 100_000 {
		t.Errorf("MaxGlobalKeys = %d, want 100000", lim.MaxGlobalKeys)
	}
}

func TestPushPrefix_LatestOne(t *testing.T) {
	rs := New(DefaultLimits())
	now := time.Now()
	dp := DataPoint{Time: now, PPS: 1000, BPS: 8000}
	rs.PushPrefix("node-1", "10.0.0.0/24", dp)

	pr := rs.GetPrefixRing("node-1", "10.0.0.0/24")
	if pr == nil {
		t.Fatal("expected prefix ring, got nil")
	}
	got, ok := pr.LatestOne(0)
	if !ok {
		t.Fatal("LatestOne returned false")
	}
	if got.PPS != 1000 {
		t.Errorf("PPS = %d, want 1000", got.PPS)
	}
}

func TestPushIP_LatestOne(t *testing.T) {
	rs := New(DefaultLimits())
	now := time.Now()
	dp := DataPoint{Time: now, PPS: 500, BPS: 4000}
	ip := net.ParseIP("10.0.0.1")
	rs.PushIP("node-1", "10.0.0.0/24", ip, dp)

	ir := rs.GetIPRing("node-1", "10.0.0.0/24", ip)
	if ir == nil {
		t.Fatal("expected IP ring, got nil")
	}
	got, ok := ir.LatestOne(0)
	if !ok {
		t.Fatal("LatestOne returned false")
	}
	if got.PPS != 500 {
		t.Errorf("PPS = %d, want 500", got.PPS)
	}
}

func TestCircularOverwrite(t *testing.T) {
	lim := Limits{
		MaxPointsPerIP:  5,
		MaxIPsPerPrefix: 100,
		MaxGlobalKeys:   1000,
	}
	rs := New(lim)
	ip := net.ParseIP("10.0.0.1")
	now := time.Now()

	// Push 10 points into a ring with capacity 5
	for i := 0; i < 10; i++ {
		dp := DataPoint{Time: now.Add(time.Duration(i) * time.Second), PPS: int64(i)}
		rs.PushIP("node-1", "10.0.0.0/24", ip, dp)
	}

	ir := rs.GetIPRing("node-1", "10.0.0.0/24", ip)
	if ir == nil {
		t.Fatal("expected IP ring")
	}
	if ir.Count() != 5 {
		t.Errorf("Count() = %d, want 5", ir.Count())
	}

	// Latest should be PPS=9 (the last pushed)
	got, ok := ir.LatestOne(0)
	if !ok {
		t.Fatal("LatestOne returned false")
	}
	if got.PPS != 9 {
		t.Errorf("latest PPS = %d, want 9", got.PPS)
	}

	// All 5 retained should be PPS 5..9
	latest := ir.Latest(5)
	for i, dp := range latest {
		wantPPS := int64(9 - i)
		if dp.PPS != wantPPS {
			t.Errorf("Latest[%d].PPS = %d, want %d", i, dp.PPS, wantPPS)
		}
	}
}

func TestLRUEviction_GlobalKeys(t *testing.T) {
	lim := Limits{
		MaxPointsPerIP:  5,
		MaxIPsPerPrefix: 100,
		MaxGlobalKeys:   10, // very small limit
	}
	rs := New(lim)
	now := time.Now()

	// Push 15 unique IPs — should evict oldest
	for i := 0; i < 15; i++ {
		ip := net.ParseIP(fmt.Sprintf("10.0.0.%d", i))
		dp := DataPoint{Time: now.Add(time.Duration(i) * time.Second), PPS: int64(i)}
		rs.PushIP("node-1", "10.0.0.0/24", ip, dp)
	}

	_, ipCount, _ := rs.Stats()
	if ipCount > lim.MaxGlobalKeys {
		t.Errorf("IP count = %d, should be <= %d after eviction", ipCount, lim.MaxGlobalKeys)
	}

	// The most recent IPs should still exist
	latestIP := net.ParseIP("10.0.0.14")
	if ir := rs.GetIPRing("node-1", "10.0.0.0/24", latestIP); ir == nil {
		t.Error("most recent IP should not be evicted")
	}
}

func TestLRUEviction_ActiveProtected(t *testing.T) {
	lim := Limits{
		MaxPointsPerIP:  5,
		MaxIPsPerPrefix: 100,
		MaxGlobalKeys:   5,
	}
	rs := New(lim)
	now := time.Now()

	// Push 4 IPs
	for i := 0; i < 4; i++ {
		ip := net.ParseIP(fmt.Sprintf("10.0.0.%d", i))
		dp := DataPoint{Time: now.Add(time.Duration(i) * time.Second), PPS: int64(i)}
		rs.PushIP("node-1", "10.0.0.0/24", ip, dp)
	}

	// Mark the oldest IP (10.0.0.0) as active
	activeIP := net.ParseIP("10.0.0.0")
	rs.MarkActive("node-1", "10.0.0.0/24", activeIP)

	// Push more IPs to trigger eviction
	for i := 4; i < 10; i++ {
		ip := net.ParseIP(fmt.Sprintf("10.0.0.%d", i))
		dp := DataPoint{Time: now.Add(time.Duration(i) * time.Second), PPS: int64(i)}
		rs.PushIP("node-1", "10.0.0.0/24", ip, dp)
	}

	// The active IP should still be present
	if ir := rs.GetIPRing("node-1", "10.0.0.0/24", activeIP); ir == nil {
		t.Error("active IP 10.0.0.0 should be protected from eviction")
	}
}

func TestGetIPRingByKey(t *testing.T) {
	rs := New(DefaultLimits())
	now := time.Now()
	dp := DataPoint{Time: now, PPS: 777, BPS: 6000}
	ip := net.ParseIP("192.168.1.100")
	rs.PushIP("node-1", "192.168.1.0/24", ip, dp)

	// GetIPRingByKey should return the same ring as GetIPRing
	ir1 := rs.GetIPRing("node-1", "192.168.1.0/24", ip)
	ir2 := rs.GetIPRingByKey("node-1", "192.168.1.0/24", "192.168.1.100")
	if ir1 == nil || ir2 == nil {
		t.Fatal("expected non-nil rings from both methods")
	}
	if ir1 != ir2 {
		t.Error("GetIPRingByKey should return the same ring pointer as GetIPRing")
	}

	got, ok := ir2.LatestOne(0)
	if !ok {
		t.Fatal("LatestOne returned false")
	}
	if got.PPS != 777 {
		t.Errorf("PPS = %d, want 777", got.PPS)
	}

	// Non-existent key should return nil
	if rs.GetIPRingByKey("node-1", "192.168.1.0/24", "192.168.1.200") != nil {
		t.Error("expected nil for non-existent IP")
	}
}
