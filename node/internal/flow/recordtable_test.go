package flow

import (
	"net"
	"testing"
)

func TestFlowRecordTableAddAccumulates(t *testing.T) {
	table := NewFlowRecordTable(100)

	src := net.ParseIP("1.2.3.4")
	dst := net.ParseIP("10.0.0.1")

	table.Add(src, dst, 12345, 80, 6, 0x10, 100, 5000)
	table.Add(src, dst, 12345, 80, 6, 0x02, 200, 10000)

	entries := table.DrainTop(10)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Packets != 300 {
		t.Errorf("expected packets=300, got %d", e.Packets)
	}
	if e.Bytes != 15000 {
		t.Errorf("expected bytes=15000, got %d", e.Bytes)
	}
	if e.TCPFlags != 0x12 { // OR of 0x10 and 0x02
		t.Errorf("expected tcp_flags=0x12, got 0x%02x", e.TCPFlags)
	}
}

func TestFlowRecordTableDrainTopSorted(t *testing.T) {
	table := NewFlowRecordTable(100)

	table.Add(net.ParseIP("1.1.1.1"), net.ParseIP("10.0.0.1"), 1, 80, 6, 0, 50, 1000)
	table.Add(net.ParseIP("2.2.2.2"), net.ParseIP("10.0.0.2"), 2, 80, 6, 0, 500, 10000)
	table.Add(net.ParseIP("3.3.3.3"), net.ParseIP("10.0.0.3"), 3, 80, 6, 0, 200, 5000)

	entries := table.DrainTop(10)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	// Should be sorted by packets descending
	if entries[0].Packets != 500 {
		t.Errorf("expected top entry 500 pkts, got %d", entries[0].Packets)
	}
	if entries[1].Packets != 200 {
		t.Errorf("expected second entry 200 pkts, got %d", entries[1].Packets)
	}
	if entries[2].Packets != 50 {
		t.Errorf("expected third entry 50 pkts, got %d", entries[2].Packets)
	}
}

func TestFlowRecordTableDrainTopResetsTable(t *testing.T) {
	table := NewFlowRecordTable(100)
	table.Add(net.ParseIP("1.1.1.1"), net.ParseIP("10.0.0.1"), 1, 80, 6, 0, 100, 5000)

	entries := table.DrainTop(10)
	if len(entries) != 1 {
		t.Fatalf("expected 1, got %d", len(entries))
	}

	// After drain, table should be empty
	entries2 := table.DrainTop(10)
	if len(entries2) != 0 {
		t.Errorf("expected 0 after drain, got %d", len(entries2))
	}
}

func TestFlowRecordTableEviction(t *testing.T) {
	table := NewFlowRecordTable(3)

	table.Add(net.ParseIP("1.1.1.1"), net.ParseIP("10.0.0.1"), 1, 80, 6, 0, 10, 100)
	table.Add(net.ParseIP("2.2.2.2"), net.ParseIP("10.0.0.2"), 2, 80, 6, 0, 50, 500)
	table.Add(net.ParseIP("3.3.3.3"), net.ParseIP("10.0.0.3"), 3, 80, 6, 0, 30, 300)

	if table.Len() != 3 {
		t.Fatalf("expected 3 entries, got %d", table.Len())
	}

	// Adding 4th entry should evict the smallest (10 pkts)
	table.Add(net.ParseIP("4.4.4.4"), net.ParseIP("10.0.0.4"), 4, 80, 6, 0, 100, 1000)

	if table.Len() != 3 {
		t.Fatalf("expected 3 after eviction, got %d", table.Len())
	}

	entries := table.DrainTop(10)
	for _, e := range entries {
		if e.Packets == 10 {
			t.Error("smallest entry (10 pkts) should have been evicted")
		}
	}
}

func TestFlowRecordTableDrainTopLimit(t *testing.T) {
	table := NewFlowRecordTable(100)
	for i := 0; i < 20; i++ {
		ip := net.IPv4(byte(i+1), 0, 0, 1)
		table.Add(ip, net.ParseIP("10.0.0.1"), uint16(i), 80, 6, 0, uint64(i+1)*10, uint64(i+1)*100)
	}

	entries := table.DrainTop(5)
	if len(entries) != 5 {
		t.Errorf("expected 5, got %d", len(entries))
	}
}
