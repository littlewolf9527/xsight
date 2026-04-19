package decoder

import "testing"

func TestIndex(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{
		{"tcp", TCP},
		{"tcp_syn", TCPSyn},
		{"udp", UDP},
		{"icmp", ICMP},
		{"fragment", Frag},
		// v1.3 Phase 1b additions
		{"tcp_ack", TCPAck},
		{"tcp_rst", TCPRst},
		{"tcp_fin", TCPFin},
		{"gre", GRE},
		{"esp", ESP},
		{"igmp", IGMP},
		{"ip_other", IPOther},
		{"bad_fragment", BadFragment},
		{"invalid", Invalid},
		// Non-decoders
		{"ip", -1}, // "ip" is the L3 aggregate, not a decoder
		{"", -1},
		{"unknown", -1},
		// Explicit sanity that reflection subclasses are NOT decoders
		// (by design — see v1.3-scope.md §A, they go through precondition instead)
		{"dns_reflect", -1},
		{"ntp_reflect", -1},
		{"memcached_reflect", -1},
	}
	for _, tt := range tests {
		got := Index(tt.name)
		if got != tt.want {
			t.Errorf("Index(%q) = %d, want %d", tt.name, got, tt.want)
		}
	}
}

// TestV13DecoderSlots asserts the v1.3 Phase 1b decoders are registered at
// their designed indices (scope.md §A). Append-only invariant: reordering
// these or inserting before them will be caught by this test.
func TestV13DecoderSlots(t *testing.T) {
	expect := []struct {
		idx  int
		name string
	}{
		{5, "tcp_ack"},
		{6, "tcp_rst"},
		{7, "tcp_fin"},
		{8, "gre"},
		{9, "esp"},
		{10, "igmp"},
		{11, "ip_other"},
		{12, "bad_fragment"},
		{13, "invalid"},
	}
	for _, e := range expect {
		if Names[e.idx] != e.name {
			t.Errorf("Names[%d] = %q, want %q — v1.3 Phase 1b decoder slot moved or renamed", e.idx, Names[e.idx], e.name)
		}
	}
	// Slots 14-15 must still be reserved (empty) so future additions stay contiguous.
	for i := 14; i < MaxDecoders; i++ {
		if Names[i] != "" {
			t.Errorf("Names[%d] = %q should still be unused (reserved for future decoders)", i, Names[i])
		}
	}
}

// TestDecoderCapacity asserts the current registry usage leaves headroom
// within MaxDecoders=16. v1.3 intentionally keeps MaxDecoders untouched;
// adding more decoders past slot 15 requires a separate capacity expansion
// project (see roadmap backlog).
func TestDecoderCapacity(t *testing.T) {
	used := 0
	for i := 0; i < MaxDecoders; i++ {
		if Names[i] != "" {
			used++
		}
	}
	if used > MaxDecoders {
		t.Fatalf("used %d slots > MaxDecoders %d — impossible by design", used, MaxDecoders)
	}
	const v13Budget = 14
	if used != v13Budget {
		// Not a hard failure — just flag the drift. If an accepted change moves
		// this, the test's v13Budget constant should move with it.
		t.Logf("decoder slots used = %d (v1.3 budget: %d). If this is intentional, update v13Budget.", used, v13Budget)
	}
}

func TestNamesConsistency(t *testing.T) {
	// Verify standard decoders are in expected slots
	if Names[TCP] != "tcp" {
		t.Errorf("Names[TCP] = %q, want tcp", Names[TCP])
	}
	if Names[TCPSyn] != "tcp_syn" {
		t.Errorf("Names[TCPSyn] = %q, want tcp_syn", Names[TCPSyn])
	}
	if Names[UDP] != "udp" {
		t.Errorf("Names[UDP] = %q, want udp", Names[UDP])
	}
	if Names[ICMP] != "icmp" {
		t.Errorf("Names[ICMP] = %q, want icmp", Names[ICMP])
	}
	if Names[Frag] != "fragment" {
		t.Errorf("Names[Frag] = %q, want fragment", Names[Frag])
	}

	// StandardCount should match
	nonEmpty := 0
	for i := 0; i < StandardCount; i++ {
		if Names[i] == "" {
			t.Errorf("Names[%d] is empty but within StandardCount=%d", i, StandardCount)
		}
		nonEmpty++
	}
	if nonEmpty != StandardCount {
		t.Errorf("expected %d standard decoders, got %d", StandardCount, nonEmpty)
	}
}

func TestAppendOnlyInvariant(t *testing.T) {
	// Verify indices are monotonically assigned (no gaps in standard range)
	if TCP != 0 || TCPSyn != 1 || UDP != 2 || ICMP != 3 || Frag != 4 {
		t.Error("standard decoder indices must be 0,1,2,3,4 — append-only invariant violated")
	}
}
