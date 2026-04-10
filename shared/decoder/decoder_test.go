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
		{"ip", -1},       // "ip" is not a decoder, it's the aggregate
		{"gre", -1},      // not registered yet
		{"", -1},         // empty
		{"unknown", -1},
	}
	for _, tt := range tests {
		got := Index(tt.name)
		if got != tt.want {
			t.Errorf("Index(%q) = %d, want %d", tt.name, got, tt.want)
		}
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
