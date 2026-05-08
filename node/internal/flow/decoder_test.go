package flow

import (
	"sort"
	"testing"

	"github.com/littlewolf9527/xsight/shared/decoder"
)

// sameElements reports whether the first n elements of arr contain
// the same int values as want (order-independent).
func sameElements(arr [MaxDecoderHits]int, n int, want []int) bool {
	if n != len(want) {
		return false
	}
	got := make([]int, n)
	copy(got, arr[:n])
	w := make([]int, len(want))
	copy(w, want)
	sort.Ints(got)
	sort.Ints(w)
	for i := range got {
		if got[i] != w[i] {
			return false
		}
	}
	return true
}

// --- single-flag TCP ---

func TestProtocolToDecoders_TCP_Plain(t *testing.T) {
	arr, n := ProtocolToDecoders(6, 0x08) // PSH only — no flag sub-decoder
	want := []int{decoder.TCP}
	if !sameElements(arr, n, want) {
		t.Errorf("TCP PSH: got %v (n=%d), want %v", arr[:n], n, want)
	}
}

func TestProtocolToDecoders_TCP_SYN(t *testing.T) {
	arr, n := ProtocolToDecoders(6, 0x02)
	want := []int{decoder.TCP, decoder.TCPSyn}
	if !sameElements(arr, n, want) {
		t.Errorf("TCP SYN: got %v (n=%d), want %v", arr[:n], n, want)
	}
}

func TestProtocolToDecoders_TCP_ACK(t *testing.T) {
	arr, n := ProtocolToDecoders(6, 0x10)
	want := []int{decoder.TCP, decoder.TCPAck}
	if !sameElements(arr, n, want) {
		t.Errorf("TCP ACK: got %v (n=%d), want %v", arr[:n], n, want)
	}
}

func TestProtocolToDecoders_TCP_RST(t *testing.T) {
	arr, n := ProtocolToDecoders(6, 0x04)
	want := []int{decoder.TCP, decoder.TCPRst}
	if !sameElements(arr, n, want) {
		t.Errorf("TCP RST: got %v (n=%d), want %v", arr[:n], n, want)
	}
}

func TestProtocolToDecoders_TCP_FIN(t *testing.T) {
	arr, n := ProtocolToDecoders(6, 0x01)
	want := []int{decoder.TCP, decoder.TCPFin}
	if !sameElements(arr, n, want) {
		t.Errorf("TCP FIN: got %v (n=%d), want %v", arr[:n], n, want)
	}
}

// --- compound TCP flags (additive semantics) ---

func TestProtocolToDecoders_TCP_SynAck(t *testing.T) {
	// SYN+ACK: neither SYN+!ACK nor ACK+!SYN matches → base TCP only
	arr, n := ProtocolToDecoders(6, 0x12)
	want := []int{decoder.TCP}
	if !sameElements(arr, n, want) {
		t.Errorf("TCP SYN+ACK: got %v (n=%d), want %v", arr[:n], n, want)
	}
}

func TestProtocolToDecoders_TCP_AckRst(t *testing.T) {
	// ACK+RST (0x14): both ACK+!SYN and RST fire
	arr, n := ProtocolToDecoders(6, 0x14)
	want := []int{decoder.TCP, decoder.TCPAck, decoder.TCPRst}
	if !sameElements(arr, n, want) {
		t.Errorf("TCP ACK+RST: got %v (n=%d), want %v", arr[:n], n, want)
	}
}

func TestProtocolToDecoders_TCP_AckFin(t *testing.T) {
	// ACK+FIN (0x11): both ACK+!SYN and FIN fire
	arr, n := ProtocolToDecoders(6, 0x11)
	want := []int{decoder.TCP, decoder.TCPAck, decoder.TCPFin}
	if !sameElements(arr, n, want) {
		t.Errorf("TCP ACK+FIN: got %v (n=%d), want %v", arr[:n], n, want)
	}
}

func TestProtocolToDecoders_TCP_RstFin(t *testing.T) {
	// RST+FIN (0x05): both RST and FIN fire
	arr, n := ProtocolToDecoders(6, 0x05)
	want := []int{decoder.TCP, decoder.TCPRst, decoder.TCPFin}
	if !sameElements(arr, n, want) {
		t.Errorf("TCP RST+FIN: got %v (n=%d), want %v", arr[:n], n, want)
	}
}

func TestProtocolToDecoders_TCP_AckRstFin(t *testing.T) {
	// ACK+RST+FIN (0x15): all three fire
	arr, n := ProtocolToDecoders(6, 0x15)
	want := []int{decoder.TCP, decoder.TCPAck, decoder.TCPRst, decoder.TCPFin}
	if !sameElements(arr, n, want) {
		t.Errorf("TCP ACK+RST+FIN: got %v (n=%d), want %v", arr[:n], n, want)
	}
}

// --- non-TCP protocols ---

func TestProtocolToDecoders_UDP(t *testing.T) {
	arr, n := ProtocolToDecoders(17, 0)
	want := []int{decoder.UDP}
	if !sameElements(arr, n, want) {
		t.Errorf("UDP: got %v (n=%d), want %v", arr[:n], n, want)
	}
}

func TestProtocolToDecoders_ICMPv4(t *testing.T) {
	arr, n := ProtocolToDecoders(1, 0)
	want := []int{decoder.ICMP}
	if !sameElements(arr, n, want) {
		t.Errorf("ICMPv4: got %v (n=%d), want %v", arr[:n], n, want)
	}
}

func TestProtocolToDecoders_ICMPv6(t *testing.T) {
	arr, n := ProtocolToDecoders(58, 0)
	want := []int{decoder.ICMP}
	if !sameElements(arr, n, want) {
		t.Errorf("ICMPv6: got %v (n=%d), want %v", arr[:n], n, want)
	}
}

func TestProtocolToDecoders_GRE(t *testing.T) {
	arr, n := ProtocolToDecoders(47, 0)
	want := []int{decoder.GRE}
	if !sameElements(arr, n, want) {
		t.Errorf("GRE: got %v (n=%d), want %v", arr[:n], n, want)
	}
}

func TestProtocolToDecoders_ESP(t *testing.T) {
	arr, n := ProtocolToDecoders(50, 0)
	want := []int{decoder.ESP}
	if !sameElements(arr, n, want) {
		t.Errorf("ESP: got %v (n=%d), want %v", arr[:n], n, want)
	}
}

func TestProtocolToDecoders_IGMP(t *testing.T) {
	arr, n := ProtocolToDecoders(2, 0)
	want := []int{decoder.IGMP}
	if !sameElements(arr, n, want) {
		t.Errorf("IGMP: got %v (n=%d), want %v", arr[:n], n, want)
	}
}

func TestProtocolToDecoders_IPOther(t *testing.T) {
	arr, n := ProtocolToDecoders(89, 0) // OSPF — unknown, should be IPOther
	want := []int{decoder.IPOther}
	if !sameElements(arr, n, want) {
		t.Errorf("IPOther (OSPF/89): got %v (n=%d), want %v", arr[:n], n, want)
	}
}
