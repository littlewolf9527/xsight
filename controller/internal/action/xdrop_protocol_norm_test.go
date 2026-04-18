package action

// v1.2.1 regression tests for normalizeXDropProtocol.
//
// Problem this guards against: xSight's decoder_family enum is broader than
// xDrop's protocol enum. Operators writing `"protocol": "{decoder}"` in a
// custom xDrop payload get HTTP 400 from xDrop when decoder is "ip" or
// "fragment" (xSight's catch-all aggregates) because xDrop only accepts
// {all, tcp, udp, icmp, icmpv6}. normalizeXDropProtocol translates those
// inline before the HTTP POST so rules succeed instead of turning into
// failed xdrop_active_rules rows.

import (
	"encoding/json"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func TestNormalizeXDropProtocol(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string // expected protocol field after normalization; "" = absent
	}{
		{
			name:    "ip decoder translates to all",
			payload: `{"dst_ip":"192.0.2.0/24","protocol":"ip","action":"drop"}`,
			want:    "all",
		},
		{
			name:    "fragment decoder translates to all",
			payload: `{"dst_ip":"192.0.2.0/24","protocol":"fragment","action":"drop"}`,
			want:    "all",
		},
		{
			name:    "tcp_syn decoder translates to tcp",
			payload: `{"dst_ip":"192.0.2.0/24","protocol":"tcp_syn","action":"drop"}`,
			want:    "tcp",
		},
		{
			name:    "udp untouched (already xDrop-valid)",
			payload: `{"dst_ip":"192.0.2.0/24","protocol":"udp","action":"drop"}`,
			want:    "udp",
		},
		{
			name:    "tcp untouched",
			payload: `{"dst_ip":"192.0.2.0/24","protocol":"tcp","action":"drop"}`,
			want:    "tcp",
		},
		{
			name:    "icmp untouched",
			payload: `{"dst_ip":"192.0.2.0/24","protocol":"icmp","action":"drop"}`,
			want:    "icmp",
		},
		{
			name:    "icmpv6 untouched (xDrop-specific, never an xSight decoder)",
			payload: `{"dst_ip":"192.0.2.0/24","protocol":"icmpv6","action":"drop"}`,
			want:    "icmpv6",
		},
		{
			name:    "all untouched",
			payload: `{"dst_ip":"192.0.2.0/24","protocol":"all","action":"drop"}`,
			want:    "all",
		},
		{
			name:    "protocol absent leaves payload alone",
			payload: `{"dst_ip":"192.0.2.0/24","action":"drop"}`,
			want:    "", // absent after round-trip
		},
		{
			name:    "empty protocol leaves payload alone",
			payload: `{"dst_ip":"192.0.2.0/24","protocol":"","action":"drop"}`,
			want:    "", // empty string after round-trip
		},
		{
			name:    "unknown protocol passes through (let xDrop reject with a clear error)",
			payload: `{"dst_ip":"192.0.2.0/24","protocol":"raw","action":"drop"}`,
			want:    "raw",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeXDropProtocol([]byte(tt.payload))
			var m map[string]any
			if err := json.Unmarshal(got, &m); err != nil {
				t.Fatalf("result not valid JSON: %v (input=%s)", err, tt.payload)
			}
			var proto string
			if v, ok := m["protocol"].(string); ok {
				proto = v
			}
			if proto != tt.want {
				t.Errorf("protocol = %q, want %q (payload: %s → %s)",
					proto, tt.want, tt.payload, string(got))
			}
		})
	}
}

// Pins the interaction between normalize and injectTcpFlags: for a tcp_syn
// attack, the normalize step translates protocol=tcp_syn → tcp, and
// injectTcpFlags then adds tcp_flags. Both steps need to work without
// undoing each other.
func TestNormalizeAndInjectTcpFlags_Integration(t *testing.T) {
	// Simulate the xdrop.go pipeline order: expand → fixPayloadTypes →
	// normalize → injectTcpFlags. We only test the normalize + inject
	// steps here; full expand is covered elsewhere.
	attack := &store.Attack{ID: 1, DstIP: "192.0.2.5/32", DecoderFamily: "tcp_syn"}
	raw := []byte(`{"dst_ip":"192.0.2.5/32","protocol":"tcp_syn","action":"drop"}`)
	normalized := normalizeXDropProtocol(raw)
	final := injectTcpFlags(normalized, attack)

	var m map[string]any
	if err := json.Unmarshal(final, &m); err != nil {
		t.Fatalf("final payload invalid JSON: %v", err)
	}
	if m["protocol"] != "tcp" {
		t.Errorf("protocol after pipeline = %v, want tcp", m["protocol"])
	}
	if m["tcp_flags"] != "SYN,!ACK" {
		t.Errorf("tcp_flags = %v, want SYN,!ACK (injectTcpFlags should add it)", m["tcp_flags"])
	}
}
