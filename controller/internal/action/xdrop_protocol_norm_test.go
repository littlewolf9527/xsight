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
		// v1.3 TCP-flag family: all collapse to protocol=tcp (tcp_flags
		// injected separately by injectTcpFlags).
		{
			name:    "tcp_ack decoder translates to tcp",
			payload: `{"dst_ip":"192.0.2.0/24","protocol":"tcp_ack","action":"drop"}`,
			want:    "tcp",
		},
		{
			name:    "tcp_rst decoder translates to tcp",
			payload: `{"dst_ip":"192.0.2.0/24","protocol":"tcp_rst","action":"drop"}`,
			want:    "tcp",
		},
		{
			name:    "tcp_fin decoder translates to tcp",
			payload: `{"dst_ip":"192.0.2.0/24","protocol":"tcp_fin","action":"drop"}`,
			want:    "tcp",
		},
		// v1.3 other IP protocols: accepted as-is by xdrop, no rewrite.
		{
			name:    "gre untouched (accepted by xdrop)",
			payload: `{"dst_ip":"192.0.2.0/24","protocol":"gre","action":"drop"}`,
			want:    "gre",
		},
		{
			name:    "esp untouched",
			payload: `{"dst_ip":"192.0.2.0/24","protocol":"esp","action":"drop"}`,
			want:    "esp",
		},
		{
			name:    "igmp untouched",
			payload: `{"dst_ip":"192.0.2.0/24","protocol":"igmp","action":"drop"}`,
			want:    "igmp",
		},
		// v1.3 anomaly family: {decoder}-expanded protocol gets moved to
		// the `decoder` field (xdrop anomaly rules are proto-wildcard).
		// The `want` here is empty because protocol is REMOVED; the
		// TestNormalizeMovesAnomalyToDecoderField test below pins the
		// decoder-field side.
		{
			name:    "bad_fragment decoder removed from protocol (moved to decoder field)",
			payload: `{"dst_ip":"192.0.2.0/24","protocol":"bad_fragment","action":"drop"}`,
			want:    "",
		},
		{
			name:    "invalid decoder removed from protocol (moved to decoder field)",
			payload: `{"dst_ip":"192.0.2.0/24","protocol":"invalid","action":"drop"}`,
			want:    "",
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

// TestNormalizeMovesAnomalyToDecoderField verifies the v1.3 behavior:
// when a custom payload carries `protocol: bad_fragment|invalid` (e.g.
// from {decoder} expansion), normalize MOVES the value to the xdrop
// `decoder` field because anomaly rules are protocol-wildcard in xdrop
// v2.6.1. Without this move xdrop would 400 the request.
func TestNormalizeMovesAnomalyToDecoderField(t *testing.T) {
	tests := []struct {
		name        string
		payload     string
		wantDecoder string
	}{
		{"bad_fragment → decoder field", `{"dst_ip":"192.0.2.1","protocol":"bad_fragment","action":"drop"}`, "bad_fragment"},
		{"invalid → decoder field", `{"dst_ip":"192.0.2.1","protocol":"invalid","action":"drop"}`, "invalid"},
		{
			"existing decoder field is preserved (no overwrite)",
			`{"dst_ip":"192.0.2.1","protocol":"bad_fragment","decoder":"invalid","action":"drop"}`,
			"invalid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeXDropProtocol([]byte(tt.payload))
			var m map[string]any
			if err := json.Unmarshal(got, &m); err != nil {
				t.Fatalf("result not valid JSON: %v", err)
			}
			if _, hasProto := m["protocol"]; hasProto {
				t.Errorf("protocol field should be removed after anomaly rewrite; got %v", m["protocol"])
			}
			if m["decoder"] != tt.wantDecoder {
				t.Errorf("decoder = %v, want %q", m["decoder"], tt.wantDecoder)
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
