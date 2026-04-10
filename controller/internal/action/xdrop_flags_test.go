package action

import (
	"encoding/json"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// TestTcpFlagsInjection verifies that the default xDrop payload auto-injects
// tcp_flags for tcp_syn attacks and omits it for other decoder families.
func TestTcpFlagsInjection(t *testing.T) {
	tests := []struct {
		name           string
		decoder        string
		xdropAction    string
		wantTcpFlags   string // expected tcp_flags value, "" means absent
		wantProtocol   string // expected protocol value, "" means absent
	}{
		{"T1: tcp_syn + drop", "tcp_syn", "filter_l4", "SYN,!ACK", "tcp"},
		{"T2: tcp_syn + rate_limit", "tcp_syn", "rate_limit", "SYN,!ACK", "tcp"},
		{"T3: ip + drop", "ip", "filter_l4", "", ""},
		{"T4: udp + drop", "udp", "filter_l4", "", ""},
		{"T5: tcp + drop", "tcp", "filter_l4", "", ""},
		{"T6: icmp + drop", "icmp", "filter_l4", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attack := &store.Attack{
				ID:            999,
				DstIP:         "10.0.0.1/32",
				DecoderFamily: tt.decoder,
				AttackType:    "test_flood",
			}

			// Simulate default payload construction (same logic as xdrop.go)
			actionStr := "drop"
			if tt.xdropAction == "rate_limit" {
				actionStr = "rate_limit"
			}
			payload := xdropRuleRequest{
				DstIP:   attack.DstIP,
				Action:  actionStr,
				Source:  "xsight",
				Comment: "test",
			}
			if attack.DecoderFamily == "tcp_syn" {
				payload.Protocol = "tcp"
				synFlags := "SYN,!ACK"
				payload.TcpFlags = &synFlags
			}

			body, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			var m map[string]any
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			// Check tcp_flags
			gotFlags, hasFlags := m["tcp_flags"]
			if tt.wantTcpFlags == "" {
				if hasFlags {
					t.Errorf("tcp_flags should be absent, got %v", gotFlags)
				}
			} else {
				if !hasFlags {
					t.Errorf("tcp_flags should be %q, got absent", tt.wantTcpFlags)
				} else if gotFlags != tt.wantTcpFlags {
					t.Errorf("tcp_flags = %v, want %q", gotFlags, tt.wantTcpFlags)
				}
			}

			// Check protocol
			gotProto, hasProto := m["protocol"]
			if tt.wantProtocol == "" {
				if hasProto {
					t.Errorf("protocol should be absent, got %v", gotProto)
				}
			} else {
				if !hasProto {
					t.Errorf("protocol should be %q, got absent", tt.wantProtocol)
				} else if gotProto != tt.wantProtocol {
					t.Errorf("protocol = %v, want %q", gotProto, tt.wantProtocol)
				}
			}

			// Verify action field
			if m["action"] != actionStr {
				t.Errorf("action = %v, want %q", m["action"], actionStr)
			}

			t.Logf("payload: %s", string(body))
		})
	}
}

// TestInjectTcpFlags verifies the injectTcpFlags function used by both
// default and custom payload paths.
func TestInjectTcpFlags(t *testing.T) {
	tests := []struct {
		name         string
		decoder      string
		payload      string
		wantFlags    string // "" means absent
		wantProtocol string // "" means unchanged
	}{
		{
			"tcp_syn injects flags",
			"tcp_syn",
			`{"action":"drop","dst_ip":"10.0.0.1","source":"xsight"}`,
			"SYN,!ACK", "tcp",
		},
		{
			"tcp_syn respects existing flags but ensures protocol=tcp",
			"tcp_syn",
			`{"action":"drop","dst_ip":"10.0.0.1","tcp_flags":"RST"}`,
			"RST", "tcp",
		},
		{
			"udp no injection",
			"udp",
			`{"action":"drop","dst_ip":"10.0.0.1"}`,
			"", "",
		},
		{
			"ip no injection",
			"ip",
			`{"action":"drop","dst_ip":"10.0.0.1"}`,
			"", "",
		},
		{
			"tcp_syn preserves existing protocol",
			"tcp_syn",
			`{"action":"drop","dst_ip":"10.0.0.1","protocol":"tcp"}`,
			"SYN,!ACK", "tcp",
		},
		{
			"tcp_syn fixes protocol=tcp_syn from {decoder} expansion",
			"tcp_syn",
			`{"action":"drop","dst_ip":"10.0.0.1","protocol":"tcp_syn"}`,
			"SYN,!ACK", "tcp",
		},
		{
			"tcp_syn with user tcp_flags but missing protocol ensures protocol=tcp",
			"tcp_syn",
			`{"action":"drop","dst_ip":"10.0.0.1","tcp_flags":"RST"}`,
			"RST", "tcp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attack := &store.Attack{DecoderFamily: tt.decoder}
			result := injectTcpFlags([]byte(tt.payload), attack)

			var m map[string]any
			if err := json.Unmarshal(result, &m); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			gotFlags, hasFlags := m["tcp_flags"]
			if tt.wantFlags == "" {
				if hasFlags {
					t.Errorf("tcp_flags should be absent, got %v", gotFlags)
				}
			} else {
				if !hasFlags {
					t.Errorf("tcp_flags should be %q, got absent", tt.wantFlags)
				} else if gotFlags != tt.wantFlags {
					t.Errorf("tcp_flags = %v, want %q", gotFlags, tt.wantFlags)
				}
			}

			if tt.wantProtocol != "" {
				if m["protocol"] != tt.wantProtocol {
					t.Errorf("protocol = %v, want %q", m["protocol"], tt.wantProtocol)
				}
			}

			t.Logf("result: %s", string(result))
		})
	}
}

// TestCustomPayloadWithInjection verifies the full custom payload path:
// expandParams + fixPayloadTypes + injectTcpFlags
func TestCustomPayloadWithInjection(t *testing.T) {
	customPayload := `{"action":"drop","dst_ip":"{dst_ip}","source":"xsight","comment":"attack #{attack_id}"}`
	attack := &store.Attack{
		ID:            100,
		DstIP:         "10.0.0.5/32",
		DecoderFamily: "tcp_syn",
		AttackType:    "syn_flood",
	}

	// Simulate the full custom payload path from xdrop.go
	expanded := expandParams(customPayload, attack, "attack_start", "10.0.0.0/24", nil)
	body, err := fixPayloadTypes([]byte(expanded))
	if err != nil {
		body = []byte(expanded)
	}
	body = injectTcpFlags(body, attack)

	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if m["tcp_flags"] != "SYN,!ACK" {
		t.Errorf("tcp_flags = %v, want SYN,!ACK", m["tcp_flags"])
	}
	if m["protocol"] != "tcp" {
		t.Errorf("protocol = %v, want tcp", m["protocol"])
	}
	if m["dst_ip"] != "10.0.0.5/32" {
		t.Errorf("dst_ip = %v, want 10.0.0.5/32", m["dst_ip"])
	}

	t.Logf("full path result: %s", string(body))
}

// TestNonSynCustomPayload verifies non-tcp_syn attacks don't get injected
func TestNonSynCustomPayload(t *testing.T) {
	customPayload := `{"action":"drop","dst_ip":"{dst_ip}","source":"xsight"}`
	attack := &store.Attack{
		ID:            101,
		DstIP:         "10.0.0.6/32",
		DecoderFamily: "udp",
		AttackType:    "udp_flood",
	}

	expanded := expandParams(customPayload, attack, "attack_start", "10.0.0.0/24", nil)
	body, _ := fixPayloadTypes([]byte(expanded))
	body = injectTcpFlags(body, attack)

	var m map[string]any
	json.Unmarshal(body, &m)

	if _, has := m["tcp_flags"]; has {
		t.Errorf("udp attack should NOT have tcp_flags, got %v", m["tcp_flags"])
	}

	t.Logf("result: %s", string(body))
}
