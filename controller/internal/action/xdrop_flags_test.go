package action

import (
	"encoding/json"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// TestSpecializeXDropDecoder exercises the default payload builder's
// per-decoder specialization for all 14 xSight decoder_family values:
// anomaly → Decoder field; TCP-flag family → protocol=tcp + flags;
// gre/esp/igmp → protocol; others (tcp/udp/icmp/fragment/ip/ip_other) →
// untouched (xdrop defaults to wildcard when dst_ip is set).
func TestSpecializeXDropDecoder(t *testing.T) {
	tests := []struct {
		name         string
		decoder      string
		xdropAction  string
		wantTcpFlags string // "" means absent
		wantProtocol string // "" means absent
		wantDecoder  string // "" means absent
	}{
		// L4 standard
		{"tcp + drop", "tcp", "filter_l4", "", "", ""},
		{"udp + drop", "udp", "filter_l4", "", "", ""},
		{"icmp + drop", "icmp", "filter_l4", "", "", ""},
		{"fragment + drop", "fragment", "filter_l4", "", "", ""},
		// TCP-flag family
		{"tcp_syn + drop", "tcp_syn", "filter_l4", "SYN,!ACK", "tcp", ""},
		{"tcp_syn + rate_limit", "tcp_syn", "rate_limit", "SYN,!ACK", "tcp", ""},
		{"tcp_ack + drop", "tcp_ack", "filter_l4", "ACK,!SYN", "tcp", ""},
		{"tcp_rst + drop", "tcp_rst", "filter_l4", "RST", "tcp", ""},
		{"tcp_fin + drop", "tcp_fin", "filter_l4", "FIN", "tcp", ""},
		// Other IP protocols
		{"gre + drop", "gre", "filter_l4", "", "gre", ""},
		{"esp + drop", "esp", "filter_l4", "", "esp", ""},
		{"igmp + drop", "igmp", "filter_l4", "", "igmp", ""},
		// Anomaly family — Decoder field set, no Protocol
		{"bad_fragment + drop", "bad_fragment", "filter_l4", "", "", "bad_fragment"},
		{"invalid + drop", "invalid", "filter_l4", "", "", "invalid"},
		// Excluded (documenting the gate — engine rejects these before
		// executeXDrop runs, but specialize is a pass-through).
		{"ip + drop (gated upstream)", "ip", "filter_l4", "", "", ""},
		{"ip_other + drop (gated upstream)", "ip_other", "filter_l4", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attack := &store.Attack{
				ID:            999,
				DstIP:         "10.0.0.1/32",
				DecoderFamily: tt.decoder,
				AttackType:    "test_flood",
			}

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
			specializeXDropDecoder(&payload, attack.DecoderFamily)

			body, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			var m map[string]any
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

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

			gotDecoder, hasDecoder := m["decoder"]
			if tt.wantDecoder == "" {
				if hasDecoder {
					t.Errorf("decoder should be absent, got %v", gotDecoder)
				}
			} else {
				if !hasDecoder {
					t.Errorf("decoder should be %q, got absent", tt.wantDecoder)
				} else if gotDecoder != tt.wantDecoder {
					t.Errorf("decoder = %v, want %q", gotDecoder, tt.wantDecoder)
				}
			}

			// Anomaly path must never carry tcp_flags (xdrop wildcards
			// protocol; operator intent is "any packet hitting match_anomaly").
			if tt.wantDecoder != "" && hasFlags {
				t.Errorf("anomaly decoder %q must not carry tcp_flags, got %v", tt.decoder, gotFlags)
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
		{
			"tcp_ack injects ACK,!SYN",
			"tcp_ack",
			`{"action":"drop","dst_ip":"10.0.0.1"}`,
			"ACK,!SYN", "tcp",
		},
		{
			"tcp_ack fixes protocol=tcp_ack from {decoder} expansion",
			"tcp_ack",
			`{"action":"drop","dst_ip":"10.0.0.1","protocol":"tcp_ack"}`,
			"ACK,!SYN", "tcp",
		},
		{
			"tcp_rst injects RST",
			"tcp_rst",
			`{"action":"drop","dst_ip":"10.0.0.1"}`,
			"RST", "tcp",
		},
		{
			"tcp_fin injects FIN",
			"tcp_fin",
			`{"action":"drop","dst_ip":"10.0.0.1"}`,
			"FIN", "tcp",
		},
		{
			"bad_fragment no tcp_flags injection (anomaly path)",
			"bad_fragment",
			`{"action":"drop","dst_ip":"10.0.0.1","decoder":"bad_fragment"}`,
			"", "",
		},
		{
			"invalid no tcp_flags injection (anomaly path)",
			"invalid",
			`{"action":"drop","dst_ip":"10.0.0.1","decoder":"invalid"}`,
			"", "",
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

// TestSpecializeXDropDecoderBody pins the custom-payload auto-fill
// parallel of specializeXDropDecoder. Covers the 4 shapes:
//   1. anomaly attack + payload without `decoder` → inject decoder
//   2. anomaly attack + stale `protocol=<anomaly>` → strip protocol
//   3. gre/esp/igmp attack + payload without `protocol` → inject protocol
//   4. pass-through for tcp/udp/icmp/fragment/tcp-flag-family/anomaly-
//      with-operator-supplied-decoder (idempotent)
func TestSpecializeXDropDecoderBody(t *testing.T) {
	tests := []struct {
		name         string
		decoder      string
		payload      string
		wantDecoder  string // "" means absent
		wantProtocol string // "" means absent
	}{
		{
			"bad_fragment without decoder → inject decoder=bad_fragment",
			"bad_fragment",
			`{"dst_ip":"192.0.2.1","action":"drop"}`,
			"bad_fragment", "",
		},
		{
			"invalid without decoder → inject decoder=invalid",
			"invalid",
			`{"dst_ip":"192.0.2.1","action":"drop"}`,
			"invalid", "",
		},
		{
			"anomaly with stale protocol=<anomaly> → strip protocol",
			"bad_fragment",
			`{"dst_ip":"192.0.2.1","protocol":"bad_fragment","action":"drop"}`,
			"bad_fragment", "",
		},
		{
			"anomaly with operator-supplied decoder → preserve (idempotent)",
			"bad_fragment",
			`{"dst_ip":"192.0.2.1","decoder":"invalid","action":"drop"}`,
			"invalid", "",
		},
		{
			"gre without protocol → inject protocol=gre",
			"gre",
			`{"dst_ip":"192.0.2.1","action":"drop"}`,
			"", "gre",
		},
		{
			"esp without protocol → inject protocol=esp",
			"esp",
			`{"dst_ip":"192.0.2.1","action":"drop"}`,
			"", "esp",
		},
		{
			"igmp without protocol → inject protocol=igmp",
			"igmp",
			`{"dst_ip":"192.0.2.1","action":"drop"}`,
			"", "igmp",
		},
		{
			"gre with operator-supplied protocol → preserve",
			"gre",
			`{"dst_ip":"192.0.2.1","protocol":"tcp","action":"drop"}`,
			"", "tcp",
		},
		{
			"tcp → pass-through (handled by injectTcpFlags)",
			"tcp",
			`{"dst_ip":"192.0.2.1","action":"drop"}`,
			"", "",
		},
		{
			"udp → pass-through (operator's wildcard is fine)",
			"udp",
			`{"dst_ip":"192.0.2.1","action":"drop"}`,
			"", "",
		},
		{
			"tcp_ack → pass-through (injectTcpFlags's job)",
			"tcp_ack",
			`{"dst_ip":"192.0.2.1","action":"drop"}`,
			"", "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attack := &store.Attack{DecoderFamily: tt.decoder}
			result := specializeXDropDecoderBody([]byte(tt.payload), attack)

			var m map[string]any
			if err := json.Unmarshal(result, &m); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			gotDecoder, hasDecoder := m["decoder"]
			if tt.wantDecoder == "" {
				if hasDecoder {
					t.Errorf("decoder should be absent, got %v", gotDecoder)
				}
			} else if gotDecoder != tt.wantDecoder {
				t.Errorf("decoder = %v, want %q", gotDecoder, tt.wantDecoder)
			}

			gotProto, hasProto := m["protocol"]
			if tt.wantProtocol == "" {
				if hasProto {
					t.Errorf("protocol should be absent, got %v", gotProto)
				}
			} else if gotProto != tt.wantProtocol {
				t.Errorf("protocol = %v, want %q", gotProto, tt.wantProtocol)
			}

			t.Logf("result: %s", string(result))
		})
	}
}

// TestIsAnomalyRateLimitBody pins the late dispatch gate used by
// executeXDrop (P2 fix). A custom payload can inject "action":"rate_limit"
// even when act.XDropAction=filter_l4 — the engine.go gate wouldn't see
// that, only this body-level check does.
func TestIsAnomalyRateLimitBody(t *testing.T) {
	tests := []struct {
		name    string
		decoder string
		body    string
		want    bool
	}{
		{"bad_fragment + action=rate_limit → true", "bad_fragment", `{"action":"rate_limit","rate_limit":5000}`, true},
		{"invalid + action=rate_limit → true", "invalid", `{"action":"rate_limit","rate_limit":5000}`, true},
		{"bad_fragment + action=drop → false", "bad_fragment", `{"action":"drop"}`, false},
		{"invalid + action=drop → false", "invalid", `{"action":"drop"}`, false},
		{"udp + action=rate_limit → false (non-anomaly)", "udp", `{"action":"rate_limit","rate_limit":5000}`, false},
		{"tcp_syn + action=rate_limit → false", "tcp_syn", `{"action":"rate_limit","rate_limit":5000}`, false},
		{"bad_fragment + no action key → false", "bad_fragment", `{"dst_ip":"192.0.2.1"}`, false},
		{"bad_fragment + malformed JSON → false", "bad_fragment", `not-json`, false},
		{"bad_fragment + action as non-string → false", "bad_fragment", `{"action":42}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAnomalyRateLimitBody([]byte(tt.body), tt.decoder)
			if got != tt.want {
				t.Errorf("isAnomalyRateLimitBody(%q, decoder=%q) = %v, want %v", tt.body, tt.decoder, got, tt.want)
			}
		})
	}
}

// TestCustomPayloadPipeline_AnomalyAutoInjectsDecoder pins the full
// custom-payload pipeline for anomaly attacks: operator writes a minimal
// payload without decoder/protocol, and the pipeline (normalize +
// injectTcpFlags + specializeXDropDecoderBody) auto-fills `decoder` so
// xdrop v2.6.1 actually applies the anomaly match_anomaly bit.
//
// Without specializeXDropDecoderBody this would dispatch a wildcard
// rule that xdrop 400-rejects (or worse, silently wildcards all packets
// to dst_ip). Codex v1.3.x audit P1 caught this gap.
func TestCustomPayloadPipeline_AnomalyAutoInjectsDecoder(t *testing.T) {
	customPayload := `{"dst_ip":"{dst_ip}","action":"drop","source":"xsight"}`
	attack := &store.Attack{
		ID:            101,
		DstIP:         "192.0.2.5/32",
		DecoderFamily: "bad_fragment",
		AttackType:    "anomaly_pod",
	}

	expanded := expandParams(customPayload, attack, "attack_start", "192.0.2.0/24", nil)
	body, err := fixPayloadTypes([]byte(expanded))
	if err != nil {
		body = []byte(expanded)
	}
	body = normalizeXDropProtocol(body)
	body = injectTcpFlags(body, attack)
	body = specializeXDropDecoderBody(body, attack)

	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("final body not valid JSON: %v", err)
	}
	if m["decoder"] != "bad_fragment" {
		t.Errorf("decoder = %v, want bad_fragment (pipeline should auto-inject)", m["decoder"])
	}
	if _, has := m["protocol"]; has {
		t.Errorf("protocol should be absent for anomaly attack, got %v", m["protocol"])
	}
}

// TestCustomPayloadPipeline_GREAutoInjectsProtocol pins the parallel for
// gre/esp/igmp: operator writes payload without protocol, pipeline fills
// it in. Guards against the silent-wildcard-rule regression (P1).
func TestCustomPayloadPipeline_GREAutoInjectsProtocol(t *testing.T) {
	customPayload := `{"dst_ip":"{dst_ip}","action":"drop","source":"xsight"}`
	attack := &store.Attack{
		ID:            102,
		DstIP:         "192.0.2.5/32",
		DecoderFamily: "gre",
		AttackType:    "gre_flood",
	}

	expanded := expandParams(customPayload, attack, "attack_start", "192.0.2.0/24", nil)
	body, err := fixPayloadTypes([]byte(expanded))
	if err != nil {
		body = []byte(expanded)
	}
	body = normalizeXDropProtocol(body)
	body = injectTcpFlags(body, attack)
	body = specializeXDropDecoderBody(body, attack)

	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("final body not valid JSON: %v", err)
	}
	if m["protocol"] != "gre" {
		t.Errorf("protocol = %v, want gre (pipeline should auto-inject)", m["protocol"])
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
