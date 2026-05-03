package action

// Bug 1 fix tests: DispatchClass-based sanitizer strips illegal port/protocol
// fields from xDrop payloads for non-L4 decoders.
// See fix-plan-xdrop-port-bgp-schedule-2026-05-02.md §Bug 1.

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/shared/decoder"
)

// A.1.1: Verify that every registered decoder has a valid DispatchClass
// and that the classification matches the design spec.
func TestDispatchClass_Registry(t *testing.T) {
	tests := []struct {
		decoder   string
		wantClass decoder.DispatchClass
	}{
		// Ported
		{"tcp", decoder.Ported},
		{"udp", decoder.Ported},
		{"tcp_syn", decoder.Ported},
		{"tcp_ack", decoder.Ported},
		{"tcp_rst", decoder.Ported},
		{"tcp_fin", decoder.Ported},
		// PortlessProto
		{"icmp", decoder.PortlessProto},
		{"fragment", decoder.PortlessProto},
		{"gre", decoder.PortlessProto},
		{"esp", decoder.PortlessProto},
		{"igmp", decoder.PortlessProto},
		// Anomaly
		{"bad_fragment", decoder.Anomaly},
		{"invalid", decoder.Anomaly},
		// Unsupported
		{"ip", decoder.Unsupported},
		{"ip_other", decoder.Unsupported},
		{"", decoder.Unsupported},
		{"unknown", decoder.Unsupported},
	}
	for _, tt := range tests {
		got := decoder.GetDispatchClass(tt.decoder)
		if got != tt.wantClass {
			t.Errorf("GetDispatchClass(%q) = %v, want %v", tt.decoder, got, tt.wantClass)
		}
	}

	// Dynamic check: every non-empty decoder in the Names registry must have
	// an explicit DispatchClass entry (not fall through to Unsupported),
	// except ip_other which is intentionally Unsupported.
	allowedUnsupported := map[string]bool{"ip_other": true}
	for _, name := range decoder.Names {
		if name == "" {
			continue
		}
		if decoder.GetDispatchClass(name) == decoder.Unsupported && !allowedUnsupported[name] {
			t.Errorf("registered decoder %q has no explicit dispatch class (got Unsupported); "+
				"add it to decoderDispatchClass in decoder.go", name)
		}
	}
}

// A.1.2: PortlessProto decoders must have src_port, dst_port, tcp_flags stripped.
func TestSanitizeXDropPayload_PortlessProto(t *testing.T) {
	portlessDecoders := []string{"gre", "esp", "igmp", "icmp", "fragment"}

	for _, dec := range portlessDecoders {
		t.Run(dec, func(t *testing.T) {
			inputJSON := fmt.Sprintf(
				`{"dst_ip":"192.0.2.1","protocol":%q,"dst_port":53,"src_port":1024,"tcp_flags":"SYN"}`,
				dec,
			)
			out := sanitizeXDropPayloadForDecoder([]byte(inputJSON), dec)

			var m map[string]any
			if err := json.Unmarshal(out, &m); err != nil {
				t.Fatalf("unmarshal: %v (payload: %s)", err, out)
			}

			for _, forbiddenKey := range []string{"src_port", "dst_port", "tcp_flags"} {
				if _, exists := m[forbiddenKey]; exists {
					t.Errorf("[%s] %q must be stripped, but found in: %s", dec, forbiddenKey, out)
				}
			}

			if m["dst_ip"] != "192.0.2.1" {
				t.Errorf("[%s] dst_ip should be preserved, got %v", dec, m["dst_ip"])
			}
			if _, exists := m["protocol"]; !exists {
				t.Errorf("[%s] protocol field should still be present after sanitize", dec)
			}
		})
	}
}

// A.1.3: Anomaly decoders must have protocol, src_port, dst_port, tcp_flags stripped.
// The decoder= field must be preserved.
func TestSanitizeXDropPayload_Anomaly(t *testing.T) {
	anomalyDecoders := []string{"bad_fragment", "invalid"}

	for _, dec := range anomalyDecoders {
		t.Run(dec, func(t *testing.T) {
			inputJSON := fmt.Sprintf(
				`{"dst_ip":"192.0.2.1","protocol":"tcp","decoder":%q,"dst_port":80,"src_port":443,"tcp_flags":"SYN,!ACK"}`,
				dec,
			)
			out := sanitizeXDropPayloadForDecoder([]byte(inputJSON), dec)

			var m map[string]any
			if err := json.Unmarshal(out, &m); err != nil {
				t.Fatalf("unmarshal: %v (payload: %s)", err, out)
			}

			for _, forbiddenKey := range []string{"protocol", "src_port", "dst_port", "tcp_flags"} {
				if _, exists := m[forbiddenKey]; exists {
					t.Errorf("[%s] %q must be stripped, found in: %s", dec, forbiddenKey, out)
				}
			}

			if m["decoder"] != dec {
				t.Errorf("[%s] decoder field should be preserved as %q, got %v", dec, dec, m["decoder"])
			}
			if m["dst_ip"] != "192.0.2.1" {
				t.Errorf("[%s] dst_ip should be preserved", dec)
			}
		})
	}
}

// A.1.4: Ported (TCP/UDP) payloads must keep port and tcp_flags values.
// DNS/NTP reflection and TCP-flag rules must not be broken.
func TestSanitizeXDropPayload_Ported_PreservesFields(t *testing.T) {
	tests := []struct {
		name         string
		decoder      string
		input        string
		wantDstPort  any
		wantSrcPort  any
		wantTcpFlags string
	}{
		{
			name:        "udp DNS reflection — src_port and dst_port preserved",
			decoder:     "udp",
			input:       `{"dst_ip":"192.0.2.1","protocol":"udp","src_port":53,"dst_port":12345}`,
			wantSrcPort: float64(53),
			wantDstPort: float64(12345),
		},
		{
			name:        "tcp — both ports preserved",
			decoder:     "tcp",
			input:       `{"dst_ip":"192.0.2.1","protocol":"tcp","dst_port":80}`,
			wantDstPort: float64(80),
		},
		{
			name:         "tcp_syn — ports + tcp_flags preserved",
			decoder:      "tcp_syn",
			input:        `{"dst_ip":"192.0.2.1","protocol":"tcp","tcp_flags":"SYN,!ACK","dst_port":443}`,
			wantDstPort:  float64(443),
			wantTcpFlags: "SYN,!ACK",
		},
		{
			name:         "tcp_ack — ACK flag preserved",
			decoder:      "tcp_ack",
			input:        `{"dst_ip":"192.0.2.1","protocol":"tcp","tcp_flags":"ACK,!SYN"}`,
			wantTcpFlags: "ACK,!SYN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := sanitizeXDropPayloadForDecoder([]byte(tt.input), tt.decoder)

			var m map[string]any
			if err := json.Unmarshal(out, &m); err != nil {
				t.Fatalf("unmarshal: %v (payload: %s)", err, out)
			}

			if tt.wantDstPort != nil {
				if m["dst_port"] != tt.wantDstPort {
					t.Errorf("dst_port = %v, want %v", m["dst_port"], tt.wantDstPort)
				}
			}
			if tt.wantSrcPort != nil {
				if m["src_port"] != tt.wantSrcPort {
					t.Errorf("src_port = %v, want %v", m["src_port"], tt.wantSrcPort)
				}
			}
			if tt.wantTcpFlags != "" {
				if m["tcp_flags"] != tt.wantTcpFlags {
					t.Errorf("tcp_flags = %v, want %q", m["tcp_flags"], tt.wantTcpFlags)
				}
			}
		})
	}
}

// A.1.5: Full pipeline GRE — reproduces the prod bug scenario.
// GRE attack, DNS traffic on same IP sets DominantDstPort=53.
// The final dispatched body must have no dst_port.
func TestSanitizeXDropPayload_FullPipeline_GRE(t *testing.T) {
	attack := &store.Attack{
		ID:            999,
		DstIP:         "192.0.2.100/32",
		DecoderFamily: "gre",
		AttackType:    "gre_flood",
	}
	flowAnalysis := &FlowAnalysis{
		DominantDstPort: 53,
		DominantSrcPort: 1024,
	}
	customPayload := `{"dst_ip":"{dst_ip}","action":"drop","dst_port":{dominant_dst_port}}`

	expanded := expandParams(customPayload, attack, "attack_start", "192.0.2.100/32", flowAnalysis)
	body, err := fixPayloadTypes([]byte(expanded))
	if err != nil {
		t.Fatalf("fixPayloadTypes: %v", err)
	}
	body = normalizeXDropProtocol(body)
	body = injectTcpFlags(body, attack)
	body = specializeXDropDecoderBody(body, attack)
	body = sanitizeXDropPayloadForDecoder(body, attack.DecoderFamily)

	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal final payload: %v (body: %s)", err, body)
	}

	t.Logf("final GRE payload: %s", body)

	if _, exists := m["dst_port"]; exists {
		t.Errorf("dst_port must be stripped for GRE, found in payload: %s", body)
	}
	if _, exists := m["src_port"]; exists {
		t.Errorf("src_port must be stripped for GRE, found in payload: %s", body)
	}
	if m["protocol"] != "gre" {
		t.Errorf("protocol = %v, want \"gre\"", m["protocol"])
	}
}

// A.1.6: Full pipeline ICMP — also portless. ICMP with {dominant_src_port}
// expanded must have src_port stripped.
func TestSanitizeXDropPayload_FullPipeline_ICMP(t *testing.T) {
	attack := &store.Attack{
		ID:            1000,
		DstIP:         "192.0.2.200/32",
		DecoderFamily: "icmp",
		AttackType:    "icmp_flood",
	}
	flowAnalysis := &FlowAnalysis{
		DominantSrcPort: 53,
		DominantDstPort: 1024,
	}
	customPayload := `{"dst_ip":"{dst_ip}","action":"drop","src_port":{dominant_src_port}}`

	expanded := expandParams(customPayload, attack, "attack_start", "192.0.2.200/32", flowAnalysis)
	body, err := fixPayloadTypes([]byte(expanded))
	if err != nil {
		t.Fatalf("fixPayloadTypes: %v", err)
	}
	body = normalizeXDropProtocol(body)
	body = injectTcpFlags(body, attack)
	body = specializeXDropDecoderBody(body, attack)
	body = sanitizeXDropPayloadForDecoder(body, attack.DecoderFamily)

	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal: %v (body: %s)", err, body)
	}

	if _, exists := m["src_port"]; exists {
		t.Errorf("src_port must be stripped for ICMP, found: %s", body)
	}
	if _, exists := m["dst_port"]; exists {
		t.Errorf("dst_port must be stripped for ICMP, found: %s", body)
	}
}

// A.1.7: ip/ip_other are gated out at engine.go and never reach the sanitizer.
// Verify the sanitizer doesn't break if called with these decoders — it should
// leave the body unchanged (Unsupported = no-op).
func TestSanitizeXDropPayload_IPAndIPOther_NotAffected(t *testing.T) {
	input := `{"dst_ip":"192.0.2.1","action":"drop"}`
	for _, dec := range []string{"ip", "ip_other"} {
		out := sanitizeXDropPayloadForDecoder([]byte(input), dec)
		var mIn, mOut map[string]any
		if err := json.Unmarshal([]byte(input), &mIn); err != nil {
			t.Fatalf("unmarshal input: %v", err)
		}
		if err := json.Unmarshal(out, &mOut); err != nil {
			t.Errorf("[%s] sanitizer corrupted body: %v (out: %s)", dec, err, out)
			continue
		}
		for k, vIn := range mIn {
			if mOut[k] != vIn {
				t.Errorf("[%s] key %q changed: got %v, want %v", dec, k, mOut[k], vIn)
			}
		}
		if len(mOut) != len(mIn) {
			t.Errorf("[%s] output has %d keys, input had %d — sanitizer added or removed keys", dec, len(mOut), len(mIn))
		}
	}
}

// A.1.8: Regression — adding DispatchClass must not accidentally remove
// ip/ip_other from the existing xDropCompatibleDecoders gate.
func TestXDropSkip_IPDecoder_StillSkipped(t *testing.T) {
	for _, dec := range []string{"ip", "ip_other"} {
		if IsXDropCompatibleDecoder(dec) {
			t.Errorf("IsXDropCompatibleDecoder(%q) returned true after registry refactor; "+
				"ip/ip_other must remain ineligible for xDrop", dec)
		}
	}
}
