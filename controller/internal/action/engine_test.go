package action

import (
	"encoding/json"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// --- phaseMatchesEvent ---

func TestPhaseMatchesEvent_OnDetected(t *testing.T) {
	tests := []struct {
		event string
		want  bool
	}{
		{"confirmed", true},
		{"type_upgrade", true},
		{"updated", true},
		{"expired", false},
		{"evicted", false},
	}
	for _, tt := range tests {
		got := phaseMatchesEvent("on_detected", tt.event)
		if got != tt.want {
			t.Errorf("phaseMatchesEvent(on_detected, %q) = %v, want %v", tt.event, got, tt.want)
		}
	}
}

func TestPhaseMatchesEvent_OnExpired(t *testing.T) {
	tests := []struct {
		event string
		want  bool
	}{
		{"expired", true},
		{"evicted", true},
		{"confirmed", false},
		{"updated", false},
		{"type_upgrade", false},
	}
	for _, tt := range tests {
		got := phaseMatchesEvent("on_expired", tt.event)
		if got != tt.want {
			t.Errorf("phaseMatchesEvent(on_expired, %q) = %v, want %v", tt.event, got, tt.want)
		}
	}
}

// --- policyMatchesEvent ---

func TestPolicyMatchesEvent(t *testing.T) {
	tests := []struct {
		policy string
		event  string
		want   bool
	}{
		{"once_on_enter", "confirmed", true},
		{"once_on_enter", "type_upgrade", true},
		{"once_on_enter", "expired", false},
		{"once_on_enter", "updated", false},
		{"once_on_exit", "expired", true},
		{"once_on_exit", "evicted", true},
		{"once_on_exit", "confirmed", false},
		{"periodic", "confirmed", true},
		{"periodic", "updated", true},
		{"periodic", "type_upgrade", true},
		{"periodic", "expired", false},
		{"retry_until_success", "confirmed", true},
		{"retry_until_success", "type_upgrade", true},
		{"retry_until_success", "expired", false},
	}
	for _, tt := range tests {
		got := policyMatchesEvent(tt.policy, tt.event)
		if got != tt.want {
			t.Errorf("policyMatchesEvent(%q, %q) = %v, want %v", tt.policy, tt.event, got, tt.want)
		}
	}
}

// --- evaluatePreconditions ---

func TestEvaluatePreconditions_Empty(t *testing.T) {
	attack := &store.Attack{}
	if !evaluatePreconditions(nil, attack, "") {
		t.Error("nil preconditions should return true")
	}
	if !evaluatePreconditions(json.RawMessage(`null`), attack, "") {
		t.Error("null preconditions should return true")
	}
	if !evaluatePreconditions(json.RawMessage(``), attack, "") {
		t.Error("empty preconditions should return true")
	}
}

func TestEvaluatePreconditions_SeverityMatch(t *testing.T) {
	attack := &store.Attack{Severity: "high"}
	conds := json.RawMessage(`{"severity": "high"}`)
	if !evaluatePreconditions(conds, attack, "") {
		t.Error("severity=high should match attack with severity=high")
	}
}

func TestEvaluatePreconditions_SeverityMismatch(t *testing.T) {
	attack := &store.Attack{Severity: "low"}
	conds := json.RawMessage(`{"severity": "high"}`)
	if evaluatePreconditions(conds, attack, "") {
		t.Error("severity=high should NOT match attack with severity=low")
	}
}

func TestEvaluatePreconditions_PeakPPS(t *testing.T) {
	attack := &store.Attack{PeakPPS: 50000}
	// >=10000 should match
	conds := json.RawMessage(`{"peak_pps": ">=10000"}`)
	if !evaluatePreconditions(conds, attack, "") {
		t.Error("peak_pps>=10000 should match attack with peak_pps=50000")
	}
	// >=100000 should NOT match
	conds = json.RawMessage(`{"peak_pps": ">=100000"}`)
	if evaluatePreconditions(conds, attack, "") {
		t.Error("peak_pps>=100000 should NOT match attack with peak_pps=50000")
	}
	// <60000 should match
	conds = json.RawMessage(`{"peak_pps": "<60000"}`)
	if !evaluatePreconditions(conds, attack, "") {
		t.Error("peak_pps<60000 should match attack with peak_pps=50000")
	}
}

func TestEvaluatePreconditions_UnknownField(t *testing.T) {
	attack := &store.Attack{}
	conds := json.RawMessage(`{"nonexistent_field": "value"}`)
	if evaluatePreconditions(conds, attack, "") {
		t.Error("unknown field should fail closed (return false)")
	}
}

// --- v2 structured precondition tests ---

func noFA() *FlowAnalysis { return nil }

func withFA(fa *FlowAnalysis) func() *FlowAnalysis {
	return func() *FlowAnalysis { return fa }
}

// Single precondition — string attributes

func TestStructuredPrecondition_DecoderEq(t *testing.T) {
	attack := &store.Attack{DecoderFamily: "udp"}
	p := store.ActionPrecondition{Attribute: "decoder", Operator: "eq", Value: "udp"}
	if !evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("decoder eq udp should match")
	}
	p.Value = "tcp"
	if evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("decoder eq tcp should NOT match udp attack")
	}
}

func TestStructuredPrecondition_DecoderNeq(t *testing.T) {
	attack := &store.Attack{DecoderFamily: "udp"}
	p := store.ActionPrecondition{Attribute: "decoder", Operator: "neq", Value: "tcp"}
	if !evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("decoder neq tcp should match udp attack")
	}
	p.Value = "udp"
	if evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("decoder neq udp should NOT match udp attack")
	}
}

func TestStructuredPrecondition_DecoderIn(t *testing.T) {
	attack := &store.Attack{DecoderFamily: "tcp_syn"}
	p := store.ActionPrecondition{Attribute: "decoder", Operator: "in", Value: "tcp,tcp_syn"}
	if !evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("decoder in tcp,tcp_syn should match tcp_syn")
	}
	p.Value = "udp,icmp"
	if evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("decoder in udp,icmp should NOT match tcp_syn")
	}
}

func TestStructuredPrecondition_DecoderNotIn(t *testing.T) {
	attack := &store.Attack{DecoderFamily: "icmp"}
	p := store.ActionPrecondition{Attribute: "decoder", Operator: "not_in", Value: "tcp,udp"}
	if !evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("decoder not_in tcp,udp should match icmp")
	}
	p.Value = "icmp,fragment"
	if evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("decoder not_in icmp,fragment should NOT match icmp")
	}
}

func TestStructuredPrecondition_SeverityEq(t *testing.T) {
	attack := &store.Attack{Severity: "critical"}
	p := store.ActionPrecondition{Attribute: "severity", Operator: "eq", Value: "critical"}
	if !evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("severity eq critical should match")
	}
	p.Value = "low"
	if evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("severity eq low should NOT match critical")
	}
}

func TestStructuredPrecondition_AttackTypeIn(t *testing.T) {
	attack := &store.Attack{AttackType: "dns_reflection"}
	p := store.ActionPrecondition{Attribute: "attack_type", Operator: "in", Value: "dns_reflection,ntp_reflection"}
	if !evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("attack_type in dns_reflection,ntp_reflection should match")
	}
	p.Value = "syn_flood,tcp_flood"
	if evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("attack_type in syn_flood,tcp_flood should NOT match dns_reflection")
	}
}

func TestStructuredPrecondition_Domain(t *testing.T) {
	// /32 = internal_ip
	attack := &store.Attack{DstIP: "10.0.0.1"}
	p := store.ActionPrecondition{Attribute: "domain", Operator: "eq", Value: "internal_ip"}
	if !evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("domain eq internal_ip should match single IP")
	}
	// /24 = subnet
	attack.DstIP = "10.0.0.0/24"
	p.Value = "subnet"
	if !evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("domain eq subnet should match CIDR")
	}
	p.Value = "internal_ip"
	if evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("domain eq internal_ip should NOT match CIDR")
	}
	// /32 suffix from postgres inet::TEXT — must still be internal_ip (bug fix: #492)
	attack.DstIP = "198.51.100.5/32"
	p.Value = "internal_ip"
	if !evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("domain eq internal_ip should match /32 (single IP from DB)")
	}
	p.Value = "subnet"
	if evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("domain eq subnet should NOT match /32")
	}
	// /128 IPv6 single IP
	attack.DstIP = "2001:db8::1/128"
	p.Value = "internal_ip"
	if !evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("domain eq internal_ip should match /128 (IPv6 single IP)")
	}
}

func TestAttackDomain(t *testing.T) {
	tests := []struct {
		dstIP string
		want  string
	}{
		{"10.0.0.1", "internal_ip"},            // bare IP (in-memory)
		{"198.51.100.5/32", "internal_ip"},      // postgres inet::TEXT IPv4
		{"2001:db8::1/128", "internal_ip"},      // postgres inet::TEXT IPv6
		{"10.0.0.0/24", "subnet"},               // subnet attack
		{"2001:db8::/32", "subnet"},             // IPv6 subnet
		{"192.168.0.0/16", "subnet"},            // large CIDR
	}
	for _, tt := range tests {
		if got := attackDomain(tt.dstIP); got != tt.want {
			t.Errorf("attackDomain(%q) = %q, want %q", tt.dstIP, got, tt.want)
		}
	}
}

func TestLegacyCheckCondition_Domain(t *testing.T) {
	// Legacy path: checkCondition("domain", expr, attack, prefix)
	// Must handle /32 from DB the same way as structured precondition
	attack := &store.Attack{DstIP: "198.51.100.5/32"}
	if !checkCondition("domain", "internal_ip", attack, "") {
		t.Error("legacy: /32 should be internal_ip")
	}
	if checkCondition("domain", "subnet", attack, "") {
		t.Error("legacy: /32 should NOT be subnet")
	}
	attack.DstIP = "2001:db8::1/128"
	if !checkCondition("domain", "internal_ip", attack, "") {
		t.Error("legacy: /128 should be internal_ip")
	}
	attack.DstIP = "10.0.0.0/24"
	if !checkCondition("domain", "subnet", attack, "") {
		t.Error("legacy: /24 should be subnet")
	}
	if checkCondition("domain", "internal_ip", attack, "") {
		t.Error("legacy: /24 should NOT be internal_ip")
	}
}

func TestStructuredPrecondition_NodeIn(t *testing.T) {
	attack := &store.Attack{NodeSources: []string{"sg-mirror-01", "hk-mirror-01"}}
	p := store.ActionPrecondition{Attribute: "node", Operator: "in", Value: "sg-mirror-01"}
	if !evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("node in sg-mirror-01 should match")
	}
	p.Value = "us-node-01"
	if evaluateStructuredPrecondition(p, attack, "", noFA) {
		t.Error("node in us-node-01 should NOT match")
	}
}

// Single precondition — int attributes

func TestStructuredPrecondition_PPS(t *testing.T) {
	attack := &store.Attack{PeakPPS: 5000}
	tests := []struct {
		op, val string
		want    bool
	}{
		{"gt", "1000", true},
		{"gt", "5000", false},
		{"gte", "5000", true},
		{"lt", "10000", true},
		{"lt", "5000", false},
		{"lte", "5000", true},
		{"eq", "5000", true},
		{"eq", "4999", false},
		{"neq", "4999", true},
		{"neq", "5000", false},
		{"in", "1000,5000,10000", true},
		{"in", "1000,2000", false},
		{"not_in", "1000,2000", true},
		{"not_in", "5000,10000", false},
	}
	for _, tt := range tests {
		p := store.ActionPrecondition{Attribute: "pps", Operator: tt.op, Value: tt.val}
		got := evaluateStructuredPrecondition(p, attack, "", noFA)
		if got != tt.want {
			t.Errorf("pps %s %s (actual=5000): got %v, want %v", tt.op, tt.val, got, tt.want)
		}
	}
}

// Single precondition — flow attributes

func TestStructuredPrecondition_DominantSrcPort(t *testing.T) {
	fa := &FlowAnalysis{DominantSrcPort: 53, DominantSrcPortPct: 95}
	getFA := withFA(fa)

	// in — match known reflection port
	p := store.ActionPrecondition{Attribute: "dominant_src_port", Operator: "in", Value: "53,123,11211"}
	if !evaluateStructuredPrecondition(p, &store.Attack{}, "", getFA) {
		t.Error("dominant_src_port in 53,123,11211 should match (actual=53)")
	}

	// in — no match
	p.Value = "123,11211"
	if evaluateStructuredPrecondition(p, &store.Attack{}, "", getFA) {
		t.Error("dominant_src_port in 123,11211 should NOT match (actual=53)")
	}

	// not_in — match (not a reflection port)
	fa2 := &FlowAnalysis{DominantSrcPort: 9999}
	p2 := store.ActionPrecondition{Attribute: "dominant_src_port", Operator: "not_in", Value: "53,123,11211"}
	if !evaluateStructuredPrecondition(p2, &store.Attack{}, "", withFA(fa2)) {
		t.Error("dominant_src_port not_in 53,123,11211 should match (actual=9999)")
	}

	// not_in — no match (IS a reflection port)
	p2.Value = "53,123"
	if evaluateStructuredPrecondition(p2, &store.Attack{}, "", getFA) {
		t.Error("dominant_src_port not_in 53,123 should NOT match (actual=53)")
	}

	// pct check
	p3 := store.ActionPrecondition{Attribute: "dominant_src_port_pct", Operator: "gte", Value: "80"}
	if !evaluateStructuredPrecondition(p3, &store.Attack{}, "", getFA) {
		t.Error("dominant_src_port_pct gte 80 should match (actual=95)")
	}
	p3.Value = "99"
	if evaluateStructuredPrecondition(p3, &store.Attack{}, "", getFA) {
		t.Error("dominant_src_port_pct gte 99 should NOT match (actual=95)")
	}
}

func TestStructuredPrecondition_DominantDstPort(t *testing.T) {
	fa := &FlowAnalysis{DominantDstPort: 443, DominantDstPortPct: 88}
	getFA := withFA(fa)

	p := store.ActionPrecondition{Attribute: "dominant_dst_port", Operator: "eq", Value: "443"}
	if !evaluateStructuredPrecondition(p, &store.Attack{}, "", getFA) {
		t.Error("dominant_dst_port eq 443 should match")
	}

	p2 := store.ActionPrecondition{Attribute: "dominant_dst_port_pct", Operator: "gt", Value: "80"}
	if !evaluateStructuredPrecondition(p2, &store.Attack{}, "", getFA) {
		t.Error("dominant_dst_port_pct gt 80 should match (actual=88)")
	}
}

func TestStructuredPrecondition_FlowNil_FailClosed(t *testing.T) {
	// All flow attributes should fail closed when FlowAnalysis is nil
	attrs := []string{"dominant_src_port", "dominant_src_port_pct", "dominant_dst_port", "dominant_dst_port_pct", "unique_src_ips"}
	for _, attr := range attrs {
		p := store.ActionPrecondition{Attribute: attr, Operator: "eq", Value: "1"}
		if evaluateStructuredPrecondition(p, &store.Attack{}, "", noFA) {
			t.Errorf("%s should fail closed when flow data is nil", attr)
		}
	}
}

// Unknown attribute — fail closed

func TestStructuredPrecondition_UnknownAttribute(t *testing.T) {
	p := store.ActionPrecondition{Attribute: "nonexistent", Operator: "eq", Value: "x"}
	if evaluateStructuredPrecondition(p, &store.Attack{}, "", noFA) {
		t.Error("unknown attribute should fail closed")
	}
}

// Multiple preconditions — AND semantics

func TestStructuredPreconditions_MultipleAND_AllPass(t *testing.T) {
	// decoder=udp AND dominant_src_port in 53,123 → both pass
	attack := &store.Attack{DecoderFamily: "udp"}
	fa := &FlowAnalysis{DominantSrcPort: 53}
	preconds := []store.ActionPrecondition{
		{Attribute: "decoder", Operator: "eq", Value: "udp"},
		{Attribute: "dominant_src_port", Operator: "in", Value: "53,123,11211"},
	}
	for _, p := range preconds {
		if !evaluateStructuredPrecondition(p, attack, "", withFA(fa)) {
			t.Errorf("precondition %s %s %s should pass", p.Attribute, p.Operator, p.Value)
		}
	}
}

func TestStructuredPreconditions_MultipleAND_OneFails(t *testing.T) {
	// decoder=udp passes, dominant_src_port in 53,123 fails (actual=9999) → overall fail
	attack := &store.Attack{DecoderFamily: "udp"}
	fa := &FlowAnalysis{DominantSrcPort: 9999}
	preconds := []store.ActionPrecondition{
		{Attribute: "decoder", Operator: "eq", Value: "udp"},
		{Attribute: "dominant_src_port", Operator: "in", Value: "53,123,11211"},
	}
	// First passes
	if !evaluateStructuredPrecondition(preconds[0], attack, "", withFA(fa)) {
		t.Error("decoder eq udp should pass")
	}
	// Second fails → AND semantics means overall fail
	if evaluateStructuredPrecondition(preconds[1], attack, "", withFA(fa)) {
		t.Error("dominant_src_port in 53,123,11211 should fail (actual=9999)")
	}
}

func TestStructuredPreconditions_MultipleAND_FirstFails(t *testing.T) {
	// decoder=tcp fails (actual=udp), even though second would pass → overall fail
	attack := &store.Attack{DecoderFamily: "udp"}
	fa := &FlowAnalysis{DominantSrcPort: 53}
	preconds := []store.ActionPrecondition{
		{Attribute: "decoder", Operator: "eq", Value: "tcp"},
		{Attribute: "dominant_src_port", Operator: "in", Value: "53,123"},
	}
	if evaluateStructuredPrecondition(preconds[0], attack, "", withFA(fa)) {
		t.Error("decoder eq tcp should fail for udp attack")
	}
}

func TestStructuredPreconditions_ThreeConditions(t *testing.T) {
	// decoder=udp AND severity in critical,high AND pps gte 1000
	attack := &store.Attack{DecoderFamily: "udp", Severity: "critical", PeakPPS: 5000}
	preconds := []store.ActionPrecondition{
		{Attribute: "decoder", Operator: "eq", Value: "udp"},
		{Attribute: "severity", Operator: "in", Value: "critical,high"},
		{Attribute: "pps", Operator: "gte", Value: "1000"},
	}
	for _, p := range preconds {
		if !evaluateStructuredPrecondition(p, attack, "", noFA) {
			t.Errorf("precondition %s %s %s should pass", p.Attribute, p.Operator, p.Value)
		}
	}

	// Change severity to low → second condition fails
	attack.Severity = "low"
	if evaluateStructuredPrecondition(preconds[1], attack, "", noFA) {
		t.Error("severity in critical,high should fail for severity=low")
	}
}

// Realistic scenario: reflection vs generic UDP routing

func TestStructuredPreconditions_ReflectionVsGeneric(t *testing.T) {
	// Scenario: DNS reflection attack
	attack := &store.Attack{DecoderFamily: "udp"}
	faReflection := &FlowAnalysis{DominantSrcPort: 53, DominantSrcPortPct: 95}

	// Action 1 preconditions: decoder=udp AND dominant_src_port in 53,123,...
	reflectionPreconds := []store.ActionPrecondition{
		{Attribute: "decoder", Operator: "eq", Value: "udp"},
		{Attribute: "dominant_src_port", Operator: "in", Value: "53,123,11211,1900,389,161"},
	}
	// Action 2 preconditions: decoder=udp (generic fallback)
	genericPreconds := []store.ActionPrecondition{
		{Attribute: "decoder", Operator: "eq", Value: "udp"},
	}

	// For reflection attack: Action 1 should pass, Action 2 also passes (but first-match skips it)
	for _, p := range reflectionPreconds {
		if !evaluateStructuredPrecondition(p, attack, "", withFA(faReflection)) {
			t.Errorf("reflection precondition %s %s %s should pass for DNS reflection", p.Attribute, p.Operator, p.Value)
		}
	}

	// For generic UDP: Action 1 should fail on dominant_src_port, Action 2 should pass
	faGeneric := &FlowAnalysis{DominantSrcPort: 9999, DominantSrcPortPct: 5}
	if evaluateStructuredPrecondition(reflectionPreconds[1], attack, "", withFA(faGeneric)) {
		t.Error("dominant_src_port in 53,123,... should fail for generic flood (src_port=9999)")
	}
	for _, p := range genericPreconds {
		if !evaluateStructuredPrecondition(p, attack, "", withFA(faGeneric)) {
			t.Errorf("generic precondition %s %s %s should pass", p.Attribute, p.Operator, p.Value)
		}
	}
}
