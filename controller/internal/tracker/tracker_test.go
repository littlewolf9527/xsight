package tracker

import (
	"testing"

	"github.com/littlewolf9527/xsight/shared/decoder"
)

// TestDecoderToAttackType_AllRegisteredDecodersMapped guards the gap that
// shipped through v1.3.0–v1.3.2: when a new decoder lands in
// shared/decoder.Names but tracker.go's switch isn't extended, every attack
// on that decoder ends up with attack_type="unknown" — breaking
// attack_type preconditions silently.
//
// Asserting that every non-empty Names entry maps to something other than
// "unknown" catches the next time someone forgets to update both.
func TestDecoderToAttackType_AllRegisteredDecodersMapped(t *testing.T) {
	for i, name := range decoder.Names {
		if name == "" {
			continue
		}
		got := decoderToAttackType(name)
		if got == "unknown" {
			t.Errorf("decoder.Names[%d]=%q has no attack_type mapping in tracker.go (got %q) — extend decoderToAttackType", i, name, got)
		}
	}
}

func TestDecoderToAttackType_KnownMappings(t *testing.T) {
	cases := []struct {
		decoder string
		want    string
	}{
		{"tcp", "tcp_flood"},
		{"tcp_syn", "syn_flood"},
		{"tcp_ack", "ack_flood"},
		{"tcp_rst", "rst_flood"},
		{"tcp_fin", "fin_flood"},
		{"udp", "udp_flood"},
		{"icmp", "icmp_flood"},
		{"fragment", "fragment_flood"},
		{"gre", "gre_flood"},
		{"esp", "esp_flood"},
		{"igmp", "igmp_flood"},
		{"ip", "volumetric_generic"},
		{"ip_other", "volumetric_other"},
		{"bad_fragment", "bad_fragment_flood"},
		{"invalid", "invalid_packet_flood"},
		{"unknown_decoder", "unknown"}, // unmapped → unknown is the documented fallback
		{"", "unknown"},
	}
	for _, c := range cases {
		got := decoderToAttackType(c.decoder)
		if got != c.want {
			t.Errorf("decoderToAttackType(%q) = %q, want %q", c.decoder, got, c.want)
		}
	}
}
