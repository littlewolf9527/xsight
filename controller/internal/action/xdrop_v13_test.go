package action

// v1.3 Phase 1c tests for carpet-bombing dst_cidr routing.
//
// Note: the syn_cookie-related tests from an earlier iteration of Phase 1c were
// removed on 2026-04-20 along with the syn_cookie scope (xSight's scrub-and-return
// xdrop topology cannot support stateless SYN cookie without synproxy-style
// state that contradicts pure-XDP). carpet_bomb precondition + splitIPOrCIDR
// remain because they stand alone — they fix a previously-silent failure where
// subnet-scope attacks dispatched dst_ip="10.0.0.0/24" and xdrop rejected them
// with HTTP 400.

import (
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// TestSplitIPOrCIDR_ExactToDstIP covers the v1.3 Phase 1c.1 splitter: exact
// IPs (including /32 and /128) route to dst_ip; CIDR ranges route to dst_cidr.
func TestSplitIPOrCIDR_ExactToDstIP(t *testing.T) {
	cases := []struct {
		in       string
		wantIP   string
		wantCIDR string
	}{
		{"10.0.0.1", "10.0.0.1", ""},
		{"10.0.0.1/32", "10.0.0.1", ""},
		{"10.0.0.0/24", "", "10.0.0.0/24"},
		{"192.168.0.0/16", "", "192.168.0.0/16"},
		{"2001:db8::1", "2001:db8::1", ""},
		{"2001:db8::1/128", "2001:db8::1", ""},
		{"2001:db8::/64", "", "2001:db8::/64"},
	}
	for _, c := range cases {
		gotIP, gotCIDR := splitIPOrCIDR(c.in)
		if gotIP != c.wantIP || gotCIDR != c.wantCIDR {
			t.Errorf("splitIPOrCIDR(%q) = (%q, %q), want (%q, %q)",
				c.in, gotIP, gotCIDR, c.wantIP, c.wantCIDR)
		}
	}
}

// TestEvaluatePrecondition_CarpetBomb asserts the `carpet_bomb` precondition
// fires on subnet-scope attacks (v1.3 Phase 1c.1).
func TestEvaluatePrecondition_CarpetBomb(t *testing.T) {
	subnetAttack := &store.Attack{DstIP: "10.0.0.0/24"}
	ipAttack := &store.Attack{DstIP: "10.0.0.5"}
	ipSlash32 := &store.Attack{DstIP: "10.0.0.5/32"}

	cases := []struct {
		name    string
		attack  *store.Attack
		op, val string
		want    bool
	}{
		{"subnet matches eq true", subnetAttack, "eq", "true", true},
		{"subnet matches eq false", subnetAttack, "eq", "false", false},
		{"subnet neq true", subnetAttack, "neq", "true", false},
		{"single IP does not carpet bomb", ipAttack, "eq", "true", false},
		{"single IP /32 does not carpet bomb", ipSlash32, "eq", "true", false},
		{"single IP eq false passes", ipAttack, "eq", "false", true},
		{"subnet matches eq 1", subnetAttack, "eq", "1", true},
		{"subnet matches eq yes", subnetAttack, "eq", "yes", true},
		{"subnet matches eq True (case-insensitive)", subnetAttack, "eq", "True", true},
		{"unsupported operator blocks", subnetAttack, "in", "true", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := store.ActionPrecondition{Attribute: "carpet_bomb", Operator: c.op, Value: c.val}
			got := evaluateStructuredPrecondition(p, c.attack, "", func() *FlowAnalysis { return nil })
			if got != c.want {
				t.Errorf("got=%v want=%v for op=%q val=%q on dst=%q",
					got, c.want, c.op, c.val, c.attack.DstIP)
			}
		})
	}
}
