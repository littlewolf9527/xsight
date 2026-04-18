package action

import "testing"

// Synthetic rule IDs are deterministic and round-trip-detectable so the
// unblock path can skip HTTP DELETE for failed-create rows without a schema
// change.
func TestSyntheticFailedXDropRuleID_Deterministic(t *testing.T) {
	a := syntheticFailedXDropRuleID(13634, 117)
	b := syntheticFailedXDropRuleID(13634, 117)
	if a != b {
		t.Errorf("same (attack, action) must yield same synthetic ID; got %q vs %q", a, b)
	}
	if a == "" {
		t.Errorf("synthetic ID should not be empty")
	}
	if !isSyntheticFailedXDropRuleID(a) {
		t.Errorf("synthetic ID %q should be recognized by isSyntheticFailedXDropRuleID", a)
	}
}

func TestSyntheticFailedXDropRuleID_DistinctPerAttackAction(t *testing.T) {
	cases := [][2]int{
		{13634, 117},
		{13634, 119}, // same attack, different action
		{13635, 117}, // same action, different attack
	}
	seen := map[string]bool{}
	for _, c := range cases {
		id := syntheticFailedXDropRuleID(c[0], c[1])
		if seen[id] {
			t.Errorf("duplicate synthetic ID %q for attack=%d action=%d", id, c[0], c[1])
		}
		seen[id] = true
	}
}

func TestIsSyntheticFailedXDropRuleID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"failed-create-13634-117", true},
		{"failed-create-0-0", true},
		{"rule_a1b2c3d4", false},                     // real xDrop rule id
		{"", false},                                   // empty
		{"rule_failed-create-xxx", false},             // prefix not at start
		{"FAILED-CREATE-13634-117", false},            // case-sensitive
		{xDropSyntheticFailedRuleIDPrefix + "x", true}, // minimal valid
	}
	for _, c := range cases {
		if got := isSyntheticFailedXDropRuleID(c.in); got != c.want {
			t.Errorf("isSyntheticFailedXDropRuleID(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
