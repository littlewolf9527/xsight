package action

import "testing"

// isFRRRouteAbsentError must recognize every vtysh error string that means
// "there's nothing here to remove", so xSight can treat the withdraw as
// idempotent success instead of surfacing a spurious failed badge.
func TestIsFRRRouteAbsentError(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		// Known idempotent phrases — verified in production / live test.
		{"classic can't find", "Can't find static route specified", true},
		{"route-map mismatch (L14)", "% route-map name doesn't match static route", true},
		{"embedded in larger output", "Building Configuration...\n% route-map name doesn't match static route\n", true},

		// Generic "not found" wordings that MUST NOT be treated as idempotent
		// — they often indicate real FRR config errors (misspelled route-map,
		// invalid address-family, etc.) that should surface as failed, not
		// silently marked withdrawn. Per PR-7 audit P1.
		{"no such route-map entry — real config error", "% No such route-map entry", false},
		{"route does not exist — real config error", "Route does not exist", false},

		{"empty", "", false},
		{"real failure", "exit status 1: unknown command", false},
		{"syntax error", "% Ambiguous command", false},
		{"permission denied", "Permission denied", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isFRRRouteAbsentError(c.in); got != c.want {
				t.Errorf("isFRRRouteAbsentError(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}
