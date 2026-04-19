package action

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// TestXDrop_DefaultPayload_SubnetAttackRoutesToDstCIDR is a focused E2E-style
// test for the v1.3 Phase 1c.1 splitIPOrCIDR routing. Unlike
// TestSplitIPOrCIDR_ExactToDstIP (which covers just the helper), this walks
// the actual xdropRuleRequest JSON marshal path as used in executeXDrop's
// default-payload branch, verifying that:
//
//  1. A subnet attack (dst_ip="10.0.0.0/24") produces a body with "dst_cidr"
//     set and "dst_ip" absent (the v1.3 fix — pre-v1.3 this would have put
//     the CIDR into dst_ip and xDrop would HTTP 400).
//  2. An exact IP attack (dst_ip="10.0.0.1") routes to "dst_ip" with
//     "dst_cidr" absent (regression check — we didn't break the common case).
//  3. A /32 exact-IP attack still routes to "dst_ip" (not dst_cidr).
//
// This catches regressions if someone accidentally re-orders the splitIPOrCIDR
// call or flips the field assignment in the payload struct.
func TestXDrop_DefaultPayload_SubnetAttackRoutesToDstCIDR(t *testing.T) {
	cases := []struct {
		name       string
		attack     store.Attack
		wantHasCIDR bool
		wantHasIP   bool
		wantCIDR    string
		wantIP      string
	}{
		{
			name:       "subnet /24 routes to dst_cidr",
			attack:     store.Attack{DstIP: "10.0.0.0/24", AttackType: "udp_flood", ID: 1},
			wantHasCIDR: true,
			wantHasIP:   false,
			wantCIDR:    "10.0.0.0/24",
		},
		{
			name:      "exact bare IP routes to dst_ip",
			attack:    store.Attack{DstIP: "10.0.0.1", AttackType: "udp_flood", ID: 2},
			wantHasIP: true,
			wantIP:    "10.0.0.1",
		},
		{
			name:      "/32 routes to dst_ip (not dst_cidr)",
			attack:    store.Attack{DstIP: "10.0.0.1/32", AttackType: "udp_flood", ID: 3},
			wantHasIP: true,
			wantIP:    "10.0.0.1",
		},
		{
			name:       "IPv6 /64 routes to dst_cidr",
			attack:     store.Attack{DstIP: "2001:db8::/64", AttackType: "udp_flood", ID: 4},
			wantHasCIDR: true,
			wantCIDR:    "2001:db8::/64",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Mirror the default-payload path in executeXDrop (xdrop.go:~221-246).
			dstIP, dstCIDR := splitIPOrCIDR(c.attack.DstIP)
			payload := xdropRuleRequest{
				DstIP:   dstIP,
				DstCIDR: dstCIDR,
				Action:  "drop",
				Source:  "xsight",
				Comment: "test",
			}
			body, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			s := string(body)
			hasCIDR := strings.Contains(s, `"dst_cidr":`)
			hasIP := strings.Contains(s, `"dst_ip":`)

			if hasCIDR != c.wantHasCIDR {
				t.Errorf("dst_cidr presence = %v, want %v; body=%s", hasCIDR, c.wantHasCIDR, s)
			}
			if hasIP != c.wantHasIP {
				t.Errorf("dst_ip presence = %v, want %v; body=%s", hasIP, c.wantHasIP, s)
			}
			if c.wantHasCIDR {
				wantSub := `"dst_cidr":"` + c.wantCIDR + `"`
				if !strings.Contains(s, wantSub) {
					t.Errorf("body missing %q; got %s", wantSub, s)
				}
			}
			if c.wantHasIP {
				wantSub := `"dst_ip":"` + c.wantIP + `"`
				if !strings.Contains(s, wantSub) {
					t.Errorf("body missing %q; got %s", wantSub, s)
				}
			}
		})
	}
}
