package tests

// v1.2 Phase 9: tests for BootstrapBGPOrphans.
//
// The bootstrap logic has three layers and each is pinned here:
//   1. Parsers   — parseRunningConfigRoutes + parseBGPRIBPrefixes (pure, fast)
//   2. Repo      — HasOperationalHistory + UpsertOrphan (mock-level)
//   3. End-to-end — orphan status selection (dismissed_on_upgrade vs orphan)
//
// We can't exercise the full BootstrapBGPOrphans() from tests because it
// shells out to vtysh. Tests cover the parsers + repo semantics; an
// integration test on the real box is in the live-test notes.

import (
	"context"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// ─────────────────────────────────────────────────────────────────────────────
// Parser tests
// ─────────────────────────────────────────────────────────────────────────────

func TestParseRunningConfigRoutes_ExtractsNetworksForOurASN(t *testing.T) {
	cfg := `Building configuration...
!
frr defaults traditional
!
router bgp 65000
 bgp router-id 10.0.0.1
 no bgp ebgp-requires-policy
 !
 address-family ipv4 unicast
  network 192.0.2.0/24 route-map BLACKHOLE
  network 192.0.2.1/32 route-map DIVERT
 exit-address-family
 !
 address-family ipv6 unicast
  network 2001:db8::/48 route-map BLACKHOLE
 exit-address-family
!
router bgp 65001
 bgp router-id 10.0.0.2
 !
 address-family ipv4 unicast
  network 203.0.113.0/24 route-map OTHER
 exit-address-family
!
line vty
!
end`

	routes := action.ParseRunningConfigRoutesForTest(cfg, 65000)
	wantKeys := []string{
		"192.0.2.0/24|BLACKHOLE",
		"192.0.2.1/32|DIVERT",
		"2001:db8::/48|BLACKHOLE",
	}
	if len(routes) != 3 {
		t.Fatalf("routes len = %d, want 3: got %+v", len(routes), routes)
	}
	for _, k := range wantKeys {
		if !routes[k] {
			t.Errorf("missing expected route %q; got %+v", k, routes)
		}
	}
	// Other ASN's network must NOT leak into our map.
	if routes["203.0.113.0/24|OTHER"] {
		t.Errorf("route from other BGP block leaked: %+v", routes)
	}
}

func TestParseRunningConfigRoutes_IgnoresPlainNetworkWithoutRouteMap(t *testing.T) {
	cfg := `router bgp 65000
 address-family ipv4 unicast
  network 10.1.1.0/24
  network 192.0.2.0/24 route-map BLACKHOLE
 exit-address-family`
	routes := action.ParseRunningConfigRoutesForTest(cfg, 65000)
	if len(routes) != 1 || !routes["192.0.2.0/24|BLACKHOLE"] {
		t.Errorf("expected only the route-map-tagged network; got %+v", routes)
	}
}

func TestParseBGPRIBPrefixes_ExtractsPresentPrefixes(t *testing.T) {
	out := `BGP table version is 7, local router ID is 10.0.0.1, vrf id 0
Default local pref 100, local AS 65000
Status codes:  s suppressed, d damped, h history, * valid, > best, = multipath,
               i internal, r RIB-failure, S Stale, R Removed
Nexthop codes: @NNN nexthop's vrf id, < announce-nh-self
Origin codes:  i - IGP, e - EGP, ? - incomplete

   Network          Next Hop            Metric LocPrf Weight Path
*> 192.0.2.0/24     0.0.0.0                  0         32768 i
*> 192.0.2.1/32     0.0.0.0                  0         32768 i
*= 203.0.113.0/24   0.0.0.0                  0         32768 i

Displayed  3 routes and 3 total paths`
	got := action.ParseBGPRIBPrefixesForTest(out)
	want := []string{"192.0.2.0/24", "192.0.2.1/32", "203.0.113.0/24"}
	if len(got) != len(want) {
		t.Fatalf("RIB prefixes len = %d, want %d: %+v", len(got), len(want), got)
	}
	for _, p := range want {
		if !got[p] {
			t.Errorf("missing RIB prefix %q; got %+v", p, got)
		}
	}
}

// FRR emits data rows without status codes when the prefix hasn't been
// validated/best-selected (e.g., locally-injected `network X route-map Y`
// with no peer receiving it). The parser must still pick those up — they
// are exactly the "orphan" state we want to surface.
func TestParseBGPRIBPrefixes_HandlesUnstarredRows(t *testing.T) {
	out := `BGP table version is 0, local router ID is 10.0.0.1, vrf id 0
Default local pref 100, local AS 65000
Status codes:  s suppressed, d damped, h history, u unsorted, * valid, > best, = multipath,
               i internal, r RIB-failure, S Stale, R Removed
Origin codes:  i - IGP, e - EGP, ? - incomplete

     Network          Next Hop            Metric LocPrf Weight Path
     192.0.2.0/24     0.0.0.0                  0         32768 i

Displayed 1 routes and 1 total paths`
	got := action.ParseBGPRIBPrefixesForTest(out)
	if !got["192.0.2.0/24"] {
		t.Errorf("unstarred RIB row must still register; got %+v", got)
	}
}

func TestParseBGPRIBPrefixes_IPv6(t *testing.T) {
	out := `BGP table version is 3, local router ID is 10.0.0.1
Status codes: ...
   Network          Next Hop            Metric LocPrf Weight Path
*> 2001:db8::/48    ::                       0         32768 i
*> fd00::/8         ::                       0         32768 i`
	got := action.ParseBGPRIBPrefixesForTest(out)
	if !got["2001:db8::/48"] || !got["fd00::/8"] {
		t.Errorf("missing expected IPv6 prefixes; got %+v", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Repo tests — HasOperationalHistory + UpsertOrphan (mock-level)
// ─────────────────────────────────────────────────────────────────────────────

func TestHasOperationalHistory_EmptyTable_ReturnsFalse(t *testing.T) {
	ms := NewMockStore()
	has, err := ms.BGPAnnouncements().HasOperationalHistory(context.Background())
	if err != nil {
		t.Fatalf("HasOperationalHistory: %v", err)
	}
	if has {
		t.Errorf("expected false on empty table, got true")
	}
}

func TestHasOperationalHistory_OnlyOrphans_ReturnsFalse(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()
	_, _ = ms.BGPAnnouncements().UpsertOrphan(ctx, "192.0.2.0/24", "BLACKHOLE", 1, "orphan")
	_, _ = ms.BGPAnnouncements().UpsertOrphan(ctx, "192.0.2.1/32", "BLACKHOLE", 1, "dismissed_on_upgrade")
	has, _ := ms.BGPAnnouncements().HasOperationalHistory(ctx)
	if has {
		t.Errorf("bootstrap-only rows must not count as history; got true")
	}
}

func TestHasOperationalHistory_ActiveAnnouncement_ReturnsTrue(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()
	_, err := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID:    1,
		Prefix:      "192.0.2.0/24",
		RouteMap:    "BLACKHOLE",
		ConnectorID: 1,
	})
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	has, _ := ms.BGPAnnouncements().HasOperationalHistory(ctx)
	if !has {
		t.Errorf("a real attach must register as history; got false")
	}
}

func TestUpsertOrphan_NoRow_Inserts(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()
	created, err := ms.BGPAnnouncements().UpsertOrphan(ctx, "192.0.2.0/24", "BLACKHOLE", 1, "orphan")
	if err != nil || !created {
		t.Fatalf("expected new orphan to be created: created=%v err=%v", created, err)
	}
	got, _ := ms.BGPAnnouncements().FindByBusinessKey(ctx, "192.0.2.0/24", "BLACKHOLE", 1)
	if got == nil || got.Status != "orphan" {
		t.Errorf("expected inserted row with status=orphan; got %+v", got)
	}
}

func TestUpsertOrphan_ActiveRow_NoOp(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()
	if _, err := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, Prefix: "192.0.2.0/24", RouteMap: "BLACKHOLE", ConnectorID: 1,
	}); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	created, _ := ms.BGPAnnouncements().UpsertOrphan(ctx, "192.0.2.0/24", "BLACKHOLE", 1, "orphan")
	if created {
		t.Errorf("must NOT overwrite an active/announcing row; created=true")
	}
	got, _ := ms.BGPAnnouncements().FindByBusinessKey(ctx, "192.0.2.0/24", "BLACKHOLE", 1)
	if got == nil || got.Status == "orphan" {
		t.Errorf("active row must not be demoted to orphan; got %+v", got)
	}
}

func TestUpsertOrphan_WithdrawnRow_UpgradesToOrphan(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()
	res, err := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, Prefix: "192.0.2.0/24", RouteMap: "BLACKHOLE", ConnectorID: 1,
	})
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	// Drive the row through Detach (→ withdrawing) then MarkWithdrawn to
	// simulate a completed vtysh withdrawal.
	if _, err := ms.BGPAnnouncements().Detach(ctx, 1, "192.0.2.0/24", "BLACKHOLE", 1); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if err := ms.BGPAnnouncements().MarkWithdrawn(ctx, res.AnnouncementID); err != nil {
		t.Fatalf("MarkWithdrawn: %v", err)
	}

	// FRR still has the route → bootstrap re-marks as orphan.
	created, _ := ms.BGPAnnouncements().UpsertOrphan(ctx, "192.0.2.0/24", "BLACKHOLE", 1, "orphan")
	if !created {
		t.Errorf("withdrawn row must be re-surfaced as orphan; created=false")
	}
	got, _ := ms.BGPAnnouncements().FindByBusinessKey(ctx, "192.0.2.0/24", "BLACKHOLE", 1)
	if got == nil || got.Status != "orphan" {
		t.Errorf("status = %v, want orphan; got %+v", got.Status, got)
	}
}

func TestUpsertOrphan_DismissedRow_StaysDismissed(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()
	// Seed an existing dismissed row (operator already said "ignore this").
	_, _ = ms.BGPAnnouncements().UpsertOrphan(ctx, "192.0.2.0/24", "BLACKHOLE", 1, "orphan")
	got, _ := ms.BGPAnnouncements().FindByBusinessKey(ctx, "192.0.2.0/24", "BLACKHOLE", 1)
	if err := ms.BGPAnnouncements().Dismiss(ctx, got.ID); err != nil {
		t.Fatalf("Dismiss: %v", err)
	}

	// Subsequent bootstrap must not re-surface it.
	created, _ := ms.BGPAnnouncements().UpsertOrphan(ctx, "192.0.2.0/24", "BLACKHOLE", 1, "orphan")
	if created {
		t.Errorf("dismissed row must NOT be re-surfaced; created=true")
	}
	after, _ := ms.BGPAnnouncements().FindByBusinessKey(ctx, "192.0.2.0/24", "BLACKHOLE", 1)
	if after.Status != "dismissed" {
		t.Errorf("dismissed row changed to %q; expected to stay dismissed", after.Status)
	}
}

func TestUpsertOrphan_AppendsEvent(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()
	_, _ = ms.BGPAnnouncements().UpsertOrphan(ctx, "192.0.2.0/24", "BLACKHOLE", 1, "orphan")
	got, _ := ms.BGPAnnouncements().FindByBusinessKey(ctx, "192.0.2.0/24", "BLACKHOLE", 1)

	events, err := ms.BGPAnnouncements().ListEvents(ctx, got.ID)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	found := false
	for _, e := range events {
		if e.EventType == store.BGPEventOrphanDetected {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected an orphan_detected event; got %+v", events)
	}
}
