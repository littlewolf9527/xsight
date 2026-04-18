package tests

// v1.2 PR-5 regression tests: BGP Announcement Manager refcount lifecycle.
//
// Covers:
//  1. Attach creates announcement + MarkAnnounced transitions to active
//  2. Shared attach bumps refcount (no vtysh)
//  3. Detach with refcount > 0 = no withdraw
//  4. Detach with refcount = 0 + delay = 0 → immediate withdraw
//  5. Detach with refcount = 0 + delay > 0 → delayed state
//  6. Attach during delayed state resurrects to active (cancels withdraw)
//  7. ForceWithdraw detaches all attacks + transitions to withdrawing
//  8. Resurrect from withdrawn/failed triggers new vtysh announce
//  9. delay_minutes dynamic recompute (MAX over active attackments)
// 10. Announce failure compensating delete vs. mark-failed

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// ─────────────────────────────────────────────────────────────────────────────
// Core lifecycle
// ─────────────────────────────────────────────────────────────────────────────

// 1 + 2: first attach triggers NeedAnnounce; second attach on same business
// key is shared (refcount bumps, no vtysh).
func TestBGPAnnouncement_Attach_NewAndShared(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	r1, err := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1,
	})
	if err != nil {
		t.Fatalf("first attach: %v", err)
	}
	if !r1.NeedAnnounce {
		t.Error("first attach must return NeedAnnounce=true")
	}
	if r1.AnnouncementID == 0 {
		t.Error("first attach returned ID=0")
	}

	r2, err := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 2, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1,
	})
	if err != nil {
		t.Fatalf("second attach: %v", err)
	}
	if r2.NeedAnnounce {
		t.Error("second attach on same business key must return NeedAnnounce=false (shared)")
	}
	if r2.AnnouncementID != r1.AnnouncementID {
		t.Errorf("shared attach returned different ID: %d vs %d", r1.AnnouncementID, r2.AnnouncementID)
	}

	a, _ := ms.BGPAnnouncements().Get(ctx, r1.AnnouncementID)
	if a == nil {
		t.Fatal("announcement not found")
	}
	if a.Refcount != 2 {
		t.Errorf("refcount after 2 attachs = %d, want 2", a.Refcount)
	}
}

// 3: Detach with refcount > 0 is a shared detach, no withdraw.
func TestBGPAnnouncement_Detach_SharedNoWithdraw(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	// 2 attacks attached
	ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1,
	})
	ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 2, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1,
	})

	result, err := ms.BGPAnnouncements().Detach(ctx, 1, "198.51.100.0/24", "DIVERT", 1)
	if err != nil {
		t.Fatalf("detach: %v", err)
	}
	if result.NeedWithdraw {
		t.Error("detach with refcount > 0 must NOT trigger withdraw")
	}
	if result.Delayed {
		t.Error("detach with refcount > 0 must NOT enter delayed state")
	}
	if result.RefcountAfter != 1 {
		t.Errorf("refcount after 1 detach = %d, want 1", result.RefcountAfter)
	}
}

// 4: Detach with refcount = 0 and no delay → immediate withdraw.
func TestBGPAnnouncement_Detach_LastAttack_NoDelay_Withdraws(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1,
		DelayMinutes: 0, // no delay
	})

	result, err := ms.BGPAnnouncements().Detach(ctx, 1, "198.51.100.0/24", "DIVERT", 1)
	if err != nil {
		t.Fatalf("detach: %v", err)
	}
	if !result.NeedWithdraw {
		t.Errorf("last detach (delay=0) must return NeedWithdraw=true; got %+v", result)
	}
	if result.Delayed {
		t.Error("last detach with delay=0 must not enter delayed state")
	}

	a, _ := ms.BGPAnnouncements().Get(ctx, result.AnnouncementID)
	if a.Status != "withdrawing" {
		t.Errorf("status after immediate withdraw trigger = %s, want withdrawing", a.Status)
	}
}

// 5: Detach with refcount = 0 and delay > 0 → delayed state, NOT NeedWithdraw.
func TestBGPAnnouncement_Detach_LastAttack_WithDelay_EntersDelayed(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1,
		DelayMinutes: 5,
	})

	result, err := ms.BGPAnnouncements().Detach(ctx, 1, "198.51.100.0/24", "DIVERT", 1)
	if err != nil {
		t.Fatalf("detach: %v", err)
	}
	if result.NeedWithdraw {
		t.Error("detach with delay > 0 must NOT return NeedWithdraw=true")
	}
	if !result.Delayed {
		t.Error("detach with delay > 0 must enter delayed state")
	}
	if result.DelayMinutes != 5 {
		t.Errorf("DelayMinutes = %d, want 5", result.DelayMinutes)
	}

	a, _ := ms.BGPAnnouncements().Get(ctx, result.AnnouncementID)
	if a.Status != "delayed" {
		t.Errorf("status after delay trigger = %s, want delayed", a.Status)
	}
	if a.DelayStartedAt == nil {
		t.Error("delay_started_at should be set after entering delayed state")
	}
}

// 6: Attack attaches during delayed state → resurrect to active.
func TestBGPAnnouncement_Attach_CancelsDelayed(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	// Initial attach + detach with delay → delayed state.
	ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1, DelayMinutes: 5,
	})
	ms.BGPAnnouncements().Detach(ctx, 1, "198.51.100.0/24", "DIVERT", 1)

	// New attack attaches — should cancel delay, bump refcount 0 → 1, status → active.
	r, err := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 2, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1, DelayMinutes: 5,
	})
	if err != nil {
		t.Fatalf("resurrect attach: %v", err)
	}
	if r.NeedAnnounce {
		t.Error("resurrect from delayed must NOT re-announce (route still in FRR)")
	}

	a, _ := ms.BGPAnnouncements().Get(ctx, r.AnnouncementID)
	if a.Status != "active" {
		t.Errorf("status after resurrect = %s, want active", a.Status)
	}
	if a.Refcount != 1 {
		t.Errorf("refcount = %d, want 1", a.Refcount)
	}
	if a.DelayStartedAt != nil {
		t.Error("delay_started_at should be cleared after resurrect")
	}
}

// 7: ForceWithdraw detaches all attacks and transitions to withdrawing.
func TestBGPAnnouncement_ForceWithdraw_DetachesAll(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	// 3 attacks attached
	for i := 1; i <= 3; i++ {
		ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
			AttackID: i, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1,
		})
	}

	annID := 1 // first announcement
	if err := ms.BGPAnnouncements().ForceWithdraw(ctx, annID); err != nil {
		t.Fatalf("force withdraw: %v", err)
	}

	a, _ := ms.BGPAnnouncements().Get(ctx, annID)
	if a.Status != "withdrawing" {
		t.Errorf("status after force withdraw = %s, want withdrawing", a.Status)
	}
	if a.Refcount != 0 {
		t.Errorf("refcount after force withdraw = %d, want 0", a.Refcount)
	}

	attacks, _ := ms.BGPAnnouncements().ListAttacks(ctx, annID)
	for _, at := range attacks {
		if at.DetachedAt == nil {
			t.Errorf("attack %d still attached after force withdraw", at.AttackID)
		}
	}
}

// 8: Resurrect from withdrawn state → new vtysh announce required.
func TestBGPAnnouncement_ResurrectFromWithdrawn(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	// Attach → MarkAnnounced → Detach (delay=0) → MarkWithdrawn.
	r1, _ := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1,
	})
	ms.BGPAnnouncements().MarkAnnounced(ctx, r1.AnnouncementID)
	ms.BGPAnnouncements().Detach(ctx, 1, "198.51.100.0/24", "DIVERT", 1)
	ms.BGPAnnouncements().MarkWithdrawn(ctx, r1.AnnouncementID)

	// Later, a new attack triggers announce on the same prefix.
	r2, err := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 2, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1,
	})
	if err != nil {
		t.Fatalf("resurrect attach: %v", err)
	}
	if !r2.NeedAnnounce {
		t.Error("resurrect from withdrawn must return NeedAnnounce=true (route not in FRR)")
	}

	a, _ := ms.BGPAnnouncements().Get(ctx, r2.AnnouncementID)
	if a.Status != "announcing" {
		t.Errorf("status after resurrect = %s, want announcing", a.Status)
	}
	if a.Refcount != 1 {
		t.Errorf("refcount = %d, want 1", a.Refcount)
	}
}

// 9: delay_minutes follows **cycle-sticky MAX** — monotonic during a cycle
// (only goes up on higher-delay attach; never regresses on a high-delay
// detach). Reset happens on resurrect (new cycle).
func TestBGPAnnouncement_DelayMinutes_CycleStickyMAX(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	// A attaches with delay=10
	ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1, DelayMinutes: 10,
	})
	// B attaches with delay=5 → MAX stays 10 (5 is lower, doesn't bump down)
	r, _ := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 2, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1, DelayMinutes: 5,
	})
	a, _ := ms.BGPAnnouncements().Get(ctx, r.AnnouncementID)
	if a.DelayMinutes != 10 {
		t.Errorf("after 2 attachs (10 + 5), delay_minutes = %d, want 10", a.DelayMinutes)
	}

	// A (the peak) detaches → delay STAYS 10 (cycle-sticky; operator intent
	// of "at least one attack in this cycle wanted 10m tail" is honored).
	ms.BGPAnnouncements().Detach(ctx, 1, "198.51.100.0/24", "DIVERT", 1)
	a2, _ := ms.BGPAnnouncements().Get(ctx, r.AnnouncementID)
	if a2.DelayMinutes != 10 {
		t.Errorf("after peak attack A detach, delay_minutes = %d, want 10 (cycle-sticky)", a2.DelayMinutes)
	}

	// B also detaches → refcount=0, delay preserved at 10, status→delayed.
	dr, _ := ms.BGPAnnouncements().Detach(ctx, 2, "198.51.100.0/24", "DIVERT", 1)
	if !dr.Delayed || dr.DelayMinutes != 10 {
		t.Errorf("after all detach, expected Delayed=true DelayMinutes=10; got %+v", dr)
	}
}

// New cycle (resurrect) resets delay_minutes: if previous cycle had peak=10
// but this cycle only has a delay=2 attack, delay should be 2 (not 10).
func TestBGPAnnouncement_DelayMinutes_ResurrectResetsCycle(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	// Cycle 1: attack with delay=10 → full lifecycle.
	r1, _ := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1, DelayMinutes: 10,
	})
	ms.BGPAnnouncements().MarkAnnounced(ctx, r1.AnnouncementID)
	ms.BGPAnnouncements().Detach(ctx, 1, "198.51.100.0/24", "DIVERT", 1)
	// Simulate delay expiry + vtysh withdraw completing the cycle.
	// In the mock, Detach transitions to 'delayed' when delay>0; ForceWithdraw
	// bypasses to withdrawing → MarkWithdrawn completes the cycle.
	ms.BGPAnnouncements().ForceWithdraw(ctx, r1.AnnouncementID)
	ms.BGPAnnouncements().MarkWithdrawn(ctx, r1.AnnouncementID)

	// Cycle 2: fresh attack with delay=2 → resurrect.
	r2, _ := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 2, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1, DelayMinutes: 2,
	})
	if r1.AnnouncementID != r2.AnnouncementID {
		t.Fatalf("expected resurrect (same announcement id); got %d vs %d", r1.AnnouncementID, r2.AnnouncementID)
	}
	a, _ := ms.BGPAnnouncements().Get(ctx, r2.AnnouncementID)
	if a.DelayMinutes != 2 {
		t.Errorf("after resurrect with delay=2, got %d; expected previous peak (10) reset", a.DelayMinutes)
	}
}

// Focused integration test (PR-7 audit suggestion): resurrect + attached_attacks
// filter + sticky delay composed in one scenario, so regressions across any
// of the three surface together.
//
// Timeline:
//   cycle 1: attack 1 (delay=3) attach → detach → withdraw (delay preserved = 3)
//   cycle 2 (resurrect): attack 2 (delay=7) attach → attack 3 (delay=2) attach
//   (both in same cycle; sticky MAX = 7)
//
// Assertions:
//   - cycle 2 announcement.delay_minutes = 7 (new cycle sticky MAX; prior
//     cycle's peak 3 does NOT leak in)
//   - only attacks 2 and 3 visible from cycle 2 perspective (attack 1 would
//     have AttachedAt before cycle 2's announced_at — hence filtered)
func TestBGPAnnouncement_CycleBoundaries_Integration(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	// Cycle 1.
	r1, _ := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1, DelayMinutes: 3,
	})
	ms.BGPAnnouncements().MarkAnnounced(ctx, r1.AnnouncementID)
	// Attack 1 ends → refcount=0; with delay=3 this enters delayed, but we
	// drive it straight to withdrawn for the scenario.
	ms.BGPAnnouncements().ForceWithdraw(ctx, r1.AnnouncementID)
	ms.BGPAnnouncements().MarkWithdrawn(ctx, r1.AnnouncementID)

	// Cycle 2 — resurrect.
	r2a, _ := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 2, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1, DelayMinutes: 7,
	})
	if r1.AnnouncementID != r2a.AnnouncementID {
		t.Fatalf("cycle 2 must reuse announcement id; got %d vs %d", r1.AnnouncementID, r2a.AnnouncementID)
	}
	ms.BGPAnnouncements().MarkAnnounced(ctx, r2a.AnnouncementID)
	ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 3, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1, DelayMinutes: 2,
	})

	// Sticky MAX on cycle 2: 7 (not 2, not leaked 3 from cycle 1).
	ann, _ := ms.BGPAnnouncements().Get(ctx, r2a.AnnouncementID)
	if ann.DelayMinutes != 7 {
		t.Errorf("cycle 2 delay_minutes = %d; want 7 (sticky MAX over cycle 2 attacks only)", ann.DelayMinutes)
	}

	// A lower-delay attack detach within cycle 2 must not lower delay.
	ms.BGPAnnouncements().Detach(ctx, 3, "198.51.100.0/24", "DIVERT", 1)
	ann2, _ := ms.BGPAnnouncements().Get(ctx, r2a.AnnouncementID)
	if ann2.DelayMinutes != 7 {
		t.Errorf("after low-delay attack 3 detach, delay_minutes = %d; want 7 (sticky)", ann2.DelayMinutes)
	}

	// ListAttacks returns all history incl. cycle 1 attack 1; the API layer
	// is what filters by AnnouncedAt. Verify the DB-level shape and also
	// verify each attack's AttachedAt ordering relative to cycle start.
	atks, _ := ms.BGPAnnouncements().ListAttacks(ctx, r2a.AnnouncementID)
	var prev, current int
	for _, a := range atks {
		if a.AttachedAt.Before(ann.AnnouncedAt) {
			prev++
		} else {
			current++
		}
	}
	if prev != 1 || current != 2 {
		t.Errorf("expected 1 prior-cycle + 2 current-cycle attacks (boundary=ann.AnnouncedAt); got prev=%d current=%d", prev, current)
	}
}

// Regression for the L16 scenario: two attacks in same cycle, one with
// delay=0 one with delay=1. Either detach order must end with delay=1 tail
// preserved (not drop to 0 if the delay=1 attack detaches first).
func TestBGPAnnouncement_DelayMinutes_DetachOrderDoesNotMatter(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1, DelayMinutes: 0,
	})
	r, _ := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 2, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1, DelayMinutes: 1,
	})
	// Detach attack 2 first (the peak-delay one — old dynamic-MAX would drop to 0).
	ms.BGPAnnouncements().Detach(ctx, 2, "198.51.100.0/24", "DIVERT", 1)
	a, _ := ms.BGPAnnouncements().Get(ctx, r.AnnouncementID)
	if a.DelayMinutes != 1 {
		t.Errorf("after peak-delay attack detach, delay_minutes = %d, want 1 (sticky)", a.DelayMinutes)
	}
	// Detach attack 1 → refcount=0; delay stays 1 → delayed state.
	dr, _ := ms.BGPAnnouncements().Detach(ctx, 1, "198.51.100.0/24", "DIVERT", 1)
	if !dr.Delayed || dr.DelayMinutes != 1 {
		t.Errorf("final detach expected Delayed=true DelayMinutes=1; got %+v", dr)
	}
}

// 10: Announce failure — refcount=1 compensates by DELETE, refcount>1 marks failed.
func TestBGPAnnouncement_MarkFailedAnnounce_CompensatesCorrectly(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	// refcount=1 path: should DELETE the row.
	r1, _ := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1,
	})
	if err := ms.BGPAnnouncements().MarkFailedAnnounce(ctx, r1.AnnouncementID, "vtysh timeout"); err != nil {
		t.Fatalf("MarkFailedAnnounce: %v", err)
	}
	if got, _ := ms.BGPAnnouncements().Get(ctx, r1.AnnouncementID); got != nil {
		t.Errorf("refcount=1 failure should DELETE row; got %+v", got)
	}

	// refcount>1 path: mark failed but keep row.
	ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 2, Prefix: "203.0.113.0/24", RouteMap: "DIVERT", ConnectorID: 1,
	})
	r2, _ := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 3, Prefix: "203.0.113.0/24", RouteMap: "DIVERT", ConnectorID: 1,
	})
	if err := ms.BGPAnnouncements().MarkFailedAnnounce(ctx, r2.AnnouncementID, "vtysh timeout"); err != nil {
		t.Fatalf("MarkFailedAnnounce: %v", err)
	}
	a, _ := ms.BGPAnnouncements().Get(ctx, r2.AnnouncementID)
	if a == nil {
		t.Fatal("refcount>1 failure must preserve row")
	}
	if a.Status != "failed" {
		t.Errorf("status = %s, want failed", a.Status)
	}
	if a.ErrorMessage != "vtysh timeout" {
		t.Errorf("error_message not preserved: %q", a.ErrorMessage)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-connector / multi-prefix isolation
// ─────────────────────────────────────────────────────────────────────────────

func TestBGPAnnouncement_MultipleConnectors_Isolated(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	// Same prefix + route_map, different connector → different announcements.
	r1, _ := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1,
	})
	r2, _ := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 2,
	})
	if r1.AnnouncementID == r2.AnnouncementID {
		t.Errorf("different connectors must produce different announcement IDs")
	}
	if !r1.NeedAnnounce || !r2.NeedAnnounce {
		t.Errorf("both first-attaches should need announce")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Timeline events
// ─────────────────────────────────────────────────────────────────────────────

func TestBGPAnnouncement_Events_Timeline(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	r, _ := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1, DelayMinutes: 5,
	})
	ms.BGPAnnouncements().MarkAnnounced(ctx, r.AnnouncementID)
	ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 2, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1, DelayMinutes: 5,
	})
	ms.BGPAnnouncements().Detach(ctx, 1, "198.51.100.0/24", "DIVERT", 1)
	ms.BGPAnnouncements().Detach(ctx, 2, "198.51.100.0/24", "DIVERT", 1)

	events, err := ms.BGPAnnouncements().ListEvents(ctx, r.AnnouncementID)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	// Expected types in order:
	// attack_attached (initial), announced, attack_attached (shared),
	// attack_detached, attack_detached, delay_started
	wantTypes := []string{
		store.BGPEventAttackAttached,
		store.BGPEventAnnounced,
		store.BGPEventAttackAttached,
		store.BGPEventAttackDetached,
		store.BGPEventAttackDetached,
		store.BGPEventDelayStarted,
	}
	if len(events) != len(wantTypes) {
		t.Fatalf("expected %d events, got %d: %+v", len(wantTypes), len(events), events)
	}
	for i, want := range wantTypes {
		if events[i].EventType != want {
			t.Errorf("event[%d].type = %s, want %s", i, events[i].EventType, want)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Idempotent Detach (already detached)
// ─────────────────────────────────────────────────────────────────────────────

func TestBGPAnnouncement_Detach_Idempotent(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1,
	})
	// Detach once
	ms.BGPAnnouncements().Detach(ctx, 1, "198.51.100.0/24", "DIVERT", 1)
	// Detach again — should not double-decrement refcount, should not re-trigger withdraw.
	r, err := ms.BGPAnnouncements().Detach(ctx, 1, "198.51.100.0/24", "DIVERT", 1)
	if err != nil {
		t.Fatalf("idempotent detach: %v", err)
	}
	if r.NeedWithdraw {
		t.Error("second detach of same attack must not re-trigger withdraw")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Non-existent announcement detach (no attach ever happened)
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Reconciliation on startup (announcing / withdrawing retries)
// ─────────────────────────────────────────────────────────────────────────────

// `announcing` rows at startup — reconciliation retries vtysh announce.
// The test can't actually exercise vtysh (no FRR), but verifies that the
// reconcile path calls MarkFailedAnnounce on lookup failure (no connector).
func TestReconcile_BGPAnnouncing_ConnectorMissing_MarksFailed(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")

	// Seed an announcing row with a connector_id that doesn't exist.
	r, _ := ms.bgpAnnouncements.Attach(context.Background(), store.BGPAttachParams{
		AttackID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 999, // missing
	})

	eng.ReconcileOnStartup(context.Background())

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ann, _ := ms.bgpAnnouncements.Get(context.Background(), r.AnnouncementID)
		// refcount=1 path → MarkFailedAnnounce deletes the row.
		// Otherwise the row is marked failed.
		if ann == nil {
			return // deleted (refcount=1 path)
		}
		if ann.Status == "failed" {
			return // marked failed (refcount>1 path)
		}
		time.Sleep(20 * time.Millisecond)
	}
	ann, _ := ms.bgpAnnouncements.Get(context.Background(), r.AnnouncementID)
	t.Errorf("expected announcing row to be cleaned up or marked failed; got %+v", ann)
}

// `withdrawing` rows at startup — reconciliation retries vtysh no network.
// Without a real FRR, the mock connector causes runVtysh to fail; the test
// verifies MarkFailedWithdraw is called.
func TestReconcile_BGPWithdrawing_ConnectorMissing_MarksFailed(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")

	// Seed a withdrawing row (force-transition after Attach).
	r, _ := ms.bgpAnnouncements.Attach(context.Background(), store.BGPAttachParams{
		AttackID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 999,
	})
	ms.bgpAnnouncements.MarkAnnounced(context.Background(), r.AnnouncementID)
	ms.bgpAnnouncements.MarkWithdrawing(context.Background(), r.AnnouncementID)

	eng.ReconcileOnStartup(context.Background())

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ann, _ := ms.bgpAnnouncements.Get(context.Background(), r.AnnouncementID)
		if ann != nil && ann.Status == "failed" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	ann, _ := ms.bgpAnnouncements.Get(context.Background(), r.AnnouncementID)
	t.Errorf("expected withdrawing row to transition to failed; got %+v", ann)
}

// Recovery of a persisted bgp_withdraw schedule with announcement_id set
// (PR-3 scheduled_actions row → PR-5 announcement semantics).
func TestReconcile_BGPWithdraw_ScheduledRecovery_ByAnnouncementID(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")

	// Setup: an active announcement that's about to be withdrawn via the
	// delayed path. Seed a scheduled_actions row with announcement_id set.
	r, _ := ms.bgpAnnouncements.Attach(context.Background(), store.BGPAttachParams{
		AttackID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 999, DelayMinutes: 5,
	})
	ms.bgpAnnouncements.MarkAnnounced(context.Background(), r.AnnouncementID)
	// Transition to delayed via final detach.
	ms.bgpAnnouncements.Detach(context.Background(), 1, "198.51.100.0/24", "DIVERT", 999)

	// Seed a scheduled_actions row whose scheduled_for already elapsed,
	// so RecoverScheduledActions executes it immediately via the announcement
	// recovery path.
	annID := r.AnnouncementID
	ms.scheduledActions.records = append(ms.scheduledActions.records, store.ScheduledAction{
		ID:             100,
		ActionType:     "bgp_withdraw",
		AnnouncementID: &annID,
		ScheduledFor:   time.Now().Add(-1 * time.Minute),
		Status:         "pending",
	})
	ms.scheduledActions.nextID = 100

	eng.ReconcileOnStartup(context.Background())

	// After recovery: scheduled row should be out of pending (completed or failed).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pending, _ := ms.ScheduledActions().ListPending(context.Background())
		stillPending := false
		for _, p := range pending {
			if p.ID == 100 {
				stillPending = true
			}
		}
		if !stillPending {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("expected bgp_withdraw scheduled row to be out of pending after reconcile")
}

// ─────────────────────────────────────────────────────────────────────────────
// API contract: orphan handling (P1 fix)
// ─────────────────────────────────────────────────────────────────────────────

// Orphan row in state table → API returns is_orphan=true + announcement_id;
// attack_id / action_id stay 0 (matches roadmap: operator uses dedicated
// orphan-force-withdraw / orphan-dismiss endpoints, not the per-artifact
// force-remove flow).
func TestBGPOrphan_APIReturnsIsOrphanFlag(t *testing.T) {
	ms := NewMockStore()

	// Seed an orphan announcement (no attached attack).
	ms.bgpAnnouncements.announcements = append(ms.bgpAnnouncements.announcements, store.BGPAnnouncement{
		ID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1,
		Status: "orphan", Refcount: 0, AnnouncedAt: time.Now().Add(-1 * time.Hour),
	})
	ms.bgpAnnouncements.nextAnnID = 1
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, store.BGPConnector{
		ID: 1, Name: "test-bgp", Enabled: true,
	})

	r := setupRouter(ms)
	w := doGet(t, r, "/api/active-actions/bgp")
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	items := decodeList(t, w)
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	it := items[0]
	if got := it["is_orphan"]; got != true {
		t.Errorf("is_orphan = %v, want true", got)
	}
	if got := it["status"]; got != "orphan" {
		t.Errorf("status = %v, want orphan", got)
	}
	// attack_id / action_id should be 0 (no attached attack) — frontend must
	// use announcement_id instead.
	if got := it["attack_id"]; got != float64(0) {
		t.Errorf("attack_id = %v, want 0 for orphan", got)
	}
	if got := it["announcement_id"]; got != float64(1) {
		t.Errorf("announcement_id = %v, want 1", got)
	}
}

// orphan-dismiss endpoint: marks orphan → dismissed.
func TestBGPOrphan_DismissEndpoint(t *testing.T) {
	ms := NewMockStore()
	ms.bgpAnnouncements.announcements = append(ms.bgpAnnouncements.announcements, store.BGPAnnouncement{
		ID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1,
		Status: "orphan", Refcount: 0, AnnouncedAt: time.Now(),
	})
	ms.bgpAnnouncements.nextAnnID = 1

	r := setupRouter(ms)
	w := doPost(t, r, "/api/active-actions/bgp/orphan-dismiss", map[string]any{"announcement_id": 1})
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	ann, _ := ms.bgpAnnouncements.Get(context.Background(), 1)
	if ann.Status != "dismissed" {
		t.Errorf("after dismiss, status = %s, want dismissed", ann.Status)
	}
}

// orphan-dismiss rejects non-orphan status (operator shouldn't accidentally
// dismiss an active announcement).
func TestBGPOrphan_DismissRejectsNonOrphan(t *testing.T) {
	ms := NewMockStore()
	ms.bgpAnnouncements.announcements = append(ms.bgpAnnouncements.announcements, store.BGPAnnouncement{
		ID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1,
		Status: "active", Refcount: 1, AnnouncedAt: time.Now(),
	})
	ms.bgpAnnouncements.nextAnnID = 1

	r := setupRouter(ms)
	w := doPost(t, r, "/api/active-actions/bgp/orphan-dismiss", map[string]any{"announcement_id": 1})
	if w.Code != 400 {
		t.Errorf("expected 400 rejecting non-orphan, got %d: %s", w.Code, w.Body.String())
	}
	ann, _ := ms.bgpAnnouncements.Get(context.Background(), 1)
	if ann.Status != "active" {
		t.Errorf("active announcement should remain active, got %s", ann.Status)
	}
}

// orphan-force-withdraw rejects non-orphan (operator must use force-remove
// for active/delayed/failed announcements — that path handles refcount).
func TestBGPOrphan_ForceWithdrawRejectsNonOrphan(t *testing.T) {
	ms := NewMockStore()
	ms.bgpAnnouncements.announcements = append(ms.bgpAnnouncements.announcements, store.BGPAnnouncement{
		ID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1,
		Status: "active", Refcount: 1, AnnouncedAt: time.Now(),
	})
	ms.bgpAnnouncements.nextAnnID = 1

	r := setupRouter(ms)
	w := doPost(t, r, "/api/active-actions/bgp/orphan-force-withdraw", map[string]any{"announcement_id": 1})
	if w.Code != 400 {
		t.Errorf("expected 400 for non-orphan, got %d: %s", w.Code, w.Body.String())
	}
}

// list-dismissed-orphans endpoint: returns both dismissed and
// dismissed_on_upgrade rows, excludes active/orphan/withdrawn.
func TestBGPOrphan_ListDismissedEndpoint(t *testing.T) {
	ms := NewMockStore()
	ms.bgpAnnouncements.announcements = append(ms.bgpAnnouncements.announcements,
		store.BGPAnnouncement{ID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1, Status: "dismissed", AnnouncedAt: time.Now()},
		store.BGPAnnouncement{ID: 2, Prefix: "198.51.100.128/25", RouteMap: "DIVERT", ConnectorID: 1, Status: "dismissed_on_upgrade", AnnouncedAt: time.Now()},
		store.BGPAnnouncement{ID: 3, Prefix: "198.51.100.0/28", RouteMap: "DIVERT", ConnectorID: 1, Status: "orphan", AnnouncedAt: time.Now()},
		store.BGPAnnouncement{ID: 4, Prefix: "198.51.100.10/32", RouteMap: "DIVERT", ConnectorID: 1, Status: "active", Refcount: 1, AnnouncedAt: time.Now()},
	)
	ms.bgpAnnouncements.nextAnnID = 4
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, store.BGPConnector{ID: 1, Name: "test-bgp"})

	r := setupRouter(ms)
	w := doGet(t, r, "/api/active-actions/bgp/dismissed-orphans")
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var rows []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 dismissed rows, got %d: %+v", len(rows), rows)
	}
	gotStatuses := map[string]bool{}
	for _, row := range rows {
		gotStatuses[row["status"].(string)] = true
		if row["connector_name"] != "test-bgp" {
			t.Errorf("connector_name not populated: %v", row)
		}
	}
	if !gotStatuses["dismissed"] || !gotStatuses["dismissed_on_upgrade"] {
		t.Errorf("expected both dismissed and dismissed_on_upgrade, got %v", gotStatuses)
	}
}

// orphan-undismiss endpoint: flips dismissed → orphan, writes event.
func TestBGPOrphan_UndismissEndpoint(t *testing.T) {
	ms := NewMockStore()
	ms.bgpAnnouncements.announcements = append(ms.bgpAnnouncements.announcements, store.BGPAnnouncement{
		ID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1,
		Status: "dismissed", Refcount: 0, AnnouncedAt: time.Now(),
	})
	ms.bgpAnnouncements.nextAnnID = 1

	r := setupRouter(ms)
	w := doPost(t, r, "/api/active-actions/bgp/orphan-undismiss", map[string]any{"announcement_id": 1})
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	ann, _ := ms.bgpAnnouncements.Get(context.Background(), 1)
	if ann.Status != "orphan" {
		t.Errorf("after undismiss, status = %s, want orphan", ann.Status)
	}
	// Verify event appended.
	events, _ := ms.bgpAnnouncements.ListEvents(context.Background(), 1)
	foundUndismissed := false
	for _, e := range events {
		if e.EventType == store.BGPEventUndismissed {
			foundUndismissed = true
		}
	}
	if !foundUndismissed {
		t.Errorf("expected undismissed event in timeline, got %+v", events)
	}
}

// orphan-undismiss also accepts dismissed_on_upgrade (symmetric).
func TestBGPOrphan_UndismissAcceptsDismissedOnUpgrade(t *testing.T) {
	ms := NewMockStore()
	ms.bgpAnnouncements.announcements = append(ms.bgpAnnouncements.announcements, store.BGPAnnouncement{
		ID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1,
		Status: "dismissed_on_upgrade", AnnouncedAt: time.Now(),
	})
	ms.bgpAnnouncements.nextAnnID = 1

	r := setupRouter(ms)
	w := doPost(t, r, "/api/active-actions/bgp/orphan-undismiss", map[string]any{"announcement_id": 1})
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	ann, _ := ms.bgpAnnouncements.Get(context.Background(), 1)
	if ann.Status != "orphan" {
		t.Errorf("after undismiss, status = %s, want orphan", ann.Status)
	}
}

// orphan-undismiss rejects active/orphan (only dismissed-family can be
// undismissed; preventing operators from flipping live routes into orphan).
func TestBGPOrphan_UndismissRejectsNonDismissed(t *testing.T) {
	ms := NewMockStore()
	ms.bgpAnnouncements.announcements = append(ms.bgpAnnouncements.announcements, store.BGPAnnouncement{
		ID: 1, Prefix: "198.51.100.0/24", RouteMap: "DIVERT", ConnectorID: 1,
		Status: "active", Refcount: 1, AnnouncedAt: time.Now(),
	})
	ms.bgpAnnouncements.nextAnnID = 1

	r := setupRouter(ms)
	w := doPost(t, r, "/api/active-actions/bgp/orphan-undismiss", map[string]any{"announcement_id": 1})
	if w.Code != 400 {
		t.Errorf("expected 400 rejecting non-dismissed, got %d: %s", w.Code, w.Body.String())
	}
	ann, _ := ms.bgpAnnouncements.Get(context.Background(), 1)
	if ann.Status != "active" {
		t.Errorf("status should remain active, got %s", ann.Status)
	}
}

func TestBGPAnnouncement_Detach_NoExistingRow(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	r, err := ms.BGPAnnouncements().Detach(ctx, 1, "198.51.100.0/24", "DIVERT", 1)
	if err != nil {
		t.Fatalf("detach with no row: %v", err)
	}
	if r.NeedWithdraw || r.Delayed {
		t.Errorf("detach with no row should be silent no-op; got %+v", r)
	}
	if r.AnnouncementID != 0 {
		t.Errorf("detach with no row should return AnnouncementID=0; got %d", r.AnnouncementID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// L14 support: route_map is part of business key (prefix, route_map,
// connector_id). Same prefix + different route_map = distinct announcement
// rows. This validates the DB/refcount layer; FRR-level behavior (BGP only
// allows one origination per prefix) is a BGP protocol constraint and
// documented in roadmap, not tested here.
// ─────────────────────────────────────────────────────────────────────────────

// Two attaches to (same prefix, same connector) but different route_maps
// must produce two distinct announcement rows — not merge into one.
func TestAttach_DifferentRouteMaps_CreateDistinctRows(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	r1, err := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, ActionID: ip(10), Prefix: "192.0.2.0/24",
		RouteMap: "RTBH", ConnectorID: 6, DelayMinutes: 0,
	})
	if err != nil {
		t.Fatalf("attach RTBH: %v", err)
	}
	r2, err := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 2, ActionID: ip(11), Prefix: "192.0.2.0/24",
		RouteMap: "DIVERT", ConnectorID: 6, DelayMinutes: 0,
	})
	if err != nil {
		t.Fatalf("attach DIVERT: %v", err)
	}
	if r1.AnnouncementID == r2.AnnouncementID {
		t.Fatalf("expected distinct announcement IDs, both got %d", r1.AnnouncementID)
	}
	if !r1.NeedAnnounce || !r2.NeedAnnounce {
		t.Errorf("both should need fresh announce; got r1.NeedAnnounce=%v r2.NeedAnnounce=%v", r1.NeedAnnounce, r2.NeedAnnounce)
	}
	// DB state: both refcount=1, status=announcing (before MarkAnnounced).
	a1, _ := ms.BGPAnnouncements().Get(ctx, r1.AnnouncementID)
	a2, _ := ms.BGPAnnouncements().Get(ctx, r2.AnnouncementID)
	if a1 == nil || a2 == nil {
		t.Fatalf("lookup by id failed; a1=%v a2=%v", a1, a2)
	}
	if a1.RouteMap != "RTBH" || a2.RouteMap != "DIVERT" {
		t.Errorf("route_map not preserved: a1=%s a2=%s", a1.RouteMap, a2.RouteMap)
	}
	if a1.Refcount != 1 || a2.Refcount != 1 {
		t.Errorf("expected each refcount=1, got %d / %d", a1.Refcount, a2.Refcount)
	}
}

// Two parallel announcements (different route_maps) maintain independent
// refcount: attach/detach on one does not affect the other.
func TestAttach_DifferentRouteMaps_IndependentRefcount(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	// Announcement A (RTBH) gets 2 attacks, Announcement B (DIVERT) gets 1.
	aRTBH, _ := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, ActionID: ip(10), Prefix: "192.0.2.0/24", RouteMap: "RTBH", ConnectorID: 6,
	})
	ms.BGPAnnouncements().MarkAnnounced(ctx, aRTBH.AnnouncementID)
	ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 2, ActionID: ip(10), Prefix: "192.0.2.0/24", RouteMap: "RTBH", ConnectorID: 6,
	})

	aDIVERT, _ := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 3, ActionID: ip(11), Prefix: "192.0.2.0/24", RouteMap: "DIVERT", ConnectorID: 6,
	})
	ms.BGPAnnouncements().MarkAnnounced(ctx, aDIVERT.AnnouncementID)

	// Detach attack 3 (DIVERT). RTBH announcement must remain refcount=2.
	r, _ := ms.BGPAnnouncements().Detach(ctx, 3, "192.0.2.0/24", "DIVERT", 6)
	if !r.NeedWithdraw {
		t.Errorf("DIVERT detach should NeedWithdraw (refcount=0, delay=0), got %+v", r)
	}
	rtbhA, _ := ms.BGPAnnouncements().Get(ctx, aRTBH.AnnouncementID)
	if rtbhA.Refcount != 2 {
		t.Errorf("RTBH refcount should stay 2 after DIVERT detach, got %d", rtbhA.Refcount)
	}
	if rtbhA.Status != "active" {
		t.Errorf("RTBH status should stay active, got %s", rtbhA.Status)
	}
}

// ForceWithdraw on one route_map's announcement does not affect the parallel
// route_map's announcement. Verifies business-key-level isolation for
// operator-driven withdraws.
func TestForceWithdraw_OneRouteMap_OtherIndependent(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	aRTBH, _ := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, ActionID: ip(10), Prefix: "192.0.2.0/24", RouteMap: "RTBH", ConnectorID: 6,
	})
	ms.BGPAnnouncements().MarkAnnounced(ctx, aRTBH.AnnouncementID)
	aDIVERT, _ := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 2, ActionID: ip(11), Prefix: "192.0.2.0/24", RouteMap: "DIVERT", ConnectorID: 6,
	})
	ms.BGPAnnouncements().MarkAnnounced(ctx, aDIVERT.AnnouncementID)

	if err := ms.BGPAnnouncements().ForceWithdraw(ctx, aRTBH.AnnouncementID); err != nil {
		t.Fatalf("force withdraw RTBH: %v", err)
	}
	ms.BGPAnnouncements().MarkWithdrawn(ctx, aRTBH.AnnouncementID)

	divertState, _ := ms.BGPAnnouncements().Get(ctx, aDIVERT.AnnouncementID)
	if divertState.Status != "active" || divertState.Refcount != 1 {
		t.Errorf("DIVERT should remain active refcount=1 after RTBH force-withdraw; got status=%s refcount=%d",
			divertState.Status, divertState.Refcount)
	}
}

// Serial policy switch (operator workflow): original RTBH announcement is
// fully withdrawn, then a new attack triggers DIVERT announcement. Audit
// history preserves both rows with distinct route_maps; only the second is
// currently active.
func TestPrefix_SerialRouteMapSwitch(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	// Phase 1: RTBH announcement.
	a1, _ := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 1, ActionID: ip(10), Prefix: "192.0.2.0/24", RouteMap: "RTBH", ConnectorID: 6,
	})
	ms.BGPAnnouncements().MarkAnnounced(ctx, a1.AnnouncementID)
	// Attack ends → withdraw.
	r, _ := ms.BGPAnnouncements().Detach(ctx, 1, "192.0.2.0/24", "RTBH", 6)
	if !r.NeedWithdraw {
		t.Fatalf("expected NeedWithdraw after first detach, got %+v", r)
	}
	ms.BGPAnnouncements().MarkWithdrawn(ctx, a1.AnnouncementID)

	// Phase 2: operator edited action.route_map=DIVERT; new attack triggers.
	a2, _ := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID: 2, ActionID: ip(11), Prefix: "192.0.2.0/24", RouteMap: "DIVERT", ConnectorID: 6,
	})
	if a1.AnnouncementID == a2.AnnouncementID {
		t.Fatalf("different route_map must yield distinct announcement ID; both are %d", a1.AnnouncementID)
	}

	// Audit: both rows still in DB (ListByStatus covers withdrawn).
	rtbhRow, _ := ms.BGPAnnouncements().Get(ctx, a1.AnnouncementID)
	divertRow, _ := ms.BGPAnnouncements().Get(ctx, a2.AnnouncementID)
	if rtbhRow.Status != "withdrawn" {
		t.Errorf("RTBH row should be withdrawn (audit), got %s", rtbhRow.Status)
	}
	if divertRow.Status != "announcing" {
		t.Errorf("DIVERT row should be announcing (fresh), got %s", divertRow.Status)
	}
	if rtbhRow.RouteMap != "RTBH" || divertRow.RouteMap != "DIVERT" {
		t.Errorf("route_map mismatch: rtbh=%s divert=%s", rtbhRow.RouteMap, divertRow.RouteMap)
	}
}
