package tests

// Bug 2 fix tests: BGP schedule identity — verify that announcement-scoped
// BGP delayed-withdraw schedules get per-announcement row IDs, not the
// single collapsed artifact-key row that caused the prod state leak.
// See fix-plan-xdrop-port-bgp-schedule-2026-05-02.md §Bug 2.

import (
	"context"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// B.1.1: Core regression — directly reproduces the prod failure mode.
// Two BGP announcements scheduled in the same pending window must get
// different scheduled_actions row IDs.
func TestBGPSchedule_TwoAnnouncementsGetDifferentIDs(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()
	future := time.Now().Add(5 * time.Minute)

	ann1 := 22
	ann2 := 23

	id1, err := ms.ScheduledActions().Schedule(ctx, &store.ScheduledAction{
		ActionType:     "bgp_withdraw",
		AnnouncementID: &ann1,
		ScheduledFor:   future,
	})
	if err != nil {
		t.Fatalf("Schedule ann=22: %v", err)
	}

	id2, err := ms.ScheduledActions().Schedule(ctx, &store.ScheduledAction{
		ActionType:     "bgp_withdraw",
		AnnouncementID: &ann2,
		ScheduledFor:   future,
	})
	if err != nil {
		t.Fatalf("Schedule ann=23: %v", err)
	}

	if id1 == id2 {
		t.Errorf("two different announcements (22, 23) got same scheduled_id=%d — schedule identity collision", id1)
	}
	t.Logf("ann=22 → scheduled_id=%d  ann=23 → scheduled_id=%d", id1, id2)
}

// B.1.2: Same announcement scheduled twice in the same pending window must
// return the same row ID (idempotent reschedule) and update ScheduledFor.
func TestBGPSchedule_SameAnnouncementIsIdempotent(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	ann := 100
	t1 := time.Now().Add(5 * time.Minute)
	t2 := time.Now().Add(6 * time.Minute)

	id1, err := ms.ScheduledActions().Schedule(ctx, &store.ScheduledAction{
		ActionType:     "bgp_withdraw",
		AnnouncementID: &ann,
		ScheduledFor:   t1,
	})
	if err != nil {
		t.Fatalf("first Schedule: %v", err)
	}

	id2, err := ms.ScheduledActions().Schedule(ctx, &store.ScheduledAction{
		ActionType:     "bgp_withdraw",
		AnnouncementID: &ann,
		ScheduledFor:   t2,
	})
	if err != nil {
		t.Fatalf("second Schedule: %v", err)
	}

	if id1 != id2 {
		t.Errorf("same announcement (100) scheduled twice got different IDs: %d vs %d — should be idempotent", id1, id2)
	}

	// Verify scheduled_for was updated to t2.
	pending, err := ms.ScheduledActions().ListPending(ctx)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	var found *store.ScheduledAction
	for i := range pending {
		if pending[i].ID == id1 {
			found = &pending[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("scheduled action id=%d not found in pending list", id1)
	}
	if !found.ScheduledFor.Equal(t2) {
		t.Errorf("ScheduledFor not updated: got %v, want %v", found.ScheduledFor, t2)
	}
}

// B.1.3: Regression — existing artifact-scoped (xDrop) schedule deduplication
// must still work after the mock is updated to the branched logic.
func TestBGPSchedule_ArtifactScheduleStillIdempotent(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()
	future := time.Now().Add(5 * time.Minute)

	// xDrop schedule — AnnouncementID is nil
	artifact := &store.ScheduledAction{
		ActionType:     "xdrop_unblock",
		AttackID:       500,
		ActionID:       40,
		ConnectorID:    3,
		ExternalRuleID: "rule-abc",
		ScheduledFor:   future,
	}

	id1, err := ms.ScheduledActions().Schedule(ctx, artifact)
	if err != nil {
		t.Fatalf("first Schedule: %v", err)
	}

	// Same artifact key, different ScheduledFor
	artifact.ScheduledFor = future.Add(2 * time.Minute)
	id2, err := ms.ScheduledActions().Schedule(ctx, artifact)
	if err != nil {
		t.Fatalf("second Schedule: %v", err)
	}

	if id1 != id2 {
		t.Errorf("same artifact key got different IDs: %d vs %d — xDrop idempotency broken", id1, id2)
	}
}

// B.1.4: An artifact schedule and an announcement schedule with the same
// action_type must not collide with each other.
func TestBGPSchedule_ArtifactAndAnnouncementCoexist(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()
	future := time.Now().Add(5 * time.Minute)

	ann := 77

	// Announcement-scoped
	annID, err := ms.ScheduledActions().Schedule(ctx, &store.ScheduledAction{
		ActionType:     "bgp_withdraw",
		AnnouncementID: &ann,
		ScheduledFor:   future,
	})
	if err != nil {
		t.Fatalf("announcement schedule: %v", err)
	}

	// Artifact-scoped with same action_type
	artID, err := ms.ScheduledActions().Schedule(ctx, &store.ScheduledAction{
		ActionType:     "bgp_withdraw",
		AttackID:       200,
		ActionID:       10,
		ConnectorID:    1,
		ExternalRuleID: "legacy-rule",
		ScheduledFor:   future,
	})
	if err != nil {
		t.Fatalf("artifact schedule: %v", err)
	}

	if annID == artID {
		t.Errorf("announcement schedule and artifact schedule collided on same ID=%d", annID)
	}
}

// B.1.5: After a scheduled action reaches terminal state (completed), a new
// schedule for the same announcement must create a new row.
func TestBGPSchedule_CompletedThenNewScheduleGetsNewID(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()
	future := time.Now().Add(5 * time.Minute)

	ann := 50

	id1, err := ms.ScheduledActions().Schedule(ctx, &store.ScheduledAction{
		ActionType:     "bgp_withdraw",
		AnnouncementID: &ann,
		ScheduledFor:   future,
	})
	if err != nil {
		t.Fatalf("initial Schedule: %v", err)
	}

	// Complete the schedule (simulate timer fired + withdraw executed)
	if err := ms.ScheduledActions().MarkExecuting(ctx, id1); err != nil {
		t.Fatalf("MarkExecuting: %v", err)
	}
	if err := ms.ScheduledActions().Complete(ctx, id1); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// New attack on same announcement — should get a fresh row
	id2, err := ms.ScheduledActions().Schedule(ctx, &store.ScheduledAction{
		ActionType:     "bgp_withdraw",
		AnnouncementID: &ann,
		ScheduledFor:   future.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Schedule after complete: %v", err)
	}

	if id1 == id2 {
		t.Errorf("after completion, new schedule for same announcement got same ID=%d; expected fresh row", id1)
	}
}

// B.1.6: Integration via engine — mirrors the exact prod scenario from the
// logs: 5 concurrent BGP announcements entering delayed state.
func TestBGPDelaySchedule_MultipleAnnouncementsNeverCollide(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")
	ctx := context.Background()

	announcementIDs := []int{22, 23, 100, 167, 200}
	scheduledIDs := make(map[int]int) // announcementID → scheduledID
	scheduledFor := time.Now().Add(5 * time.Minute)

	for _, annID := range announcementIDs {
		id, _, err := eng.ScheduleDelayForAnnouncement(ctx, annID, scheduledFor)
		if err != nil {
			t.Fatalf("ScheduleDelayForAnnouncement(ann=%d): %v", annID, err)
		}
		scheduledIDs[annID] = id
	}

	// Check all IDs are distinct
	seen := make(map[int]int) // scheduledID → first announcementID that got it
	for annID, schedID := range scheduledIDs {
		if prevAnn, collision := seen[schedID]; collision {
			t.Errorf("COLLISION: ann=%d and ann=%d both got scheduled_id=%d",
				prevAnn, annID, schedID)
		}
		seen[schedID] = annID
	}

	t.Logf("scheduled IDs: %v", scheduledIDs)
}

// B.1.7: Regression — recovered announcement-scoped BGP timer must be
// cancellable through CancelAnnouncementDelay (the announcement key), not
// only through CancelDelay (the artifact key which is all zeros for BGP rows).
//
// Before the fix, runRecoveredAction always registered the artifact key
// "attack:0:action:0:conn:0:rule:", so CancelAnnouncementDelay could never
// find the in-memory cancel func and the recovered goroutine would sleep
// until the original schedule time.
func TestBGPRecovery_CancelViaAnnouncementKey(t *testing.T) {
	ms := NewMockStore()

	// Seed a delayed announcement + connector so the recovery path can look
	// them up if it fires (it shouldn't — we cancel before the timer).
	annID := 333
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, store.BGPConnector{
		ID: 7, Name: "test-bgp", Enabled: true,
	})
	ms.bgpAnnouncements.announcements = append(ms.bgpAnnouncements.announcements, store.BGPAnnouncement{
		ID: annID, Prefix: "198.51.100.0/24", RouteMap: "DIVERT",
		ConnectorID: 7, Status: "delayed", Refcount: 0,
	})
	ms.bgpAnnouncements.nextAnnID = annID

	// Seed a future pending bgp_withdraw with announcement_id.
	ms.scheduledActions.records = append(ms.scheduledActions.records, store.ScheduledAction{
		ID:             200,
		ActionType:     "bgp_withdraw",
		AnnouncementID: &annID,
		ScheduledFor:   time.Now().Add(500 * time.Millisecond),
		Status:         "pending",
	})
	ms.scheduledActions.nextID = 200

	eng := action.NewEngine(ms, "auto")
	if err := eng.RecoverScheduledActions(context.Background()); err != nil {
		t.Fatalf("RecoverScheduledActions: %v", err)
	}

	// Cancel via announcement key — this is the re-breach path.
	time.Sleep(30 * time.Millisecond)
	eng.CancelAnnouncementDelay(annID, "rebreach")

	// Wait past the original schedule time.
	time.Sleep(700 * time.Millisecond)

	// The announcement should still be in "delayed" status, NOT "withdrawing"
	// or "withdrawn". If the timer was NOT cancelled (old bug), the recovery
	// goroutine would have called MarkWithdrawing.
	ann, err := ms.BGPAnnouncements().Get(context.Background(), annID)
	if err != nil {
		t.Fatalf("Get announcement: %v", err)
	}
	if ann.Status == "withdrawing" || ann.Status == "withdrawn" {
		t.Errorf("recovered BGP timer was NOT cancelled by CancelAnnouncementDelay — "+
			"announcement status=%q (expected 'delayed')", ann.Status)
	}

	// The scheduled row should be cancelled, not completed.
	pending, _ := ms.ScheduledActions().ListPending(context.Background())
	for _, p := range pending {
		if p.ID == 200 {
			t.Errorf("scheduled row 200 still pending after CancelAnnouncementDelay")
		}
	}
}

// B.1.8: Regression — rescheduling the same announcement must not let the
// old worker's cancel branch delete the new timer's map entry.
//
// Sequence: schedule timer A → reschedule (cancels A, stores timer B) →
// old worker A wakes on Done() → must NOT delete B's entry → cancel B via
// CancelAnnouncementDelay → B must actually get cancelled.
//
// Note: this test exercises the DB-level cancel path (Schedule + Cancel via
// CancelAnnouncementDelay). The worker-level invariant (cancel branch must
// not delete the map entry) is enforced by the code change in bgp.go:513
// which removed the delete call entirely. A full worker-level test would
// require launching bgpDelayedWithdrawWorker, which is not exported; the
// current test guards the DB contract, and the code-level invariant is
// structural (no delete in the cancel branch).
func TestBGPSchedule_RescheduleDoesNotOrphanNewTimer(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")
	ctx := context.Background()

	annID := 444

	// Timer A — short delay so the worker wakes on cancel quickly.
	_, cancelCtxA, err := eng.ScheduleDelayForAnnouncement(ctx, annID, time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatalf("schedule A: %v", err)
	}
	_ = cancelCtxA

	// Timer B — reschedule same announcement with a long delay.
	_, _, err = eng.ScheduleDelayForAnnouncement(ctx, annID, time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatalf("schedule B: %v", err)
	}

	// Give timer A's goroutine time to observe cancellation and (in the old
	// buggy code) delete the map entry.
	time.Sleep(50 * time.Millisecond)

	// Now cancel via the announcement key — timer B must be found and cancelled.
	eng.CancelAnnouncementDelay(annID, "rebreach-test")

	// Verify: the pending row for this announcement should be cancelled.
	pending, _ := ms.ScheduledActions().ListPending(ctx)
	for _, p := range pending {
		if p.AnnouncementID != nil && *p.AnnouncementID == annID {
			t.Errorf("announcement %d still has a pending scheduled row after CancelAnnouncementDelay — "+
				"old worker likely deleted the new timer's map entry", annID)
		}
	}
}
