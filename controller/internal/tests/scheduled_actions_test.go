package tests

// v1.2 PR-3 regression tests: scheduled_actions persistence + RecoverScheduledActions.
//
// The critical v1.1 bug these tests guard against: pendingDelay map was
// in-memory only, so delayed withdraw/unblock tasks silently disappeared on
// controller restart. PR-3 persists schedules to DB; on startup the engine
// re-arms timers, and overdue schedules are compensated by immediate execution.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// ─────────────────────────────────────────────────────────────────────────────
// Repo-level tests
// ─────────────────────────────────────────────────────────────────────────────

func TestScheduledActions_Schedule_WritesPendingRow(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")
	ctx := context.Background()
	scheduledFor := time.Now().Add(5 * time.Minute)

	id, cctx, err := eng.ScheduleDelay(ctx, "bgp_withdraw", 1, 2, 3, "192.0.2.1/32|RTBH", scheduledFor)
	if err != nil {
		t.Fatalf("ScheduleDelay: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero schedule ID")
	}
	if cctx == nil {
		t.Fatal("expected non-nil cancel context")
	}

	rows, _ := ms.ScheduledActions().ListPending(ctx)
	if len(rows) != 1 {
		t.Fatalf("expected 1 pending row, got %d", len(rows))
	}
	r := rows[0]
	if r.ActionType != "bgp_withdraw" || r.AttackID != 1 || r.ActionID != 2 ||
		r.ConnectorID != 3 || r.ExternalRuleID != "192.0.2.1/32|RTBH" {
		t.Errorf("row fields wrong: %+v", r)
	}
	if r.Status != "pending" {
		t.Errorf("status = %q, want pending", r.Status)
	}
}

// Partial UNIQUE emulation: re-scheduling the same pending key returns the same ID.
func TestScheduledActions_Schedule_IdempotentOnPendingBusinessKey(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")
	ctx := context.Background()

	id1, _, _ := eng.ScheduleDelay(ctx, "xdrop_unblock", 1, 2, 3, "rule-1", time.Now().Add(1*time.Minute))
	id2, _, err := eng.ScheduleDelay(ctx, "xdrop_unblock", 1, 2, 3, "rule-1", time.Now().Add(2*time.Minute))
	if err != nil {
		t.Fatalf("second schedule: %v", err)
	}
	if id1 != id2 {
		t.Errorf("expected same ID on re-schedule of pending key, got %d then %d", id1, id2)
	}
	rows, _ := ms.ScheduledActions().ListPending(ctx)
	if len(rows) != 1 {
		t.Errorf("expected exactly 1 pending row, got %d", len(rows))
	}
}

// Complete / Cancel / Fail terminal transitions.
func TestScheduledActions_StateTransitions(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")
	ctx := context.Background()
	scheduledFor := time.Now().Add(1 * time.Minute)

	idComplete, _, _ := eng.ScheduleDelay(ctx, "bgp_withdraw", 1, 10, 1, "r-c", scheduledFor)
	idFail, _, _ := eng.ScheduleDelay(ctx, "bgp_withdraw", 1, 11, 1, "r-f", scheduledFor)
	_, _, _ = eng.ScheduleDelay(ctx, "bgp_withdraw", 1, 12, 1, "r-x", scheduledFor)

	eng.CompleteDelay(ctx, idComplete, 1, 10, 1, "r-c")
	eng.FailDelay(ctx, idFail, 1, 11, 1, "r-f", "simulated failure")
	eng.CancelDelay(1, 12, 1, "r-x")
	// Pending list should now be empty
	pending, _ := ms.ScheduledActions().ListPending(ctx)
	if len(pending) != 0 {
		t.Errorf("expected 0 pending after all terminal transitions, got %d", len(pending))
	}
}

// MarkExecuting race guard: exactly one caller can transition pending → executing.
func TestScheduledActions_MarkExecuting_RaceGuard(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")
	ctx := context.Background()

	id, _, _ := eng.ScheduleDelay(ctx, "bgp_withdraw", 1, 2, 3, "r-race", time.Now().Add(1*time.Minute))

	// First caller succeeds, second fails
	if !eng.MarkExecutingDelay(ctx, id) {
		t.Fatal("first MarkExecutingDelay should succeed")
	}
	if eng.MarkExecutingDelay(ctx, id) {
		t.Error("second MarkExecutingDelay must fail (row no longer pending)")
	}
}

// CancelDelay's DB-level side effect cancels the row, not just the in-memory cancel.
func TestScheduledActions_CancelDelay_UpdatesDB(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")
	ctx := context.Background()

	id, _, _ := eng.ScheduleDelay(ctx, "bgp_withdraw", 1, 2, 3, "rule", time.Now().Add(5*time.Minute))

	eng.CancelDelay(1, 2, 3, "rule")

	pending, _ := ms.ScheduledActions().ListPending(ctx)
	for _, r := range pending {
		if r.ID == id {
			t.Errorf("row %d should have been cancelled, still in pending list: %+v", id, r)
		}
	}
}

// CancelDelaysForAttack cancels every pending row for the attack.
func TestScheduledActions_CancelAllForAttack(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")
	ctx := context.Background()

	// 3 schedules for attack 1, 1 schedule for attack 2.
	eng.ScheduleDelay(ctx, "bgp_withdraw", 1, 10, 1, "r1", time.Now().Add(1*time.Minute))
	eng.ScheduleDelay(ctx, "bgp_withdraw", 1, 11, 1, "r2", time.Now().Add(1*time.Minute))
	eng.ScheduleDelay(ctx, "xdrop_unblock", 1, 12, 2, "rx", time.Now().Add(1*time.Minute))
	eng.ScheduleDelay(ctx, "bgp_withdraw", 2, 20, 1, "r3", time.Now().Add(1*time.Minute))

	eng.CancelDelaysForAttack(1)

	pending, _ := ms.ScheduledActions().ListPending(ctx)
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending row (attack 2) after cancel, got %d: %+v", len(pending), pending)
	}
	if pending[0].AttackID != 2 {
		t.Errorf("wrong remaining row: %+v", pending[0])
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Recovery: the critical v1.1 bug fix
// ─────────────────────────────────────────────────────────────────────────────

// Overdue (scheduled_for in the past) — recovery executes immediately.
func TestScheduledActions_Recovery_OverdueExecutesImmediately(t *testing.T) {
	var deletes int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			atomic.AddInt32(&deletes, 1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ms := NewMockStore()
	// Seed an xDrop connector that points to our test server
	ms.xdropConnectors.connectors = append(ms.xdropConnectors.connectors, store.XDropConnector{
		ID: 5, Name: "test-xdrop", APIURL: srv.URL, Enabled: true,
	})
	// Seed an overdue pending row (scheduled_for already elapsed)
	overdueRow := store.ScheduledAction{
		ActionType:     "xdrop_unblock",
		AttackID:       100,
		ActionID:       40,
		ConnectorID:    5,
		ExternalRuleID: "rule-overdue",
		ScheduledFor:   time.Now().Add(-1 * time.Minute), // past
	}
	id, err := ms.ScheduledActions().Schedule(context.Background(), &overdueRow)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	eng := action.NewEngine(ms, "auto")
	if err := eng.RecoverScheduledActions(context.Background()); err != nil {
		t.Fatalf("RecoverScheduledActions: %v", err)
	}

	// Give the recovery goroutine time to run — it's async.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&deletes) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if atomic.LoadInt32(&deletes) == 0 {
		t.Error("expected xDrop DELETE to fire for overdue schedule")
	}

	// Row should eventually be marked completed (or failed if anything went wrong).
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pending, _ := ms.ScheduledActions().ListPending(context.Background())
		stillPending := false
		for _, r := range pending {
			if r.ID == id {
				stillPending = true
				break
			}
		}
		if !stillPending {
			return // success — row transitioned out of pending
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("row remained pending after recovery — expected completed/failed")
}

// Future-scheduled — recovery arms a timer that fires after the remaining delay.
func TestScheduledActions_Recovery_FutureArmsTimer(t *testing.T) {
	var deletes int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			atomic.AddInt32(&deletes, 1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ms := NewMockStore()
	ms.xdropConnectors.connectors = append(ms.xdropConnectors.connectors, store.XDropConnector{
		ID: 5, Name: "test-xdrop", APIURL: srv.URL, Enabled: true,
	})
	// Schedule 150ms in the future — tight enough for tests, long enough to
	// distinguish "deleted immediately" (a bug) from "deleted after timer".
	futureRow := store.ScheduledAction{
		ActionType:     "xdrop_unblock",
		AttackID:       101,
		ActionID:       41,
		ConnectorID:    5,
		ExternalRuleID: "rule-future",
		ScheduledFor:   time.Now().Add(150 * time.Millisecond),
	}
	if _, err := ms.ScheduledActions().Schedule(context.Background(), &futureRow); err != nil {
		t.Fatalf("seed: %v", err)
	}

	eng := action.NewEngine(ms, "auto")
	if err := eng.RecoverScheduledActions(context.Background()); err != nil {
		t.Fatalf("RecoverScheduledActions: %v", err)
	}

	// Immediately after recovery: NO delete yet (timer still armed).
	time.Sleep(30 * time.Millisecond)
	if atomic.LoadInt32(&deletes) != 0 {
		t.Error("future-scheduled recovery fired too early — timer not honored")
	}

	// After the delay elapses: DELETE should fire.
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&deletes) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("future-scheduled recovery did not fire after timer elapsed")
}

// PR-3 P1 regression: recovery path must write per-rule action_execution_log
// so Mitigations UI / timeline correctly reflect the recovered task's outcome.
// Without this log, buildActiveActions() sees the original `scheduled` row
// but no matching `on_expired success`, keeping the artifact displayed as
// pending/delayed forever even after recovery succeeded.
func TestScheduledActions_Recovery_WritesAuditLog_XDrop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ms := NewMockStore()
	ms.xdropConnectors.connectors = append(ms.xdropConnectors.connectors, store.XDropConnector{
		ID: 5, Name: "test-xdrop", APIURL: srv.URL, Enabled: true,
	})
	overdue := store.ScheduledAction{
		ActionType:     "xdrop_unblock",
		AttackID:       103,
		ActionID:       43,
		ConnectorID:    5,
		ExternalRuleID: "rule-audit",
		ScheduledFor:   time.Now().Add(-1 * time.Minute),
	}
	ms.ScheduledActions().Schedule(context.Background(), &overdue)

	eng := action.NewEngine(ms, "auto")
	if err := eng.RecoverScheduledActions(context.Background()); err != nil {
		t.Fatalf("RecoverScheduledActions: %v", err)
	}

	// Wait for recovery goroutine to finish and write logs.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		logs, _ := ms.actionExecLog.ListByAttack(context.Background(), 103)
		for _, l := range logs {
			if l.ActionType == "xdrop" && l.TriggerPhase == "on_expired" &&
				l.ExternalRuleID == "rule-audit" && l.Status == "success" {
				// Success — the audit log row was written with the right shape.
				if l.ConnectorID == nil || *l.ConnectorID != 5 {
					t.Errorf("ConnectorID wrong: got %v, want 5", l.ConnectorID)
				}
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	logs, _ := ms.actionExecLog.ListByAttack(context.Background(), 103)
	t.Errorf("recovered xdrop unblock did not write audit log with trigger_phase=on_expired + status=success; got %+v", logs)
}

// Recovery failure path must also write an audit log (status=failed) so the
// Mitigations UI can show the failure state instead of stale pending/delayed.
func TestScheduledActions_Recovery_WritesAuditLog_XDropFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError) // force failure
	}))
	defer srv.Close()

	ms := NewMockStore()
	ms.xdropConnectors.connectors = append(ms.xdropConnectors.connectors, store.XDropConnector{
		ID: 5, Name: "test-xdrop", APIURL: srv.URL, Enabled: true,
	})
	overdue := store.ScheduledAction{
		ActionType:     "xdrop_unblock",
		AttackID:       104,
		ActionID:       44,
		ConnectorID:    5,
		ExternalRuleID: "rule-failaudit",
		ScheduledFor:   time.Now().Add(-1 * time.Minute),
	}
	ms.ScheduledActions().Schedule(context.Background(), &overdue)

	eng := action.NewEngine(ms, "auto")
	if err := eng.RecoverScheduledActions(context.Background()); err != nil {
		t.Fatalf("RecoverScheduledActions: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		logs, _ := ms.actionExecLog.ListByAttack(context.Background(), 104)
		for _, l := range logs {
			if l.ActionType == "xdrop" && l.TriggerPhase == "on_expired" &&
				l.ExternalRuleID == "rule-failaudit" && l.Status == "failed" {
				return // success — failed row written
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	logs, _ := ms.actionExecLog.ListByAttack(context.Background(), 104)
	t.Errorf("recovered xdrop unblock failure did not write audit log with status=failed; got %+v", logs)
}

// Cancel during recovery's wait — the cancelCtx terminates cleanly and no side
// effect runs.
func TestScheduledActions_Recovery_CancelDuringWait(t *testing.T) {
	var deletes int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			atomic.AddInt32(&deletes, 1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ms := NewMockStore()
	ms.xdropConnectors.connectors = append(ms.xdropConnectors.connectors, store.XDropConnector{
		ID: 5, Name: "test-xdrop", APIURL: srv.URL, Enabled: true,
	})
	futureRow := store.ScheduledAction{
		ActionType:     "xdrop_unblock",
		AttackID:       102,
		ActionID:       42,
		ConnectorID:    5,
		ExternalRuleID: "rule-cancel",
		ScheduledFor:   time.Now().Add(500 * time.Millisecond),
	}
	ms.ScheduledActions().Schedule(context.Background(), &futureRow)

	eng := action.NewEngine(ms, "auto")
	if err := eng.RecoverScheduledActions(context.Background()); err != nil {
		t.Fatalf("RecoverScheduledActions: %v", err)
	}

	// Cancel before the timer fires.
	time.Sleep(30 * time.Millisecond)
	eng.CancelDelay(102, 42, 5, "rule-cancel")

	// Wait past the original schedule time — DELETE should NOT fire.
	time.Sleep(700 * time.Millisecond)
	if got := atomic.LoadInt32(&deletes); got != 0 {
		t.Errorf("CancelDelay during recovery wait did not prevent execution; got %d deletes", got)
	}
}
