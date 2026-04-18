package tests

// v1.2 PR-1 regression tests: verify that action_execution_log rows are
// written with status=skipped + structured skip_reason when the action
// engine declines to execute an action. These logs are the authoritative
// source for the upcoming /api/attacks/:id/mitigation-summary endpoint.

import (
	"strings"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/tracker"
)

// setupDispatchMock builds a MockStore pre-seeded with a Response, an Attack,
// and actions the caller provides. Returns the store + the engine for driving
// HandleEvent. All actions share response_id=1; attack.ResponseID=1.
func setupDispatchMock(t *testing.T, mode string, actions []store.ResponseAction) (*MockStore, *action.Engine, *store.Attack) {
	t.Helper()
	ms := NewMockStore()
	ms.responses.responses = append(ms.responses.responses, store.Response{ID: 1, Name: "test-response", Enabled: true})
	for i := range actions {
		actions[i].ResponseID = 1
		ms.responses.actions = append(ms.responses.actions, actions[i])
	}
	respID := 1
	attack := &store.Attack{
		ID:            100,
		DstIP:         "192.0.2.1",
		DecoderFamily: "ip",
		Direction:     "receives",
		Severity:      "high",
		PeakPPS:       1000000,
		ResponseID:    &respID,
	}
	eng := action.NewEngine(ms, mode)
	return ms, eng, attack
}

// dispatch is a helper to fire a "confirmed" event (which maps to on_detected
// via phaseMatchesEvent) for the given attack.
func dispatch(eng *action.Engine, attack *store.Attack) {
	eng.HandleEvent(tracker.AttackEvent{
		Type:   "confirmed",
		Attack: attack,
		DBID:   attack.ID,
	})
}

// findSkipLog returns the first skipped log for the given action_id.
func findSkipLog(ms *MockStore, actionID int) *store.ActionExecutionLog {
	for i := range ms.actionExecLog.logs {
		l := &ms.actionExecLog.logs[i]
		if l.ActionID == actionID && l.Status == "skipped" {
			return l
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// S11: precondition_not_matched — structured precondition fails
// ─────────────────────────────────────────────────────────────────────────────

func TestSkipReason_PreconditionNotMatched_StructuredFailure(t *testing.T) {
	act := store.ResponseAction{
		ID:           10,
		ActionType:   "webhook",
		TriggerPhase: "on_detected",
		RunMode:      "once",
		Enabled:      true,
	}
	ms, eng, attack := setupDispatchMock(t, "auto", []store.ResponseAction{act})

	// Precondition: domain eq internal_ip, but attack.DstIP="192.0.2.1" has no
	// CIDR suffix → internal_ip. We need a FAILING precondition. Use decoder.
	ms.preconditions.SeedPreconditions(10, []store.ActionPrecondition{
		{ID: 1, ActionID: 10, Attribute: "decoder", Operator: "eq", Value: "udp"},
	})
	// attack.DecoderFamily="ip" != "udp" → precondition fails

	dispatch(eng, attack)

	l := findSkipLog(ms, 10)
	if l == nil {
		t.Fatalf("S11: expected skipped log for action 10, got none: all=%+v", ms.actionExecLog.logs)
	}
	if l.SkipReason != action.SkipReasonPreconditionNotMatched {
		t.Errorf("S11: skip_reason = %q, want %q", l.SkipReason, action.SkipReasonPreconditionNotMatched)
	}
	if !strings.Contains(l.ErrorMessage, "decoder eq udp") {
		t.Errorf("S11: error_message should describe failed precondition, got %q", l.ErrorMessage)
	}
	if l.ResponseName != "test-response" {
		t.Errorf("S11: response_name = %q, want test-response", l.ResponseName)
	}
	if l.ActionType != "webhook" {
		t.Errorf("S11: action_type = %q, want webhook", l.ActionType)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// S12: first_match_suppressed — second same-type action is suppressed
// ─────────────────────────────────────────────────────────────────────────────

func TestSkipReason_FirstMatchSuppressed(t *testing.T) {
	// Two xdrop actions on the same response — the second must be skipped.
	act1 := store.ResponseAction{
		ID: 20, ActionType: "xdrop", TriggerPhase: "on_detected",
		RunMode: "once", Enabled: true, Priority: 1,
	}
	act2 := store.ResponseAction{
		ID: 21, ActionType: "xdrop", TriggerPhase: "on_detected",
		RunMode: "once", Enabled: true, Priority: 2,
	}
	ms, eng, attack := setupDispatchMock(t, "auto", []store.ResponseAction{act1, act2})

	dispatch(eng, attack)

	// act1 will attempt to execute (and fail because no xdrop connector is
	// set up, but that's not our concern). act2 must be skipped with
	// first_match_suppressed.
	l := findSkipLog(ms, 21)
	if l == nil {
		t.Fatalf("S12: expected skipped log for action 21, got none: all=%+v", ms.actionExecLog.logs)
	}
	if l.SkipReason != action.SkipReasonFirstMatchSuppressed {
		t.Errorf("S12: skip_reason = %q, want %q", l.SkipReason, action.SkipReasonFirstMatchSuppressed)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// S13: mode_observe — xdrop in observe mode is skipped
// ─────────────────────────────────────────────────────────────────────────────

func TestSkipReason_ModeObserve_XDropSkipped(t *testing.T) {
	act := store.ResponseAction{
		ID: 30, ActionType: "xdrop", TriggerPhase: "on_detected",
		RunMode: "once", Enabled: true,
	}
	ms, eng, attack := setupDispatchMock(t, "observe", []store.ResponseAction{act})

	dispatch(eng, attack)

	l := findSkipLog(ms, 30)
	if l == nil {
		t.Fatalf("S13: expected skipped log for action 30 in observe mode, got none")
	}
	if l.SkipReason != action.SkipReasonModeObserve {
		t.Errorf("S13: skip_reason = %q, want %q", l.SkipReason, action.SkipReasonModeObserve)
	}
	if !strings.Contains(l.ErrorMessage, "observe") {
		t.Errorf("S13: error_message should mention observe mode, got %q", l.ErrorMessage)
	}
}

// Control: BGP in observe mode is NOT skipped (mode gate only applies to xdrop).
func TestSkipReason_ModeObserve_BGPNotSkipped(t *testing.T) {
	act := store.ResponseAction{
		ID: 31, ActionType: "bgp", TriggerPhase: "on_detected",
		RunMode: "once", Enabled: true,
	}
	ms, eng, attack := setupDispatchMock(t, "observe", []store.ResponseAction{act})

	dispatch(eng, attack)

	// BGP in observe mode must NOT produce a mode_observe skip log — it
	// proceeds to execution (will fail on missing connector, but that's
	// a different code path with status != "skipped").
	if l := findSkipLog(ms, 31); l != nil && l.SkipReason == action.SkipReasonModeObserve {
		t.Errorf("BGP in observe mode should NOT be skipped; got skip_reason=%q", l.SkipReason)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// S14: already_executed — run_mode=once with prior success
// ─────────────────────────────────────────────────────────────────────────────

func TestSkipReason_AlreadyExecuted_RunModeOnce(t *testing.T) {
	act := store.ResponseAction{
		ID: 40, ActionType: "webhook", TriggerPhase: "on_detected",
		RunMode: "once", Enabled: true,
	}
	ms, eng, attack := setupDispatchMock(t, "auto", []store.ResponseAction{act})

	// Pre-seed a prior success log → alreadyExecutedV2 returns true
	ms.actionExecLog.logs = append(ms.actionExecLog.logs, store.ActionExecutionLog{
		ID: 999, AttackID: attack.ID, ActionID: 40, TriggerPhase: "on_detected", Status: "success",
	})

	dispatch(eng, attack)

	var skipLog *store.ActionExecutionLog
	for i := range ms.actionExecLog.logs {
		l := &ms.actionExecLog.logs[i]
		if l.ActionID == 40 && l.Status == "skipped" {
			skipLog = l
			break
		}
	}
	if skipLog == nil {
		t.Fatalf("S14: expected skipped log for action 40 (already executed), got none")
	}
	if skipLog.SkipReason != action.SkipReasonAlreadyExecuted {
		t.Errorf("S14: skip_reason = %q, want %q", skipLog.SkipReason, action.SkipReasonAlreadyExecuted)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// S15 (PR-1 P1 audit regression): auto-paired on_expired child must NOT be
// logged as first_match_suppressed during a "confirmed" event.
//
// Real DB sorts actions by (trigger_phase, priority). For an on_detected +
// auto-paired on_expired pair on the same type (e.g. both xdrop), the
// on_detected parent runs and marks firstMatchTypes[xdrop]=true. In the old
// PR-1 code, the on_expired child would then get tagged
// skip_reason=first_match_suppressed — but it was really just phase-mismatched
// (on_expired vs confirmed). The fix moves first_match check AFTER the phase
// gate so the on_expired child is silently filtered, as intended.
// ─────────────────────────────────────────────────────────────────────────────

func TestSkipReason_AutoPairedChild_NotFirstMatchSuppressed(t *testing.T) {
	parent := store.ResponseAction{
		ID:           60,
		ActionType:   "xdrop",
		TriggerPhase: "on_detected",
		RunMode:      "once",
		Enabled:      true,
	}
	child := store.ResponseAction{
		ID:            61,
		ActionType:    "xdrop",
		TriggerPhase:  "on_expired",
		RunMode:       "once",
		Enabled:       true,
		AutoGenerated: true,
	}
	ms, eng, attack := setupDispatchMock(t, "auto", []store.ResponseAction{parent, child})

	// "confirmed" maps to on_detected. The parent will attempt to execute
	// (will fail with missing connector, but that's status=failed, not
	// status=skipped). The child, being on_expired, should be SILENTLY
	// filtered by the phase gate — NOT logged as first_match_suppressed.
	dispatch(eng, attack)

	for _, l := range ms.actionExecLog.logs {
		if l.ActionID == 61 && l.SkipReason == action.SkipReasonFirstMatchSuppressed {
			t.Fatalf("S15: on_expired child (id=61) was misattributed as first_match_suppressed; "+
				"full log=%+v", l)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// S16 (PR-1 P3 guard): execution=manual is a silent gate — no skip log.
// Locks in the silent/logged gate ordering invariant. If someone later
// refactors the dispatch loop and accidentally writes a skip log for
// manual actions, this test catches it.
// ─────────────────────────────────────────────────────────────────────────────

func TestSkipReason_ExecutionManual_NoSkipLog(t *testing.T) {
	act := store.ResponseAction{
		ID: 70, ActionType: "webhook", TriggerPhase: "on_detected",
		RunMode: "once", Enabled: true, Execution: "manual",
	}
	ms, eng, attack := setupDispatchMock(t, "auto", []store.ResponseAction{act})

	dispatch(eng, attack)

	if len(ms.actionExecLog.logs) > 0 {
		t.Errorf("S16: execution=manual should NOT produce any log; got %+v", ms.actionExecLog.logs)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// S17 (PR-1 P3 guard): execution=manual must NOT consume the first-match slot.
// If a manual action came first in the loop, it should NOT mark
// firstMatchTypes[type], so a later auto action of the same type can still
// execute. Conversely: if an auto action already marked, a later manual
// action should be filtered silently (by execution=manual), not logged as
// first_match_suppressed.
// ─────────────────────────────────────────────────────────────────────────────

func TestSkipReason_ExecutionManual_DoesNotBlockAutoFirstMatch(t *testing.T) {
	// manual comes first (lower priority number), auto comes second.
	manualAct := store.ResponseAction{
		ID: 80, ActionType: "xdrop", TriggerPhase: "on_detected",
		RunMode: "once", Enabled: true, Execution: "manual", Priority: 1,
	}
	autoAct := store.ResponseAction{
		ID: 81, ActionType: "xdrop", TriggerPhase: "on_detected",
		RunMode: "once", Enabled: true, Execution: "automatic", Priority: 2,
	}
	ms, eng, attack := setupDispatchMock(t, "auto", []store.ResponseAction{manualAct, autoAct})

	dispatch(eng, attack)

	// manual (id=80) must NOT have any log
	for _, l := range ms.actionExecLog.logs {
		if l.ActionID == 80 {
			t.Errorf("S17: manual action (id=80) must not produce any log; got %+v", l)
		}
	}
	// auto (id=81) must NOT be logged as first_match_suppressed by the manual
	for _, l := range ms.actionExecLog.logs {
		if l.ActionID == 81 && l.SkipReason == action.SkipReasonFirstMatchSuppressed {
			t.Errorf("S17: auto action (id=81) should NOT be blocked by manual predecessor; got %+v", l)
		}
	}
}

// Inverse of S17: an auto action that already executed DOES suppress a later
// manual action of the same type, but silently (manual is a silent gate).
func TestSkipReason_ExecutionManual_NotFirstMatchSuppressed_EvenWhenAfterAuto(t *testing.T) {
	autoAct := store.ResponseAction{
		ID: 90, ActionType: "xdrop", TriggerPhase: "on_detected",
		RunMode: "once", Enabled: true, Execution: "automatic", Priority: 1,
	}
	manualAct := store.ResponseAction{
		ID: 91, ActionType: "xdrop", TriggerPhase: "on_detected",
		RunMode: "once", Enabled: true, Execution: "manual", Priority: 2,
	}
	ms, eng, attack := setupDispatchMock(t, "auto", []store.ResponseAction{autoAct, manualAct})

	dispatch(eng, attack)

	// manual (id=91) must NOT be logged as first_match_suppressed
	for _, l := range ms.actionExecLog.logs {
		if l.ActionID == 91 {
			t.Errorf("S17 inverse: manual action (id=91) must not produce any log even when it comes after a matched auto; got %+v", l)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Positive: precondition passes → no skip log, action proceeds
// ─────────────────────────────────────────────────────────────────────────────

func TestSkipReason_PreconditionPasses_NoSkipLog(t *testing.T) {
	act := store.ResponseAction{
		ID: 50, ActionType: "webhook", TriggerPhase: "on_detected",
		RunMode: "once", Enabled: true,
	}
	ms, eng, attack := setupDispatchMock(t, "auto", []store.ResponseAction{act})

	// Precondition that matches: decoder eq ip
	ms.preconditions.SeedPreconditions(50, []store.ActionPrecondition{
		{ID: 1, ActionID: 50, Attribute: "decoder", Operator: "eq", Value: "ip"},
	})

	dispatch(eng, attack)

	if l := findSkipLog(ms, 50); l != nil {
		t.Errorf("expected NO skip log when precondition passes, got skip_reason=%q", l.SkipReason)
	}
}
