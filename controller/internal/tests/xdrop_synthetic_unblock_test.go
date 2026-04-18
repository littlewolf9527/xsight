package tests

import (
	"context"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// Focused integration test (PR-8 audit suggestion): the synthetic-ID short
// circuit must keep immediate and delayed unblock paths consistent. Both
// paths now go through CloseSyntheticXDropRuleLocal — this test pins the
// contract that a synthetic "failed-create-*" row ends up withdrawn with
// no external HTTP side effect and an audit log marker, so future refactors
// can't silently drift back into "delayed-only fires real DELETE".
//
// We test the helper directly rather than spinning up the full goroutine
// path — both call sites (immediate loop + delayed goroutine) now pass
// through this single function, so exercising it covers the contract both
// paths must satisfy.
func TestCloseSyntheticXDropRuleLocal_MarksWithdrawnWithoutHTTP(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	// Seed a synthetic failed row (what PR-8 create-failure path produces).
	ruleID := "failed-create-777-42"
	if _, err := ms.XDropActiveRules().Upsert(ctx, &store.XDropActiveRule{
		AttackID:       777,
		ActionID:       42,
		ConnectorID:    4,
		ExternalRuleID: ruleID,
		Status:         "withdrawing", // caller just transitioned via MarkWithdrawing
		ErrorMessage:   "dial tcp ...: connect: connection refused",
	}); err != nil {
		t.Fatalf("seed synthetic row: %v", err)
	}

	// Immediate-path semantics: engine=nil, sid=0. No HTTP server set up —
	// if the code ever tries to fall through to an HTTP DELETE, the whole
	// test harness has no network target and the assertion below would fail
	// (row would not transition to withdrawn).
	action.CloseSyntheticXDropRuleLocal(
		ctx, ms, nil,
		777, 42, 4,
		"Test-xDrop", "on_expired", ruleID,
		0,
	)

	// Row must now be withdrawn.
	rows, _ := ms.XDropActiveRules().ListByAttack(ctx, 777)
	var row *store.XDropActiveRule
	for i := range rows {
		if rows[i].ExternalRuleID == ruleID {
			row = &rows[i]
			break
		}
	}
	if row == nil {
		t.Fatalf("row disappeared; expected withdrawn row still present")
	}
	if row.Status != "withdrawn" {
		t.Errorf("status = %q, want withdrawn", row.Status)
	}

	// Audit log entry must exist with Status=success and the synthetic-marker
	// ErrorMessage — the audit trail is how operators confirm the row was
	// closed out WITHOUT a real DELETE being issued.
	const marker = "synthetic failed-create rule; no xDrop DELETE needed"
	found := false
	for _, l := range ms.actionExecLog.logs {
		if l.AttackID == 777 && l.ExternalRuleID == ruleID &&
			l.Status == "success" && l.ErrorMessage == marker {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected audit log with marker %q for rule %s; got %+v", marker, ruleID, ms.actionExecLog.logs)
	}
}

