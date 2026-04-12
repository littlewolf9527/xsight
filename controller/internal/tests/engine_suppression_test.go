package tests

import (
	"context"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// insertManualOverride is a helper that writes a manual_override success log
// into the mock store's ActionExecLog.
func insertManualOverride(t *testing.T, ms *MockStore, attackID, actionID, connectorID int, ruleID string) {
	t.Helper()
	cid := connectorID
	log := &store.ActionExecutionLog{
		AttackID:       attackID,
		ActionID:       actionID,
		TriggerPhase:   "manual_override",
		Status:         "success",
		ExternalRuleID: ruleID,
		ConnectorID:    &cid,
		ExecutedAt:     time.Now(),
	}
	if _, err := ms.actionExecLogRepo.Create(context.Background(), log); err != nil {
		t.Fatalf("insertManualOverride: %v", err)
	}
}

// U31: A manual_override success log causes HasManualOverride to return true.
func TestManualOverride_SuppressesOnExpired(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")

	insertManualOverride(t, ms, 1, 2, 3, "r1")

	got := eng.HasManualOverride(context.Background(), 1, 2, 3, "r1")
	if !got {
		t.Error("U31: HasManualOverride should return true when manual_override success log exists")
	}
}

// U32: A manual_override for attack 1 does NOT suppress actions for attack 2.
func TestManualOverride_DoesNotAffectOtherAttacks(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")

	// Override recorded for attack 1.
	insertManualOverride(t, ms, 1, 2, 3, "r1")

	// Query for attack 2 — should return false.
	got := eng.HasManualOverride(context.Background(), 2, 2, 3, "r1")
	if got {
		t.Error("U32: HasManualOverride should return false for a different attackID")
	}
}

// U33: Manual override is per-artifact (connectorID + externalRuleID combination).
func TestManualOverride_PerArtifactSuppression(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")

	// Override only for connector 3 / rule "r1".
	insertManualOverride(t, ms, 1, 2, 3, "r1")

	t.Run("matching artifact returns true", func(t *testing.T) {
		got := eng.HasManualOverride(context.Background(), 1, 2, 3, "r1")
		if !got {
			t.Error("U33a: HasManualOverride should return true for the exact (connector=3, rule=r1)")
		}
	})

	t.Run("different connector+rule returns false", func(t *testing.T) {
		got := eng.HasManualOverride(context.Background(), 1, 2, 4, "r2")
		if got {
			t.Error("U33b: HasManualOverride should return false for (connector=4, rule=r2)")
		}
	})
}
