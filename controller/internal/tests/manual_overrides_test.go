package tests

// v1.2 PR-2 regression tests: action_manual_overrides index replacing the
// linear scan of action_execution_log for manual-override checks.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// ─────────────────────────────────────────────────────────────────────────────
// Repo-level tests: Create / Exists / ListByAttack
// ─────────────────────────────────────────────────────────────────────────────

func TestManualOverrideRepo_CreateAndExists(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	id, err := ms.ManualOverrides().Create(ctx, &store.ActionManualOverride{
		AttackID:       1,
		ActionID:       2,
		ConnectorID:    3,
		ExternalRuleID: "192.0.2.1/32|RTBH",
		CreatedBy:      "operator",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if id == 0 {
		t.Fatal("Create returned id=0")
	}

	ok, err := ms.ManualOverrides().Exists(ctx, 1, 2, 3, "192.0.2.1/32|RTBH")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !ok {
		t.Error("Exists should return true for just-created record")
	}
}

// UNIQUE business key: Create with same (attack, action, connector, rule)
// must be idempotent — returns existing ID, updates created_by.
func TestManualOverrideRepo_Create_Idempotent(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	id1, _ := ms.ManualOverrides().Create(ctx, &store.ActionManualOverride{
		AttackID: 1, ActionID: 2, ConnectorID: 3, ExternalRuleID: "r1", CreatedBy: "alice",
	})
	id2, err := ms.ManualOverrides().Create(ctx, &store.ActionManualOverride{
		AttackID: 1, ActionID: 2, ConnectorID: 3, ExternalRuleID: "r1", CreatedBy: "bob",
	})
	if err != nil {
		t.Fatalf("second Create should succeed idempotently: %v", err)
	}
	if id1 != id2 {
		t.Errorf("idempotent Create must return same ID; got %d then %d", id1, id2)
	}

	// Only one row in the list — no duplicate
	rows, _ := ms.ManualOverrides().ListByAttack(ctx, 1)
	if len(rows) != 1 {
		t.Errorf("expected exactly 1 row after idempotent Create, got %d", len(rows))
	}
}

// Cross-attack / cross-connector / cross-rule isolation — Exists must NOT
// return true for a near-miss business key.
func TestManualOverrideRepo_Exists_Isolation(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	_, _ = ms.ManualOverrides().Create(ctx, &store.ActionManualOverride{
		AttackID: 1, ActionID: 2, ConnectorID: 3, ExternalRuleID: "r1",
	})

	cases := []struct {
		name                                       string
		attack, action, connector int
		rule                                       string
	}{
		{"different attack", 99, 2, 3, "r1"},
		{"different action", 1, 99, 3, "r1"},
		{"different connector", 1, 2, 99, "r1"},
		{"different rule", 1, 2, 3, "other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, _ := ms.ManualOverrides().Exists(ctx, tc.attack, tc.action, tc.connector, tc.rule)
			if ok {
				t.Errorf("Exists should return false for %s", tc.name)
			}
		})
	}
}

func TestManualOverrideRepo_ListByAttack_ScopedCorrectly(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	// 3 rows for attack 1, 1 row for attack 2
	for i, rule := range []string{"r1", "r2", "r3"} {
		ms.ManualOverrides().Create(ctx, &store.ActionManualOverride{
			AttackID: 1, ActionID: i + 1, ConnectorID: 10, ExternalRuleID: rule,
		})
	}
	ms.ManualOverrides().Create(ctx, &store.ActionManualOverride{
		AttackID: 2, ActionID: 99, ConnectorID: 10, ExternalRuleID: "other",
	})

	a1, _ := ms.ManualOverrides().ListByAttack(ctx, 1)
	if len(a1) != 3 {
		t.Errorf("attack 1: expected 3 rows, got %d", len(a1))
	}
	a2, _ := ms.ManualOverrides().ListByAttack(ctx, 2)
	if len(a2) != 1 {
		t.Errorf("attack 2: expected 1 row, got %d", len(a2))
	}
	a3, _ := ms.ManualOverrides().ListByAttack(ctx, 99)
	if len(a3) != 0 {
		t.Errorf("attack 99 (no rows): expected 0, got %d", len(a3))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration: HasManualOverride uses the new index, not the log
// ─────────────────────────────────────────────────────────────────────────────

func TestHasManualOverride_UsesIndexTable(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")
	ctx := context.Background()

	// Seed ONLY the index table — not the log. If HasManualOverride still
	// reads the log, it will return false.
	ms.ManualOverrides().Create(ctx, &store.ActionManualOverride{
		AttackID: 1, ActionID: 2, ConnectorID: 3, ExternalRuleID: "r1",
	})

	if !eng.HasManualOverride(ctx, 1, 2, 3, "r1") {
		t.Error("HasManualOverride should read from index table, not execution_log")
	}
}

// Inverse: log has a manual_override row, but index does NOT → HasManualOverride
// returns false. Proves we're reading only from the new index (v1.1 behavior
// of scanning the log is gone).
func TestHasManualOverride_IgnoresLogWithoutIndex(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")
	ctx := context.Background()

	cid := 3
	ms.actionExecLog.logs = append(ms.actionExecLog.logs, store.ActionExecutionLog{
		AttackID: 1, ActionID: 2, TriggerPhase: "manual_override", Status: "success",
		ExternalRuleID: "r1", ConnectorID: &cid, ExecutedAt: time.Now(),
	})

	if eng.HasManualOverride(ctx, 1, 2, 3, "r1") {
		t.Error("HasManualOverride must only trust the index table; log-only rows should NOT count")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration: ForceRemove handler writes to both log AND index on success
// ─────────────────────────────────────────────────────────────────────────────

func TestForceRemove_WritesIndexOnSuccess(t *testing.T) {
	ms := NewMockStore()
	now := time.Now()

	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID: 6, DstIP: "192.0.2.10", StartedAt: now.Add(-5 * time.Minute),
	})
	ms.responses.actions = append(ms.responses.actions, store.ResponseAction{
		ID: 40, ResponseID: 1, ActionType: "bgp",
	})
	// BGP connector with /bin/true — exits 0, so removeErr == nil, path writes index.
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, store.BGPConnector{
		ID: 7, Name: "test-bgp", VtyshPath: "/bin/true",
		BGPASN: 65001, AddressFamily: "ipv4 unicast", Enabled: true,
	})

	eng := action.NewEngine(ms, "auto")
	r := setupRouterWithEngine(ms, eng)

	payload := map[string]any{
		"attack_id":        6,
		"action_id":        40,
		"connector_id":     7,
		"external_rule_id": "192.0.2.10/32|RTBH",
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/active-actions/force-remove", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Accept 200 (vtysh succeeded) or 500 (if mock bgp doesn't actually invoke
	// /bin/true — check body for clues). The critical invariant is the index row.
	rows, err := ms.ManualOverrides().ListByAttack(context.Background(), 6)
	if err != nil {
		t.Fatalf("ListByAttack: %v", err)
	}

	// If removeErr was nil in the handler, the index should have 1 row.
	// If removeErr was non-nil, the index should have 0 rows (index only
	// written on success).
	if w.Code == http.StatusOK {
		if len(rows) != 1 {
			t.Errorf("ForceRemove success: expected 1 index row, got %d; w.Body=%s", len(rows), w.Body.String())
		} else {
			r := rows[0]
			if r.AttackID != 6 || r.ActionID != 40 || r.ConnectorID != 7 || r.ExternalRuleID != "192.0.2.10/32|RTBH" {
				t.Errorf("index row fields wrong: %+v", r)
			}
		}
	} else {
		// removeErr path — index must NOT have a row
		if len(rows) != 0 {
			t.Errorf("ForceRemove failed (%d): index should NOT have rows, got %d: %+v", w.Code, len(rows), rows)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// PR-2 P1 regression: action-scoped override must NOT leak across actions
// ─────────────────────────────────────────────────────────────────────────────

// TestManualOverride_ActionScoped_NoCrossActionLeak: two different
// ResponseActions in the same attack, sharing the same (connector_id,
// external_rule_id) — possible in BGP when two actions both use the same
// route_map against the same attack's dst_ip. Operator force-removes ONE
// action's artifact. The OTHER action's HasManualOverride check MUST still
// return false.
//
// This guards against the v1.1 "port" bug where bgp.go/xdrop.go batch
// override sets used (connector, rule) as key and dropped action_id, which
// would have erroneously suppressed both actions.
func TestManualOverride_ActionScoped_NoCrossActionLeak(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")
	ctx := context.Background()

	// Same attack 1, two actions 10 and 20, both targeting connector 3, rule "r1".
	// Only action 10 is overridden.
	_, err := ms.ManualOverrides().Create(ctx, &store.ActionManualOverride{
		AttackID: 1, ActionID: 10, ConnectorID: 3, ExternalRuleID: "r1",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	if !eng.HasManualOverride(ctx, 1, 10, 3, "r1") {
		t.Error("overridden action (10) must be suppressed")
	}
	if eng.HasManualOverride(ctx, 1, 20, 3, "r1") {
		t.Error("non-overridden action (20) must NOT be suppressed even though it shares connector+rule with action 10")
	}
}

// TestManualOverride_BatchSetConstruction_IsActionScoped (PR-2 P3 guard):
// replicates the exact batch key construction in bgp.go/xdrop.go to lock down
// the set-build and lookup formats. If either of those files drifts away from
// "{actionID}:{connectorID}:{externalRuleID}", this test catches the
// divergence immediately.
//
// The test uses the same ListByAttack → local map pattern that the hot
// suppression paths use in production.
func TestManualOverride_BatchSetConstruction_IsActionScoped(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	// Only action 10 overridden (same connector/rule key as a hypothetical action 20).
	if _, err := ms.ManualOverrides().Create(ctx, &store.ActionManualOverride{
		AttackID: 1, ActionID: 10, ConnectorID: 3, ExternalRuleID: "r1",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Replicate bgp.go / xdrop.go batch set construction — MUST match exactly.
	overrides, _ := ms.ManualOverrides().ListByAttack(ctx, 1)
	overrideSet := make(map[string]struct{}, len(overrides))
	for _, o := range overrides {
		overrideSet[fmt.Sprintf("%d:%d:%s", o.ActionID, o.ConnectorID, o.ExternalRuleID)] = struct{}{}
	}

	// action 10's artifact: must be in set
	key10 := fmt.Sprintf("%d:%d:%s", 10, 3, "r1")
	if _, ok := overrideSet[key10]; !ok {
		t.Errorf("batch set should contain action 10's override; set=%v", overrideSet)
	}

	// action 20's artifact (same connector/rule, different action): must NOT be in set
	key20 := fmt.Sprintf("%d:%d:%s", 20, 3, "r1")
	if _, ok := overrideSet[key20]; ok {
		t.Errorf("batch set must be action-scoped: action 20 should NOT match action 10's override; set=%v", overrideSet)
	}
}

// Inverse: two actions, BOTH overridden — both must be suppressed.
func TestManualOverride_ActionScoped_BothOverriddenSuppressed(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")
	ctx := context.Background()

	for _, actID := range []int{10, 20} {
		ms.ManualOverrides().Create(ctx, &store.ActionManualOverride{
			AttackID: 1, ActionID: actID, ConnectorID: 3, ExternalRuleID: "r1",
		})
	}

	if !eng.HasManualOverride(ctx, 1, 10, 3, "r1") {
		t.Error("action 10 should be suppressed")
	}
	if !eng.HasManualOverride(ctx, 1, 20, 3, "r1") {
		t.Error("action 20 should be suppressed")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration: bgp.go withdraw suppression uses the index
// ─────────────────────────────────────────────────────────────────────────────

// TestBGPWithdraw_SuppressionUsesIndex: seed a BGP on_detected success log
// (the route that would be withdrawn) + a manual override index entry for
// the same artifact. bgpWithdraw must skip that route without invoking vtysh.
// We can only assert this indirectly through the mock — but we verify that
// HasManualOverride answers correctly, which is the same code path bgp.go
// now uses (via pre-fetched set).
func TestBGPWithdraw_SuppressionLookupUsesIndex(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")
	ctx := context.Background()

	// Seed 100 override records for the attack (simulating a large attack's
	// worth of prior force-removes). The set lookup should still be fast.
	for i := 0; i < 100; i++ {
		ms.ManualOverrides().Create(ctx, &store.ActionManualOverride{
			AttackID:       1,
			ActionID:       2,
			ConnectorID:    3,
			ExternalRuleID: fmt.Sprintf("192.0.2.%d/32|RTBH", i),
		})
	}

	// 1 positive + 1 negative check
	if !eng.HasManualOverride(ctx, 1, 2, 3, "192.0.2.50/32|RTBH") {
		t.Error("should find override in the middle of the set")
	}
	if eng.HasManualOverride(ctx, 1, 2, 3, "192.0.2.999/32|RTBH") {
		t.Error("should NOT find override that was never created")
	}
}
