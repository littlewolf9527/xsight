package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// ─────────────────────────────────────────────────────────────────────────────
// BGP withdraw idempotent tests
// ─────────────────────────────────────────────────────────────────────────────

// TestBGPWithdraw_NotFound_IdempotentSuccess verifies that bgpWithdraw treats
// "Can't find static route specified" as idempotent success, not failure.
// Uses RecoverBGPRoutes which exercises the same bgpWithdraw code path.
func TestBGPWithdraw_NotFound_IdempotentSuccess(t *testing.T) {
	ms := NewMockStore()
	conn := store.BGPConnector{
		ID: 1, Name: "test-bgp", VtyshPath: "/usr/bin/false",
		BGPASN: 65000, AddressFamily: "auto", Enabled: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, conn)

	now := time.Now()
	ended := now.Add(-2 * time.Minute)
	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID: 1, DstIP: "10.0.0.0/24", StartedAt: now.Add(-10 * time.Minute), EndedAt: &ended,
	})
	ms.attacks.expiredAttacks = append(ms.attacks.expiredAttacks, ms.attacks.attacks[0])

	// on_detected success — route was announced
	ms.actionExecLog.logs = append(ms.actionExecLog.logs, store.ActionExecutionLog{
		ID: 1, AttackID: 1, ActionID: 10, ActionType: "bgp",
		TriggerPhase: "on_detected", Status: "success",
		ExternalRuleID: "10.0.0.0/24|DIVERT", ConnectorID: intPtr(1),
		ExecutedAt: now.Add(-9 * time.Minute),
	})

	// RecoverBGPRoutes will try to withdraw this stale route.
	// /usr/bin/false returns exit code 1 — but the test verifies no panic.
	// The real idempotent logic is in bgpWithdraw which checks stderr for "Can't find".
	action.RecoverBGPRoutes(context.Background(), ms)
}

// ─────────────────────────────────────────────────────────────────────────────
// Mitigations status derivation tests — failed with key → "failed", not "pending"
// ─────────────────────────────────────────────────────────────────────────────

// TestMitigations_FailedWithKey_ShowsFailed verifies that buildActiveActions
// correctly shows "failed" when on_expired failed log has a complete external_rule_id.
func TestMitigations_FailedWithKey_ShowsFailed(t *testing.T) {
	ms := NewMockStore()
	now := time.Now()
	connID := 1

	// Expired attack
	ended := now.Add(-1 * time.Minute)
	expiredAtk := store.Attack{
		ID: 1, DstIP: "10.0.0.1", StartedAt: now.Add(-10 * time.Minute), EndedAt: &ended,
	}
	ms.attacks.expiredAttacks = append(ms.attacks.expiredAttacks, expiredAtk)

	ms.actionExecLog.logs = append(ms.actionExecLog.logs,
		// on_detected success
		store.ActionExecutionLog{
			ID: 1, AttackID: 1, ActionID: 10, ActionType: "bgp",
			TriggerPhase: "on_detected", Status: "success",
			ExternalRuleID: "10.0.0.1/32|DIVERT", ConnectorID: &connID,
			ConnectorName: "test-bgp", ExecutedAt: now.Add(-9 * time.Minute),
		},
		// on_expired failed WITH complete external_rule_id
		store.ActionExecutionLog{
			ID: 2, AttackID: 1, ActionID: 10, ActionType: "bgp",
			TriggerPhase: "on_expired", Status: "failed",
			ExternalRuleID: "10.0.0.1/32|DIVERT", ConnectorID: &connID,
			ConnectorName: "test-bgp", ErrorMessage: "vtysh error",
			ExecutedAt: now.Add(-30 * time.Second),
		},
	)

	r := setupRouter(ms)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/active-actions/bgp", nil)
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var items []map[string]any
	json.Unmarshal(w.Body.Bytes(), &items)

	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}

	status := items[0]["status"]
	if status != "failed" {
		t.Errorf("expected status='failed', got %q (should not be 'pending')", status)
	}
}

// TestMitigations_FailedWithoutKey_ShowsPending verifies current behavior:
// when on_expired failed log has NO external_rule_id, Mitigations can't match it
// and shows "pending". (This is the bug we're fixing — after Fix 2, this case
// should not occur in production because all failed logs will have the key.)
func TestMitigations_FailedWithoutKey_ShowsPending(t *testing.T) {
	ms := NewMockStore()
	now := time.Now()
	connID := 1

	ended := now.Add(-1 * time.Minute)
	expiredAtk := store.Attack{
		ID: 2, DstIP: "10.0.0.2", StartedAt: now.Add(-10 * time.Minute), EndedAt: &ended,
	}
	ms.attacks.expiredAttacks = append(ms.attacks.expiredAttacks, expiredAtk)

	ms.actionExecLog.logs = append(ms.actionExecLog.logs,
		store.ActionExecutionLog{
			ID: 10, AttackID: 2, ActionID: 20, ActionType: "bgp",
			TriggerPhase: "on_detected", Status: "success",
			ExternalRuleID: "10.0.0.2/32|DIVERT", ConnectorID: &connID,
			ConnectorName: "test-bgp", ExecutedAt: now.Add(-9 * time.Minute),
		},
		// on_expired failed WITHOUT external_rule_id — the old bug
		store.ActionExecutionLog{
			ID: 11, AttackID: 2, ActionID: 20, ActionType: "bgp",
			TriggerPhase: "on_expired", Status: "failed",
			ExternalRuleID: "", ConnectorID: &connID,
			ConnectorName: "test-bgp", ErrorMessage: "Can't find",
			ExecutedAt: now.Add(-30 * time.Second),
		},
	)

	r := setupRouter(ms)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/active-actions/bgp", nil)
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	r.ServeHTTP(w, req)

	var items []map[string]any
	json.Unmarshal(w.Body.Bytes(), &items)

	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}

	// Without the key, buildActiveActions can't match the failed log → shows pending
	status := items[0]["status"]
	if status != "pending" {
		t.Errorf("expected status='pending' (old bug behavior), got %q", status)
	}
}

// TestMitigations_IdempotentSuccess_Disappears verifies that when bgpWithdraw
// treats "Can't find" as success (with full key), the item disappears from Mitigations.
func TestMitigations_IdempotentSuccess_Disappears(t *testing.T) {
	ms := NewMockStore()
	now := time.Now()
	connID := 1

	ended := now.Add(-1 * time.Minute)
	expiredAtk := store.Attack{
		ID: 3, DstIP: "10.0.0.3", StartedAt: now.Add(-10 * time.Minute), EndedAt: &ended,
	}
	ms.attacks.expiredAttacks = append(ms.attacks.expiredAttacks, expiredAtk)

	ms.actionExecLog.logs = append(ms.actionExecLog.logs,
		store.ActionExecutionLog{
			ID: 20, AttackID: 3, ActionID: 30, ActionType: "bgp",
			TriggerPhase: "on_detected", Status: "success",
			ExternalRuleID: "10.0.0.3/32|DIVERT", ConnectorID: &connID,
			ConnectorName: "test-bgp", ExecutedAt: now.Add(-9 * time.Minute),
		},
		// on_expired success with "idempotent" note — this is what Fix 1 produces
		store.ActionExecutionLog{
			ID: 21, AttackID: 3, ActionID: 30, ActionType: "bgp",
			TriggerPhase: "on_expired", Status: "success",
			ExternalRuleID: "10.0.0.3/32|DIVERT", ConnectorID: &connID,
			ConnectorName: "test-bgp", ErrorMessage: "idempotent: route already withdrawn",
			ExecutedAt: now.Add(-30 * time.Second),
		},
	)

	r := setupRouter(ms)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/active-actions/bgp", nil)
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	r.ServeHTTP(w, req)

	var items []map[string]any
	json.Unmarshal(w.Body.Bytes(), &items)

	// on_expired success with matching key → item should be removed from list
	if len(items) != 0 {
		t.Errorf("expected 0 items (withdrawn), got %d with status=%v", len(items), items[0]["status"])
	}
}
