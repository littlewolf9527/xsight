package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// U34: TestTimelineAPI_ReturnsFilteredLogs
func TestTimelineAPI_ReturnsFilteredLogs(t *testing.T) {
	ms := NewMockStore()
	now := time.Now()
	connID := 3

	// Attack
	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID:        1,
		DstIP:     "10.0.0.1",
		StartedAt: now.Add(-10 * time.Minute),
	})

	// Logs: two different artifacts for same attack
	ms.actionExecLog.logs = append(ms.actionExecLog.logs,
		store.ActionExecutionLog{
			ID: 1, AttackID: 1, ActionID: 10, ActionType: "bgp",
			TriggerPhase: "on_detected", Status: "success",
			ExternalRuleID: "10.0.0.1/32|RTBH", ConnectorID: &connID,
			ExecutedAt: now.Add(-9 * time.Minute),
		},
		store.ActionExecutionLog{
			ID: 2, AttackID: 1, ActionID: 10, ActionType: "bgp",
			TriggerPhase: "on_expired", Status: "success",
			ExternalRuleID: "10.0.0.1/32|RTBH", ConnectorID: &connID,
			ExecutedAt: now.Add(-5 * time.Minute),
		},
		store.ActionExecutionLog{
			ID: 3, AttackID: 1, ActionID: 20, ActionType: "xdrop",
			TriggerPhase: "on_detected", Status: "success",
			ExternalRuleID: "rule-99", ConnectorID: &connID,
			ExecutedAt: now.Add(-9 * time.Minute),
		},
	)

	r := setupRouter(ms)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET",
		"/api/active-actions/timeline?attack_id=1&connector_id=3&external_rule_id=10.0.0.1/32|RTBH",
		nil)
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result struct {
		Logs []map[string]any `json:"logs"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)

	// Should only contain logs for "10.0.0.1/32|RTBH", not "rule-99"
	if len(result.Logs) != 2 {
		t.Fatalf("expected 2 filtered logs, got %d", len(result.Logs))
	}
	for _, log := range result.Logs {
		if log["external_rule_id"] != "10.0.0.1/32|RTBH" {
			t.Errorf("unexpected external_rule_id: %v", log["external_rule_id"])
		}
	}
}

// U35: TestTimelineAPI_ChronologicalOrder
func TestTimelineAPI_ChronologicalOrder(t *testing.T) {
	ms := NewMockStore()
	now := time.Now()
	connID := 5

	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID: 2, DstIP: "10.1.0.1", StartedAt: now.Add(-20 * time.Minute),
	})

	// Insert in reverse order (ListByAttack returns DESC)
	ms.actionExecLog.logs = append(ms.actionExecLog.logs,
		store.ActionExecutionLog{
			ID: 10, AttackID: 2, ActionID: 30, ActionType: "bgp",
			TriggerPhase: "on_expired", Status: "success",
			ExternalRuleID: "10.1.0.1/32|RTBH", ConnectorID: &connID,
			ExecutedAt: now.Add(-5 * time.Minute),
		},
		store.ActionExecutionLog{
			ID: 11, AttackID: 2, ActionID: 30, ActionType: "bgp",
			TriggerPhase: "scheduled", Status: "scheduled",
			ExternalRuleID: "10.1.0.1/32|RTBH", ConnectorID: &connID,
			ExecutedAt: now.Add(-10 * time.Minute),
		},
		store.ActionExecutionLog{
			ID: 12, AttackID: 2, ActionID: 30, ActionType: "bgp",
			TriggerPhase: "on_detected", Status: "success",
			ExternalRuleID: "10.1.0.1/32|RTBH", ConnectorID: &connID,
			ExecutedAt: now.Add(-15 * time.Minute),
		},
	)

	r := setupRouter(ms)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET",
		"/api/active-actions/timeline?attack_id=2&connector_id=5&external_rule_id=10.1.0.1/32|RTBH",
		nil)
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result struct {
		Logs []map[string]any `json:"logs"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)

	if len(result.Logs) != 3 {
		t.Fatalf("expected 3 logs, got %d", len(result.Logs))
	}

	// Verify chronological order: on_detected → scheduled → on_expired
	phases := []string{"on_detected", "scheduled", "on_expired"}
	for i, log := range result.Logs {
		if log["trigger_phase"] != phases[i] {
			t.Errorf("log[%d] trigger_phase = %v, want %s", i, log["trigger_phase"], phases[i])
		}
	}
}

// U36: TestTimelineAPI_IncludesManualOverride
func TestTimelineAPI_IncludesManualOverride(t *testing.T) {
	ms := NewMockStore()
	now := time.Now()
	connID := 3

	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID: 3, DstIP: "10.2.0.1", StartedAt: now.Add(-10 * time.Minute),
	})

	ms.actionExecLog.logs = append(ms.actionExecLog.logs,
		store.ActionExecutionLog{
			ID: 20, AttackID: 3, ActionID: 40, ActionType: "bgp",
			TriggerPhase: "on_detected", Status: "success",
			ExternalRuleID: "10.2.0.1/32|RTBH", ConnectorID: &connID,
			ExecutedAt: now.Add(-9 * time.Minute),
		},
		store.ActionExecutionLog{
			ID: 21, AttackID: 3, ActionID: 40, ActionType: "manual_override",
			TriggerPhase: "manual_override", Status: "success",
			ExternalRuleID: "10.2.0.1/32|RTBH", ConnectorID: &connID,
			ExecutedAt: now.Add(-3 * time.Minute),
		},
	)

	r := setupRouter(ms)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET",
		"/api/active-actions/timeline?attack_id=3&connector_id=3&external_rule_id=10.2.0.1/32|RTBH",
		nil)
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result struct {
		Logs []map[string]any `json:"logs"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)

	if len(result.Logs) != 2 {
		t.Fatalf("expected 2 logs (including manual_override), got %d", len(result.Logs))
	}

	// Second log should be manual_override
	found := false
	for _, log := range result.Logs {
		if log["trigger_phase"] == "manual_override" {
			found = true
		}
	}
	if !found {
		t.Error("manual_override log not included in timeline")
	}
}

// U37: TestTimelineAPI_RequiresParams
func TestTimelineAPI_RequiresParams(t *testing.T) {
	ms := NewMockStore()
	r := setupRouter(ms)

	tests := []struct {
		name  string
		query string
	}{
		{"missing attack_id", "external_rule_id=foo"},
		{"missing external_rule_id", "attack_id=1"},
		{"both missing", ""},
		{"attack_id=0", "attack_id=0&external_rule_id=foo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			url := "/api/active-actions/timeline"
			if tt.query != "" {
				url += "?" + tt.query
			}
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
			r.ServeHTTP(w, req)

			if w.Code != 400 {
				t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}
