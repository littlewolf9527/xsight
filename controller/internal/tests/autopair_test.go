package tests

// Tests U1-U13: auto-pairing of xDrop/BGP on_detected → on_expired actions.
//
// Authentication: uses makeTestToken / testJWTSecret from active_actions_test.go.
// Router helper: uses newTestRouter from active_actions_test.go.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/api"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// ── router helper ─────────────────────────────────────────────────────────────

// setupAutoPairRouter builds a gin.Engine wired to the given store for
// autopair/transaction tests (no ActionEngine needed).
func setupAutoPairRouter(s store.Store) *gin.Engine {
	gin.SetMode(gin.TestMode)
	deps := api.Dependencies{
		Store:     s,
		JWTSecret: testJWTSecret,
		APIKey:    "test-api-key",
	}
	return api.NewRouter(deps)
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

// postAction sends POST /api/responses/{respID}/actions and asserts 201.
// Returns the created action ID.
func postAction(t *testing.T, r *gin.Engine, respID int, body map[string]any) int {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/responses/%d/actions", respID), bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("postAction: want 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]int
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("postAction: decode response: %v", err)
	}
	return resp["id"]
}

// postActionExpectCode posts an action and asserts the given HTTP status code.
func postActionExpectCode(t *testing.T, r *gin.Engine, respID int, body map[string]any, wantCode int) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/responses/%d/actions", respID), bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != wantCode {
		t.Fatalf("postAction: want %d, got %d: %s", wantCode, w.Code, w.Body.String())
	}
}

// listResponseActions calls GET /api/responses/{respID}/actions and returns the slice.
func listResponseActions(t *testing.T, r *gin.Engine, respID int) []store.ResponseAction {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/responses/%d/actions", respID), nil)
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("listResponseActions: want 200, got %d: %s", w.Code, w.Body.String())
	}
	var actions []store.ResponseAction
	if err := json.Unmarshal(w.Body.Bytes(), &actions); err != nil {
		t.Fatalf("listResponseActions: decode: %v", err)
	}
	return actions
}

// putResponseAction calls PUT /api/actions/{id} and asserts 200.
func putResponseAction(t *testing.T, r *gin.Engine, actionID int, body map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/actions/%d", actionID), bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("putResponseAction: want 200, got %d: %s", w.Code, w.Body.String())
	}
}

// deleteResponseAction calls DELETE /api/actions/{id} and asserts 200.
func deleteResponseAction(t *testing.T, r *gin.Engine, actionID int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/actions/%d", actionID), nil)
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("deleteResponseAction: want 200, got %d: %s", w.Code, w.Body.String())
	}
}

// findActionByPhase returns the first action with the given trigger_phase, or nil.
func findActionByPhase(actions []store.ResponseAction, phase string) *store.ResponseAction {
	for i := range actions {
		if actions[i].TriggerPhase == phase {
			return &actions[i]
		}
	}
	return nil
}

// ── DTO body builders ─────────────────────────────────────────────────────────

// xDropFilterBody returns a minimal valid xDrop filter_l4 on_detected action DTO.
// The payload includes "dst_ip" so the field-presence check passes.
func xDropFilterBody(overrides map[string]any) map[string]any {
	base := map[string]any{
		"action_type":          "xdrop",
		"trigger_phase":        "on_detected",
		"run_mode":             "once",
		"execution":            "automatic",
		"xdrop_action":         "filter_l4",
		"xdrop_custom_payload": map[string]any{"dst_ip": true},
	}
	for k, v := range overrides {
		base[k] = v
	}
	return base
}

// bgpBody returns a minimal valid BGP on_detected action DTO.
func bgpBody(connectorID int, overrides map[string]any) map[string]any {
	base := map[string]any{
		"action_type":   "bgp",
		"trigger_phase": "on_detected",
		"run_mode":      "once",
		"execution":     "automatic",
		"connector_id":  connectorID,
		"bgp_route_map": "BLACKHOLE",
	}
	for k, v := range overrides {
		base[k] = v
	}
	return base
}

// webhookBody returns a minimal valid webhook on_detected action DTO.
func webhookBody(connectorID int, overrides map[string]any) map[string]any {
	base := map[string]any{
		"action_type":   "webhook",
		"trigger_phase": "on_detected",
		"run_mode":      "once",
		"execution":     "automatic",
		"connector_id":  connectorID,
	}
	for k, v := range overrides {
		base[k] = v
	}
	return base
}

// shellBody returns a minimal valid shell on_detected action DTO.
func shellBody(connectorID int, overrides map[string]any) map[string]any {
	base := map[string]any{
		"action_type":   "shell",
		"trigger_phase": "on_detected",
		"run_mode":      "once",
		"execution":     "automatic",
		"connector_id":  connectorID,
	}
	for k, v := range overrides {
		base[k] = v
	}
	return base
}

// ── U1: xDrop filter_l4 on_detected auto-creates unblock on_expired ──────────

func TestAutoPair_XDropFilterCreatesUnblock(t *testing.T) {
	ms := NewMockStore()
	r := setupAutoPairRouter(ms)

	postAction(t, r, 1, xDropFilterBody(nil))

	actions := listResponseActions(t, r, 1)
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions (detected + expired), got %d", len(actions))
	}

	parent := findActionByPhase(actions, "on_detected")
	child := findActionByPhase(actions, "on_expired")

	if parent == nil {
		t.Fatal("on_detected action not found")
	}
	if child == nil {
		t.Fatal("auto-generated on_expired action not found")
	}
	if child.XDropAction != "unblock" {
		t.Errorf("paired action xdrop_action = %q, want unblock", child.XDropAction)
	}
	if !child.AutoGenerated {
		t.Error("paired action auto_generated should be true")
	}
	if parent.PairedWith == nil || *parent.PairedWith != child.ID {
		t.Errorf("parent.PairedWith = %v, want ptr(%d)", parent.PairedWith, child.ID)
	}
}

// ── U2: xDrop rate_limit on_detected auto-creates unblock on_expired ─────────

func TestAutoPair_XDropRateLimitCreatesUnblock(t *testing.T) {
	ms := NewMockStore()
	r := setupAutoPairRouter(ms)

	postAction(t, r, 1, xDropFilterBody(map[string]any{
		"xdrop_action":         "rate_limit",
		"xdrop_custom_payload": map[string]any{"dst_ip": true, "rate_limit": 1000},
	}))

	actions := listResponseActions(t, r, 1)
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(actions))
	}
	child := findActionByPhase(actions, "on_expired")
	if child == nil {
		t.Fatal("on_expired action not found")
	}
	if child.XDropAction != "unblock" {
		t.Errorf("paired action xdrop_action = %q, want unblock", child.XDropAction)
	}
}

// ── U3: BGP on_detected auto-creates BGP withdraw on_expired ─────────────────

func TestAutoPair_BGPCreatesWithdraw(t *testing.T) {
	ms := NewMockStore()
	r := setupAutoPairRouter(ms)

	postAction(t, r, 1, bgpBody(42, nil))

	actions := listResponseActions(t, r, 1)
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(actions))
	}

	parent := findActionByPhase(actions, "on_detected")
	child := findActionByPhase(actions, "on_expired")

	if parent == nil {
		t.Fatal("on_detected action not found")
	}
	if child == nil {
		t.Fatal("on_expired action not found")
	}
	if child.ActionType != "bgp" {
		t.Errorf("paired action type = %q, want bgp", child.ActionType)
	}
	if !child.AutoGenerated {
		t.Error("paired action auto_generated should be true")
	}
	if child.BGPConnectorID == nil || *child.BGPConnectorID != 42 {
		t.Errorf("paired action BGPConnectorID = %v, want ptr(42)", child.BGPConnectorID)
	}
}

// ── U4: Webhook on_detected does NOT auto-create on_expired ──────────────────

func TestAutoPair_WebhookNoAutoPair(t *testing.T) {
	ms := NewMockStore()
	r := setupAutoPairRouter(ms)

	postAction(t, r, 1, webhookBody(99, nil))

	actions := listResponseActions(t, r, 1)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action (no auto-pair for webhook), got %d", len(actions))
	}
	if findActionByPhase(actions, "on_expired") != nil {
		t.Error("webhook should not create an on_expired action")
	}
}

// ── U5: Shell on_detected does NOT auto-create on_expired ────────────────────

func TestAutoPair_ShellNoAutoPair(t *testing.T) {
	ms := NewMockStore()
	r := setupAutoPairRouter(ms)

	postAction(t, r, 1, shellBody(77, nil))

	actions := listResponseActions(t, r, 1)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action (no auto-pair for shell), got %d", len(actions))
	}
	if findActionByPhase(actions, "on_expired") != nil {
		t.Error("shell should not create an on_expired action")
	}
}

// ── U6: Manual xDrop on_expired is rejected (400) ────────────────────────────

func TestReject_ManualXDropOnExpired(t *testing.T) {
	ms := NewMockStore()
	r := setupAutoPairRouter(ms)

	body := map[string]any{
		"action_type":          "xdrop",
		"trigger_phase":        "on_expired",
		"run_mode":             "once",
		"xdrop_action":         "unblock",
		"xdrop_custom_payload": map[string]any{"dst_ip": true},
	}
	postActionExpectCode(t, r, 1, body, http.StatusBadRequest)
}

// ── U7: Manual BGP on_expired is rejected (400) ───────────────────────────────

func TestReject_ManualBGPOnExpired(t *testing.T) {
	ms := NewMockStore()
	r := setupAutoPairRouter(ms)

	body := map[string]any{
		"action_type":   "bgp",
		"trigger_phase": "on_expired",
		"run_mode":      "once",
		"connector_id":  1,
		"bgp_route_map": "BLACKHOLE",
	}
	postActionExpectCode(t, r, 1, body, http.StatusBadRequest)
}

// ── U8: Deleting on_detected cascades to its paired on_expired ───────────────

func TestDelete_OnDetectedCascadesOnExpired(t *testing.T) {
	ms := NewMockStore()
	r := setupAutoPairRouter(ms)

	parentID := postAction(t, r, 1, xDropFilterBody(nil))

	actions := listResponseActions(t, r, 1)
	if len(actions) != 2 {
		t.Fatalf("precondition: expected 2 actions, got %d", len(actions))
	}
	childAction := findActionByPhase(actions, "on_expired")
	if childAction == nil {
		t.Fatal("precondition: on_expired child not found")
	}
	childID := childAction.ID

	// Delete the on_detected parent — should cascade to child.
	deleteResponseAction(t, r, parentID)

	remaining := listResponseActions(t, r, 1)
	for _, a := range remaining {
		if a.ID == parentID {
			t.Errorf("parent action %d still present after delete", parentID)
		}
		if a.ID == childID {
			t.Errorf("child action %d still present after cascaded delete", childID)
		}
	}
	if len(remaining) != 0 {
		t.Errorf("expected 0 remaining actions, got %d", len(remaining))
	}
}

// ── U9: xDrop unblock_delay_minutes propagated to paired on_expired ───────────

func TestAutoPair_DelayPropagated(t *testing.T) {
	ms := NewMockStore()
	r := setupAutoPairRouter(ms)

	postAction(t, r, 1, xDropFilterBody(map[string]any{
		"unblock_delay_minutes": 10,
	}))

	actions := listResponseActions(t, r, 1)
	child := findActionByPhase(actions, "on_expired")
	if child == nil {
		t.Fatal("on_expired action not found")
	}
	if child.UnblockDelayMinutes != 10 {
		t.Errorf("paired on_expired UnblockDelayMinutes = %d, want 10", child.UnblockDelayMinutes)
	}
}

// ── U10: BGP bgp_withdraw_delay_minutes propagated to paired on_expired ───────

func TestAutoPair_BGPDelayPropagated(t *testing.T) {
	ms := NewMockStore()
	r := setupAutoPairRouter(ms)

	postAction(t, r, 1, bgpBody(42, map[string]any{
		"bgp_withdraw_delay_minutes": 5,
	}))

	actions := listResponseActions(t, r, 1)
	child := findActionByPhase(actions, "on_expired")
	if child == nil {
		t.Fatal("on_expired action not found")
	}
	if child.BGPWithdrawDelayMinutes != 5 {
		t.Errorf("paired on_expired BGPWithdrawDelayMinutes = %d, want 5", child.BGPWithdrawDelayMinutes)
	}
}

// ── U11: Updating on_detected syncs delay to paired on_expired ───────────────

func TestUpdate_OnDetectedSyncsOnExpired(t *testing.T) {
	ms := NewMockStore()
	r := setupAutoPairRouter(ms)

	parentID := postAction(t, r, 1, xDropFilterBody(map[string]any{
		"unblock_delay_minutes": 5,
	}))

	// Verify initial state.
	actions := listResponseActions(t, r, 1)
	child := findActionByPhase(actions, "on_expired")
	if child == nil {
		t.Fatal("on_expired action not found after create")
	}
	if child.UnblockDelayMinutes != 5 {
		t.Fatalf("precondition: paired delay = %d, want 5", child.UnblockDelayMinutes)
	}

	// Update parent delay from 5 → 10.
	putResponseAction(t, r, parentID, xDropFilterBody(map[string]any{
		"unblock_delay_minutes": 10,
	}))

	// Verify paired action was synced.
	updatedActions := listResponseActions(t, r, 1)
	updatedChild := findActionByPhase(updatedActions, "on_expired")
	if updatedChild == nil {
		t.Fatal("on_expired action missing after update")
	}
	if updatedChild.UnblockDelayMinutes != 10 {
		t.Errorf("after sync: paired delay = %d, want 10", updatedChild.UnblockDelayMinutes)
	}
}

// ── U12: Disabling on_detected also disables paired on_expired ───────────────

func TestDisable_OnDetectedDisablesOnExpired(t *testing.T) {
	ms := NewMockStore()
	r := setupAutoPairRouter(ms)

	parentID := postAction(t, r, 1, xDropFilterBody(nil))

	// Confirm both start enabled.
	actions := listResponseActions(t, r, 1)
	child := findActionByPhase(actions, "on_expired")
	if child == nil {
		t.Fatal("on_expired action not found after create")
	}
	if !child.Enabled {
		t.Fatal("precondition: paired action should start enabled")
	}

	// Disable the on_detected parent.
	f := false
	putResponseAction(t, r, parentID, xDropFilterBody(map[string]any{
		"enabled": &f,
	}))

	updatedActions := listResponseActions(t, r, 1)
	updatedChild := findActionByPhase(updatedActions, "on_expired")
	if updatedChild == nil {
		t.Fatal("on_expired action missing after disable")
	}
	if updatedChild.Enabled {
		t.Error("paired on_expired should be disabled after disabling on_detected")
	}
}

// ── U13: Re-enabling on_detected also re-enables paired on_expired ───────────

func TestEnable_OnDetectedEnablesOnExpired(t *testing.T) {
	ms := NewMockStore()
	r := setupAutoPairRouter(ms)

	f := false
	parentID := postAction(t, r, 1, xDropFilterBody(map[string]any{
		"enabled": &f,
	}))

	// Confirm both start disabled.
	actions := listResponseActions(t, r, 1)
	parent := findActionByPhase(actions, "on_detected")
	child := findActionByPhase(actions, "on_expired")
	if parent == nil || child == nil {
		t.Fatal("precondition: both actions must exist")
	}
	if parent.Enabled || child.Enabled {
		t.Fatal("precondition: both should start disabled")
	}

	// Re-enable the on_detected parent.
	tr := true
	putResponseAction(t, r, parentID, xDropFilterBody(map[string]any{
		"enabled": &tr,
	}))

	updatedActions := listResponseActions(t, r, 1)
	updatedChild := findActionByPhase(updatedActions, "on_expired")
	if updatedChild == nil {
		t.Fatal("on_expired action missing after re-enable")
	}
	if !updatedChild.Enabled {
		t.Error("paired on_expired should be enabled after re-enabling on_detected")
	}
}
