package tests

// Regression tests for the v1.2 P2 gap fixes.
//
//   P2-1  GET  /api/attacks/:id/mitigation-summary   — aggregated per-attack view
//   P2-2  PUT  /api/actions/:id                       — merge semantics (no clobber)
//   P2-3  POST /api/threshold-templates/:id/rules     — response_id honored
//   P2-4  action.ValidateTemplateVars                  — reject unknown, allow shell ${VAR}
//
// These tests lock down the behaviors the GPT audit flagged as the most
// valuable to pin: cross-type PUT must 400, and shell $${VAR} must not be
// misclassified as an unknown template variable.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/api"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// ─────────────────────────────────────────────────────────────────────────────
// Recording threshold repo — lets P2-3 roundtrip test inspect what the handler
// actually wrote into ResponseID. The production stub is a no-op that drops
// the Threshold on the floor.
// ─────────────────────────────────────────────────────────────────────────────

type recordingThresholdRepo struct {
	lastCreate *store.Threshold
}

func (r *recordingThresholdRepo) List(_ context.Context) ([]store.Threshold, error) {
	return nil, nil
}
func (r *recordingThresholdRepo) Count(_ context.Context) (int, error) { return 0, nil }
func (r *recordingThresholdRepo) ListByPrefix(_ context.Context, _ int) ([]store.Threshold, error) {
	return nil, nil
}
func (r *recordingThresholdRepo) Get(_ context.Context, _ int) (*store.Threshold, error) {
	return nil, fmt.Errorf("not implemented")
}
func (r *recordingThresholdRepo) Create(_ context.Context, t *store.Threshold) (int, error) {
	cp := *t
	r.lastCreate = &cp
	return 1, nil
}
func (r *recordingThresholdRepo) Update(_ context.Context, _ *store.Threshold) error { return nil }
func (r *recordingThresholdRepo) Delete(_ context.Context, _ int) error              { return nil }

// storeWithThresholdRec overrides MockStore.Thresholds() with the recorder.
type storeWithThresholdRec struct {
	*MockStore
	rec *recordingThresholdRepo
}

func (s *storeWithThresholdRec) Thresholds() store.ThresholdRepo { return s.rec }

// ─────────────────────────────────────────────────────────────────────────────
// P2-4 / audit P2: ValidateTemplateVars pure-function regression
// ─────────────────────────────────────────────────────────────────────────────

// Shell variables (${VAR}) are a shell-layer construct and must not be
// mistaken for xSight template placeholders. This pins the audit fix.
func TestValidateTemplateVars_ShellVariableNotFlagged(t *testing.T) {
	cases := []string{
		"--label=${HOSTNAME}",
		"echo ${USER} triggered ${ATTACK}",
		"--dst={ip} --host=${HOSTNAME}", // mixed: xSight {ip} + shell ${HOSTNAME}
	}
	for _, s := range cases {
		if err := action.ValidateTemplateVars("shell_extra_args", s); err != nil {
			t.Errorf("shell ${VAR} should not be flagged as unknown template var for %q: %v", s, err)
		}
	}
}

func TestValidateTemplateVars_UnknownVarRejected(t *testing.T) {
	err := action.ValidateTemplateVars("xdrop_custom_payload",
		`{"action":"drop","dst":"{attack_dst_ip}"}`)
	if err == nil {
		t.Fatal("expected error for unknown template var {attack_dst_ip}")
	}
	if !strings.Contains(err.Error(), "attack_dst_ip") {
		t.Errorf("error should name the offending var; got %v", err)
	}
}

func TestValidateTemplateVars_KnownVarsAccepted(t *testing.T) {
	payload := `{"action":"drop","dst_ip":"{dst_ip}","attack_id":"{attack_id}","src":"{src_ip}"}`
	if err := action.ValidateTemplateVars("xdrop_custom_payload", payload); err != nil {
		t.Errorf("known template vars should pass; got %v", err)
	}
}

func TestValidateTemplateVars_EmptyPayload_NoOp(t *testing.T) {
	if err := action.ValidateTemplateVars("shell_extra_args", ""); err != nil {
		t.Errorf("empty payload must be a no-op; got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// P2-2 / audit P1: updateAction merge semantics + cross-type rejection
// ─────────────────────────────────────────────────────────────────────────────

// Cross-type PUT must 400. The audit finding: after the merge refactor, a
// naked `{"action_type":"shell"}` PUT would carry the old webhook connector
// ID into the shell FK slot, silently binding the action to a connector of
// the wrong type. The safe resolution is to reject cross-type updates
// outright and force delete+recreate.
func TestUpdateAction_CrossTypeUpdateRejected(t *testing.T) {
	ms := NewMockStore()
	r := setupAutoPairRouter(ms)

	// Seed a webhook action.
	actionID := postAction(t, r, 1, webhookBody(7, nil))

	// PUT with a different action_type must 400.
	body, _ := json.Marshal(map[string]any{"action_type": "shell"})
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/actions/%d", actionID), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("cross-type PUT must return 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "action_type") {
		t.Errorf("error body should mention action_type; got %s", w.Body.String())
	}
}

// Partial PUT must not clobber fields the client didn't send. This was the
// original P2-2 bug: PUT {"bgp_withdraw_delay_minutes":30} zeroed
// action_type / trigger_phase / bgp_connector_id.
func TestUpdateAction_PartialPUT_PreservesUnsetFields(t *testing.T) {
	ms := NewMockStore()
	r := setupAutoPairRouter(ms)

	// Seed a BGP on_detected action with delay=5, route_map=BLACKHOLE, connector=42.
	actionID := postAction(t, r, 1, bgpBody(42, map[string]any{
		"bgp_withdraw_delay_minutes": 5,
	}))

	// PUT only the delay field.
	putResponseAction(t, r, actionID, map[string]any{
		"bgp_withdraw_delay_minutes": 30,
	})

	// Read back via ListActions: every other field must be preserved.
	actions := listResponseActions(t, r, 1)
	var got *store.ResponseAction
	for i := range actions {
		if actions[i].ID == actionID {
			got = &actions[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("action %d not found after partial PUT", actionID)
	}
	if got.BGPWithdrawDelayMinutes != 30 {
		t.Errorf("delay = %d, want 30", got.BGPWithdrawDelayMinutes)
	}
	if got.ActionType != "bgp" {
		t.Errorf("action_type = %q, want bgp (must not be clobbered)", got.ActionType)
	}
	if got.TriggerPhase != "on_detected" {
		t.Errorf("trigger_phase = %q, want on_detected", got.TriggerPhase)
	}
	if got.BGPRouteMap != "BLACKHOLE" {
		t.Errorf("bgp_route_map = %q, want BLACKHOLE", got.BGPRouteMap)
	}
	if got.BGPConnectorID == nil || *got.BGPConnectorID != 42 {
		t.Errorf("bgp_connector_id = %v, want 42", got.BGPConnectorID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// P2-4: unknown template var must be rejected at the API layer (end-to-end)
// ─────────────────────────────────────────────────────────────────────────────

func TestCreateAction_UnknownTemplateVar_Rejected(t *testing.T) {
	ms := NewMockStore()
	r := setupAutoPairRouter(ms)

	body := shellBody(9, map[string]any{
		"shell_extra_args": "--target={bogus_var}",
	})
	postActionExpectCode(t, r, 1, body, http.StatusBadRequest)
}

// Confirms the audit P2 fix reaches the end-to-end API path: shell $${VAR}
// must create successfully even though it contains braces.
func TestCreateAction_ShellVariable_Accepted(t *testing.T) {
	ms := NewMockStore()
	r := setupAutoPairRouter(ms)

	body := shellBody(9, map[string]any{
		"shell_extra_args": "--host=${HOSTNAME} --dst={dst_ip}",
	})
	postAction(t, r, 1, body) // postAction asserts 201 internally
}

// ─────────────────────────────────────────────────────────────────────────────
// P2-3: createTemplateRule must honor response_id
// ─────────────────────────────────────────────────────────────────────────────

// createTemplateRule exercises the stub ThresholdRepo / ThresholdTemplateRepo.
// stubThresholdRepo.Create is a no-op that returns (0, nil); this is enough to
// exercise the handler path and confirm the Threshold struct built from the
// body carries response_id through. We cannot read back the stored row (stub
// doesn't persist), so we assert at the handler level: 201 response indicates
// validation + write succeeded with response_id parsed.
func TestCreateTemplateRule_ResponseIDParsed(t *testing.T) {
	ms := NewMockStore()
	r := setupAutoPairRouter(ms)

	body, _ := json.Marshal(map[string]any{
		"domain":      "subnet",
		"direction":   "receives",
		"decoder":     "udp",
		"unit":        "pps",
		"comparison":  "over",
		"value":       1000,
		"inheritable": true,
		"response_id": 42, // previously silently dropped
	})
	req := httptest.NewRequest(http.MethodPost, "/api/threshold-templates/1/rules", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("createTemplateRule with response_id must 201, got %d: %s", w.Code, w.Body.String())
	}
}

// Cross-check: a Threshold built in-process with response_id must match what
// the API parses. This asserts the JSON-decoding branch in templates.go
// (raw["response_id"] → float64 → *int) has been wired correctly.
func TestCreateTemplateRule_ResponseIDRoundtrip(t *testing.T) {
	// Use a recording threshold repo so we can inspect what was written.
	rec := &recordingThresholdRepo{}
	ms := NewMockStore()
	recStore := &storeWithThresholdRec{MockStore: ms, rec: rec}

	deps := api.Dependencies{
		Store:     recStore,
		JWTSecret: testJWTSecret,
		APIKey:    "test-api-key",
	}
	gin.SetMode(gin.TestMode)
	router := api.NewRouter(deps)

	body, _ := json.Marshal(map[string]any{
		"domain":      "subnet",
		"direction":   "receives",
		"decoder":     "udp",
		"unit":        "pps",
		"comparison":  "over",
		"value":       1000,
		"response_id": 77,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/threshold-templates/1/rules", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", w.Code, w.Body.String())
	}
	if rec.lastCreate == nil {
		t.Fatalf("recordingThresholdRepo never saw a Create call")
	}
	if rec.lastCreate.ResponseID == nil {
		t.Fatalf("response_id was not carried through to Threshold.ResponseID (still nil)")
	}
	if *rec.lastCreate.ResponseID != 77 {
		t.Errorf("ResponseID = %d, want 77", *rec.lastCreate.ResponseID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// P2-1: mitigation-summary basic shape
// ─────────────────────────────────────────────────────────────────────────────

func TestGetMitigationSummary_AggregatesAllThreeSources(t *testing.T) {
	ms := NewMockStore()

	// Seed an attack.
	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID:            500,
		DstIP:         "192.0.2.10",
		DecoderFamily: "udp",
		Direction:     "receives",
		Severity:      "high",
		StartedAt:     time.Now().Add(-1 * time.Minute),
	})

	// Seed an execution log row.
	ms.actionExecLog.logs = append(ms.actionExecLog.logs, store.ActionExecutionLog{
		ID:           1,
		AttackID:     500,
		ActionID:     10,
		ActionType:   "webhook",
		TriggerPhase: "on_detected",
		Status:       "success",
		ExecutedAt:   time.Now(),
	})
	// And a skipped one with structured reason.
	ms.actionExecLog.logs = append(ms.actionExecLog.logs, store.ActionExecutionLog{
		ID:           2,
		AttackID:     500,
		ActionID:     11,
		ActionType:   "shell",
		TriggerPhase: "on_detected",
		Status:       "skipped",
		SkipReason:   action.SkipReasonPreconditionNotMatched,
		ExecutedAt:   time.Now(),
	})

	// Seed an xDrop rule.
	ctx := context.Background()
	_, _ = ms.xdropActiveRules.Upsert(ctx, &store.XDropActiveRule{
		AttackID:       500,
		ActionID:       12,
		ConnectorID:    4,
		ExternalRuleID: "rule_abc",
		Status:         "active",
	})

	// Seed a BGP announcement + attachment for this attack.
	_, err := ms.bgpAnnouncements.Attach(ctx, store.BGPAttachParams{
		AttackID:    500,
		ActionID:    intPtr(13),
		Prefix:      "192.0.2.0/24",
		RouteMap:    "BLACKHOLE",
		ConnectorID: 1,
	})
	if err != nil {
		t.Fatalf("seed announcement: %v", err)
	}

	r := setupAutoPairRouter(ms)
	req := httptest.NewRequest(http.MethodGet, "/api/attacks/500/mitigation-summary", nil)
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Attack           map[string]any   `json:"attack"`
		Executions       []map[string]any `json:"executions"`
		XDropRules       []map[string]any `json:"xdrop_rules"`
		BGPAnnouncements []map[string]any `json:"bgp_announcements"`
		Summary          map[string]any   `json:"summary"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Attack["id"] == nil {
		t.Errorf("attack missing from response")
	}
	if len(resp.Executions) != 2 {
		t.Errorf("executions len=%d, want 2", len(resp.Executions))
	}
	if len(resp.XDropRules) != 1 {
		t.Errorf("xdrop_rules len=%d, want 1", len(resp.XDropRules))
	}
	if len(resp.BGPAnnouncements) != 1 {
		t.Errorf("bgp_announcements len=%d, want 1", len(resp.BGPAnnouncements))
	}
	if resp.Summary["success"].(float64) != 1 {
		t.Errorf("summary.success = %v, want 1", resp.Summary["success"])
	}
	if resp.Summary["skipped"].(float64) != 1 {
		t.Errorf("summary.skipped = %v, want 1", resp.Summary["skipped"])
	}
	skipReasons, ok := resp.Summary["skip_reasons"].(map[string]any)
	if !ok {
		t.Fatalf("skip_reasons not a map: %T", resp.Summary["skip_reasons"])
	}
	if skipReasons[action.SkipReasonPreconditionNotMatched].(float64) != 1 {
		t.Errorf("skip_reasons[%s] = %v, want 1",
			action.SkipReasonPreconditionNotMatched, skipReasons[action.SkipReasonPreconditionNotMatched])
	}
}
