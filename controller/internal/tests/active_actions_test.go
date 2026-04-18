package tests

// active_actions_test.go — HTTP-level tests for the active-actions endpoints.
// Tests U18–U24 per task specification.
//
// Shared helpers (testJWTSecret, makeTestToken, setupRouter) are defined in autopair_test.go.
// MockStore is defined in mock_store_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/api"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// ─────────────────────────────────────────────────────────────────────────────
// local helpers
// ─────────────────────────────────────────────────────────────────────────────

// setupRouterWithEngine builds a router with an optional *action.Engine.
// Use setupRouter (from autopair_test.go) when no engine is needed.
func setupRouterWithEngine(s store.Store, eng *action.Engine) *gin.Engine {
	gin.SetMode(gin.TestMode)
	deps := api.Dependencies{
		Store:        s,
		JWTSecret:    testJWTSecret,
		ActionEngine: eng,
	}
	return api.NewRouter(deps)
}

// doGet issues an authenticated GET to the given path.
func doGet(t *testing.T, r *gin.Engine, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// doPost issues an authenticated POST with a JSON-encoded body.
func doPost(t *testing.T, r *gin.Engine, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("doPost: marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// decodeList decodes a JSON-array response into []map[string]any.
func decodeList(t *testing.T, w *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	var result []map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decodeList: %v (body=%s)", err, w.Body.String())
	}
	return result
}

// ip returns a pointer to the given int value.
func ip(i int) *int { return &i }

// ─────────────────────────────────────────────────────────────────────────────
// U18: GET /api/active-actions/bgp — active attack with BGP on_detected success
// Verify: response contains the route with status="active"
// ─────────────────────────────────────────────────────────────────────────────

func TestListActiveBGPRoutes_ReturnsOnlyActive(t *testing.T) {
	ms := NewMockStore()
	now := time.Now()

	// Active attack (EndedAt == nil)
	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID:        1,
		DstIP:     "10.0.0.1",
		StartedAt: now.Add(-5 * time.Minute),
		EndedAt:   nil,
	})

	// on_detected success log for this attack, action_type=bgp
	connID := 3
	ms.actionExecLog.logs = append(ms.actionExecLog.logs, store.ActionExecutionLog{
		ID:             1,
		AttackID:       1,
		ActionID:       10,
		ActionType:     "bgp",
		TriggerPhase:   "on_detected",
		Status:         "success",
		ExternalRuleID: "10.0.0.1/32|RTBH",
		ConnectorID:    ip(connID),
		ConnectorName:  "bgp-main",
		ExecutedAt:     now.Add(-4 * time.Minute),
	})
	// v1.2 PR-5: BGP Mitigations now reads bgp_announcements. Seed the
	// announcement row + attach row so the API can see it.
	annID, _ := ms.bgpAnnouncements.Attach(context.Background(), store.BGPAttachParams{
		AttackID: 1, ActionID: ip(10), Prefix: "10.0.0.1/32", RouteMap: "RTBH", ConnectorID: connID,
	})
	ms.bgpAnnouncements.MarkAnnounced(context.Background(), annID.AnnouncementID)
	// Seed BGP connector so buildActiveBGPFromAnnouncements can resolve name.
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, store.BGPConnector{
		ID: connID, Name: "bgp-main", Enabled: true,
	})

	r := setupRouter(ms)
	w := doGet(t, r, "/api/active-actions/bgp")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", w.Code, w.Body.String())
	}

	result := decodeList(t, w)
	if len(result) != 1 {
		t.Fatalf("expected 1 active BGP route, got %d", len(result))
	}

	item := result[0]
	if got := item["status"]; got != "active" {
		t.Errorf("expected status=active, got %v", got)
	}
	if got := item["external_rule_id"]; got != "10.0.0.1/32|RTBH" {
		t.Errorf("expected external_rule_id=10.0.0.1/32|RTBH, got %v", got)
	}
	if got := item["action_type"]; got != "bgp" {
		t.Errorf("expected action_type=bgp, got %v", got)
	}
	// BGP-specific parsed fields
	if got := item["prefix"]; got != "10.0.0.1/32" {
		t.Errorf("expected prefix=10.0.0.1/32, got %v", got)
	}
	if got := item["route_map"]; got != "RTBH" {
		t.Errorf("expected route_map=RTBH, got %v", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// U19: GET /api/active-actions/bgp — on_expired success must exclude the route
// ─────────────────────────────────────────────────────────────────────────────

func TestListActiveBGPRoutes_ExcludesWithdrawn(t *testing.T) {
	ms := NewMockStore()
	now := time.Now()

	endedAt := now.Add(-2 * time.Minute)
	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID:        2,
		DstIP:     "10.1.0.1",
		StartedAt: now.Add(-10 * time.Minute),
		EndedAt:   &endedAt,
	})

	connID := 3
	ms.actionExecLog.logs = append(ms.actionExecLog.logs,
		store.ActionExecutionLog{
			ID:             1,
			AttackID:       2,
			ActionID:       10,
			ActionType:     "bgp",
			TriggerPhase:   "on_detected",
			Status:         "success",
			ExternalRuleID: "10.1.0.1/32|RTBH",
			ConnectorID:    ip(connID),
			ExecutedAt:     now.Add(-9 * time.Minute),
		},
		// Withdrawal marks the route as no longer active
		store.ActionExecutionLog{
			ID:             2,
			AttackID:       2,
			ActionID:       10,
			ActionType:     "bgp",
			TriggerPhase:   "on_expired",
			Status:         "success",
			ExternalRuleID: "10.1.0.1/32|RTBH",
			ConnectorID:    ip(connID),
			ExecutedAt:     now.Add(-1 * time.Minute),
		},
	)

	r := setupRouter(ms)
	w := doGet(t, r, "/api/active-actions/bgp")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", w.Code, w.Body.String())
	}

	result := decodeList(t, w)
	if len(result) != 0 {
		t.Fatalf("expected empty list (route withdrawn), got %d items", len(result))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// U20: GET /api/active-actions/xdrop — returns active xDrop rule
// ─────────────────────────────────────────────────────────────────────────────

func TestListActiveXDropRules_ReturnsOnlyActive(t *testing.T) {
	ms := NewMockStore()
	now := time.Now()

	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID:        3,
		DstIP:     "192.168.1.5",
		StartedAt: now.Add(-3 * time.Minute),
		EndedAt:   nil,
	})

	connID := 5
	ms.actionExecLog.logs = append(ms.actionExecLog.logs, store.ActionExecutionLog{
		ID:             1,
		AttackID:       3,
		ActionID:       20,
		ActionType:     "xdrop",
		TriggerPhase:   "on_detected",
		Status:         "success",
		ExternalRuleID: "123",
		ConnectorID:    ip(connID),
		ConnectorName:  "xdrop-node-01",
		ExecutedAt:     now.Add(-2 * time.Minute),
	})
	// v1.2 PR-4: seed authoritative state row — Mitigations queries from here now.
	ms.ManualOverrides() // noop touch to satisfy any lazy init
	ms.xdropActiveRules.Upsert(context.Background(), &store.XDropActiveRule{
		AttackID: 3, ActionID: 20, ConnectorID: connID, ExternalRuleID: "123", Status: "active",
	})

	r := setupRouter(ms)
	w := doGet(t, r, "/api/active-actions/xdrop")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", w.Code, w.Body.String())
	}

	result := decodeList(t, w)
	if len(result) != 1 {
		t.Fatalf("expected 1 active xDrop rule, got %d", len(result))
	}
	item := result[0]
	if got := item["status"]; got != "active" {
		t.Errorf("expected status=active, got %v", got)
	}
	if got := item["external_rule_id"]; got != "123" {
		t.Errorf("expected external_rule_id=123, got %v", got)
	}
	if got := item["action_type"]; got != "xdrop" {
		t.Errorf("expected action_type=xdrop, got %v", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// U21: GET /api/active-actions/xdrop — on_expired success excludes the rule
// ─────────────────────────────────────────────────────────────────────────────

func TestListActiveXDropRules_ExcludesUnblocked(t *testing.T) {
	ms := NewMockStore()
	now := time.Now()

	endedAt := now.Add(-1 * time.Minute)
	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID:        4,
		DstIP:     "192.168.1.10",
		StartedAt: now.Add(-8 * time.Minute),
		EndedAt:   &endedAt,
	})

	connID := 5
	ms.actionExecLog.logs = append(ms.actionExecLog.logs,
		store.ActionExecutionLog{
			ID:             1,
			AttackID:       4,
			ActionID:       20,
			ActionType:     "xdrop",
			TriggerPhase:   "on_detected",
			Status:         "success",
			ExternalRuleID: "456",
			ConnectorID:    ip(connID),
			ExecutedAt:     now.Add(-7 * time.Minute),
		},
		store.ActionExecutionLog{
			ID:             2,
			AttackID:       4,
			ActionID:       20,
			ActionType:     "xdrop",
			TriggerPhase:   "on_expired",
			Status:         "success",
			ExternalRuleID: "456",
			ConnectorID:    ip(connID),
			ExecutedAt:     now.Add(-30 * time.Second),
		},
	)

	r := setupRouter(ms)
	w := doGet(t, r, "/api/active-actions/xdrop")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", w.Code, w.Body.String())
	}

	result := decodeList(t, w)
	if len(result) != 0 {
		t.Fatalf("expected empty list (rule unblocked), got %d items", len(result))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// U22: GET /api/active-actions/bgp — two connectors, no cross-contamination
// ─────────────────────────────────────────────────────────────────────────────

func TestListActive_MultiConnector_NoCrossContamination(t *testing.T) {
	ms := NewMockStore()
	now := time.Now()

	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID:        5,
		DstIP:     "10.5.0.1",
		StartedAt: now.Add(-6 * time.Minute),
		EndedAt:   nil,
	})

	conn3, conn4 := 3, 4
	ms.actionExecLog.logs = append(ms.actionExecLog.logs,
		store.ActionExecutionLog{
			ID:             1,
			AttackID:       5,
			ActionID:       30,
			ActionType:     "bgp",
			TriggerPhase:   "on_detected",
			Status:         "success",
			ExternalRuleID: "10.5.0.1/32|RTBH",
			ConnectorID:    ip(conn3),
			ConnectorName:  "bgp-connector-3",
			ExecutedAt:     now.Add(-5 * time.Minute),
		},
		store.ActionExecutionLog{
			ID:             2,
			AttackID:       5,
			ActionID:       31,
			ActionType:     "bgp",
			TriggerPhase:   "on_detected",
			Status:         "success",
			ExternalRuleID: "10.5.0.1/32|BLACKHOLE",
			ConnectorID:    ip(conn4),
			ConnectorName:  "bgp-connector-4",
			ExecutedAt:     now.Add(-5 * time.Minute),
		},
	)
	// v1.2 PR-5: seed bgp_announcements state + connectors for API
	a1, _ := ms.bgpAnnouncements.Attach(context.Background(), store.BGPAttachParams{
		AttackID: 5, ActionID: ip(30), Prefix: "10.5.0.1/32", RouteMap: "RTBH", ConnectorID: conn3,
	})
	ms.bgpAnnouncements.MarkAnnounced(context.Background(), a1.AnnouncementID)
	a2, _ := ms.bgpAnnouncements.Attach(context.Background(), store.BGPAttachParams{
		AttackID: 5, ActionID: ip(31), Prefix: "10.5.0.1/32", RouteMap: "BLACKHOLE", ConnectorID: conn4,
	})
	ms.bgpAnnouncements.MarkAnnounced(context.Background(), a2.AnnouncementID)
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors,
		store.BGPConnector{ID: conn3, Name: "bgp-connector-3", Enabled: true},
		store.BGPConnector{ID: conn4, Name: "bgp-connector-4", Enabled: true},
	)

	r := setupRouter(ms)
	w := doGet(t, r, "/api/active-actions/bgp")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", w.Code, w.Body.String())
	}

	result := decodeList(t, w)
	if len(result) != 2 {
		t.Fatalf("expected 2 active BGP routes, got %d", len(result))
	}

	// Index by connector_id for targeted assertions
	byConn := make(map[int]map[string]any)
	for _, item := range result {
		cid := int(item["connector_id"].(float64))
		byConn[cid] = item
	}

	if _, ok := byConn[conn3]; !ok {
		t.Errorf("expected entry with connector_id=%d", conn3)
	}
	if _, ok := byConn[conn4]; !ok {
		t.Errorf("expected entry with connector_id=%d", conn4)
	}
	if got := byConn[conn3]["external_rule_id"]; got != "10.5.0.1/32|RTBH" {
		t.Errorf("connector 3: expected external_rule_id=10.5.0.1/32|RTBH, got %v", got)
	}
	if got := byConn[conn4]["external_rule_id"]; got != "10.5.0.1/32|BLACKHOLE" {
		t.Errorf("connector 4: expected external_rule_id=10.5.0.1/32|BLACKHOLE, got %v", got)
	}
	if byConn[conn3]["connector_name"] == byConn[conn4]["connector_name"] {
		t.Errorf("connector names must differ; both are %v", byConn[conn3]["connector_name"])
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// U23: POST /api/active-actions/force-remove — writes an execution log
//
// ForceRemove calls vtysh at /usr/bin/false (always exits 1), so removeErr is
// non-nil.  The handler still writes the log before returning 500.  We verify:
//   - a log with trigger_phase=manual_override was written
//   - status=failed (no real vtysh)
//   - fields match the request payload
// ─────────────────────────────────────────────────────────────────────────────

func TestForceRemove_WritesExecutionLog(t *testing.T) {
	ms := NewMockStore()
	now := time.Now()

	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID:        6,
		DstIP:     "10.6.0.1",
		StartedAt: now.Add(-10 * time.Minute),
		EndedAt:   nil,
	})

	// Seed a bgp response action so ForceRemove can call GetAction(40)
	const actionID = 40
	ms.responses.actions = append(ms.responses.actions, store.ResponseAction{
		ID:         actionID,
		ResponseID: 1,
		ActionType: "bgp",
	})

	// BGP connector — vtysh path /usr/bin/false exits 1 immediately
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, store.BGPConnector{
		ID:            7,
		Name:          "test-bgp",
		VtyshPath:     "/usr/bin/false",
		BGPASN:        65001,
		AddressFamily: "ipv4 unicast",
		Enabled:       true,
	})

	eng := action.NewEngine(ms, "auto")
	r := setupRouterWithEngine(ms, eng)

	payload := map[string]any{
		"attack_id":        6,
		"action_id":        actionID,
		"connector_id":     7,
		"external_rule_id": "10.6.0.1/32|RTBH",
	}
	w := doPost(t, r, "/api/active-actions/force-remove", payload)

	// Handler writes the log BEFORE checking removeErr, then returns 500 on error.
	// Accept both codes: 500 (normal: vtysh failed) or 200 (unexpected success).
	if w.Code != http.StatusInternalServerError && w.Code != http.StatusOK {
		t.Logf("NOTE: unexpected HTTP status %d; body=%s", w.Code, w.Body.String())
	}

	// Primary assertion: a manual_override log must have been written
	if len(ms.actionExecLog.logs) == 0 {
		t.Fatalf("expected execution log from force-remove, got none")
	}

	var found *store.ActionExecutionLog
	for i := range ms.actionExecLog.logs {
		l := &ms.actionExecLog.logs[i]
		if l.TriggerPhase == "manual_override" {
			found = l
			break
		}
	}
	if found == nil {
		t.Fatalf("no log with trigger_phase=manual_override; logs=%+v", ms.actionExecLog.logs)
	}
	if found.AttackID != 6 {
		t.Errorf("expected attack_id=6, got %d", found.AttackID)
	}
	if found.ActionID != actionID {
		t.Errorf("expected action_id=%d, got %d", actionID, found.ActionID)
	}
	if found.ConnectorID == nil || *found.ConnectorID != 7 {
		t.Errorf("expected connector_id=7, got %v", found.ConnectorID)
	}
	if found.ExternalRuleID != "10.6.0.1/32|RTBH" {
		t.Errorf("expected external_rule_id=10.6.0.1/32|RTBH, got %s", found.ExternalRuleID)
	}
	if found.Status != "failed" {
		t.Errorf("expected status=failed (vtysh unavailable), got %s", found.Status)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// U24: manual_override success log suppresses the artifact in GET active-actions
// ─────────────────────────────────────────────────────────────────────────────

func TestForceRemove_PreventsSubsequentAutoPairedExecution(t *testing.T) {
	ms := NewMockStore()
	now := time.Now()

	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID:        7,
		DstIP:     "10.7.0.1",
		StartedAt: now.Add(-20 * time.Minute),
		EndedAt:   nil,
	})

	connID := 3
	ms.actionExecLog.logs = append(ms.actionExecLog.logs,
		// Original injection
		store.ActionExecutionLog{
			ID:             1,
			AttackID:       7,
			ActionID:       50,
			ActionType:     "bgp",
			TriggerPhase:   "on_detected",
			Status:         "success",
			ExternalRuleID: "10.7.0.1/32|RTBH",
			ConnectorID:    ip(connID),
			ConnectorName:  "bgp-main",
			ExecutedAt:     now.Add(-19 * time.Minute),
		},
		// manual_override success — buildActiveActions treats this as withdrawn
		store.ActionExecutionLog{
			ID:             2,
			AttackID:       7,
			ActionID:       50,
			ActionType:     "manual_override",
			TriggerPhase:   "manual_override",
			Status:         "success",
			ExternalRuleID: "10.7.0.1/32|RTBH",
			ConnectorID:    ip(connID),
			ExecutedAt:     now.Add(-15 * time.Minute),
		},
	)

	r := setupRouter(ms)
	w := doGet(t, r, "/api/active-actions/bgp")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", w.Code, w.Body.String())
	}

	result := decodeList(t, w)
	if len(result) != 0 {
		t.Fatalf("expected empty list (force-removed artifact suppressed), got %d items: %v", len(result), result)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Extra: BGP and xDrop routes must not interfere with each other
// ─────────────────────────────────────────────────────────────────────────────

func TestListActive_BGPAndXDropDoNotInterfere(t *testing.T) {
	ms := NewMockStore()
	now := time.Now()

	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID:        8,
		DstIP:     "10.8.0.1",
		StartedAt: now.Add(-5 * time.Minute),
		EndedAt:   nil,
	})

	connID := 3
	ms.actionExecLog.logs = append(ms.actionExecLog.logs,
		store.ActionExecutionLog{
			ID:             1,
			AttackID:       8,
			ActionID:       60,
			ActionType:     "bgp",
			TriggerPhase:   "on_detected",
			Status:         "success",
			ExternalRuleID: "10.8.0.1/32|RTBH",
			ConnectorID:    ip(connID),
			ExecutedAt:     now.Add(-4 * time.Minute),
		},
	)
	// v1.2 PR-5: seed bgp_announcements so BGP Mitigations API sees it.
	ar, _ := ms.bgpAnnouncements.Attach(context.Background(), store.BGPAttachParams{
		AttackID: 8, ActionID: ip(60), Prefix: "10.8.0.1/32", RouteMap: "RTBH", ConnectorID: connID,
	})
	ms.bgpAnnouncements.MarkAnnounced(context.Background(), ar.AnnouncementID)
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, store.BGPConnector{
		ID: connID, Name: "test-bgp", Enabled: true,
	})
	// xDrop rule was withdrawn — seed xdrop_active_rules as withdrawn so it
	// doesn't appear in the Mitigations xDrop list (ListActive filters it).
	ms.xdropActiveRules.Upsert(context.Background(), &store.XDropActiveRule{
		AttackID: 8, ActionID: 61, ConnectorID: connID, ExternalRuleID: "789", Status: "withdrawn",
	})

	r := setupRouter(ms)

	// BGP endpoint must still show the route
	wBGP := doGet(t, r, "/api/active-actions/bgp")
	if wBGP.Code != http.StatusOK {
		t.Fatalf("bgp: expected 200, got %d", wBGP.Code)
	}
	if got := decodeList(t, wBGP); len(got) != 1 {
		t.Fatalf("bgp: expected 1 active route, got %d", len(got))
	}

	// xDrop endpoint must show nothing (unblocked)
	wXDrop := doGet(t, r, "/api/active-actions/xdrop")
	if wXDrop.Code != http.StatusOK {
		t.Fatalf("xdrop: expected 200, got %d", wXDrop.Code)
	}
	if got := decodeList(t, wXDrop); len(got) != 0 {
		t.Fatalf("xdrop: expected empty list, got %d items", len(got))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// attached_attacks: shared announcement (2 attacks) must surface both
// ─────────────────────────────────────────────────────────────────────────────

func TestListActiveBGPRoutes_AttachedAttacksShared(t *testing.T) {
	ms := NewMockStore()
	now := time.Now()
	ctx := context.Background()

	ms.attacks.attacks = append(ms.attacks.attacks,
		store.Attack{ID: 11, DstIP: "192.0.2.0/24", DecoderFamily: "ip", StartedAt: now.Add(-3 * time.Minute)},
		store.Attack{ID: 12, DstIP: "192.0.2.0/24", DecoderFamily: "udp", StartedAt: now.Add(-3 * time.Minute)},
	)
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, store.BGPConnector{ID: 6, Name: "Main BGP", Enabled: true})

	// Two attacks attach to same announcement (business key shared).
	r1, _ := ms.bgpAnnouncements.Attach(ctx, store.BGPAttachParams{
		AttackID: 11, ActionID: ip(114), ResponseName: "v1.2-test-B",
		Prefix: "192.0.2.0/24", RouteMap: "RTBH", ConnectorID: 6, DelayMinutes: 1,
	})
	ms.bgpAnnouncements.MarkAnnounced(ctx, r1.AnnouncementID)
	ms.bgpAnnouncements.Attach(ctx, store.BGPAttachParams{
		AttackID: 12, ActionID: ip(121), ResponseName: "v1.2-test-C",
		Prefix: "192.0.2.0/24", RouteMap: "RTBH", ConnectorID: 6, DelayMinutes: 5,
	})

	r := setupRouter(ms)
	w := doGet(t, r, "/api/active-actions/bgp")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	list := decodeList(t, w)
	if len(list) != 1 {
		t.Fatalf("expected 1 row (shared announcement), got %d", len(list))
	}
	item := list[0]
	atks, ok := item["attached_attacks"].([]any)
	if !ok {
		t.Fatalf("attached_attacks missing/wrong type: %+v", item["attached_attacks"])
	}
	if len(atks) != 2 {
		t.Fatalf("expected 2 attached_attacks, got %d: %+v", len(atks), atks)
	}
	// Both attack IDs should be present.
	ids := map[float64]map[string]any{}
	for _, raw := range atks {
		m := raw.(map[string]any)
		ids[m["attack_id"].(float64)] = m
	}
	if _, ok := ids[11]; !ok {
		t.Errorf("attack_id=11 not in attached_attacks")
	}
	if _, ok := ids[12]; !ok {
		t.Errorf("attack_id=12 not in attached_attacks")
	}
	// Each should carry decoder + delay_minutes (config snapshot) + response_name.
	if got := ids[11]["decoder"]; got != "ip" {
		t.Errorf("attack 11 decoder = %v, want ip", got)
	}
	if got := ids[12]["decoder"]; got != "udp" {
		t.Errorf("attack 12 decoder = %v, want udp", got)
	}
	if got := ids[11]["delay_minutes"]; got != float64(1) {
		t.Errorf("attack 11 delay_minutes = %v, want 1", got)
	}
	if got := ids[12]["delay_minutes"]; got != float64(5) {
		t.Errorf("attack 12 delay_minutes = %v, want 5", got)
	}
	// detached_at nil → key absent via omitempty; absent keys mean still attached.
	if _, present := ids[11]["detached_at"]; present {
		t.Errorf("attack 11 should be currently attached (no detached_at)")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// attached_attacks: detached history capped at 30, all active always surfaced
// ─────────────────────────────────────────────────────────────────────────────

func TestListActiveBGPRoutes_AttachedAttacksDetachedCap(t *testing.T) {
	ms := NewMockStore()
	now := time.Now()
	ctx := context.Background()

	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, store.BGPConnector{ID: 6, Name: "Main BGP", Enabled: true})

	// To test the cap, we need many detach events WITHIN the same cycle
	// (not each in its own cycle — those would be filtered by cycle scope).
	// Simulate a long-running announcement with churn: 45 attacks all attach
	// (refcount grows to 45, announcement stays active), then 43 detach
	// (refcount drops to 2, but never hits 0 so announcement stays in the
	// same cycle). 2 remain attached, 43 are historical detached within
	// the cycle.
	var firstAnnID int
	for i := 1; i <= 45; i++ {
		ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
			ID: i, DstIP: "192.0.2.0/24", DecoderFamily: "udp",
			StartedAt: now.Add(-time.Duration(45-i) * time.Minute),
		})
		ar, _ := ms.bgpAnnouncements.Attach(ctx, store.BGPAttachParams{
			AttackID: i, ActionID: ip(111), Prefix: "192.0.2.0/24",
			RouteMap: "RTBH", ConnectorID: 6, DelayMinutes: 0,
		})
		if i == 1 {
			firstAnnID = ar.AnnouncementID
			ms.bgpAnnouncements.MarkAnnounced(ctx, firstAnnID)
		}
	}
	// Detach 1..43, leaving 44 and 45 currently attached.
	for i := 1; i <= 43; i++ {
		ms.bgpAnnouncements.Detach(ctx, i, "192.0.2.0/24", "RTBH", 6)
	}

	r := setupRouter(ms)
	w := doGet(t, r, "/api/active-actions/bgp")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	list := decodeList(t, w)
	if len(list) != 1 {
		t.Fatalf("expected 1 row, got %d", len(list))
	}
	atks := list[0]["attached_attacks"].([]any)
	// Expect: 2 active + 30 detached cap = 32 total.
	if len(atks) != 32 {
		t.Fatalf("expected 32 entries (2 active + 30 capped detached), got %d", len(atks))
	}
	// First 2 must be currently-attached (no detached_at field).
	for i := 0; i < 2; i++ {
		entry := atks[i].(map[string]any)
		if _, present := entry["detached_at"]; present {
			t.Errorf("entry %d should be active (no detached_at), got %+v", i, entry)
		}
	}
	// Remaining 30 must all have detached_at populated.
	for i := 2; i < 32; i++ {
		entry := atks[i].(map[string]any)
		if _, present := entry["detached_at"]; !present {
			t.Errorf("entry %d should be detached, got %+v", i, entry)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// attached_attacks must filter to CURRENT cycle only. Previous-cycle attacks
// (attached before announcement's most recent announced_at — resurrect) are
// excluded, so the operator drawer shows only who's attached to THIS run.
// ─────────────────────────────────────────────────────────────────────────────

func TestListActiveBGPRoutes_AttachedAttacksCycleFiltered(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()

	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, store.BGPConnector{ID: 6, Name: "Main BGP", Enabled: true})

	// Cycle 1: attack 1 attached + detached, then cycle ends (withdraw).
	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID: 1, DstIP: "192.0.2.0/24", DecoderFamily: "udp",
	})
	ar1, _ := ms.bgpAnnouncements.Attach(ctx, store.BGPAttachParams{
		AttackID: 1, Prefix: "192.0.2.0/24", RouteMap: "RTBH", ConnectorID: 6,
	})
	ms.bgpAnnouncements.MarkAnnounced(ctx, ar1.AnnouncementID)
	ms.bgpAnnouncements.Detach(ctx, 1, "192.0.2.0/24", "RTBH", 6)
	ms.bgpAnnouncements.MarkWithdrawn(ctx, ar1.AnnouncementID)

	// Cycle 2 (resurrect): attack 2 attached.
	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID: 2, DstIP: "192.0.2.0/24", DecoderFamily: "udp",
	})
	ar2, _ := ms.bgpAnnouncements.Attach(ctx, store.BGPAttachParams{
		AttackID: 2, Prefix: "192.0.2.0/24", RouteMap: "RTBH", ConnectorID: 6,
	})
	ms.bgpAnnouncements.MarkAnnounced(ctx, ar2.AnnouncementID)
	if ar1.AnnouncementID != ar2.AnnouncementID {
		t.Fatalf("expected resurrect (same id); got %d vs %d", ar1.AnnouncementID, ar2.AnnouncementID)
	}

	r := setupRouter(ms)
	w := doGet(t, r, "/api/active-actions/bgp")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	list := decodeList(t, w)
	if len(list) != 1 {
		t.Fatalf("expected 1 row, got %d", len(list))
	}
	atks := list[0]["attached_attacks"].([]any)
	// Only current-cycle attack (attack_id=2) should appear; attack 1 from
	// the previous lifecycle must be filtered out.
	if len(atks) != 1 {
		t.Fatalf("expected 1 current-cycle attack, got %d: %+v", len(atks), atks)
	}
	entry := atks[0].(map[string]any)
	if entry["attack_id"].(float64) != 2 {
		t.Errorf("expected attack_id=2 (current cycle), got %v", entry["attack_id"])
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Extra: unauthenticated request must return 401
// ─────────────────────────────────────────────────────────────────────────────

func TestListActiveBGPRoutes_Unauthenticated(t *testing.T) {
	ms := NewMockStore()
	r := setupRouter(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/active-actions/bgp", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
