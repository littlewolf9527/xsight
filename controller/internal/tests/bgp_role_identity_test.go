package tests

// v1.2.1 Part 2 regression test — locks in the identity-based bgp_role
// semantics that replaced the original "attached_at == earliest_attached_at"
// time-equality check (flagged by GPT audit).
//
// Why this test exists: Postgres timestamp precision (and tests that seed
// attach rows inside a single transaction) can produce two bgp_announcement_
// attacks rows whose `attached_at` values are byte-identical. The old logic
// would tag BOTH attacks as "triggered", which mis-represents the vtysh
// side-effect (only the first Attach actually ran vtysh). The new logic
// sorts by (attached_at ASC, attack_id ASC) and picks the earliest
// deterministic attach identity as the canonical trigger.
//
// This test pins that behavior: if anyone refactors the logic back to
// time-equality heuristics, this test breaks.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func TestEnrichBGPRole_IdenticalAttachedAt_DeterministicByAttackID(t *testing.T) {
	ms := NewMockStore()
	r := setupRouter(ms)

	// Same timestamp for both attaches — the exact scenario the old
	// time-equality check got wrong.
	t0 := time.Date(2026, 4, 18, 10, 0, 0, 0, time.UTC)
	connID := 6
	actionID := 111

	// Seed an announcement. refcount=2 reflects the 2 shared attaches.
	ms.bgpAnnouncements.announcements = append(ms.bgpAnnouncements.announcements,
		store.BGPAnnouncement{
			ID:            1,
			Prefix:        "192.0.2.0/24",
			RouteMap:      "RTBH",
			ConnectorID:   connID,
			FirstActionID: &actionID,
			Status:        "active",
			Refcount:      2,
			AnnouncedAt:   t0,
		})

	// Two attacks attach at the exact same instant. attack_id=1000 is
	// smaller so tie-break sorts it first → canonical trigger.
	ms.bgpAnnouncements.attacks = append(ms.bgpAnnouncements.attacks,
		store.BGPAnnouncementAttack{
			AnnouncementID: 1, AttackID: 1000, ActionID: &actionID,
			AttachedAt: t0,
		},
		store.BGPAnnouncementAttack{
			AnnouncementID: 1, AttackID: 1001, ActionID: &actionID,
			AttachedAt: t0,
		})

	// One action_execution_log row per attack. Both reference the same
	// BGP (prefix, route_map, connector) triple via external_rule_id so
	// enrichActionLogsWithBGPRole resolves them to the same announcement.
	ms.actionExecLog.logs = append(ms.actionExecLog.logs,
		store.ActionExecutionLog{
			ID: 1, AttackID: 1000, ActionID: actionID,
			ActionType: "bgp", TriggerPhase: "on_detected", Status: "success",
			ConnectorID: &connID, ExternalRuleID: "192.0.2.0/24|RTBH",
			ExecutedAt: t0,
		},
		store.ActionExecutionLog{
			ID: 2, AttackID: 1001, ActionID: actionID,
			ActionType: "bgp", TriggerPhase: "on_detected", Status: "success",
			ConnectorID: &connID, ExternalRuleID: "192.0.2.0/24|RTBH",
			ExecutedAt: t0,
		})

	// attack_id=1000 queries: its single log row must be "triggered".
	if got := fetchBGPRole(t, r, 1000, 1); got != "triggered" {
		t.Errorf("attack 1000 (earliest by tie-break) expected bgp_role=triggered, got %q", got)
	}

	// attack_id=1001 queries: its single log row must be "attached_shared".
	// The same identical attached_at must NOT grant it triggered status —
	// this is the exact regression the test guards against.
	if got := fetchBGPRole(t, r, 1001, 2); got != "attached_shared" {
		t.Errorf("attack 1001 (loses tie-break) expected bgp_role=attached_shared, got %q", got)
	}
}

// bgp_announcement_attacks is append-only across resurrects, so a long-
// lived announcement that cycled active → withdrawn → active accumulates
// ghost rows from prior cycles (detached_at set but attached_at in the
// past). enrichActionLogsWithBGPRole must anchor the "earliest attach"
// computation on ann.AnnouncedAt (cycle start); otherwise every current-
// cycle attack gets tagged attached_shared because the global minimum
// attached_at points at a long-expired ghost.
//
// This pins that behavior: without cycle filter, attack 3000 (current
// cycle's first attach) would be shadowed by a prior-cycle ghost row.
func TestEnrichBGPRole_CycleFilter_IgnoresPriorCycleGhost(t *testing.T) {
	ms := NewMockStore()
	r := setupRouter(ms)

	priorCycle := time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC)
	currentCycle := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	detached := time.Date(2026, 4, 17, 11, 0, 0, 0, time.UTC)
	connID := 6
	actionID := 111

	// Announcement currently in its SECOND cycle. announced_at marks the
	// resurrect point; anything attached before that is a ghost row.
	ms.bgpAnnouncements.announcements = append(ms.bgpAnnouncements.announcements,
		store.BGPAnnouncement{
			ID:            1,
			Prefix:        "192.0.2.0/24",
			RouteMap:      "RTBH",
			ConnectorID:   connID,
			FirstActionID: &actionID,
			Status:        "active",
			Refcount:      1,
			AnnouncedAt:   currentCycle,
		})

	// Ghost: attached during the first cycle, already detached. Has the
	// smallest attack_id, so a non-filtered implementation would pin the
	// trigger identity on it and wrongly return attached_shared for the
	// real current-cycle attack.
	ms.bgpAnnouncements.attacks = append(ms.bgpAnnouncements.attacks,
		store.BGPAnnouncementAttack{
			AnnouncementID: 1, AttackID: 1, ActionID: &actionID,
			AttachedAt: priorCycle, DetachedAt: &detached,
		},
		// Current cycle, only live attach.
		store.BGPAnnouncementAttack{
			AnnouncementID: 1, AttackID: 3000, ActionID: &actionID,
			AttachedAt: currentCycle,
		})

	ms.actionExecLog.logs = append(ms.actionExecLog.logs,
		store.ActionExecutionLog{
			ID: 1, AttackID: 3000, ActionID: actionID,
			ActionType: "bgp", TriggerPhase: "on_detected", Status: "success",
			ConnectorID: &connID, ExternalRuleID: "192.0.2.0/24|RTBH",
			ExecutedAt: currentCycle,
		})

	// attack 3000 is THIS cycle's first (and only) attach → triggered.
	// Regression guard: if someone removes the cycle filter, the ghost
	// row with attack_id=1 would take the trigger slot and attack 3000
	// would flip to "attached_shared".
	if got := fetchBGPRole(t, r, 3000, 1); got != "triggered" {
		t.Errorf("cycle-filter bypass: attack 3000 is the only current-cycle attach but got bgp_role=%q (ghost prior-cycle attack pollutes the trigger identity)", got)
	}
}

// fetchBGPRole drives the HTTP handler and returns the bgp_role field on
// the log row with the given id. Encapsulates the HTTP scaffolding so the
// assertion in the test body stays readable.
func fetchBGPRole(t *testing.T, r http.Handler, attackID, logID int) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/attacks/%d/action-log", attackID), nil)
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /action-log attack=%d: status=%d body=%s", attackID, w.Code, w.Body.String())
	}
	var rows []struct {
		ID      int    `json:"id"`
		BGPRole string `json:"bgp_role"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode: %v body=%s", err, w.Body.String())
	}
	for _, row := range rows {
		if row.ID == logID {
			return row.BGPRole
		}
	}
	t.Fatalf("log id=%d not found in response: %s", logID, w.Body.String())
	return ""
}
