package tests

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// ─────────────────────────── MockStore ───────────────────────────

// MockStore implements store.Store with in-memory repositories.
// Multiple field aliases are provided so that test files can access the same
// underlying repo through the name they use:
//
//	ms.responses      — used by transaction_test.go
//	ms.responseRepo   — used by active_actions_test.go
//	ms.attackRepo     — used by active_actions_test.go
//	ms.actionExecLog  — used by engine_suppression_test.go helper
//	ms.actionExecLogRepo — used by active_actions_test.go
//	ms.bgpConnectors  — used by store.BGPConnectors() method
//	ms.bgpConnRepo    — used by active_actions_test.go
type MockStore struct {
	// Primary repo fields — names match NewMockStore() assignments and method receivers.
	responses     *mockResponseRepo
	attacks       *mockAttackRepo
	bgpConnectors *mockBGPConnectorRepo
	xdropTargets  *mockXDropTargetRepo
	xdropConnectors *mockXDropConnectorRepo
	actionsLog    *mockActionsLogRepo
	preconditions *mockPreconditionRepo
	// v1.2 PR-2
	manualOverrides *mockManualOverrideRepo
	// v1.2 PR-3
	scheduledActions *mockScheduledActionRepo
	// v1.2 PR-4
	xdropActiveRules *mockXDropActiveRuleRepo
	// v1.2 PR-5
	bgpAnnouncements *mockBGPAnnouncementRepo

	// Aliases — same pointer, alternative names used by different test files.
	// active_actions_test.go uses: responseRepo, actionExecLog, actionExecLogRepo, bgpConnRepo
	// engine_suppression_test.go / transaction_test.go use: actionExecLogRepo
	responseRepo      *mockResponseRepo
	actionExecLog     *mockActionExecLogRepo
	actionExecLogRepo *mockActionExecLogRepo
	bgpConnRepo       *mockBGPConnectorRepo

	// Stub repos for everything else.
	nodeRepo              stubNodeRepo
	prefixRepo            stubPrefixRepo
	thresholdTemplateRepo stubThresholdTemplateRepo
	thresholdRepo         stubThresholdRepo
	userRepo              stubUserRepo
	webhookRepo           stubWebhookRepo
	auditLogRepo          stubAuditLogRepo
	statsRepo             stubStatsRepo
	dynDetectRepo         stubDynDetectRepo
	webhookConnectorRepo  stubWebhookConnectorRepo
	shellConnectorRepo    stubShellConnectorRepo
	flowLogRepo           stubFlowLogRepo
	flowListenerRepo      stubFlowListenerRepo
	flowSourceRepo        stubFlowSourceRepo
}

// NewMockStore constructs a fully-wired MockStore with all aliases wired to
// the same underlying repo instances.
func NewMockStore() *MockStore {
	xdc := &mockXDropConnectorRepo{}
	aelog := &mockActionExecLogRepo{nextID: 1}
	respRepo := &mockResponseRepo{nextID: 1}
	atkRepo := &mockAttackRepo{}
	bgpRepo := &mockBGPConnectorRepo{}
	ms := &MockStore{
		// Primary fields
		responses:       respRepo,
		attacks:         atkRepo,
		bgpConnectors:   bgpRepo,
		xdropTargets:    &mockXDropTargetRepo{targets: make(map[int][]int), connectors: xdc},
		xdropConnectors: xdc,
		actionsLog:       &mockActionsLogRepo{},
		preconditions:    &mockPreconditionRepo{},
		manualOverrides:  &mockManualOverrideRepo{},
		scheduledActions: &mockScheduledActionRepo{},
		xdropActiveRules: &mockXDropActiveRuleRepo{},
		bgpAnnouncements: &mockBGPAnnouncementRepo{},
		// Aliases (same pointers, different names used by different test files)
		responseRepo:      respRepo,
		actionExecLog:     aelog,
		actionExecLogRepo: aelog,
		bgpConnRepo:       bgpRepo,
	}
	return ms
}

// seedResponse is a test helper used by autopair/transaction tests.
// It pre-seeds a Response record so that createAction can find
// response.ID=id in the store (no-op for our mock since CreateAction
// accepts any responseID, but avoids "response not found" if code checks).
func (m *MockStore) seedResponse(id int) {
	// Our mock ResponseRepo does not check whether the Response record exists
	// before creating actions — the API handler does not look up the response
	// in createAction/updateAction/deleteAction, so a seed is not required for
	// the action-level operations.  This method is a no-op placeholder kept
	// so that callers compile cleanly.
}

func (m *MockStore) Nodes() store.NodeRepo                          { return m.nodeRepo }
func (m *MockStore) Prefixes() store.PrefixRepo                     { return m.prefixRepo }
func (m *MockStore) ThresholdTemplates() store.ThresholdTemplateRepo { return m.thresholdTemplateRepo }
func (m *MockStore) Thresholds() store.ThresholdRepo                { return m.thresholdRepo }
func (m *MockStore) Responses() store.ResponseRepo                  { return m.responses }
func (m *MockStore) Attacks() store.AttackRepo                      { return m.attacks }
func (m *MockStore) ActionsLog() store.ActionsLogRepo               { return m.actionsLog }
func (m *MockStore) Users() store.UserRepo                          { return m.userRepo }
func (m *MockStore) Webhooks() store.WebhookRepo                    { return m.webhookRepo }
func (m *MockStore) AuditLog() store.AuditLogRepo                   { return m.auditLogRepo }
func (m *MockStore) Stats() store.StatsRepo                         { return m.statsRepo }
func (m *MockStore) DynDetect() store.DynDetectRepo                 { return m.dynDetectRepo }
func (m *MockStore) WebhookConnectors() store.WebhookConnectorRepo  { return m.webhookConnectorRepo }
func (m *MockStore) XDropConnectors() store.XDropConnectorRepo      { return m.xdropConnectors }
func (m *MockStore) ShellConnectors() store.ShellConnectorRepo      { return m.shellConnectorRepo }
func (m *MockStore) ActionExecLog() store.ActionExecLogRepo         { return m.actionExecLog }
func (m *MockStore) XDropTargets() store.XDropTargetRepo            { return m.xdropTargets }
func (m *MockStore) Preconditions() store.PreconditionRepo          { return m.preconditions }
func (m *MockStore) FlowLogs() store.FlowLogRepo                    { return m.flowLogRepo }
func (m *MockStore) FlowListeners() store.FlowListenerRepo          { return m.flowListenerRepo }
func (m *MockStore) FlowSources() store.FlowSourceRepo              { return m.flowSourceRepo }
func (m *MockStore) BGPConnectors() store.BGPConnectorRepo          { return m.bgpConnectors }
func (m *MockStore) ManualOverrides() store.ActionManualOverrideRepo { return m.manualOverrides }   // v1.2 PR-2
func (m *MockStore) ScheduledActions() store.ScheduledActionRepo     { return m.scheduledActions } // v1.2 PR-3
func (m *MockStore) XDropActiveRules() store.XDropActiveRuleRepo      { return m.xdropActiveRules }  // v1.2 PR-4
func (m *MockStore) BGPAnnouncements() store.BGPAnnouncementRepo      { return m.bgpAnnouncements }  // v1.2 PR-5
func (m *MockStore) Close()                                         {}

// ─────────────────────────── mockResponseRepo ───────────────────────────

// mockResponseRepo stores actions as a slice so test files can seed fixture
// actions via append (e.g. ms.responseRepo.actions = append(...)).
// All interface methods do linear scans — acceptable for test volumes.
type mockResponseRepo struct {
	mu        sync.Mutex
	actions   []store.ResponseAction // slice — supports direct append by tests
	responses []store.Response       // seeded by tests; enables Get() for HandleEvent dispatch
	nextID    int
}

func (r *mockResponseRepo) List(_ context.Context) ([]store.Response, error) { return nil, nil }
func (r *mockResponseRepo) Get(_ context.Context, id int) (*store.Response, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.responses {
		if r.responses[i].ID == id {
			cp := r.responses[i]
			return &cp, nil
		}
	}
	return nil, errors.New("response not found")
}
func (r *mockResponseRepo) Create(_ context.Context, _ *store.Response) (int, error) {
	return 0, errors.New("not implemented")
}
func (r *mockResponseRepo) Update(_ context.Context, _ *store.Response) error {
	return errors.New("not implemented")
}
func (r *mockResponseRepo) Delete(_ context.Context, _ int) error {
	return errors.New("not implemented")
}

func (r *mockResponseRepo) ListActions(_ context.Context, responseID int) ([]store.ResponseAction, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.ResponseAction
	for _, a := range r.actions {
		if a.ResponseID == responseID {
			cp := a
			out = append(out, cp)
		}
	}
	// Match postgres repo ordering: `ORDER BY trigger_phase, priority`.
	// Critical for first_match ACL tests — phase-mismatched actions must appear
	// after phase-matched actions, otherwise ordering masks real bugs.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].TriggerPhase != out[j].TriggerPhase {
			return out[i].TriggerPhase < out[j].TriggerPhase
		}
		return out[i].Priority < out[j].Priority
	})
	return out, nil
}

func (r *mockResponseRepo) GetAction(_ context.Context, id int) (*store.ResponseAction, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.actions {
		if r.actions[i].ID == id {
			cp := r.actions[i]
			return &cp, nil
		}
	}
	return nil, errors.New("action not found")
}

func (r *mockResponseRepo) CreateAction(_ context.Context, a *store.ResponseAction) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID
	r.nextID++
	cp := *a
	cp.ID = id
	r.actions = append(r.actions, cp)
	return id, nil
}

func (r *mockResponseRepo) UpdateAction(_ context.Context, a *store.ResponseAction) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.actions {
		if r.actions[i].ID == a.ID {
			r.actions[i] = *a
			return nil
		}
	}
	return errors.New("action not found")
}

func (r *mockResponseRepo) DeleteAction(_ context.Context, id int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.actions {
		if r.actions[i].ID == id {
			r.actions = append(r.actions[:i], r.actions[i+1:]...)
			return nil
		}
	}
	return nil // idempotent delete
}

func (r *mockResponseRepo) SetPairedWith(_ context.Context, actionID int, pairedID *int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.actions {
		if r.actions[i].ID == actionID {
			r.actions[i].PairedWith = pairedID
			return nil
		}
	}
	return errors.New("action not found")
}

func (r *mockResponseRepo) CountActionsByWebhookConnector(_ context.Context, _ int) (int, error) {
	return 0, nil
}
func (r *mockResponseRepo) CountActionsByShellConnector(_ context.Context, _ int) (int, error) {
	return 0, nil
}
func (r *mockResponseRepo) CountActionsByBGPConnector(_ context.Context, _ int) (int, error) {
	return 0, nil
}

// ─────────────────────────── mockAttackRepo ───────────────────────────

type mockAttackRepo struct {
	mu             sync.Mutex
	attacks        []store.Attack // active attacks (EndedAt == nil)
	expiredAttacks []store.Attack // expired attacks seeded by recovery tests
}

func (r *mockAttackRepo) ListActive(_ context.Context, limit int) ([]store.Attack, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.Attack
	for _, a := range r.attacks {
		if a.EndedAt == nil {
			out = append(out, a)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (r *mockAttackRepo) List(_ context.Context, filter store.AttackFilter) ([]store.Attack, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Combine both slices for iteration.
	all := make([]store.Attack, 0, len(r.attacks)+len(r.expiredAttacks))
	all = append(all, r.attacks...)
	all = append(all, r.expiredAttacks...)
	var out []store.Attack
	for _, a := range all {
		switch filter.Status {
		case "expired":
			if a.EndedAt == nil {
				continue
			}
		case "active":
			if a.EndedAt != nil {
				continue
			}
		}
		out = append(out, a)
	}
	return out, nil
}

func (r *mockAttackRepo) Count(_ context.Context, _ store.AttackFilter) (int, error) {
	return len(r.attacks), nil
}

func (r *mockAttackRepo) Get(_ context.Context, id int) (*store.Attack, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.attacks {
		if a.ID == id {
			cp := a
			return &cp, nil
		}
	}
	for _, a := range r.expiredAttacks {
		if a.ID == id {
			cp := a
			return &cp, nil
		}
	}
	return nil, errors.New("attack not found")
}

func (r *mockAttackRepo) Create(_ context.Context, a *store.Attack) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := len(r.attacks) + 1
	cp := *a
	cp.ID = id
	r.attacks = append(r.attacks, cp)
	return id, nil
}

func (r *mockAttackRepo) Update(_ context.Context, a *store.Attack) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, existing := range r.attacks {
		if existing.ID == a.ID {
			r.attacks[i] = *a
			return nil
		}
	}
	return errors.New("attack not found")
}

func (r *mockAttackRepo) CountActive(_ context.Context) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, a := range r.attacks {
		if a.EndedAt == nil {
			count++
		}
	}
	return count, nil
}

// ─────────────────────────── mockActionExecLogRepo ───────────────────────────

type mockActionExecLogRepo struct {
	mu     sync.Mutex
	logs   []store.ActionExecutionLog
	nextID int
}

func (r *mockActionExecLogRepo) Create(_ context.Context, l *store.ActionExecutionLog) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID
	r.nextID++
	cp := *l
	cp.ID = id
	r.logs = append(r.logs, cp)
	return id, nil
}

func (r *mockActionExecLogRepo) ListByAttack(_ context.Context, attackID int) ([]store.ActionExecutionLog, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.ActionExecutionLog
	for _, l := range r.logs {
		if l.AttackID == attackID {
			out = append(out, l)
		}
	}
	return out, nil
}

// FindByAttackAndAction returns the latest log for (attackID, actionID, triggerPhase).
func (r *mockActionExecLogRepo) FindByAttackAndAction(_ context.Context, attackID, actionID int, triggerPhase string) (*store.ActionExecutionLog, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var found *store.ActionExecutionLog
	for i := range r.logs {
		l := &r.logs[i]
		if l.AttackID == attackID && l.ActionID == actionID && l.TriggerPhase == triggerPhase {
			if found == nil || l.ExecutedAt.After(found.ExecutedAt) {
				cp := *l
				found = &cp
			}
		}
	}
	if found == nil {
		return nil, errors.New("not found")
	}
	return found, nil
}

func (r *mockActionExecLogRepo) FindExternalRuleIDs(_ context.Context, attackID, actionID int) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var ids []string
	for _, l := range r.logs {
		if l.AttackID == attackID && l.ActionID == actionID && l.ExternalRuleID != "" {
			ids = append(ids, l.ExternalRuleID)
		}
	}
	return ids, nil
}

func (r *mockActionExecLogRepo) FindExternalRulesWithActions(_ context.Context, attackID int) ([]store.RuleWithAction, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.RuleWithAction
	for _, l := range r.logs {
		if l.AttackID == attackID && l.ExternalRuleID != "" {
			connID := 0
			if l.ConnectorID != nil {
				connID = *l.ConnectorID
			}
			out = append(out, store.RuleWithAction{
				RuleID:      l.ExternalRuleID,
				ActionID:    l.ActionID,
				ConnectorID: connID,
			})
		}
	}
	return out, nil
}

// ─────────────────────────── mockXDropTargetRepo ───────────────────────────

type mockXDropTargetRepo struct {
	mu         sync.Mutex
	targets    map[int][]int // actionID → connectorIDs
	connectors *mockXDropConnectorRepo
}

func (r *mockXDropTargetRepo) Set(_ context.Context, actionID int, connectorIDs []int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]int, len(connectorIDs))
	copy(cp, connectorIDs)
	r.targets[actionID] = cp
	return nil
}

func (r *mockXDropTargetRepo) List(ctx context.Context, actionID int) ([]store.XDropConnector, error) {
	r.mu.Lock()
	ids := r.targets[actionID]
	r.mu.Unlock()

	var out []store.XDropConnector
	for _, cid := range ids {
		conn, err := r.connectors.Get(ctx, cid)
		if err == nil {
			out = append(out, *conn)
		}
	}
	return out, nil
}

func (r *mockXDropTargetRepo) CountByConnector(_ context.Context, connectorID int) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, ids := range r.targets {
		for _, id := range ids {
			if id == connectorID {
				count++
			}
		}
	}
	return count, nil
}

// ─────────────────────────── mockBGPConnectorRepo ───────────────────────────

type mockBGPConnectorRepo struct {
	mu         sync.Mutex
	connectors []store.BGPConnector
}

func (r *mockBGPConnectorRepo) List(_ context.Context) ([]store.BGPConnector, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]store.BGPConnector, len(r.connectors))
	copy(cp, r.connectors)
	return cp, nil
}

func (r *mockBGPConnectorRepo) Get(_ context.Context, id int) (*store.BGPConnector, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.connectors {
		if c.ID == id {
			cp := c
			return &cp, nil
		}
	}
	return nil, errors.New("bgp connector not found")
}

func (r *mockBGPConnectorRepo) Create(_ context.Context, c *store.BGPConnector) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := len(r.connectors) + 1
	cp := *c
	cp.ID = id
	r.connectors = append(r.connectors, cp)
	return id, nil
}

func (r *mockBGPConnectorRepo) Update(_ context.Context, c *store.BGPConnector) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, existing := range r.connectors {
		if existing.ID == c.ID {
			r.connectors[i] = *c
			return nil
		}
	}
	return errors.New("bgp connector not found")
}

func (r *mockBGPConnectorRepo) Delete(_ context.Context, id int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, c := range r.connectors {
		if c.ID == id {
			r.connectors = append(r.connectors[:i], r.connectors[i+1:]...)
			return nil
		}
	}
	return errors.New("bgp connector not found")
}

// ─────────────────────────── mockXDropConnectorRepo ───────────────────────────

type mockXDropConnectorRepo struct {
	mu         sync.Mutex
	connectors []store.XDropConnector
}

func (r *mockXDropConnectorRepo) List(_ context.Context) ([]store.XDropConnector, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]store.XDropConnector, len(r.connectors))
	copy(cp, r.connectors)
	return cp, nil
}

func (r *mockXDropConnectorRepo) ListEnabled(_ context.Context) ([]store.XDropConnector, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.XDropConnector
	for _, c := range r.connectors {
		if c.Enabled {
			out = append(out, c)
		}
	}
	return out, nil
}

func (r *mockXDropConnectorRepo) Get(_ context.Context, id int) (*store.XDropConnector, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.connectors {
		if c.ID == id {
			cp := c
			return &cp, nil
		}
	}
	return nil, errors.New("xdrop connector not found")
}

func (r *mockXDropConnectorRepo) Create(_ context.Context, c *store.XDropConnector) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := len(r.connectors) + 1
	cp := *c
	cp.ID = id
	r.connectors = append(r.connectors, cp)
	return id, nil
}

func (r *mockXDropConnectorRepo) Update(_ context.Context, c *store.XDropConnector) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, existing := range r.connectors {
		if existing.ID == c.ID {
			r.connectors[i] = *c
			return nil
		}
	}
	return errors.New("xdrop connector not found")
}

func (r *mockXDropConnectorRepo) Delete(_ context.Context, id int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, c := range r.connectors {
		if c.ID == id {
			r.connectors = append(r.connectors[:i], r.connectors[i+1:]...)
			return nil
		}
	}
	return errors.New("xdrop connector not found")
}

// ─────────────────────────── mockActionsLogRepo ───────────────────────────

type mockActionsLogRepo struct{}

func (r *mockActionsLogRepo) Create(_ context.Context, _ *store.ActionLog) (int, error) {
	return 0, nil
}
func (r *mockActionsLogRepo) Update(_ context.Context, _ *store.ActionLog) error { return nil }
func (r *mockActionsLogRepo) FindByAttackAndAction(_ context.Context, _, _ int) (*store.ActionLog, error) {
	return nil, errors.New("not found")
}
func (r *mockActionsLogRepo) ListByAttack(_ context.Context, _ int) ([]store.ActionLog, error) {
	return nil, nil
}

// ─────────────────────────── mockPreconditionRepo ───────────────────────────

// mockPreconditionRepo stores preconditions per action so tests can drive
// precondition-fail paths in the engine (v1.2 PR-1 skip_reason tests).
type mockPreconditionRepo struct {
	mu     sync.Mutex
	byActionID map[int][]store.ActionPrecondition
}

func (r *mockPreconditionRepo) List(_ context.Context, actionID int) ([]store.ActionPrecondition, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byActionID == nil {
		return nil, nil
	}
	return append([]store.ActionPrecondition(nil), r.byActionID[actionID]...), nil
}
func (r *mockPreconditionRepo) Create(_ context.Context, _ *store.ActionPrecondition) (int, error) {
	return 0, nil
}
func (r *mockPreconditionRepo) Delete(_ context.Context, _ int) error         { return nil }
func (r *mockPreconditionRepo) DeleteByAction(_ context.Context, _ int) error  { return nil }
func (r *mockPreconditionRepo) ReplaceAll(_ context.Context, _ int, _ []store.ActionPrecondition) error {
	return nil
}

// SeedPreconditions is a test helper to attach preconditions to an action.
func (r *mockPreconditionRepo) SeedPreconditions(actionID int, pcs []store.ActionPrecondition) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byActionID == nil {
		r.byActionID = make(map[int][]store.ActionPrecondition)
	}
	r.byActionID[actionID] = append(r.byActionID[actionID], pcs...)
}

// v1.2 PR-2: mockManualOverrideRepo emulates action_manual_overrides with a
// slice + map index keyed on (attack, action, connector, rule). UNIQUE
// constraint is enforced by Create() — duplicate keys update created_by and
// return the existing ID, matching postgres ON CONFLICT behavior.
type mockManualOverrideRepo struct {
	mu        sync.Mutex
	records   []store.ActionManualOverride
	nextID    int
}

func (r *mockManualOverrideRepo) key(attackID, actionID, connectorID int, externalRuleID string) string {
	return fmt.Sprintf("%d:%d:%d:%s", attackID, actionID, connectorID, externalRuleID)
}

func (r *mockManualOverrideRepo) Create(_ context.Context, o *store.ActionManualOverride) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := r.key(o.AttackID, o.ActionID, o.ConnectorID, o.ExternalRuleID)
	for i := range r.records {
		if r.key(r.records[i].AttackID, r.records[i].ActionID, r.records[i].ConnectorID, r.records[i].ExternalRuleID) == key {
			// Idempotent: update created_by, return existing ID
			r.records[i].CreatedBy = o.CreatedBy
			return r.records[i].ID, nil
		}
	}
	r.nextID++
	cp := *o
	cp.ID = r.nextID
	cp.CreatedAt = time.Now()
	r.records = append(r.records, cp)
	return cp.ID, nil
}

func (r *mockManualOverrideRepo) Exists(_ context.Context, attackID, actionID, connectorID int, externalRuleID string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	target := r.key(attackID, actionID, connectorID, externalRuleID)
	for i := range r.records {
		if r.key(r.records[i].AttackID, r.records[i].ActionID, r.records[i].ConnectorID, r.records[i].ExternalRuleID) == target {
			return true, nil
		}
	}
	return false, nil
}

func (r *mockManualOverrideRepo) ListByAttack(_ context.Context, attackID int) ([]store.ActionManualOverride, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.ActionManualOverride
	for _, o := range r.records {
		if o.AttackID == attackID {
			out = append(out, o)
		}
	}
	return out, nil
}

// v1.2 PR-3: mockScheduledActionRepo persists ScheduledAction records in a
// slice and enforces the partial UNIQUE on pending rows via the businessKey
// helper. Tests can seed rows and inspect state transitions.
type mockScheduledActionRepo struct {
	mu      sync.Mutex
	records []store.ScheduledAction
	nextID  int
	// v1.2 PR-4 P2 fault-injection: when non-nil, Schedule returns this error
	// so tests can exercise the "persist failed" fallback path.
	scheduleErr error
}

func (r *mockScheduledActionRepo) businessKey(actionType string, attackID, actionID, connectorID int, externalRuleID string) string {
	return fmt.Sprintf("%s:%d:%d:%d:%s", actionType, attackID, actionID, connectorID, externalRuleID)
}

func (r *mockScheduledActionRepo) Schedule(_ context.Context, a *store.ScheduledAction) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.scheduleErr != nil {
		return 0, r.scheduleErr
	}
	bk := r.businessKey(a.ActionType, a.AttackID, a.ActionID, a.ConnectorID, a.ExternalRuleID)
	// Partial UNIQUE (pending only) emulation
	for i := range r.records {
		rec := &r.records[i]
		if rec.Status == "pending" && r.businessKey(rec.ActionType, rec.AttackID, rec.ActionID, rec.ConnectorID, rec.ExternalRuleID) == bk {
			rec.ScheduledFor = a.ScheduledFor
			return rec.ID, nil
		}
	}
	r.nextID++
	cp := *a
	cp.ID = r.nextID
	cp.Status = "pending"
	cp.CreatedAt = time.Now()
	r.records = append(r.records, cp)
	return cp.ID, nil
}

func (r *mockScheduledActionRepo) Cancel(_ context.Context, id int, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.records {
		if r.records[i].ID == id && r.records[i].Status == "pending" {
			now := time.Now()
			r.records[i].Status = "cancelled"
			r.records[i].CancelReason = reason
			r.records[i].CompletedAt = &now
			return nil
		}
	}
	return nil
}

func (r *mockScheduledActionRepo) CancelByBusinessKey(_ context.Context, actionType string, attackID, actionID, connectorID int, externalRuleID, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	bk := r.businessKey(actionType, attackID, actionID, connectorID, externalRuleID)
	for i := range r.records {
		rec := &r.records[i]
		if rec.Status == "pending" && r.businessKey(rec.ActionType, rec.AttackID, rec.ActionID, rec.ConnectorID, rec.ExternalRuleID) == bk {
			now := time.Now()
			rec.Status = "cancelled"
			rec.CancelReason = reason
			rec.CompletedAt = &now
		}
	}
	return nil
}

func (r *mockScheduledActionRepo) CancelAllForAttack(_ context.Context, attackID int, reason string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for i := range r.records {
		rec := &r.records[i]
		if rec.Status == "pending" && rec.AttackID == attackID {
			now := time.Now()
			rec.Status = "cancelled"
			rec.CancelReason = reason
			rec.CompletedAt = &now
			n++
		}
	}
	return n, nil
}

func (r *mockScheduledActionRepo) MarkExecuting(_ context.Context, id int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.records {
		if r.records[i].ID == id {
			if r.records[i].Status != "pending" {
				return fmt.Errorf("scheduled_action %d status=%s, not pending", id, r.records[i].Status)
			}
			r.records[i].Status = "executing"
			return nil
		}
	}
	return fmt.Errorf("scheduled_action %d not found", id)
}

func (r *mockScheduledActionRepo) Complete(_ context.Context, id int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.records {
		if r.records[i].ID == id {
			now := time.Now()
			r.records[i].Status = "completed"
			r.records[i].CompletedAt = &now
			return nil
		}
	}
	return nil
}

func (r *mockScheduledActionRepo) Fail(_ context.Context, id int, errMsg string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.records {
		if r.records[i].ID == id {
			now := time.Now()
			r.records[i].Status = "failed"
			r.records[i].ErrorMessage = errMsg
			r.records[i].CompletedAt = &now
			return nil
		}
	}
	return nil
}

func (r *mockScheduledActionRepo) ListPending(_ context.Context) ([]store.ScheduledAction, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.ScheduledAction
	for _, rec := range r.records {
		if rec.Status == "pending" {
			out = append(out, rec)
		}
	}
	return out, nil
}

// v1.2 PR-4: ListExecuting for reconciliation of stuck 'executing' rows.
func (r *mockScheduledActionRepo) ListExecuting(_ context.Context) ([]store.ScheduledAction, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.ScheduledAction
	for _, rec := range r.records {
		if rec.Status == "executing" {
			out = append(out, rec)
		}
	}
	return out, nil
}

func (r *mockScheduledActionRepo) CountByStatus(_ context.Context) (map[string]int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]int)
	for _, rec := range r.records {
		out[rec.Status]++
	}
	return out, nil
}

// v1.2 PR-4: mockXDropActiveRuleRepo persists XDropActiveRule records with
// UNIQUE business-key semantics. Upsert consolidates existing rows.
type mockXDropActiveRuleRepo struct {
	mu      sync.Mutex
	records []store.XDropActiveRule
	nextID  int
}

func (r *mockXDropActiveRuleRepo) businessKey(attackID, actionID, connectorID int, externalRuleID string) string {
	return fmt.Sprintf("%d:%d:%d:%s", attackID, actionID, connectorID, externalRuleID)
}

func (r *mockXDropActiveRuleRepo) findIdxLocked(attackID, actionID, connectorID int, externalRuleID string) int {
	target := r.businessKey(attackID, actionID, connectorID, externalRuleID)
	for i := range r.records {
		rec := &r.records[i]
		if r.businessKey(rec.AttackID, rec.ActionID, rec.ConnectorID, rec.ExternalRuleID) == target {
			return i
		}
	}
	return -1
}

func (r *mockXDropActiveRuleRepo) Upsert(_ context.Context, rule *store.XDropActiveRule) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if idx := r.findIdxLocked(rule.AttackID, rule.ActionID, rule.ConnectorID, rule.ExternalRuleID); idx >= 0 {
		existing := &r.records[idx]
		existing.Status = rule.Status
		existing.DelayMinutes = rule.DelayMinutes
		existing.DelayStartedAt = rule.DelayStartedAt
		existing.ErrorMessage = rule.ErrorMessage
		return existing.ID, nil
	}
	r.nextID++
	cp := *rule
	cp.ID = r.nextID
	cp.CreatedAt = time.Now()
	r.records = append(r.records, cp)
	return cp.ID, nil
}

func (r *mockXDropActiveRuleRepo) MarkWithdrawing(_ context.Context, attackID, actionID, connectorID int, externalRuleID string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := r.findIdxLocked(attackID, actionID, connectorID, externalRuleID)
	if idx < 0 {
		return false, nil
	}
	switch r.records[idx].Status {
	case "active", "delayed":
		r.records[idx].Status = "withdrawing"
		return true, nil
	}
	return false, nil
}

func (r *mockXDropActiveRuleRepo) MarkWithdrawn(_ context.Context, attackID, actionID, connectorID int, externalRuleID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := r.findIdxLocked(attackID, actionID, connectorID, externalRuleID)
	if idx < 0 {
		return nil
	}
	now := time.Now()
	r.records[idx].Status = "withdrawn"
	r.records[idx].WithdrawnAt = &now
	return nil
}

func (r *mockXDropActiveRuleRepo) MarkFailed(_ context.Context, attackID, actionID, connectorID int, externalRuleID, errMsg string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := r.findIdxLocked(attackID, actionID, connectorID, externalRuleID)
	if idx < 0 {
		return nil
	}
	r.records[idx].Status = "failed"
	r.records[idx].ErrorMessage = errMsg
	return nil
}

func (r *mockXDropActiveRuleRepo) MarkDelayed(_ context.Context, attackID, actionID, connectorID int, externalRuleID string, delayMinutes int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := r.findIdxLocked(attackID, actionID, connectorID, externalRuleID)
	if idx < 0 {
		return nil
	}
	now := time.Now()
	r.records[idx].Status = "delayed"
	r.records[idx].DelayStartedAt = &now
	r.records[idx].DelayMinutes = delayMinutes
	return nil
}

func (r *mockXDropActiveRuleRepo) ListActive(_ context.Context) ([]store.XDropActiveRule, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.XDropActiveRule
	for _, rec := range r.records {
		switch rec.Status {
		case "active", "delayed", "failed":
			out = append(out, rec)
		}
	}
	return out, nil
}

func (r *mockXDropActiveRuleRepo) ListWithdrawing(_ context.Context) ([]store.XDropActiveRule, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.XDropActiveRule
	for _, rec := range r.records {
		if rec.Status == "withdrawing" {
			out = append(out, rec)
		}
	}
	return out, nil
}

func (r *mockXDropActiveRuleRepo) ListByAttack(_ context.Context, attackID int) ([]store.XDropActiveRule, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.XDropActiveRule
	for _, rec := range r.records {
		if rec.AttackID == attackID {
			out = append(out, rec)
		}
	}
	return out, nil
}

func (r *mockXDropActiveRuleRepo) CountByStatus(_ context.Context) (map[string]int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]int)
	for _, rec := range r.records {
		out[rec.Status]++
	}
	return out, nil
}

// v1.2 PR-5: mockBGPAnnouncementRepo emulates the refcount lifecycle in
// memory. The tx-style locking is simulated by a single mutex held across
// each Attach/Detach/ForceWithdraw — matches the serialization guarantee
// that SELECT ... FOR UPDATE provides in postgres.
type mockBGPAnnouncementRepo struct {
	mu             sync.Mutex
	announcements  []store.BGPAnnouncement
	attacks        []store.BGPAnnouncementAttack
	events         []store.BGPAnnouncementEvent
	nextAnnID      int
	nextEventID    int
}

func (r *mockBGPAnnouncementRepo) findByBKLocked(prefix, routeMap string, connectorID int) *store.BGPAnnouncement {
	for i := range r.announcements {
		a := &r.announcements[i]
		if a.Prefix == prefix && a.RouteMap == routeMap && a.ConnectorID == connectorID {
			return a
		}
	}
	return nil
}

func (r *mockBGPAnnouncementRepo) findByIDLocked(id int) *store.BGPAnnouncement {
	for i := range r.announcements {
		if r.announcements[i].ID == id {
			return &r.announcements[i]
		}
	}
	return nil
}

func (r *mockBGPAnnouncementRepo) recomputeDelayLocked(annID int) {
	// Cycle-sticky MAX: delay_minutes only increases during a cycle. Never
	// regresses when a high-delay attack detaches — operator intent that "at
	// least one attack wanted delay=N" holds for the whole cycle. Reset back
	// to 0 happens in the resurrect branch of Attach (new cycle starts fresh).
	currentMax := 0
	for _, at := range r.attacks {
		if at.AnnouncementID == annID && at.DetachedAt == nil {
			if at.DelayMinutes > currentMax {
				currentMax = at.DelayMinutes
			}
		}
	}
	if a := r.findByIDLocked(annID); a != nil && currentMax > a.DelayMinutes {
		a.DelayMinutes = currentMax
	}
}

func (r *mockBGPAnnouncementRepo) appendEventLocked(annID int, eventType string, attackID *int, detail string) {
	r.nextEventID++
	r.events = append(r.events, store.BGPAnnouncementEvent{
		ID:             r.nextEventID,
		AnnouncementID: annID,
		EventType:      eventType,
		AttackID:       attackID,
		Detail:         detail,
		CreatedAt:      time.Now(),
	})
}

func (r *mockBGPAnnouncementRepo) upsertAttackLocked(annID, attackID int, actionID *int, responseName string, delayMinutes int) {
	for i := range r.attacks {
		a := &r.attacks[i]
		if a.AnnouncementID == annID && a.AttackID == attackID {
			a.DetachedAt = nil
			a.ActionID = actionID
			a.ResponseName = responseName
			a.DelayMinutes = delayMinutes
			return
		}
	}
	r.attacks = append(r.attacks, store.BGPAnnouncementAttack{
		AnnouncementID: annID,
		AttackID:       attackID,
		ActionID:       actionID,
		ResponseName:   responseName,
		DelayMinutes:   delayMinutes,
		AttachedAt:     time.Now(),
	})
}

func (r *mockBGPAnnouncementRepo) Get(_ context.Context, id int) (*store.BGPAnnouncement, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a := r.findByIDLocked(id); a != nil {
		cp := *a
		return &cp, nil
	}
	return nil, nil
}

func (r *mockBGPAnnouncementRepo) FindByBusinessKey(_ context.Context, prefix, routeMap string, connectorID int) (*store.BGPAnnouncement, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a := r.findByBKLocked(prefix, routeMap, connectorID); a != nil {
		cp := *a
		return &cp, nil
	}
	return nil, nil
}

func (r *mockBGPAnnouncementRepo) Attach(_ context.Context, p store.BGPAttachParams) (store.BGPAttachResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	existing := r.findByBKLocked(p.Prefix, p.RouteMap, p.ConnectorID)
	aid := p.AttackID
	if existing == nil {
		r.nextAnnID++
		a := store.BGPAnnouncement{
			ID:           r.nextAnnID,
			Prefix:       p.Prefix,
			RouteMap:     p.RouteMap,
			ConnectorID:  p.ConnectorID,
			FirstActionID: p.ActionID,
			Status:       "announcing",
			Refcount:     1,
			DelayMinutes: p.DelayMinutes,
			AnnouncedAt:  time.Now(),
			CreatedAt:    time.Now(),
		}
		r.announcements = append(r.announcements, a)
		r.upsertAttackLocked(a.ID, p.AttackID, p.ActionID, p.ResponseName, p.DelayMinutes)
		r.appendEventLocked(a.ID, store.BGPEventAttackAttached, &aid, "initial attach")
		return store.BGPAttachResult{AnnouncementID: a.ID, NeedAnnounce: true}, nil
	}
	switch existing.Status {
	case "announcing", "active":
		existing.Refcount++
		r.upsertAttackLocked(existing.ID, p.AttackID, p.ActionID, p.ResponseName, p.DelayMinutes)
		r.recomputeDelayLocked(existing.ID)
		r.appendEventLocked(existing.ID, store.BGPEventAttackAttached, &aid, fmt.Sprintf("shared (refcount=%d)", existing.Refcount))
		return store.BGPAttachResult{AnnouncementID: existing.ID, NeedAnnounce: false}, nil
	case "delayed":
		existing.Refcount++
		existing.Status = "active"
		existing.DelayStartedAt = nil
		r.upsertAttackLocked(existing.ID, p.AttackID, p.ActionID, p.ResponseName, p.DelayMinutes)
		r.recomputeDelayLocked(existing.ID)
		r.appendEventLocked(existing.ID, store.BGPEventDelayCancelled, &aid, "new attack attached during delay")
		return store.BGPAttachResult{AnnouncementID: existing.ID, NeedAnnounce: false}, nil
	case "withdrawn", "failed":
		existing.Status = "announcing"
		existing.Refcount = 1
		existing.AnnouncedAt = time.Now()
		existing.WithdrawnAt = nil
		existing.DelayStartedAt = nil
		existing.ErrorMessage = ""
		existing.DelayMinutes = 0 // reset for new cycle; recompute picks up new attack
		r.upsertAttackLocked(existing.ID, p.AttackID, p.ActionID, p.ResponseName, p.DelayMinutes)
		r.recomputeDelayLocked(existing.ID)
		r.appendEventLocked(existing.ID, store.BGPEventAttackAttached, &aid, "resurrect")
		return store.BGPAttachResult{AnnouncementID: existing.ID, NeedAnnounce: true}, nil
	}
	return store.BGPAttachResult{}, fmt.Errorf("cannot attach to announcement %d in status %s", existing.ID, existing.Status)
}

func (r *mockBGPAnnouncementRepo) Detach(_ context.Context, attackID int, prefix, routeMap string, connectorID int) (store.BGPDetachResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	existing := r.findByBKLocked(prefix, routeMap, connectorID)
	if existing == nil {
		return store.BGPDetachResult{}, nil
	}
	aid := attackID
	detached := false
	for i := range r.attacks {
		a := &r.attacks[i]
		if a.AnnouncementID == existing.ID && a.AttackID == attackID && a.DetachedAt == nil {
			now := time.Now()
			a.DetachedAt = &now
			detached = true
			break
		}
	}
	if !detached {
		return store.BGPDetachResult{AnnouncementID: existing.ID}, nil
	}
	if existing.Refcount > 0 {
		existing.Refcount--
	}
	r.recomputeDelayLocked(existing.ID)
	r.appendEventLocked(existing.ID, store.BGPEventAttackDetached, &aid, fmt.Sprintf("refcount=%d", existing.Refcount))

	result := store.BGPDetachResult{AnnouncementID: existing.ID, RefcountAfter: existing.Refcount}
	if existing.Refcount > 0 {
		return result, nil
	}
	if existing.DelayMinutes > 0 {
		existing.Status = "delayed"
		now := time.Now()
		existing.DelayStartedAt = &now
		r.appendEventLocked(existing.ID, store.BGPEventDelayStarted, &aid, fmt.Sprintf("delay_minutes=%d", existing.DelayMinutes))
		result.Delayed = true
		result.DelayMinutes = existing.DelayMinutes
		return result, nil
	}
	existing.Status = "withdrawing"
	result.NeedWithdraw = true
	return result, nil
}

func (r *mockBGPAnnouncementRepo) MarkAnnounced(_ context.Context, id int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a := r.findByIDLocked(id); a != nil && a.Status == "announcing" {
		a.Status = "active"
	}
	r.appendEventLocked(id, store.BGPEventAnnounced, nil, "vtysh announce succeeded")
	return nil
}

func (r *mockBGPAnnouncementRepo) MarkWithdrawing(_ context.Context, id int) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a := r.findByIDLocked(id); a != nil {
		switch a.Status {
		case "active", "delayed":
			a.Status = "withdrawing"
			return true, nil
		}
	}
	return false, nil
}

func (r *mockBGPAnnouncementRepo) MarkWithdrawn(_ context.Context, id int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a := r.findByIDLocked(id); a != nil {
		a.Status = "withdrawn"
		now := time.Now()
		a.WithdrawnAt = &now
	}
	r.appendEventLocked(id, store.BGPEventWithdrawn, nil, "vtysh withdraw succeeded")
	return nil
}

func (r *mockBGPAnnouncementRepo) MarkFailedAnnounce(_ context.Context, id int, errMsg string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.findByIDLocked(id)
	if a == nil {
		return nil
	}
	if a.Refcount == 1 {
		// safe delete — drop row + attacks + events
		idx := -1
		for i := range r.announcements {
			if r.announcements[i].ID == id {
				idx = i
				break
			}
		}
		if idx >= 0 {
			r.announcements = append(r.announcements[:idx], r.announcements[idx+1:]...)
		}
		// drop related attacks and events (simulating CASCADE)
		var na []store.BGPAnnouncementAttack
		for _, x := range r.attacks {
			if x.AnnouncementID != id {
				na = append(na, x)
			}
		}
		r.attacks = na
		var ne []store.BGPAnnouncementEvent
		for _, x := range r.events {
			if x.AnnouncementID != id {
				ne = append(ne, x)
			}
		}
		r.events = ne
		return nil
	}
	a.Status = "failed"
	a.ErrorMessage = errMsg
	r.appendEventLocked(id, store.BGPEventAnnounceFailed, nil, errMsg)
	return nil
}

func (r *mockBGPAnnouncementRepo) MarkFailedWithdraw(_ context.Context, id int, errMsg string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a := r.findByIDLocked(id); a != nil {
		a.Status = "failed"
		a.ErrorMessage = errMsg
	}
	r.appendEventLocked(id, store.BGPEventWithdrawFailed, nil, errMsg)
	return nil
}

func (r *mockBGPAnnouncementRepo) ForceWithdraw(_ context.Context, id int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.findByIDLocked(id)
	if a == nil || a.Status == "withdrawn" || a.Status == "dismissed" {
		return nil
	}
	a.Status = "withdrawing"
	a.Refcount = 0
	now := time.Now()
	for i := range r.attacks {
		if r.attacks[i].AnnouncementID == id && r.attacks[i].DetachedAt == nil {
			r.attacks[i].DetachedAt = &now
		}
	}
	r.appendEventLocked(id, store.BGPEventAttackDetached, nil, "force withdraw by operator")
	return nil
}

func (r *mockBGPAnnouncementRepo) Dismiss(_ context.Context, id int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a := r.findByIDLocked(id); a != nil && a.Status == "orphan" {
		a.Status = "dismissed"
	}
	r.appendEventLocked(id, store.BGPEventDismissed, nil, "orphan dismissed by operator")
	return nil
}

func (r *mockBGPAnnouncementRepo) Undismiss(_ context.Context, id int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a := r.findByIDLocked(id); a != nil && (a.Status == "dismissed" || a.Status == "dismissed_on_upgrade") {
		a.Status = "orphan"
	}
	r.appendEventLocked(id, store.BGPEventUndismissed, nil, "dismissed orphan re-surfaced by operator")
	return nil
}

func (r *mockBGPAnnouncementRepo) CountByStatus(_ context.Context) (map[string]int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]int)
	for _, a := range r.announcements {
		out[a.Status]++
	}
	return out, nil
}

func (r *mockBGPAnnouncementRepo) HasOperationalHistory(_ context.Context) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.announcements {
		if a.Status != "orphan" && a.Status != "dismissed_on_upgrade" {
			return true, nil
		}
	}
	return false, nil
}

func (r *mockBGPAnnouncementRepo) UpsertOrphan(_ context.Context, prefix, routeMap string, connectorID int, status string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Look up existing business-key match.
	for i := range r.announcements {
		a := &r.announcements[i]
		if a.Prefix == prefix && a.RouteMap == routeMap && a.ConnectorID == connectorID {
			if a.Status == "withdrawn" {
				a.Status = status
				a.Refcount = 0
				r.appendEventLocked(a.ID, store.BGPEventOrphanDetected, nil,
					"bootstrap scan marked "+prefix+" route-map="+routeMap+" as "+status)
				return true, nil
			}
			return false, nil
		}
	}
	// No row — insert.
	r.nextAnnID++
	r.announcements = append(r.announcements, store.BGPAnnouncement{
		ID:          r.nextAnnID,
		Prefix:      prefix,
		RouteMap:    routeMap,
		ConnectorID: connectorID,
		Status:      status,
		Refcount:    0,
	})
	r.appendEventLocked(r.nextAnnID, store.BGPEventOrphanDetected, nil,
		"bootstrap scan marked "+prefix+" route-map="+routeMap+" as "+status)
	return true, nil
}

func (r *mockBGPAnnouncementRepo) ListDismissed(_ context.Context) ([]store.BGPAnnouncement, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.BGPAnnouncement
	for _, a := range r.announcements {
		if a.Status == "dismissed" || a.Status == "dismissed_on_upgrade" {
			out = append(out, a)
		}
	}
	return out, nil
}

func (r *mockBGPAnnouncementRepo) ListActive(_ context.Context) ([]store.BGPAnnouncement, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.BGPAnnouncement
	for _, a := range r.announcements {
		switch a.Status {
		case "announcing", "active", "delayed", "withdrawing", "failed", "orphan":
			out = append(out, a)
		}
	}
	return out, nil
}

func (r *mockBGPAnnouncementRepo) ListByStatus(_ context.Context, status string) ([]store.BGPAnnouncement, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.BGPAnnouncement
	for _, a := range r.announcements {
		if a.Status == status {
			out = append(out, a)
		}
	}
	return out, nil
}

func (r *mockBGPAnnouncementRepo) ListAttacks(_ context.Context, announcementID int) ([]store.BGPAnnouncementAttack, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.BGPAnnouncementAttack
	for _, a := range r.attacks {
		if a.AnnouncementID == announcementID {
			out = append(out, a)
		}
	}
	return out, nil
}

func (r *mockBGPAnnouncementRepo) ListAttachmentsForAttack(_ context.Context, attackID int) ([]store.BGPAnnouncementAttack, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.BGPAnnouncementAttack
	for _, a := range r.attacks {
		if a.AttackID == attackID {
			out = append(out, a)
		}
	}
	return out, nil
}

func (r *mockBGPAnnouncementRepo) AppendEvent(_ context.Context, announcementID int, eventType string, attackID *int, detail string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.appendEventLocked(announcementID, eventType, attackID, detail)
	return nil
}

func (r *mockBGPAnnouncementRepo) ListEvents(_ context.Context, announcementID int) ([]store.BGPAnnouncementEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.BGPAnnouncementEvent
	for _, e := range r.events {
		if e.AnnouncementID == announcementID {
			out = append(out, e)
		}
	}
	return out, nil
}

// ─────────────────────────── Stub repos ───────────────────────────

type stubNodeRepo struct{}

func (stubNodeRepo) List(_ context.Context) ([]store.Node, error)                            { return nil, nil }
func (stubNodeRepo) Get(_ context.Context, _ string) (*store.Node, error)                    { return nil, errors.New("not implemented") }
func (stubNodeRepo) Create(_ context.Context, _ *store.Node) error                           { return nil }
func (stubNodeRepo) Update(_ context.Context, _ *store.Node) error                           { return nil }
func (stubNodeRepo) Delete(_ context.Context, _ string) error                                { return nil }
func (stubNodeRepo) UpdateMode(_ context.Context, _, _ string) error                         { return nil }
func (stubNodeRepo) UpdateDeliveryVersionCurrent(_ context.Context, _ string, _ int64) error { return nil }
func (stubNodeRepo) UpdateACK(_ context.Context, _ string, _ int64) error                    { return nil }

type stubPrefixRepo struct{}

func (stubPrefixRepo) List(_ context.Context) ([]store.WatchPrefix, error)         { return nil, nil }
func (stubPrefixRepo) Count(_ context.Context) (int, error)                        { return 0, nil }
func (stubPrefixRepo) Get(_ context.Context, _ int) (*store.WatchPrefix, error)    { return nil, errors.New("not implemented") }
func (stubPrefixRepo) Create(_ context.Context, _ *store.WatchPrefix) (int, error) { return 0, nil }
func (stubPrefixRepo) Update(_ context.Context, _ *store.WatchPrefix) error        { return nil }
func (stubPrefixRepo) Delete(_ context.Context, _ int) error                       { return nil }
func (stubPrefixRepo) ListTree(_ context.Context) ([]store.WatchPrefix, error)     { return nil, nil }

type stubThresholdTemplateRepo struct{}

func (stubThresholdTemplateRepo) List(_ context.Context) ([]store.ThresholdTemplate, error) {
	return nil, nil
}
func (stubThresholdTemplateRepo) Get(_ context.Context, _ int) (*store.ThresholdTemplate, error) {
	return nil, errors.New("not implemented")
}
func (stubThresholdTemplateRepo) Create(_ context.Context, _ *store.ThresholdTemplate) (int, error) {
	return 0, nil
}
func (stubThresholdTemplateRepo) Update(_ context.Context, _ *store.ThresholdTemplate) error {
	return nil
}
func (stubThresholdTemplateRepo) Delete(_ context.Context, _ int) error { return nil }
func (stubThresholdTemplateRepo) Duplicate(_ context.Context, _ int, _ string) (int, error) {
	return 0, nil
}
func (stubThresholdTemplateRepo) ListRules(_ context.Context, _ int) ([]store.Threshold, error) {
	return nil, nil
}
func (stubThresholdTemplateRepo) ListPrefixesUsing(_ context.Context, _ int) ([]store.WatchPrefix, error) {
	return nil, nil
}

type stubThresholdRepo struct{}

func (stubThresholdRepo) List(_ context.Context) ([]store.Threshold, error)                { return nil, nil }
func (stubThresholdRepo) Count(_ context.Context) (int, error)                             { return 0, nil }
func (stubThresholdRepo) ListByPrefix(_ context.Context, _ int) ([]store.Threshold, error) { return nil, nil }
func (stubThresholdRepo) Get(_ context.Context, _ int) (*store.Threshold, error)           { return nil, errors.New("not implemented") }
func (stubThresholdRepo) Create(_ context.Context, _ *store.Threshold) (int, error)        { return 0, nil }
func (stubThresholdRepo) Update(_ context.Context, _ *store.Threshold) error               { return nil }
func (stubThresholdRepo) Delete(_ context.Context, _ int) error                            { return nil }

type stubUserRepo struct{}

func (stubUserRepo) List(_ context.Context) ([]store.User, error)                   { return nil, nil }
func (stubUserRepo) Get(_ context.Context, _ int) (*store.User, error)              { return nil, errors.New("not implemented") }
func (stubUserRepo) GetByUsername(_ context.Context, _ string) (*store.User, error) { return nil, errors.New("not implemented") }
func (stubUserRepo) Create(_ context.Context, _ *store.User) (int, error)           { return 0, nil }
func (stubUserRepo) Update(_ context.Context, _ *store.User) error                  { return nil }
func (stubUserRepo) Delete(_ context.Context, _ int) error                          { return nil }

type stubWebhookRepo struct{}

func (stubWebhookRepo) List(_ context.Context) ([]store.Webhook, error)          { return nil, nil }
func (stubWebhookRepo) Get(_ context.Context, _ int) (*store.Webhook, error)     { return nil, errors.New("not implemented") }
func (stubWebhookRepo) Create(_ context.Context, _ *store.Webhook) (int, error)  { return 0, nil }
func (stubWebhookRepo) Update(_ context.Context, _ *store.Webhook) error         { return nil }
func (stubWebhookRepo) Delete(_ context.Context, _ int) error                    { return nil }

type stubAuditLogRepo struct{}

func (stubAuditLogRepo) Create(_ context.Context, _ *store.AuditLog) error { return nil }
func (stubAuditLogRepo) List(_ context.Context, _ store.AuditFilter) ([]store.AuditLog, error) {
	return nil, nil
}

type stubStatsRepo struct{}

func (stubStatsRepo) BulkInsert(_ context.Context, _ []store.StatPoint) error { return nil }
func (stubStatsRepo) QueryTimeseries(_ context.Context, _ store.TimeseriesFilter) ([]store.TimeseriesPoint, error) {
	return nil, nil
}
func (stubStatsRepo) QueryTotalTimeseries(_ context.Context, _ store.TimeseriesFilter) ([]store.TimeseriesPoint, error) {
	return nil, nil
}
func (stubStatsRepo) QueryHourP95(_ context.Context, _, _ time.Time, _ int) ([]store.P95Result, error) {
	return nil, nil
}
func (stubStatsRepo) QueryWindowP95(_ context.Context, _ time.Time, _ time.Duration, _ int) ([]store.P95Result, error) {
	return nil, nil
}

type stubDynDetectRepo struct{}

func (stubDynDetectRepo) GetConfig(_ context.Context) (*store.DynDetectConfig, error) {
	return &store.DynDetectConfig{}, nil
}
func (stubDynDetectRepo) UpdateConfig(_ context.Context, _ *store.DynDetectConfig) error { return nil }
func (stubDynDetectRepo) ListProfiles(_ context.Context, _ int) ([]store.PrefixProfile, error) {
	return nil, nil
}
func (stubDynDetectRepo) UpsertProfile(_ context.Context, _ *store.PrefixProfile) error { return nil }
func (stubDynDetectRepo) BulkUpsertProfiles(_ context.Context, _ []store.PrefixProfile) error {
	return nil
}
func (stubDynDetectRepo) DeleteAllProfiles(_ context.Context) error { return nil }

type stubWebhookConnectorRepo struct{}

func (stubWebhookConnectorRepo) List(_ context.Context) ([]store.WebhookConnector, error) {
	return nil, nil
}
func (stubWebhookConnectorRepo) ListGlobal(_ context.Context) ([]store.WebhookConnector, error) {
	return nil, nil
}
func (stubWebhookConnectorRepo) Get(_ context.Context, _ int) (*store.WebhookConnector, error) {
	return nil, errors.New("not implemented")
}
func (stubWebhookConnectorRepo) Create(_ context.Context, _ *store.WebhookConnector) (int, error) {
	return 0, nil
}
func (stubWebhookConnectorRepo) Update(_ context.Context, _ *store.WebhookConnector) error {
	return nil
}
func (stubWebhookConnectorRepo) Delete(_ context.Context, _ int) error { return nil }

type stubShellConnectorRepo struct{}

func (stubShellConnectorRepo) List(_ context.Context) ([]store.ShellConnector, error)          { return nil, nil }
func (stubShellConnectorRepo) Get(_ context.Context, _ int) (*store.ShellConnector, error)     { return nil, errors.New("not implemented") }
func (stubShellConnectorRepo) Create(_ context.Context, _ *store.ShellConnector) (int, error)  { return 0, nil }
func (stubShellConnectorRepo) Update(_ context.Context, _ *store.ShellConnector) error         { return nil }
func (stubShellConnectorRepo) Delete(_ context.Context, _ int) error                           { return nil }

type stubFlowLogRepo struct{}

func (stubFlowLogRepo) BulkInsert(_ context.Context, _ []store.FlowLog) error { return nil }
func (stubFlowLogRepo) QueryByDstIP(_ context.Context, _ store.FlowLogFilter) ([]store.FlowLog, error) {
	return nil, nil
}
func (stubFlowLogRepo) QueryBySrcIP(_ context.Context, _ store.FlowLogFilter) ([]store.FlowLog, error) {
	return nil, nil
}

type stubFlowListenerRepo struct{}

func (stubFlowListenerRepo) List(_ context.Context, _ string) ([]store.FlowListener, error)      { return nil, nil }
func (stubFlowListenerRepo) Get(_ context.Context, _ int) (*store.FlowListener, error)           { return nil, errors.New("not implemented") }
func (stubFlowListenerRepo) Create(_ context.Context, _ *store.FlowListener) (int, error)        { return 0, nil }
func (stubFlowListenerRepo) Update(_ context.Context, _ *store.FlowListener) error               { return nil }
func (stubFlowListenerRepo) Delete(_ context.Context, _ int) error                               { return nil }

type stubFlowSourceRepo struct{}

func (stubFlowSourceRepo) List(_ context.Context, _ int) ([]store.FlowSource, error)      { return nil, nil }
func (stubFlowSourceRepo) Get(_ context.Context, _ int) (*store.FlowSource, error)        { return nil, errors.New("not implemented") }
func (stubFlowSourceRepo) Create(_ context.Context, _ *store.FlowSource) (int, error)     { return 0, nil }
func (stubFlowSourceRepo) Update(_ context.Context, _ *store.FlowSource) error            { return nil }
func (stubFlowSourceRepo) Delete(_ context.Context, _ int) error                          { return nil }
