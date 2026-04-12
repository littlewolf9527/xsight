package tests

import (
	"context"
	"errors"
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
		actionsLog:      &mockActionsLogRepo{},
		preconditions:   &mockPreconditionRepo{},
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
func (m *MockStore) Close()                                         {}

// ─────────────────────────── mockResponseRepo ───────────────────────────

// mockResponseRepo stores actions as a slice so test files can seed fixture
// actions via append (e.g. ms.responseRepo.actions = append(...)).
// All interface methods do linear scans — acceptable for test volumes.
type mockResponseRepo struct {
	mu      sync.Mutex
	actions []store.ResponseAction // slice — supports direct append by tests
	nextID  int
}

func (r *mockResponseRepo) List(_ context.Context) ([]store.Response, error) { return nil, nil }
func (r *mockResponseRepo) Get(_ context.Context, _ int) (*store.Response, error) {
	return nil, errors.New("not implemented")
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

type mockPreconditionRepo struct{}

func (r *mockPreconditionRepo) List(_ context.Context, _ int) ([]store.ActionPrecondition, error) {
	return nil, nil
}
func (r *mockPreconditionRepo) Create(_ context.Context, _ *store.ActionPrecondition) (int, error) {
	return 0, nil
}
func (r *mockPreconditionRepo) Delete(_ context.Context, _ int) error         { return nil }
func (r *mockPreconditionRepo) DeleteByAction(_ context.Context, _ int) error  { return nil }
func (r *mockPreconditionRepo) ReplaceAll(_ context.Context, _ int, _ []store.ActionPrecondition) error {
	return nil
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
