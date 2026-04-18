package metrics

// ActionExecLogRecorder wraps an ActionExecLogRepo and increments the
// xsight_action_executions_total counter on every Create call. This is the
// single instrumentation point for action-engine outcomes — every code
// path that writes to action_execution_log goes through
// Store.ActionExecLog().Create, so installing this wrapper makes the
// counter track the DB with zero per-call-site edits.
//
// Install pattern (in main.go):
//
//	db := postgres.NewPGStore(pool)
//	db = metrics.InstrumentStore(db)
//
// Tests that don't want metrics instrumentation just skip the wrap.

import (
	"context"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// actionExecLogRecorder is the actual wrapper. Exported types live in the
// InstrumentStore / WrapActionExecLog functions.
type actionExecLogRecorder struct {
	inner store.ActionExecLogRepo
}

// WrapActionExecLog returns a Create-instrumented wrapper around the
// provided repo. All other interface methods are simple pass-throughs.
func WrapActionExecLog(inner store.ActionExecLogRepo) store.ActionExecLogRepo {
	return &actionExecLogRecorder{inner: inner}
}

func (r *actionExecLogRecorder) Create(ctx context.Context, l *store.ActionExecutionLog) (int, error) {
	id, err := r.inner.Create(ctx, l)
	// Record regardless of DB error — the action itself already ran; the
	// log write is a side effect. Gating on err would under-count runs
	// during DB transient failures, which is exactly when observability
	// matters most.
	RecordAction(l.ActionType, l.Status)
	return id, err
}

func (r *actionExecLogRecorder) ListByAttack(ctx context.Context, attackID int) ([]store.ActionExecutionLog, error) {
	return r.inner.ListByAttack(ctx, attackID)
}

func (r *actionExecLogRecorder) FindByAttackAndAction(ctx context.Context, attackID, actionID int, triggerPhase string) (*store.ActionExecutionLog, error) {
	return r.inner.FindByAttackAndAction(ctx, attackID, actionID, triggerPhase)
}

func (r *actionExecLogRecorder) FindExternalRuleIDs(ctx context.Context, attackID, actionID int) ([]string, error) {
	return r.inner.FindExternalRuleIDs(ctx, attackID, actionID)
}

func (r *actionExecLogRecorder) FindExternalRulesWithActions(ctx context.Context, attackID int) ([]store.RuleWithAction, error) {
	return r.inner.FindExternalRulesWithActions(ctx, attackID)
}

// instrumentedStore embeds a store.Store and overrides only ActionExecLog()
// to return the wrapped repo. Every other repo is returned unchanged.
type instrumentedStore struct {
	store.Store
	actionExecLog store.ActionExecLogRepo
}

func (s *instrumentedStore) ActionExecLog() store.ActionExecLogRepo { return s.actionExecLog }

// InstrumentStore wraps a Store so that ActionExecLog writes are instrumented
// with the xsight_action_executions_total counter. All other repos pass
// through unchanged (embedding). Call once at startup, before handing the
// store to anything that dispatches actions.
func InstrumentStore(s store.Store) store.Store {
	return &instrumentedStore{
		Store:         s,
		actionExecLog: WrapActionExecLog(s.ActionExecLog()),
	}
}
