package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type actionExecLogRepo struct{ pool *pgxpool.Pool }

func (r *actionExecLogRepo) Create(ctx context.Context, l *store.ActionExecutionLog) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO action_execution_log
		 (attack_id, action_id, response_name, action_type, connector_name, trigger_phase,
		  status, status_code, error_message, request_body, response_body, external_rule_id,
		  connector_id, duration_ms, scheduled_for)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) RETURNING id`,
		l.AttackID, l.ActionID, l.ResponseName, l.ActionType, l.ConnectorName, l.TriggerPhase,
		l.Status, l.StatusCode, l.ErrorMessage, l.RequestBody, l.ResponseBody, l.ExternalRuleID,
		l.ConnectorID, l.DurationMs, l.ScheduledFor).
		Scan(&id)
	return id, err
}

func (r *actionExecLogRepo) ListByAttack(ctx context.Context, attackID int) ([]store.ActionExecutionLog, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, attack_id, action_id, response_name, action_type, connector_name, trigger_phase,
		        status, status_code, error_message, request_body, response_body, external_rule_id,
		        connector_id, duration_ms, executed_at, scheduled_for
		 FROM action_execution_log
		 WHERE attack_id=$1 ORDER BY executed_at DESC`, attackID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []store.ActionExecutionLog
	for rows.Next() {
		var l store.ActionExecutionLog
		if err := rows.Scan(&l.ID, &l.AttackID, &l.ActionID, &l.ResponseName, &l.ActionType,
			&l.ConnectorName, &l.TriggerPhase, &l.Status, &l.StatusCode, &l.ErrorMessage,
			&l.RequestBody, &l.ResponseBody, &l.ExternalRuleID, &l.ConnectorID, &l.DurationMs, &l.ExecutedAt, &l.ScheduledFor); err != nil {
			return nil, err
		}
		list = append(list, l)
	}
	return list, rows.Err()
}

func (r *actionExecLogRepo) FindByAttackAndAction(ctx context.Context, attackID, actionID int, triggerPhase string) (*store.ActionExecutionLog, error) {
	var l store.ActionExecutionLog
	err := r.pool.QueryRow(ctx,
		`SELECT id, attack_id, action_id, response_name, action_type, connector_name, trigger_phase,
		        status, status_code, error_message, request_body, response_body, external_rule_id,
		        connector_id, duration_ms, executed_at, scheduled_for
		 FROM action_execution_log
		 WHERE attack_id=$1 AND action_id=$2 AND trigger_phase=$3
		 ORDER BY executed_at DESC LIMIT 1`, attackID, actionID, triggerPhase).
		Scan(&l.ID, &l.AttackID, &l.ActionID, &l.ResponseName, &l.ActionType,
			&l.ConnectorName, &l.TriggerPhase, &l.Status, &l.StatusCode, &l.ErrorMessage,
			&l.RequestBody, &l.ResponseBody, &l.ExternalRuleID, &l.ConnectorID, &l.DurationMs, &l.ExecutedAt, &l.ScheduledFor)
	if err != nil {
		return nil, fmt.Errorf("action_execution_log attack=%d action=%d phase=%s: %w", attackID, actionID, triggerPhase, err)
	}
	return &l, nil
}

// FindExternalRulesWithActions returns all (external_rule_id, action_id, connector_id) for a given attack.
// Used by unblock to delete rules only on the connector that originally created them.
func (r *actionExecLogRepo) FindExternalRulesWithActions(ctx context.Context, attackID int) ([]store.RuleWithAction, error) {
	query := `SELECT DISTINCT external_rule_id, action_id, COALESCE(connector_id, 0)
		 FROM action_execution_log
		 WHERE attack_id=$1 AND action_type='xdrop' AND external_rule_id != '' AND status='success'`
	rows, err := r.pool.Query(ctx, query, attackID)
	if err != nil {
		return nil, fmt.Errorf("find external_rules attack=%d: %w", attackID, err)
	}
	defer rows.Close()
	var results []store.RuleWithAction
	for rows.Next() {
		var r store.RuleWithAction
		if err := rows.Scan(&r.RuleID, &r.ActionID, &r.ConnectorID); err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

// FindExternalRuleIDs returns all distinct external_rule_ids for a given attack.
// When actionID > 0, scopes to that specific action; when 0, returns all xdrop rules.
// Used by unblock to delete ALL rules created during an attack.
func (r *actionExecLogRepo) FindExternalRuleIDs(ctx context.Context, attackID, actionID int) ([]string, error) {
	var query string
	var args []any
	if actionID > 0 {
		query = `SELECT DISTINCT external_rule_id FROM action_execution_log
			 WHERE attack_id=$1 AND action_id=$2 AND external_rule_id != '' AND status='success'`
		args = []any{attackID, actionID}
	} else {
		query = `SELECT DISTINCT external_rule_id FROM action_execution_log
			 WHERE attack_id=$1 AND action_type='xdrop' AND external_rule_id != '' AND status='success'`
		args = []any{attackID}
	}
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("find external_rule_ids attack=%d action=%d: %w", attackID, actionID, err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
