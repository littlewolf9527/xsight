package postgres

// v1.2 PR-3: scheduled_actions repo — persists pending delayed actions so
// the controller can re-arm timers across restarts. The in-memory
// pendingDelay map in engine.go continues to provide the hot-path cancel
// mechanism; this table is the durable source of truth.

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type scheduledActionRepo struct{ pool *pgxpool.Pool }

// Schedule inserts a new pending row or, if one already exists for the same
// business key in pending status, returns the existing ID. The partial
// UNIQUE index on (action_type, attack_id, action_id, connector_id,
// external_rule_id) WHERE status='pending' enforces the uniqueness.
func (r *scheduledActionRepo) Schedule(ctx context.Context, a *store.ScheduledAction) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO scheduled_actions
		 (action_type, attack_id, action_id, connector_id, external_rule_id,
		  announcement_id, scheduled_for, status)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')
		 ON CONFLICT (action_type, attack_id, action_id, connector_id, external_rule_id)
		   WHERE status = 'pending'
		 DO UPDATE SET scheduled_for = EXCLUDED.scheduled_for
		 RETURNING id`,
		a.ActionType, a.AttackID, a.ActionID, a.ConnectorID, a.ExternalRuleID,
		a.AnnouncementID, a.ScheduledFor).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("schedule %s attack=%d action=%d conn=%d rule=%q: %w",
			a.ActionType, a.AttackID, a.ActionID, a.ConnectorID, a.ExternalRuleID, err)
	}
	return id, nil
}

// Cancel transitions a pending row to cancelled. Idempotent — rows already in
// a terminal state (completed, cancelled, failed) are left untouched.
func (r *scheduledActionRepo) Cancel(ctx context.Context, id int, reason string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE scheduled_actions
		 SET status='cancelled', cancel_reason=$2, completed_at=now()
		 WHERE id=$1 AND status='pending'`,
		id, reason)
	if err != nil {
		return fmt.Errorf("cancel scheduled_action id=%d: %w", id, err)
	}
	return nil
}

func (r *scheduledActionRepo) CancelByBusinessKey(ctx context.Context, actionType string, attackID, actionID, connectorID int, externalRuleID, reason string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE scheduled_actions
		 SET status='cancelled', cancel_reason=$6, completed_at=now()
		 WHERE status='pending'
		   AND action_type=$1 AND attack_id=$2 AND action_id=$3
		   AND connector_id=$4 AND external_rule_id=$5`,
		actionType, attackID, actionID, connectorID, externalRuleID, reason)
	if err != nil {
		return fmt.Errorf("cancel by key: %w", err)
	}
	return nil
}

// CancelAllForAttack returns the number of rows cancelled, for logging.
func (r *scheduledActionRepo) CancelAllForAttack(ctx context.Context, attackID int, reason string) (int, error) {
	tag, err := r.pool.Exec(ctx,
		`UPDATE scheduled_actions
		 SET status='cancelled', cancel_reason=$2, completed_at=now()
		 WHERE status='pending' AND attack_id=$1`,
		attackID, reason)
	if err != nil {
		return 0, fmt.Errorf("cancel all attack=%d: %w", attackID, err)
	}
	return int(tag.RowsAffected()), nil
}

// MarkExecuting transitions pending → executing. Only succeeds if the row is
// currently pending — prevents two concurrent goroutines (e.g. recovery racing
// normal dispatch) from both running the same task. Returns an error if the
// row is not pending (expected; the other goroutine got there first).
func (r *scheduledActionRepo) MarkExecuting(ctx context.Context, id int) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE scheduled_actions SET status='executing' WHERE id=$1 AND status='pending'`,
		id)
	if err != nil {
		return fmt.Errorf("mark executing %d: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("scheduled_action %d no longer pending", id)
	}
	return nil
}

func (r *scheduledActionRepo) Complete(ctx context.Context, id int) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE scheduled_actions SET status='completed', completed_at=now() WHERE id=$1`,
		id)
	if err != nil {
		return fmt.Errorf("complete %d: %w", id, err)
	}
	return nil
}

func (r *scheduledActionRepo) Fail(ctx context.Context, id int, errMsg string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE scheduled_actions
		 SET status='failed', error_message=$2, completed_at=now()
		 WHERE id=$1`,
		id, errMsg)
	if err != nil {
		return fmt.Errorf("fail %d: %w", id, err)
	}
	return nil
}

func (r *scheduledActionRepo) ListPending(ctx context.Context) ([]store.ScheduledAction, error) {
	return r.listByStatus(ctx, "pending")
}

// ListExecuting returns rows stuck in 'executing' — used by PR-4
// reconciliation to retry side effects that crashed before completion.
func (r *scheduledActionRepo) ListExecuting(ctx context.Context) ([]store.ScheduledAction, error) {
	return r.listByStatus(ctx, "executing")
}

// CountByStatus returns status → row count for all scheduled_actions.
// Used by the Prometheus xsight_scheduled_actions gauge collector.
func (r *scheduledActionRepo) CountByStatus(ctx context.Context) (map[string]int, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT status, COUNT(*) FROM scheduled_actions GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int)
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		out[status] = n
	}
	return out, rows.Err()
}

func (r *scheduledActionRepo) listByStatus(ctx context.Context, status string) ([]store.ScheduledAction, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, action_type, attack_id, action_id, connector_id, external_rule_id,
		        announcement_id, scheduled_for, status,
		        COALESCE(cancel_reason, ''), COALESCE(error_message, ''),
		        created_at, completed_at
		 FROM scheduled_actions
		 WHERE status = $1
		 ORDER BY scheduled_for ASC`, status)
	if err != nil {
		return nil, fmt.Errorf("list scheduled_actions status=%s: %w", status, err)
	}
	defer rows.Close()
	var out []store.ScheduledAction
	for rows.Next() {
		var a store.ScheduledAction
		if err := rows.Scan(&a.ID, &a.ActionType, &a.AttackID, &a.ActionID,
			&a.ConnectorID, &a.ExternalRuleID, &a.AnnouncementID, &a.ScheduledFor,
			&a.Status, &a.CancelReason, &a.ErrorMessage,
			&a.CreatedAt, &a.CompletedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
