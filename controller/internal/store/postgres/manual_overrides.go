package postgres

// v1.2 PR-2: action_manual_overrides repo — O(1) lookup that replaces the
// linear scan of action_execution_log used in v1.1 bgp.go / xdrop.go.
//
// The UNIQUE (attack_id, action_id, connector_id, external_rule_id) index
// on the table provides O(1) existence checks. connector_id is NOT NULL at
// the schema level so the UNIQUE constraint actually deduplicates — NULL
// would be treated as distinct by PostgreSQL and break the semantics.

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type manualOverrideRepo struct{ pool *pgxpool.Pool }

// Create inserts an override row. Idempotent: ON CONFLICT returns the
// existing row's ID, so repeated Force Remove calls against the same artifact
// do not fail.
func (r *manualOverrideRepo) Create(ctx context.Context, o *store.ActionManualOverride) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO action_manual_overrides
		 (attack_id, action_id, connector_id, external_rule_id, created_by)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (attack_id, action_id, connector_id, external_rule_id)
		 DO UPDATE SET created_by = EXCLUDED.created_by
		 RETURNING id`,
		o.AttackID, o.ActionID, o.ConnectorID, o.ExternalRuleID, o.CreatedBy).
		Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert manual_override (attack=%d action=%d conn=%d rule=%q): %w",
			o.AttackID, o.ActionID, o.ConnectorID, o.ExternalRuleID, err)
	}
	return id, nil
}

// Exists is the hot-path lookup used by every bgp.go / xdrop.go artifact
// iteration. O(1) via the UNIQUE index.
func (r *manualOverrideRepo) Exists(ctx context.Context, attackID, actionID, connectorID int, externalRuleID string) (bool, error) {
	var one int
	err := r.pool.QueryRow(ctx,
		`SELECT 1 FROM action_manual_overrides
		 WHERE attack_id=$1 AND action_id=$2 AND connector_id=$3 AND external_rule_id=$4
		 LIMIT 1`,
		attackID, actionID, connectorID, externalRuleID).Scan(&one)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("lookup manual_override (attack=%d action=%d conn=%d rule=%q): %w",
			attackID, actionID, connectorID, externalRuleID, err)
	}
	return true, nil
}

// ListByAttack returns all overrides for an attack. Callers that iterate many
// artifacts (e.g. xDrop unblocking 5000+ rules) should fetch once with this
// and build a local set, instead of calling Exists() N times.
func (r *manualOverrideRepo) ListByAttack(ctx context.Context, attackID int) ([]store.ActionManualOverride, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, attack_id, action_id, connector_id, external_rule_id, created_at, COALESCE(created_by, '')
		 FROM action_manual_overrides
		 WHERE attack_id=$1
		 ORDER BY created_at DESC`, attackID)
	if err != nil {
		return nil, fmt.Errorf("list manual_overrides attack=%d: %w", attackID, err)
	}
	defer rows.Close()
	var out []store.ActionManualOverride
	for rows.Next() {
		var o store.ActionManualOverride
		if err := rows.Scan(&o.ID, &o.AttackID, &o.ActionID, &o.ConnectorID,
			&o.ExternalRuleID, &o.CreatedAt, &o.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
