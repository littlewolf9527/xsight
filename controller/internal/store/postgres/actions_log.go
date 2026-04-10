package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type actionsLogRepo struct{ pool *pgxpool.Pool }

func (r *actionsLogRepo) Create(ctx context.Context, l *store.ActionLog) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO actions_log (attack_id, action_id, execution_policy, status,
								  external_id, first_attempt_at, last_attempt_at,
								  last_result, retry_count)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
		l.AttackID, l.ActionID, l.ExecutionPolicy, l.Status,
		l.ExternalID, l.FirstAttemptAt, l.LastAttemptAt,
		l.LastResult, l.RetryCount).Scan(&id)
	return id, err
}

func (r *actionsLogRepo) Update(ctx context.Context, l *store.ActionLog) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE actions_log SET status=$1, external_id=$2, last_attempt_at=$3,
							   last_result=$4, retry_count=$5
		 WHERE id=$6`,
		l.Status, l.ExternalID, l.LastAttemptAt,
		l.LastResult, l.RetryCount, l.ID)
	return err
}

func (r *actionsLogRepo) FindByAttackAndAction(ctx context.Context, attackID, actionID int) (*store.ActionLog, error) {
	var l store.ActionLog
	err := r.pool.QueryRow(ctx,
		`SELECT id, attack_id, action_id, execution_policy, status,
				external_id, first_attempt_at, last_attempt_at,
				last_result, retry_count, created_at
		 FROM actions_log WHERE attack_id=$1 AND action_id=$2
		 ORDER BY created_at DESC LIMIT 1`, attackID, actionID).
		Scan(&l.ID, &l.AttackID, &l.ActionID, &l.ExecutionPolicy, &l.Status,
			&l.ExternalID, &l.FirstAttemptAt, &l.LastAttemptAt,
			&l.LastResult, &l.RetryCount, &l.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("actions_log attack=%d action=%d: %w", attackID, actionID, err)
	}
	return &l, nil
}

func (r *actionsLogRepo) ListByAttack(ctx context.Context, attackID int) ([]store.ActionLog, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, attack_id, action_id, execution_policy, status,
				external_id, first_attempt_at, last_attempt_at,
				last_result, retry_count, created_at
		 FROM actions_log WHERE attack_id=$1 ORDER BY created_at`, attackID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []store.ActionLog
	for rows.Next() {
		var l store.ActionLog
		if err := rows.Scan(&l.ID, &l.AttackID, &l.ActionID, &l.ExecutionPolicy, &l.Status,
			&l.ExternalID, &l.FirstAttemptAt, &l.LastAttemptAt,
			&l.LastResult, &l.RetryCount, &l.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, l)
	}
	return list, rows.Err()
}
