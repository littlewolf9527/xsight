package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type preconditionRepo struct{ pool *pgxpool.Pool }

func (r *preconditionRepo) List(ctx context.Context, actionID int) ([]store.ActionPrecondition, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, action_id, attribute, operator, value, created_at
		 FROM action_preconditions WHERE action_id=$1 ORDER BY id`, actionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []store.ActionPrecondition
	for rows.Next() {
		var p store.ActionPrecondition
		if err := rows.Scan(&p.ID, &p.ActionID, &p.Attribute, &p.Operator, &p.Value, &p.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, p)
	}
	return list, rows.Err()
}

func (r *preconditionRepo) Create(ctx context.Context, p *store.ActionPrecondition) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO action_preconditions (action_id, attribute, operator, value)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		p.ActionID, p.Attribute, p.Operator, p.Value).Scan(&id)
	return id, err
}

func (r *preconditionRepo) Delete(ctx context.Context, id int) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM action_preconditions WHERE id=$1`, id)
	return err
}

func (r *preconditionRepo) DeleteByAction(ctx context.Context, actionID int) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM action_preconditions WHERE action_id=$1`, actionID)
	return err
}

func (r *preconditionRepo) ReplaceAll(ctx context.Context, actionID int, preconditions []store.ActionPrecondition) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `DELETE FROM action_preconditions WHERE action_id=$1`, actionID)
	if err != nil {
		return err
	}

	for _, p := range preconditions {
		_, err = tx.Exec(ctx,
			`INSERT INTO action_preconditions (action_id, attribute, operator, value)
			 VALUES ($1, $2, $3, $4)`, actionID, p.Attribute, p.Operator, p.Value)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}
