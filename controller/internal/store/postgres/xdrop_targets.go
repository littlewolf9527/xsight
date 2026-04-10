package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type xdropTargetRepo struct{ pool *pgxpool.Pool }

func (r *xdropTargetRepo) List(ctx context.Context, actionID int) ([]store.XDropConnector, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT c.id, c.name, c.api_url, c.api_key, c.timeout_ms, c.enabled, c.created_at, c.updated_at
		 FROM xdrop_connectors c
		 JOIN response_action_xdrop_targets t ON t.connector_id = c.id
		 WHERE t.action_id = $1
		 ORDER BY c.id`, actionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []store.XDropConnector
	for rows.Next() {
		var c store.XDropConnector
		if err := rows.Scan(&c.ID, &c.Name, &c.APIURL, &c.APIKey,
			&c.TimeoutMs, &c.Enabled, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, rows.Err()
}

func (r *xdropTargetRepo) Set(ctx context.Context, actionID int, connectorIDs []int) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("xdrop_targets begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Delete existing mappings
	if _, err := tx.Exec(ctx,
		`DELETE FROM response_action_xdrop_targets WHERE action_id = $1`, actionID); err != nil {
		return fmt.Errorf("xdrop_targets delete: %w", err)
	}

	// Insert new mappings
	for _, cid := range connectorIDs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO response_action_xdrop_targets (action_id, connector_id) VALUES ($1, $2)`,
			actionID, cid); err != nil {
			return fmt.Errorf("xdrop_targets insert action=%d connector=%d: %w", actionID, cid, err)
		}
	}

	return tx.Commit(ctx)
}

func (r *xdropTargetRepo) CountByConnector(ctx context.Context, connectorID int) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM response_action_xdrop_targets WHERE connector_id = $1`, connectorID).Scan(&count)
	return count, err
}
