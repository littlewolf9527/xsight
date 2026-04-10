package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type nodeRepo struct{ pool *pgxpool.Pool }

func (r *nodeRepo) List(ctx context.Context) ([]store.Node, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, api_key, description, mode, enabled,
				delivery_version_current, delivery_version_applied,
				config_status, last_ack_at, created_at, updated_at
		 FROM nodes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []store.Node
	for rows.Next() {
		var n store.Node
		if err := rows.Scan(&n.ID, &n.APIKey, &n.Description, &n.Mode, &n.Enabled,
			&n.DeliveryVersionCurrent, &n.DeliveryVersionApplied,
			&n.ConfigStatus, &n.LastACKAt, &n.CreatedAt, &n.UpdatedAt); err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}

func (r *nodeRepo) Get(ctx context.Context, id string) (*store.Node, error) {
	var n store.Node
	err := r.pool.QueryRow(ctx,
		`SELECT id, api_key, description, mode, enabled,
				delivery_version_current, delivery_version_applied,
				config_status, last_ack_at, created_at, updated_at
		 FROM nodes WHERE id = $1`, id).
		Scan(&n.ID, &n.APIKey, &n.Description, &n.Mode, &n.Enabled,
			&n.DeliveryVersionCurrent, &n.DeliveryVersionApplied,
			&n.ConfigStatus, &n.LastACKAt, &n.CreatedAt, &n.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("node %q: %w", id, err)
	}
	return &n, nil
}

func (r *nodeRepo) Create(ctx context.Context, n *store.Node) error {
	mode := n.Mode
	if mode == "" {
		mode = "xdp"
	}
	_, err := r.pool.Exec(ctx,
		`INSERT INTO nodes (id, api_key, description, mode, enabled)
		 VALUES ($1, $2, $3, $4, $5)`,
		n.ID, n.APIKey, n.Description, mode, n.Enabled)
	return err
}

func (r *nodeRepo) Update(ctx context.Context, n *store.Node) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE nodes SET description=$1, mode=$2, enabled=$3, updated_at=now()
		 WHERE id=$4`,
		n.Description, n.Mode, n.Enabled, n.ID)
	return err
}

func (r *nodeRepo) Delete(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM nodes WHERE id=$1`, id)
	return err
}

func (r *nodeRepo) UpdateMode(ctx context.Context, id, mode string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE nodes SET mode=$1, updated_at=now() WHERE id=$2`,
		mode, id)
	return err
}

func (r *nodeRepo) UpdateDeliveryVersionCurrent(ctx context.Context, id string, version int64) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE nodes SET delivery_version_current=$1, config_status='pending', updated_at=now()
		 WHERE id=$2`,
		version, id)
	return err
}

func (r *nodeRepo) UpdateACK(ctx context.Context, id string, versionApplied int64) error {
	now := time.Now()
	_, err := r.pool.Exec(ctx,
		`UPDATE nodes SET delivery_version_applied=$1, config_status='synced',
		 last_ack_at=$2, updated_at=$2
		 WHERE id=$3`,
		versionApplied, now, id)
	return err
}
