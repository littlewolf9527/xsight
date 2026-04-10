package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type xdropConnectorRepo struct{ pool *pgxpool.Pool }

func (r *xdropConnectorRepo) List(ctx context.Context) ([]store.XDropConnector, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, name, api_url, api_key, timeout_ms, enabled, created_at, updated_at
		 FROM xdrop_connectors ORDER BY id`)
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

func (r *xdropConnectorRepo) ListEnabled(ctx context.Context) ([]store.XDropConnector, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, name, api_url, api_key, timeout_ms, enabled, created_at, updated_at
		 FROM xdrop_connectors WHERE enabled = true ORDER BY id`)
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

func (r *xdropConnectorRepo) Get(ctx context.Context, id int) (*store.XDropConnector, error) {
	var c store.XDropConnector
	err := r.pool.QueryRow(ctx,
		`SELECT id, name, api_url, api_key, timeout_ms, enabled, created_at, updated_at
		 FROM xdrop_connectors WHERE id=$1`, id).
		Scan(&c.ID, &c.Name, &c.APIURL, &c.APIKey,
			&c.TimeoutMs, &c.Enabled, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("xdrop_connector %d: %w", id, err)
	}
	return &c, nil
}

func (r *xdropConnectorRepo) Create(ctx context.Context, c *store.XDropConnector) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO xdrop_connectors (name, api_url, api_key, timeout_ms, enabled)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		c.Name, c.APIURL, c.APIKey, c.TimeoutMs, c.Enabled).Scan(&id)
	return id, err
}

func (r *xdropConnectorRepo) Update(ctx context.Context, c *store.XDropConnector) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE xdrop_connectors
		 SET name=$1, api_url=$2, api_key=$3, timeout_ms=$4, enabled=$5, updated_at=now()
		 WHERE id=$6`,
		c.Name, c.APIURL, c.APIKey, c.TimeoutMs, c.Enabled, c.ID)
	return err
}

func (r *xdropConnectorRepo) Delete(ctx context.Context, id int) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM xdrop_connectors WHERE id=$1`, id)
	return err
}
