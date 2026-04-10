package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type webhookConnectorRepo struct{ pool *pgxpool.Pool }

func (r *webhookConnectorRepo) List(ctx context.Context) ([]store.WebhookConnector, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, name, url, method, headers, timeout_ms, global, enabled, created_at, updated_at
		 FROM webhook_connectors ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []store.WebhookConnector
	for rows.Next() {
		var c store.WebhookConnector
		if err := rows.Scan(&c.ID, &c.Name, &c.URL, &c.Method, &c.Headers,
			&c.TimeoutMs, &c.Global, &c.Enabled, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, rows.Err()
}

func (r *webhookConnectorRepo) ListGlobal(ctx context.Context) ([]store.WebhookConnector, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, name, url, method, headers, timeout_ms, global, enabled, created_at, updated_at
		 FROM webhook_connectors WHERE global = true AND enabled = true ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []store.WebhookConnector
	for rows.Next() {
		var c store.WebhookConnector
		if err := rows.Scan(&c.ID, &c.Name, &c.URL, &c.Method, &c.Headers,
			&c.TimeoutMs, &c.Global, &c.Enabled, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, rows.Err()
}

func (r *webhookConnectorRepo) Get(ctx context.Context, id int) (*store.WebhookConnector, error) {
	var c store.WebhookConnector
	err := r.pool.QueryRow(ctx,
		`SELECT id, name, url, method, headers, timeout_ms, global, enabled, created_at, updated_at
		 FROM webhook_connectors WHERE id=$1`, id).
		Scan(&c.ID, &c.Name, &c.URL, &c.Method, &c.Headers,
			&c.TimeoutMs, &c.Global, &c.Enabled, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("webhook_connector %d: %w", id, err)
	}
	return &c, nil
}

func (r *webhookConnectorRepo) Create(ctx context.Context, c *store.WebhookConnector) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO webhook_connectors (name, url, method, headers, timeout_ms, global, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		c.Name, c.URL, c.Method, c.Headers, c.TimeoutMs, c.Global, c.Enabled).Scan(&id)
	return id, err
}

func (r *webhookConnectorRepo) Update(ctx context.Context, c *store.WebhookConnector) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE webhook_connectors
		 SET name=$1, url=$2, method=$3, headers=$4, timeout_ms=$5, global=$6, enabled=$7, updated_at=now()
		 WHERE id=$8`,
		c.Name, c.URL, c.Method, c.Headers, c.TimeoutMs, c.Global, c.Enabled, c.ID)
	return err
}

func (r *webhookConnectorRepo) Delete(ctx context.Context, id int) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM webhook_connectors WHERE id=$1`, id)
	return err
}
