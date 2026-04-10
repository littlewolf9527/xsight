package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type webhookRepo struct{ pool *pgxpool.Pool }

func (r *webhookRepo) List(ctx context.Context) ([]store.Webhook, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, url, events, headers, enabled
		 FROM webhooks ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []store.Webhook
	for rows.Next() {
		var w store.Webhook
		if err := rows.Scan(&w.ID, &w.URL, &w.Events, &w.Headers, &w.Enabled); err != nil {
			return nil, err
		}
		list = append(list, w)
	}
	return list, rows.Err()
}

func (r *webhookRepo) Get(ctx context.Context, id int) (*store.Webhook, error) {
	var w store.Webhook
	err := r.pool.QueryRow(ctx,
		`SELECT id, url, events, headers, enabled
		 FROM webhooks WHERE id=$1`, id).
		Scan(&w.ID, &w.URL, &w.Events, &w.Headers, &w.Enabled)
	if err != nil {
		return nil, fmt.Errorf("webhook %d: %w", id, err)
	}
	return &w, nil
}

func (r *webhookRepo) Create(ctx context.Context, w *store.Webhook) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO webhooks (url, events, headers, enabled)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		w.URL, w.Events, w.Headers, w.Enabled).Scan(&id)
	return id, err
}

func (r *webhookRepo) Update(ctx context.Context, w *store.Webhook) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE webhooks SET url=$1, events=$2, headers=$3, enabled=$4
		 WHERE id=$5`,
		w.URL, w.Events, w.Headers, w.Enabled, w.ID)
	return err
}

func (r *webhookRepo) Delete(ctx context.Context, id int) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM webhooks WHERE id=$1`, id)
	return err
}
