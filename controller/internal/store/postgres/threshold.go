package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type thresholdRepo struct{ pool *pgxpool.Pool }

const thresholdCols = `id, template_id, prefix_id, domain, direction, decoder, unit, comparison,
		value, inheritable, response_id, enabled, created_at`

func (r *thresholdRepo) Count(ctx context.Context) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx, `SELECT count(*) FROM thresholds`).Scan(&count)
	return count, err
}

func (r *thresholdRepo) List(ctx context.Context) ([]store.Threshold, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+thresholdCols+` FROM thresholds ORDER BY prefix_id, template_id, decoder`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanThresholds(rows)
}

func (r *thresholdRepo) ListByPrefix(ctx context.Context, prefixID int) ([]store.Threshold, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+thresholdCols+` FROM thresholds WHERE prefix_id=$1 ORDER BY decoder`, prefixID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanThresholds(rows)
}

func (r *thresholdRepo) Get(ctx context.Context, id int) (*store.Threshold, error) {
	var t store.Threshold
	err := r.pool.QueryRow(ctx,
		`SELECT `+thresholdCols+` FROM thresholds WHERE id=$1`, id).
		Scan(&t.ID, &t.TemplateID, &t.PrefixID, &t.Domain, &t.Direction, &t.Decoder, &t.Unit,
			&t.Comparison, &t.Value, &t.Inheritable, &t.ResponseID, &t.Enabled, &t.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("threshold %d: %w", id, err)
	}
	return &t, nil
}

func (r *thresholdRepo) Create(ctx context.Context, t *store.Threshold) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO thresholds (template_id, prefix_id, domain, direction, decoder, unit, comparison,
								value, inheritable, response_id, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
		t.TemplateID, t.PrefixID, t.Domain, t.Direction, t.Decoder, t.Unit, t.Comparison,
		t.Value, t.Inheritable, t.ResponseID, t.Enabled).Scan(&id)
	return id, err
}

func (r *thresholdRepo) Update(ctx context.Context, t *store.Threshold) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE thresholds SET template_id=$1, prefix_id=$2, domain=$3, direction=$4, decoder=$5,
								unit=$6, comparison=$7, value=$8, inheritable=$9,
								response_id=$10, enabled=$11
		 WHERE id=$12`,
		t.TemplateID, t.PrefixID, t.Domain, t.Direction, t.Decoder, t.Unit, t.Comparison,
		t.Value, t.Inheritable, t.ResponseID, t.Enabled, t.ID)
	return err
}

func (r *thresholdRepo) Delete(ctx context.Context, id int) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM thresholds WHERE id=$1`, id)
	return err
}

type rowScanner interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

func scanThresholds(rows rowScanner) ([]store.Threshold, error) {
	var thresholds []store.Threshold
	for rows.Next() {
		var t store.Threshold
		if err := rows.Scan(&t.ID, &t.TemplateID, &t.PrefixID, &t.Domain, &t.Direction, &t.Decoder,
			&t.Unit, &t.Comparison, &t.Value, &t.Inheritable, &t.ResponseID,
			&t.Enabled, &t.CreatedAt); err != nil {
			return nil, err
		}
		thresholds = append(thresholds, t)
	}
	return thresholds, rows.Err()
}
