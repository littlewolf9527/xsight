package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type prefixRepo struct{ pool *pgxpool.Pool }

const prefixCols = `id, prefix::TEXT, parent_id, threshold_template_id, name, ip_group, enabled, created_at`

func (r *prefixRepo) Count(ctx context.Context) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx, `SELECT count(*) FROM watch_prefixes`).Scan(&count)
	return count, err
}

func (r *prefixRepo) List(ctx context.Context) ([]store.WatchPrefix, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+prefixCols+` FROM watch_prefixes ORDER BY prefix`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPrefixes(rows)
}

func (r *prefixRepo) Get(ctx context.Context, id int) (*store.WatchPrefix, error) {
	var p store.WatchPrefix
	err := r.pool.QueryRow(ctx, `SELECT `+prefixCols+` FROM watch_prefixes WHERE id=$1`, id).
		Scan(&p.ID, &p.Prefix, &p.ParentID, &p.ThresholdTemplateID, &p.Name, &p.IPGroup, &p.Enabled, &p.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("prefix %d: %w", id, err)
	}
	return &p, nil
}

func (r *prefixRepo) Create(ctx context.Context, p *store.WatchPrefix) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO watch_prefixes (prefix, parent_id, threshold_template_id, name, ip_group, enabled)
		 VALUES ($1::CIDR, $2, $3, $4, $5, $6) RETURNING id`,
		p.Prefix, p.ParentID, p.ThresholdTemplateID, p.Name, p.IPGroup, p.Enabled).Scan(&id)
	return id, err
}

func (r *prefixRepo) Update(ctx context.Context, p *store.WatchPrefix) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE watch_prefixes SET prefix=$1::CIDR, parent_id=$2, threshold_template_id=$3, name=$4, ip_group=$5, enabled=$6
		 WHERE id=$7`,
		p.Prefix, p.ParentID, p.ThresholdTemplateID, p.Name, p.IPGroup, p.Enabled, p.ID)
	return err
}

func (r *prefixRepo) Delete(ctx context.Context, id int) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM watch_prefixes WHERE id=$1`, id)
	return err
}

func (r *prefixRepo) ListTree(ctx context.Context) ([]store.WatchPrefix, error) {
	return r.List(ctx)
}

func scanPrefixes(rows rowScanner) ([]store.WatchPrefix, error) {
	var list []store.WatchPrefix
	for rows.Next() {
		var p store.WatchPrefix
		if err := rows.Scan(&p.ID, &p.Prefix, &p.ParentID, &p.ThresholdTemplateID, &p.Name, &p.IPGroup, &p.Enabled, &p.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, p)
	}
	return list, rows.Err()
}
