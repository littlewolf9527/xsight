package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type templateRepo struct{ pool *pgxpool.Pool }

func (r *templateRepo) List(ctx context.Context) ([]store.ThresholdTemplate, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT tt.id, tt.name, tt.description, tt.response_id, tt.created_at, tt.updated_at,
				COALESCE(rc.cnt, 0) AS rule_count,
				COALESCE(pc.cnt, 0) AS prefix_count
		 FROM threshold_templates tt
		 LEFT JOIN (SELECT template_id, count(*) AS cnt FROM thresholds WHERE template_id IS NOT NULL GROUP BY template_id) rc ON rc.template_id = tt.id
		 LEFT JOIN (SELECT threshold_template_id, count(*) AS cnt FROM watch_prefixes WHERE threshold_template_id IS NOT NULL GROUP BY threshold_template_id) pc ON pc.threshold_template_id = tt.id
		 ORDER BY tt.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []store.ThresholdTemplate
	for rows.Next() {
		var t store.ThresholdTemplate
		if err := rows.Scan(&t.ID, &t.Name, &t.Description, &t.ResponseID, &t.CreatedAt, &t.UpdatedAt, &t.RuleCount, &t.PrefixCount); err != nil {
			return nil, err
		}
		list = append(list, t)
	}
	return list, rows.Err()
}

func (r *templateRepo) Get(ctx context.Context, id int) (*store.ThresholdTemplate, error) {
	var t store.ThresholdTemplate
	err := r.pool.QueryRow(ctx,
		`SELECT id, name, description, response_id, created_at, updated_at
		 FROM threshold_templates WHERE id=$1`, id).
		Scan(&t.ID, &t.Name, &t.Description, &t.ResponseID, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("template %d: %w", id, err)
	}
	return &t, nil
}

func (r *templateRepo) Create(ctx context.Context, t *store.ThresholdTemplate) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO threshold_templates (name, description) VALUES ($1, $2) RETURNING id`,
		t.Name, t.Description).Scan(&id)
	return id, err
}

func (r *templateRepo) Update(ctx context.Context, t *store.ThresholdTemplate) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE threshold_templates SET name=$1, description=$2, response_id=$3, updated_at=now() WHERE id=$4`,
		t.Name, t.Description, t.ResponseID, t.ID)
	return err
}

func (r *templateRepo) Delete(ctx context.Context, id int) error {
	// ON DELETE RESTRICT will fail if any prefix references this template
	_, err := r.pool.Exec(ctx, `DELETE FROM threshold_templates WHERE id=$1`, id)
	return err
}

func (r *templateRepo) Duplicate(ctx context.Context, id int, newName string) (int, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	// Create new template
	var newID int
	err = tx.QueryRow(ctx,
		`INSERT INTO threshold_templates (name, description)
		 SELECT $1, description FROM threshold_templates WHERE id=$2
		 RETURNING id`, newName, id).Scan(&newID)
	if err != nil {
		return 0, fmt.Errorf("duplicate template: %w", err)
	}

	// Copy all rules
	_, err = tx.Exec(ctx,
		`INSERT INTO thresholds (template_id, domain, direction, decoder, unit, comparison, value, inheritable, response_id, enabled)
		 SELECT $1, domain, direction, decoder, unit, comparison, value, inheritable, response_id, enabled
		 FROM thresholds WHERE template_id=$2`, newID, id)
	if err != nil {
		return 0, fmt.Errorf("duplicate rules: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return newID, nil
}

func (r *templateRepo) ListRules(ctx context.Context, templateID int) ([]store.Threshold, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, template_id, prefix_id, domain, direction, decoder, unit, comparison,
				value, inheritable, response_id, enabled, created_at
		 FROM thresholds WHERE template_id=$1 ORDER BY decoder, unit`, templateID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanThresholds(rows)
}

func (r *templateRepo) ListPrefixesUsing(ctx context.Context, templateID int) ([]store.WatchPrefix, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, prefix::TEXT, parent_id, threshold_template_id, name, ip_group, enabled, created_at
		 FROM watch_prefixes WHERE threshold_template_id=$1 ORDER BY prefix`, templateID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
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
