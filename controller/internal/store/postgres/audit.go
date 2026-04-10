package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type auditLogRepo struct{ pool *pgxpool.Pool }

func (r *auditLogRepo) Create(ctx context.Context, l *store.AuditLog) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO config_audit_log (user_id, entity_type, entity_id, action, diff, delivery_version)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		l.UserID, l.EntityType, l.EntityID, l.Action, l.Diff, l.DeliveryVersion)
	return err
}

func (r *auditLogRepo) List(ctx context.Context, f store.AuditFilter) ([]store.AuditLog, error) {
	var conds []string
	var args []any
	argN := 1

	if f.EntityType != "" {
		conds = append(conds, fmt.Sprintf("entity_type=$%d", argN))
		args = append(args, f.EntityType)
		argN++
	}
	if f.UserID != nil {
		conds = append(conds, fmt.Sprintf("user_id=$%d", argN))
		args = append(args, *f.UserID)
		argN++
	}
	if f.TimeFrom != nil {
		conds = append(conds, fmt.Sprintf("created_at >= $%d", argN))
		args = append(args, *f.TimeFrom)
		argN++
	}
	if f.TimeTo != nil {
		conds = append(conds, fmt.Sprintf("created_at <= $%d", argN))
		args = append(args, *f.TimeTo)
		argN++
	}

	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	limit := 100
	if f.Limit > 0 {
		limit = f.Limit
	}

	q := fmt.Sprintf(
		`SELECT id, user_id, entity_type, entity_id, action, diff, delivery_version, created_at
		 FROM config_audit_log%s ORDER BY created_at DESC LIMIT %d OFFSET %d`,
		where, limit, f.Offset)

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []store.AuditLog
	for rows.Next() {
		var l store.AuditLog
		if err := rows.Scan(&l.ID, &l.UserID, &l.EntityType, &l.EntityID,
			&l.Action, &l.Diff, &l.DeliveryVersion, &l.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, l)
	}
	return list, rows.Err()
}
