package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type attackRepo struct{ pool *pgxpool.Pool }

const attackCols = `id, dst_ip::TEXT, prefix_id, direction, decoder_family,
		attack_type, severity, confidence, peak_pps, peak_bps,
		reason_codes, node_sources, response_id, threshold_rule_id, started_at, ended_at, created_at,
		template_name, rule_summary`

// buildAttackWhere builds the WHERE clause and args for attack queries.
func buildAttackWhere(f store.AttackFilter) (string, []any) {
	var conds []string
	var args []any
	argN := 1

	if f.Status == "active" {
		conds = append(conds, "ended_at IS NULL")
	} else if f.Status == "expired" {
		conds = append(conds, "ended_at IS NOT NULL")
	}
	if f.Direction != "" {
		conds = append(conds, fmt.Sprintf("direction=$%d", argN))
		args = append(args, f.Direction)
		argN++
	}
	if f.PrefixID != nil {
		conds = append(conds, fmt.Sprintf("prefix_id=$%d", argN))
		args = append(args, *f.PrefixID)
		argN++
	}
	if f.TimeFrom != nil {
		conds = append(conds, fmt.Sprintf("started_at >= $%d", argN))
		args = append(args, *f.TimeFrom)
		argN++
	}
	if f.TimeTo != nil {
		conds = append(conds, fmt.Sprintf("started_at <= $%d", argN))
		args = append(args, *f.TimeTo)
		argN++
	}

	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	return where, args
}

func (r *attackRepo) Count(ctx context.Context, f store.AttackFilter) (int, error) {
	where, args := buildAttackWhere(f)
	var count int
	err := r.pool.QueryRow(ctx, "SELECT count(*) FROM attacks"+where, args...).Scan(&count)
	return count, err
}

func (r *attackRepo) List(ctx context.Context, f store.AttackFilter) ([]store.Attack, error) {
	where, args := buildAttackWhere(f)

	limit := 100
	if f.Limit > 0 {
		limit = f.Limit
	}

	q := fmt.Sprintf(`SELECT %s FROM attacks%s ORDER BY started_at DESC LIMIT %d OFFSET %d`,
		attackCols, where, limit, f.Offset)

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAttacks(rows)
}

func (r *attackRepo) Get(ctx context.Context, id int) (*store.Attack, error) {
	var a store.Attack
	err := r.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM attacks WHERE id=$1`, attackCols), id).
		Scan(&a.ID, &a.DstIP, &a.PrefixID, &a.Direction, &a.DecoderFamily,
			&a.AttackType, &a.Severity, &a.Confidence, &a.PeakPPS, &a.PeakBPS,
			&a.ReasonCodes, &a.NodeSources, &a.ResponseID, &a.ThresholdRuleID, &a.StartedAt, &a.EndedAt, &a.CreatedAt,
			&a.TemplateName, &a.RuleSummary)
	if err != nil {
		return nil, fmt.Errorf("attack %d: %w", id, err)
	}
	return &a, nil
}

func (r *attackRepo) Create(ctx context.Context, a *store.Attack) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO attacks (dst_ip, prefix_id, direction, decoder_family,
							  attack_type, severity, confidence, peak_pps, peak_bps,
							  reason_codes, node_sources, response_id, threshold_rule_id, started_at,
							  template_name, rule_summary)
		 VALUES ($1::INET, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		 RETURNING id`,
		a.DstIP, a.PrefixID, a.Direction, a.DecoderFamily,
		a.AttackType, a.Severity, a.Confidence, a.PeakPPS, a.PeakBPS,
		a.ReasonCodes, a.NodeSources, a.ResponseID, a.ThresholdRuleID, a.StartedAt,
		a.TemplateName, a.RuleSummary).Scan(&id)
	return id, err
}

func (r *attackRepo) Update(ctx context.Context, a *store.Attack) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE attacks SET attack_type=$1, severity=$2, confidence=$3,
						   peak_pps=$4, peak_bps=$5, reason_codes=$6,
						   node_sources=$7, response_id=$8, ended_at=$9
		 WHERE id=$10`,
		a.AttackType, a.Severity, a.Confidence,
		a.PeakPPS, a.PeakBPS, a.ReasonCodes,
		a.NodeSources, a.ResponseID, a.EndedAt, a.ID)
	return err
}

func (r *attackRepo) ListActive(ctx context.Context, limit int) ([]store.Attack, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := r.pool.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM attacks WHERE ended_at IS NULL ORDER BY peak_pps DESC LIMIT $1`, attackCols), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAttacks(rows)
}

func (r *attackRepo) CountActive(ctx context.Context) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx, `SELECT count(*) FROM attacks WHERE ended_at IS NULL`).Scan(&count)
	return count, err
}

func scanAttacks(rows rowScanner) ([]store.Attack, error) {
	var attacks []store.Attack
	for rows.Next() {
		var a store.Attack
		if err := rows.Scan(&a.ID, &a.DstIP, &a.PrefixID, &a.Direction, &a.DecoderFamily,
			&a.AttackType, &a.Severity, &a.Confidence, &a.PeakPPS, &a.PeakBPS,
			&a.ReasonCodes, &a.NodeSources, &a.ResponseID, &a.ThresholdRuleID, &a.StartedAt, &a.EndedAt, &a.CreatedAt,
			&a.TemplateName, &a.RuleSummary); err != nil {
			return nil, err
		}
		attacks = append(attacks, a)
	}
	return attacks, rows.Err()
}
