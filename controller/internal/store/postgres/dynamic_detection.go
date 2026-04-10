package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type dynDetectRepo struct{ pool *pgxpool.Pool }

func (r *dynDetectRepo) GetConfig(ctx context.Context) (*store.DynDetectConfig, error) {
	var cfg store.DynDetectConfig
	err := r.pool.QueryRow(ctx,
		`SELECT enabled, deviation_min, deviation_max, stable_weeks, min_pps, min_bps, ewma_alpha
		 FROM dynamic_detection_config WHERE id = 1`).
		Scan(&cfg.Enabled, &cfg.DeviationMin, &cfg.DeviationMax, &cfg.StableWeeks,
			&cfg.MinPPS, &cfg.MinBPS, &cfg.EWMAAlpha)
	if err != nil {
		return nil, fmt.Errorf("get dyn detect config: %w", err)
	}
	return &cfg, nil
}

func (r *dynDetectRepo) UpdateConfig(ctx context.Context, cfg *store.DynDetectConfig) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE dynamic_detection_config SET
			enabled=$1, deviation_min=$2, deviation_max=$3, stable_weeks=$4,
			min_pps=$5, min_bps=$6, ewma_alpha=$7, updated_at=now()
		 WHERE id = 1`,
		cfg.Enabled, cfg.DeviationMin, cfg.DeviationMax, cfg.StableWeeks,
		cfg.MinPPS, cfg.MinBPS, cfg.EWMAAlpha)
	if err != nil {
		return fmt.Errorf("update dyn detect config: %w", err)
	}
	return nil
}

func (r *dynDetectRepo) ListProfiles(ctx context.Context, slotIndex int) ([]store.PrefixProfile, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT node_id, prefix::TEXT, slot_index, expected_pps, expected_bps, sample_weeks, last_sample_yw
		 FROM prefix_profiles WHERE slot_index = $1`, slotIndex)
	if err != nil {
		return nil, fmt.Errorf("list profiles: %w", err)
	}
	defer rows.Close()

	var list []store.PrefixProfile
	for rows.Next() {
		var p store.PrefixProfile
		if err := rows.Scan(&p.NodeID, &p.Prefix, &p.SlotIndex, &p.ExpectedPPS, &p.ExpectedBPS,
			&p.SampleWeeks, &p.LastSampleYW); err != nil {
			return nil, fmt.Errorf("scan profile: %w", err)
		}
		list = append(list, p)
	}
	return list, rows.Err()
}

func (r *dynDetectRepo) UpsertProfile(ctx context.Context, p *store.PrefixProfile) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO prefix_profiles (node_id, prefix, slot_index, expected_pps, expected_bps, sample_weeks, last_sample_yw, updated_at)
		 VALUES ($1, $2::CIDR, $3, $4, $5, $6, $7, now())
		 ON CONFLICT (node_id, prefix, slot_index) DO UPDATE SET
			expected_pps=$4, expected_bps=$5, sample_weeks=$6, last_sample_yw=$7, updated_at=now()`,
		p.NodeID, p.Prefix, p.SlotIndex, p.ExpectedPPS, p.ExpectedBPS, p.SampleWeeks, p.LastSampleYW)
	if err != nil {
		return fmt.Errorf("upsert profile: %w", err)
	}
	return nil
}

func (r *dynDetectRepo) BulkUpsertProfiles(ctx context.Context, profiles []store.PrefixProfile) error {
	if len(profiles) == 0 {
		return nil
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("bulk upsert begin: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, p := range profiles {
		_, err := tx.Exec(ctx,
			`INSERT INTO prefix_profiles (node_id, prefix, slot_index, expected_pps, expected_bps, sample_weeks, last_sample_yw, updated_at)
			 VALUES ($1, $2::CIDR, $3, $4, $5, $6, $7, now())
			 ON CONFLICT (node_id, prefix, slot_index) DO UPDATE SET
				expected_pps=$4, expected_bps=$5, sample_weeks=$6, last_sample_yw=$7, updated_at=now()`,
			p.NodeID, p.Prefix, p.SlotIndex, p.ExpectedPPS, p.ExpectedBPS, p.SampleWeeks, p.LastSampleYW)
		if err != nil {
			return fmt.Errorf("bulk upsert row: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("bulk upsert commit: %w", err)
	}
	return nil
}

func (r *dynDetectRepo) DeleteAllProfiles(ctx context.Context) error {
	_, err := r.pool.Exec(ctx, `TRUNCATE prefix_profiles`)
	if err != nil {
		return fmt.Errorf("truncate profiles: %w", err)
	}
	return nil
}
