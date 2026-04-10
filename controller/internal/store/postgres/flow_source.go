package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type flowSourceRepo struct{ pool *pgxpool.Pool }

func (r *flowSourceRepo) List(ctx context.Context, listenerID int) ([]store.FlowSource, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, listener_id, name, device_ip::TEXT, sample_mode, sample_rate, description, enabled, created_at
		 FROM flow_sources WHERE listener_id=$1 ORDER BY id`, listenerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []store.FlowSource
	for rows.Next() {
		var s store.FlowSource
		if err := rows.Scan(&s.ID, &s.ListenerID, &s.Name, &s.DeviceIP, &s.SampleMode,
			&s.SampleRate, &s.Description, &s.Enabled, &s.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, s)
	}
	return list, rows.Err()
}

func (r *flowSourceRepo) Get(ctx context.Context, id int) (*store.FlowSource, error) {
	var s store.FlowSource
	err := r.pool.QueryRow(ctx,
		`SELECT id, listener_id, name, device_ip::TEXT, sample_mode, sample_rate, description, enabled, created_at
		 FROM flow_sources WHERE id=$1`, id).
		Scan(&s.ID, &s.ListenerID, &s.Name, &s.DeviceIP, &s.SampleMode,
			&s.SampleRate, &s.Description, &s.Enabled, &s.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("flow_source %d: %w", id, err)
	}
	return &s, nil
}

func (r *flowSourceRepo) Create(ctx context.Context, s *store.FlowSource) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO flow_sources (listener_id, name, device_ip, sample_mode, sample_rate, description, enabled)
		 VALUES ($1, $2, $3::INET, $4, $5, $6, $7) RETURNING id`,
		s.ListenerID, s.Name, s.DeviceIP, s.SampleMode, s.SampleRate, s.Description, s.Enabled).Scan(&id)
	return id, err
}

func (r *flowSourceRepo) Update(ctx context.Context, s *store.FlowSource) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE flow_sources SET name=$1, device_ip=$2::INET, sample_mode=$3, sample_rate=$4, description=$5, enabled=$6
		 WHERE id=$7`,
		s.Name, s.DeviceIP, s.SampleMode, s.SampleRate, s.Description, s.Enabled, s.ID)
	return err
}

func (r *flowSourceRepo) Delete(ctx context.Context, id int) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM flow_sources WHERE id=$1`, id)
	return err
}
