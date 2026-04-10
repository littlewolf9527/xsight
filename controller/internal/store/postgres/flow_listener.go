package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type flowListenerRepo struct{ pool *pgxpool.Pool }

func (r *flowListenerRepo) List(ctx context.Context, nodeID string) ([]store.FlowListener, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, node_id, listen_address, protocol_mode, enabled, description, created_at
		 FROM flow_listeners WHERE node_id=$1 ORDER BY id`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []store.FlowListener
	for rows.Next() {
		var l store.FlowListener
		if err := rows.Scan(&l.ID, &l.NodeID, &l.ListenAddress, &l.ProtocolMode,
			&l.Enabled, &l.Description, &l.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, l)
	}
	return list, rows.Err()
}

func (r *flowListenerRepo) Get(ctx context.Context, id int) (*store.FlowListener, error) {
	var l store.FlowListener
	err := r.pool.QueryRow(ctx,
		`SELECT id, node_id, listen_address, protocol_mode, enabled, description, created_at
		 FROM flow_listeners WHERE id=$1`, id).
		Scan(&l.ID, &l.NodeID, &l.ListenAddress, &l.ProtocolMode,
			&l.Enabled, &l.Description, &l.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("flow_listener %d: %w", id, err)
	}
	return &l, nil
}

func (r *flowListenerRepo) Create(ctx context.Context, l *store.FlowListener) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO flow_listeners (node_id, listen_address, protocol_mode, enabled, description)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		l.NodeID, l.ListenAddress, l.ProtocolMode, l.Enabled, l.Description).Scan(&id)
	return id, err
}

func (r *flowListenerRepo) Update(ctx context.Context, l *store.FlowListener) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE flow_listeners SET listen_address=$1, protocol_mode=$2, enabled=$3, description=$4
		 WHERE id=$5`,
		l.ListenAddress, l.ProtocolMode, l.Enabled, l.Description, l.ID)
	return err
}

func (r *flowListenerRepo) Delete(ctx context.Context, id int) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM flow_listeners WHERE id=$1`, id)
	return err
}
