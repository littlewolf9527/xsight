package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type shellConnectorRepo struct{ pool *pgxpool.Pool }

func (r *shellConnectorRepo) List(ctx context.Context) ([]store.ShellConnector, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, name, command, default_args, timeout_ms, pass_stdin, enabled, created_at, updated_at
		 FROM shell_connectors ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []store.ShellConnector
	for rows.Next() {
		var c store.ShellConnector
		if err := rows.Scan(&c.ID, &c.Name, &c.Command, &c.DefaultArgs,
			&c.TimeoutMs, &c.PassStdin, &c.Enabled, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, rows.Err()
}

func (r *shellConnectorRepo) Get(ctx context.Context, id int) (*store.ShellConnector, error) {
	var c store.ShellConnector
	err := r.pool.QueryRow(ctx,
		`SELECT id, name, command, default_args, timeout_ms, pass_stdin, enabled, created_at, updated_at
		 FROM shell_connectors WHERE id=$1`, id).
		Scan(&c.ID, &c.Name, &c.Command, &c.DefaultArgs,
			&c.TimeoutMs, &c.PassStdin, &c.Enabled, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("shell_connector %d: %w", id, err)
	}
	return &c, nil
}

func (r *shellConnectorRepo) Create(ctx context.Context, c *store.ShellConnector) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO shell_connectors (name, command, default_args, timeout_ms, pass_stdin, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		c.Name, c.Command, c.DefaultArgs, c.TimeoutMs, c.PassStdin, c.Enabled).Scan(&id)
	return id, err
}

func (r *shellConnectorRepo) Update(ctx context.Context, c *store.ShellConnector) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE shell_connectors
		 SET name=$1, command=$2, default_args=$3, timeout_ms=$4, pass_stdin=$5, enabled=$6, updated_at=now()
		 WHERE id=$7`,
		c.Name, c.Command, c.DefaultArgs, c.TimeoutMs, c.PassStdin, c.Enabled, c.ID)
	return err
}

func (r *shellConnectorRepo) Delete(ctx context.Context, id int) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM shell_connectors WHERE id=$1`, id)
	return err
}
