package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type userRepo struct{ pool *pgxpool.Pool }

func (r *userRepo) List(ctx context.Context) ([]store.User, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, username, password, role, enabled, created_at, updated_at
		 FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []store.User
	for rows.Next() {
		var u store.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Password, &u.Role, &u.Enabled,
			&u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (r *userRepo) Get(ctx context.Context, id int) (*store.User, error) {
	var u store.User
	err := r.pool.QueryRow(ctx,
		`SELECT id, username, password, role, enabled, created_at, updated_at
		 FROM users WHERE id=$1`, id).
		Scan(&u.ID, &u.Username, &u.Password, &u.Role, &u.Enabled,
			&u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("user %d: %w", id, err)
	}
	return &u, nil
}

func (r *userRepo) GetByUsername(ctx context.Context, username string) (*store.User, error) {
	var u store.User
	err := r.pool.QueryRow(ctx,
		`SELECT id, username, password, role, enabled, created_at, updated_at
		 FROM users WHERE username=$1`, username).
		Scan(&u.ID, &u.Username, &u.Password, &u.Role, &u.Enabled,
			&u.CreatedAt, &u.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("user %q: %w", username, err)
	}
	return &u, nil
}

func (r *userRepo) Create(ctx context.Context, u *store.User) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO users (username, password, role, enabled)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		u.Username, u.Password, u.Role, u.Enabled).Scan(&id)
	return id, err
}

func (r *userRepo) Update(ctx context.Context, u *store.User) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE users SET username=$1, password=$2, role=$3, enabled=$4, updated_at=now()
		 WHERE id=$5`,
		u.Username, u.Password, u.Role, u.Enabled, u.ID)
	return err
}

func (r *userRepo) Delete(ctx context.Context, id int) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	return err
}
