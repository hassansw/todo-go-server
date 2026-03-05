package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"todo-server-secure/internal/model"
)

type Store struct {
	db *sql.DB
}

func New(databaseURL string, maxOpen, maxIdle int, maxLife time.Duration) (*Store, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(maxLife)
	db.SetConnMaxIdleTime(time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// ============================================================
// Migrations
// ============================================================

func (s *Store) Migrate(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id            SERIAL       PRIMARY KEY,
			email         TEXT         NOT NULL UNIQUE,
			password_hash TEXT         NOT NULL,
			name          TEXT         NOT NULL DEFAULT '',
			created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
			updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			id         SERIAL       PRIMARY KEY,
			user_id    INT          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			token_hash TEXT         NOT NULL UNIQUE,
			expires_at TIMESTAMPTZ  NOT NULL,
			revoked    BOOLEAN      NOT NULL DEFAULT FALSE,
			created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user   ON refresh_tokens (user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash   ON refresh_tokens (token_hash)`,
		`CREATE TABLE IF NOT EXISTS todos (
			id          SERIAL       PRIMARY KEY,
			user_id     INT          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			title       TEXT         NOT NULL,
			description TEXT         NOT NULL DEFAULT '',
			completed   BOOLEAN      NOT NULL DEFAULT FALSE,
			priority    TEXT         NOT NULL DEFAULT 'medium'
				CHECK (priority IN ('low', 'medium', 'high')),
			image_path  TEXT,
			created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
			updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_todos_user      ON todos (user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_todos_completed ON todos (user_id, completed)`,
		`CREATE INDEX IF NOT EXISTS idx_todos_priority  ON todos (user_id, priority)`,
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	for _, q := range queries {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return tx.Commit()
}

// ============================================================
// Users
// ============================================================

func (s *Store) CreateUser(ctx context.Context, email, passwordHash, name string) (*model.User, error) {
	var u model.User
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO users (email, password_hash, name)
		 VALUES ($1, $2, $3)
		 RETURNING id, email, password_hash, name, created_at, updated_at`,
		email, passwordHash, name).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	var u model.User
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, name, created_at, updated_at
		 FROM users WHERE email = $1`, email).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.CreatedAt, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) GetUserByID(ctx context.Context, id int) (*model.User, error) {
	var u model.User
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, name, created_at, updated_at
		 FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.CreatedAt, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ============================================================
// Refresh Tokens
// ============================================================

func (s *Store) SaveRefreshToken(ctx context.Context, userID int, tokenHash string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		 VALUES ($1, $2, $3)`,
		userID, tokenHash, expiresAt)
	return err
}

func (s *Store) GetRefreshToken(ctx context.Context, tokenHash string) (*model.RefreshToken, error) {
	var rt model.RefreshToken
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, token_hash, expires_at, revoked, created_at
		 FROM refresh_tokens WHERE token_hash = $1`, tokenHash).
		Scan(&rt.ID, &rt.UserID, &rt.TokenHash, &rt.ExpiresAt, &rt.Revoked, &rt.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rt, nil
}

func (s *Store) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = $1`, tokenHash)
	return err
}

// RevokeAllUserTokens is for "log out everywhere".
func (s *Store) RevokeAllUserTokens(ctx context.Context, userID int) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE`, userID)
	return err
}

// CleanExpiredTokens removes old tokens (run periodically).
func (s *Store) CleanExpiredTokens(ctx context.Context) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM refresh_tokens WHERE expires_at < NOW() OR revoked = TRUE`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ============================================================
// Todos (all scoped to user_id)
// ============================================================

func (s *Store) ListTodos(ctx context.Context, userID int, completed *bool) ([]model.Todo, error) {
	query := `SELECT id, user_id, title, description, completed, priority, image_path, created_at, updated_at
	          FROM todos WHERE user_id = $1`
	args := []interface{}{userID}

	if completed != nil {
		query += ` AND completed = $2`
		args = append(args, *completed)
	}
	query += ` ORDER BY
		CASE priority WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 END,
		created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var todos []model.Todo
	for rows.Next() {
		var t model.Todo
		if err := rows.Scan(&t.ID, &t.UserID, &t.Title, &t.Description, &t.Completed,
			&t.Priority, &t.ImagePath, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		todos = append(todos, t)
	}
	return todos, rows.Err()
}

func (s *Store) GetTodo(ctx context.Context, userID int, todoID string) (*model.Todo, error) {
	var t model.Todo
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, title, description, completed, priority, image_path, created_at, updated_at
		 FROM todos WHERE id = $1 AND user_id = $2`, todoID, userID).
		Scan(&t.ID, &t.UserID, &t.Title, &t.Description, &t.Completed,
			&t.Priority, &t.ImagePath, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) CreateTodo(ctx context.Context, userID int, req model.CreateTodoRequest) (*model.Todo, error) {
	priority := req.Priority
	if priority == "" {
		priority = "medium"
	}

	var t model.Todo
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO todos (user_id, title, description, priority)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, user_id, title, description, completed, priority, image_path, created_at, updated_at`,
		userID, req.Title, req.Description, priority).
		Scan(&t.ID, &t.UserID, &t.Title, &t.Description, &t.Completed,
			&t.Priority, &t.ImagePath, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) UpdateTodo(ctx context.Context, userID int, todoID string, req model.UpdateTodoRequest) (*model.Todo, error) {
	existing, err := s.GetTodo(ctx, userID, todoID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, nil
	}

	if req.Title != nil {
		existing.Title = *req.Title
	}
	if req.Description != nil {
		existing.Description = *req.Description
	}
	if req.Completed != nil {
		existing.Completed = *req.Completed
	}
	if req.Priority != nil {
		existing.Priority = *req.Priority
	}

	var t model.Todo
	err = s.db.QueryRowContext(ctx,
		`UPDATE todos SET title=$1, description=$2, completed=$3, priority=$4, updated_at=NOW()
		 WHERE id=$5 AND user_id=$6
		 RETURNING id, user_id, title, description, completed, priority, image_path, created_at, updated_at`,
		existing.Title, existing.Description, existing.Completed, existing.Priority, todoID, userID).
		Scan(&t.ID, &t.UserID, &t.Title, &t.Description, &t.Completed,
			&t.Priority, &t.ImagePath, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) SetTodoImage(ctx context.Context, userID int, todoID string, imagePath string) (*model.Todo, error) {
	var t model.Todo
	err := s.db.QueryRowContext(ctx,
		`UPDATE todos SET image_path=$1, updated_at=NOW()
		 WHERE id=$2 AND user_id=$3
		 RETURNING id, user_id, title, description, completed, priority, image_path, created_at, updated_at`,
		imagePath, todoID, userID).
		Scan(&t.ID, &t.UserID, &t.Title, &t.Description, &t.Completed,
			&t.Priority, &t.ImagePath, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) DeleteTodo(ctx context.Context, userID int, todoID string) (*model.Todo, error) {
	// Return the deleted row so we can clean up the image
	var t model.Todo
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM todos WHERE id=$1 AND user_id=$2
		 RETURNING id, user_id, title, description, completed, priority, image_path, created_at, updated_at`,
		todoID, userID).
		Scan(&t.ID, &t.UserID, &t.Title, &t.Description, &t.Completed,
			&t.Priority, &t.ImagePath, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}
