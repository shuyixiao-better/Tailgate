// Package store owns SQLite schema migrations, Web users and sessions.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound           = errors.New("not found")
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrLastAdmin          = errors.New("the last administrator cannot be removed")
	usernamePattern       = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	dummyOnce             sync.Once
	dummyHash             []byte
)

type Store struct{ DB *sql.DB }

type User struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Admin     bool      `json:"admin"`
	CreatedAt time.Time `json:"created_at"`
}

type Session struct {
	Token     string    `json:"-"`
	CSRF      string    `json:"csrf"`
	User      User      `json:"user"`
	ExpiresAt time.Time `json:"expires_at"`
}

func Open(ctx context.Context, path string) (*Store, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, fmt.Errorf("create database file: %w", err)
		}
		if err := file.Close(); err != nil {
			return nil, fmt.Errorf("close database file: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open SQLite: %w", err)
	}
	// One connection serializes transactions and guarantees per-connection PRAGMAs.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	for _, statement := range []string{"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			db.Close()
			return nil, fmt.Errorf("configure SQLite: %w", err)
		}
	}
	s := &Store{DB: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schema migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  admin INTEGER NOT NULL DEFAULT 0 CHECK(admin IN (0,1)),
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  source TEXT NOT NULL CHECK(source IN ('mcp','web','terminal')),
  actor TEXT NOT NULL DEFAULT '',
  client_ip TEXT NOT NULL DEFAULT '',
  host TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL DEFAULT '',
  command TEXT NOT NULL DEFAULT '',
  exit_code INTEGER,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  output_bytes INTEGER NOT NULL DEFAULT 0,
  output_excerpt TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_log_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS audit_log_host_ts ON audit_log(host,ts);
CREATE INDEX IF NOT EXISTS audit_log_source_ts ON audit_log(source,ts);
INSERT OR IGNORE INTO schema_version(version) VALUES(1);`); err != nil {
		return fmt.Errorf("apply schema migration 1: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schema migration: %w", err)
	}
	return nil
}

func (s *Store) Close() error { return s.DB.Close() }

func validatePassword(password string) error {
	if len(password) < 8 || len(password) > 72 {
		return errors.New("password must contain between 8 and 72 bytes")
	}
	return nil
}

func (s *Store) CreateUser(ctx context.Context, name, password string, admin bool) error {
	if !usernamePattern.MatchString(name) {
		return errors.New("username must contain 1 to 64 ASCII letters, digits, dots, underscores or hyphens")
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash Web password: %w", err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO users(username,password_hash,admin,created_at) VALUES(?,?,?,?)`, name, string(hash), admin, time.Now().Unix()); err != nil {
		return fmt.Errorf("create Web user %s: %w", name, err)
	}
	return nil
}

func (s *Store) SetPassword(ctx context.Context, name, password string) error {
	if err := validatePassword(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash Web password: %w", err)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin password update: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE users SET password_hash=? WHERE username=?`, string(hash), name)
	if err != nil {
		return fmt.Errorf("update Web password: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil {
		return fmt.Errorf("count updated users: %w", err)
	} else if count == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=(SELECT id FROM users WHERE username=?)`, name); err != nil {
		return fmt.Errorf("invalidate Web sessions: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit password update: %w", err)
	}
	return nil
}

func (s *Store) DeleteUser(ctx context.Context, name string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin user removal: %w", err)
	}
	defer tx.Rollback()
	var id int64
	var admin bool
	if err := tx.QueryRowContext(ctx, `SELECT id,admin FROM users WHERE username=?`, name).Scan(&id, &admin); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("find Web user: %w", err)
	}
	if admin {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE admin=1`).Scan(&count); err != nil {
			return fmt.Errorf("count administrators: %w", err)
		}
		if count < 2 {
			return ErrLastAdmin
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id); err != nil {
		return fmt.Errorf("remove Web user: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit user removal: %w", err)
	}
	return nil
}

func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id,username,admin,created_at FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("list Web users: %w", err)
	}
	defer rows.Close()
	users := []User{}
	for rows.Next() {
		var user User
		var created int64
		if err := rows.Scan(&user.ID, &user.Name, &user.Admin, &created); err != nil {
			return nil, fmt.Errorf("read Web user: %w", err)
		}
		user.CreatedAt = time.Unix(created, 0).UTC()
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Web users: %w", err)
	}
	return users, nil
}

func (s *Store) Authenticate(ctx context.Context, name, password string) (User, error) {
	var user User
	var created int64
	var hash string
	err := s.DB.QueryRowContext(ctx, `SELECT id,username,admin,created_at,password_hash FROM users WHERE username=?`, name).Scan(&user.ID, &user.Name, &user.Admin, &created, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		// Unknown names still consume a bcrypt comparison to reduce enumeration.
		dummyOnce.Do(func() {
			dummyHash, _ = bcrypt.GenerateFromPassword([]byte("tailgate-dummy-auth-placeholder"), bcrypt.DefaultCost)
		})
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return User{}, ErrInvalidCredentials
	}
	if err != nil {
		return User{}, fmt.Errorf("query Web credentials: %w", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return User{}, ErrInvalidCredentials
	}
	user.CreatedAt = time.Unix(created, 0).UTC()
	return user, nil
}

func randomToken() (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate session credential: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func tokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (s *Store) CreateSession(ctx context.Context, user User, ttl time.Duration) (Session, error) {
	if ttl <= 0 || ttl > 30*24*time.Hour {
		return Session{}, errors.New("session lifetime must be positive and at most 30 days")
	}
	token, err := randomToken()
	if err != nil {
		return Session{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return Session{}, err
	}
	expires := time.Now().Add(ttl).UTC()
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO sessions(token_hash,user_id,csrf_token,created_at,expires_at) VALUES(?,?,?,?,?)`, tokenHash(token), user.ID, csrf, time.Now().Unix(), expires.Unix()); err != nil {
		return Session{}, fmt.Errorf("create Web session: %w", err)
	}
	return Session{Token: token, CSRF: csrf, User: user, ExpiresAt: expires}, nil
}

func (s *Store) GetSession(ctx context.Context, token string) (Session, error) {
	var session Session
	var created, expires int64
	err := s.DB.QueryRowContext(ctx, `SELECT u.id,u.username,u.admin,u.created_at,s.csrf_token,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`, tokenHash(token), time.Now().Unix()).Scan(&session.User.ID, &session.User.Name, &session.User.Admin, &created, &session.CSRF, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("read Web session: %w", err)
	}
	session.User.CreatedAt = time.Unix(created, 0).UTC()
	session.ExpiresAt = time.Unix(expires, 0).UTC()
	return session, nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, tokenHash(token)); err != nil {
		return fmt.Errorf("delete Web session: %w", err)
	}
	return nil
}

func (s *Store) CleanupSessions(ctx context.Context) error {
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at<=?`, time.Now().Unix()); err != nil {
		return fmt.Errorf("clean expired Web sessions: %w", err)
	}
	return nil
}
