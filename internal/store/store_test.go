package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestUsersAndSessions(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "tailgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreateUser(ctx, "admin", "correct-horse-password", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "admin", "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	user, err := s.Authenticate(ctx, "admin", "correct-horse-password")
	if err != nil || !user.Admin {
		t.Fatalf("authenticate: %v", err)
	}
	var hash string
	if err := s.DB.QueryRowContext(ctx, "SELECT password_hash FROM users").Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash == "correct-horse-password" {
		t.Fatal("plaintext stored")
	}
	session, err := s.CreateSession(ctx, user, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(session.Token) < 40 || len(session.CSRF) < 40 {
		t.Fatal("weak session credentials")
	}
	got, err := s.GetSession(ctx, session.Token)
	if err != nil || got.User.Name != "admin" || got.CSRF != session.CSRF {
		t.Fatalf("session round trip: %v", err)
	}
	var storedToken string
	if err := s.DB.QueryRowContext(ctx, "SELECT token_hash FROM sessions").Scan(&storedToken); err != nil {
		t.Fatal(err)
	}
	if storedToken == session.Token {
		t.Fatal("plaintext bearer session token stored")
	}
	if err := s.SetPassword(ctx, "admin", "another-valid-password"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, session.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("password change did not invalidate session: %v", err)
	}
	if err := s.DeleteUser(ctx, "admin"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last administrator deletion: %v", err)
	}
	if err := s.CreateUser(ctx, "second", "another-valid-password", true); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	users, err := s.Users(ctx)
	if err != nil || len(users) != 1 || users[0].Name != "second" {
		t.Fatalf("remaining users: %#v, %v", users, err)
	}
}

func TestMigrationReopenAndCanceledQuery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailgate.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Users(ctx); err == nil {
		t.Fatal("canceled query succeeded")
	}
	var table string
	if err := s.DB.QueryRow("SELECT name FROM sqlite_master WHERE name='audit_log'").Scan(&table); err != nil {
		t.Fatal(err)
	}
}
