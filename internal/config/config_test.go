package config

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type reloadLogHandler struct {
	slog.Handler
	rejected chan struct{}
}

func (h reloadLogHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Message == "configuration reload rejected" {
		select {
		case h.rejected <- struct{}{}:
		default:
		}
	}
	return h.Handler.Handle(ctx, record)
}

func TestValidation(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Config)
		field  string
	}{
		{"cidr", func(c *Config) { c.Server.AllowedCIDRs = []string{"invalid"} }, "server.allowed_cidrs[0]"},
		{"duration", func(c *Config) { c.SSH.ConnectTimeout = 0 }, "ssh.connect_timeout"},
		{"timeout bounds", func(c *Config) { c.SSH.DefaultCommandTimeout = c.SSH.MaxCommandTimeout + 1 }, "ssh.default_command_timeout"},
		{"token plaintext", func(c *Config) { c.MCP.Tokens = []Token{{Name: "dev", Hash: "plaintext"}} }, "mcp.tokens[0].hash"},
		{"host plaintext", func(c *Config) {
			c.Hosts = []Host{{Name: "dev", Address: "localhost", Port: 22, Username: "user", PasswordEnc: "plaintext"}}
		}, "hosts[0].password_enc"},
		{"mcp wildcard", func(c *Config) { c.MCP.Path = "/{wildcard}" }, "mcp.path"},
		{"duplicate host", func(c *Config) {
			host := Host{Name: "dev", Address: "localhost", Port: 22, Username: "user", PasswordEnc: base64.StdEncoding.EncodeToString(make([]byte, 28))}
			c.Hosts = []Host{host, host}
		}, "hosts[1].name"},
	}
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := Default()
			test.change(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("expected error mentioning %s, got %v", test.field, err)
			}
		})
	}
}

func TestLoadUpdateAndIsolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := WriteDefault(path); err != nil {
		t.Fatal(err)
	}
	manager, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := manager.Snapshot()
	if cfg.SSH.ConnectTimeout.String() != "10s" {
		t.Fatalf("duration: %v", cfg.SSH.ConnectTimeout)
	}
	cfg.Server.AllowedCIDRs[0] = "invalid"
	if manager.Snapshot().Server.AllowedCIDRs[0] == "invalid" {
		t.Fatal("snapshot shares configuration storage")
	}
	if err := manager.Update(func(c *Config) error { c.Monitor.Interval = 0; return nil }); err == nil {
		t.Fatal("accepted invalid update")
	}
	if manager.Snapshot().Monitor.Interval <= 0 {
		t.Fatal("invalid update changed memory")
	}
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				_ = manager.Snapshot()
			}
		}()
	}
	if err := manager.Update(func(c *Config) error { c.Audit.RetentionDays = 30; return nil }); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Snapshot().Audit.RetentionDays != 30 {
		t.Fatal("configuration update was not persisted")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "Tailgate 配置") {
		t.Fatal("configuration comments were not preserved")
	}
}

func TestLoadRejectsUnknownAndExtraDocument(t *testing.T) {
	for _, contents := range []string{"password: should-not-be-present\n", DefaultYAML + "\n---\nserver: {}\n"} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("accepted unknown field or extra YAML document")
		}
	}
}

func TestWatchStartupEditInvalidRetentionAndValidReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := WriteDefault(path); err != nil {
		t.Fatal(err)
	}
	manager, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := Default()
	changed.Monitor.Interval = 25 * time.Second
	// This edit occurs after Load and before Watch starts, reproducing the
	// startup race without depending on a goroutine's scheduling or a sleep.
	if err := Save(path, changed); err != nil {
		t.Fatal(err)
	}
	rejected := make(chan struct{}, 1)
	previousLogger := slog.Default()
	// SetDefault also rewires the standard logger, so use an independent handler.
	slog.SetDefault(slog.New(reloadLogHandler{Handler: slog.NewTextHandler(io.Discard, nil), rejected: rejected}))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	changes := make(chan Config, 3)
	done := make(chan struct{})
	go func() {
		defer close(done)
		manager.Watch(ctx, 5*time.Millisecond, func(cfg Config) {
			select {
			case changes <- cfg:
			case <-ctx.Done():
			}
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("configuration watch did not stop after cancellation")
		}
	})
	awaitChange := func(want time.Duration) {
		t.Helper()
		select {
		case cfg := <-changes:
			if cfg.Monitor.Interval != want {
				t.Fatalf("reload interval: got %s, want %s", cfg.Monitor.Interval, want)
			}
		case <-ctx.Done():
			t.Fatal("configuration reload was not observed before deadline")
		}
	}
	awaitChange(25 * time.Second)
	if err := os.WriteFile(path, []byte("monitor:\n  interval: 0s\n"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-rejected:
	case <-ctx.Done():
		t.Fatal("invalid configuration was not inspected before deadline")
	}
	if got := manager.Snapshot().Monitor.Interval; got != 25*time.Second {
		t.Fatalf("invalid reload replaced last valid config: %s", got)
	}
	select {
	case <-changes:
		t.Fatal("invalid configuration triggered a change callback")
	default:
	}
	changed.Monitor.Interval = 35 * time.Second
	if err := Save(path, changed); err != nil {
		t.Fatal(err)
	}
	awaitChange(35 * time.Second)
}
