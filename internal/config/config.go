// Package config loads, validates and atomically updates Tailgate configuration.
package config

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server  Server  `yaml:"server" json:"server"`
	MCP     MCP     `yaml:"mcp" json:"mcp"`
	SSH     SSH     `yaml:"ssh" json:"ssh"`
	Monitor Monitor `yaml:"monitor" json:"monitor"`
	Audit   Audit   `yaml:"audit" json:"audit"`
	Hosts   []Host  `yaml:"hosts" json:"hosts"`
}

type Server struct {
	Listen       string   `yaml:"listen" json:"listen"`
	AllowedCIDRs []string `yaml:"allowed_cidrs" json:"allowed_cidrs"`
	TLS          TLS      `yaml:"tls" json:"tls"`
}

type TLS struct {
	Enabled        bool   `yaml:"enabled" json:"enabled"`
	AutoSelfSigned bool   `yaml:"auto_self_signed" json:"auto_self_signed"`
	CertFile       string `yaml:"cert_file,omitempty" json:"cert_file,omitempty"`
	KeyFile        string `yaml:"key_file,omitempty" json:"key_file,omitempty"`
}

type MCP struct {
	Enabled bool    `yaml:"enabled" json:"enabled"`
	Path    string  `yaml:"path" json:"path"`
	Tokens  []Token `yaml:"tokens" json:"tokens"`
}

type Token struct {
	Name string `yaml:"name" json:"name"`
	Hash string `yaml:"hash" json:"-"`
}

type SSH struct {
	ConnectTimeout        time.Duration `yaml:"connect_timeout" json:"connect_timeout"`
	KeepaliveInterval     time.Duration `yaml:"keepalive_interval" json:"keepalive_interval"`
	DefaultCommandTimeout time.Duration `yaml:"default_command_timeout" json:"default_command_timeout"`
	MaxCommandTimeout     time.Duration `yaml:"max_command_timeout" json:"max_command_timeout"`
	MaxOutputBytes        int           `yaml:"max_output_bytes" json:"max_output_bytes"`
	MaxSessionsPerHost    int           `yaml:"max_sessions_per_host" json:"max_sessions_per_host"`
	HostKeyPolicy         string        `yaml:"host_key_policy" json:"host_key_policy"`
}

type Monitor struct {
	Interval time.Duration `yaml:"interval" json:"interval"`
}

type Audit struct {
	RetentionDays int `yaml:"retention_days" json:"retention_days"`
	QueueSize     int `yaml:"queue_size" json:"queue_size"`
}

type Host struct {
	Name               string   `yaml:"name" json:"name"`
	Address            string   `yaml:"address" json:"address"`
	Port               int      `yaml:"port" json:"port"`
	Username           string   `yaml:"username" json:"username"`
	PasswordEnc        string   `yaml:"password_enc" json:"-"`
	SudoPasswordInject bool     `yaml:"sudo_password_inject" json:"sudo_password_inject"`
	Tags               []string `yaml:"tags" json:"tags"`
	Description        string   `yaml:"description" json:"description"`
}

func Default() Config {
	return Config{
		Server:  Server{Listen: "0.0.0.0:8722", AllowedCIDRs: []string{"192.168.0.0/16", "10.0.0.0/8", "127.0.0.1/32", "::1/128"}, TLS: TLS{AutoSelfSigned: true}},
		MCP:     MCP{Enabled: true, Path: "/mcp", Tokens: []Token{}},
		SSH:     SSH{ConnectTimeout: 10 * time.Second, KeepaliveInterval: 30 * time.Second, DefaultCommandTimeout: 60 * time.Second, MaxCommandTimeout: 600 * time.Second, MaxOutputBytes: 262144, MaxSessionsPerHost: 8, HostKeyPolicy: "tofu"},
		Monitor: Monitor{Interval: 15 * time.Second}, Audit: Audit{RetentionDays: 90, QueueSize: 1024}, Hosts: []Host{},
	}
}

func (c Config) FindHost(name string) (Host, bool) {
	for _, host := range c.Hosts {
		if host.Name == name {
			host.Tags = append([]string(nil), host.Tags...)
			return host, true
		}
	}
	return Host{}, false
}

func (c Config) Validate() error {
	_, port, err := net.SplitHostPort(c.Server.Listen)
	if err != nil || port == "" {
		return fmt.Errorf("server.listen: expected an IP or hostname and port, got %q", c.Server.Listen)
	}
	if p, err := net.LookupPort("tcp", port); err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("server.listen: invalid port %q", port)
	}
	if len(c.Server.AllowedCIDRs) == 0 {
		return errors.New("server.allowed_cidrs: must contain at least one allowed network")
	}
	for i, cidr := range c.Server.AllowedCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("server.allowed_cidrs[%d]: %w", i, err)
		}
	}
	if c.Server.TLS.Enabled && !c.Server.TLS.AutoSelfSigned && (c.Server.TLS.CertFile == "" || c.Server.TLS.KeyFile == "") {
		return errors.New("server.tls: cert_file and key_file are required when auto_self_signed is false")
	}
	if !strings.HasPrefix(c.MCP.Path, "/") || strings.ContainsAny(c.MCP.Path, " ?#{}\r\n") || hasControl(c.MCP.Path) || c.MCP.Path == "/" || c.MCP.Path == "/api" || strings.HasPrefix(c.MCP.Path, "/api/") || strings.HasPrefix(c.MCP.Path, "/assets/") {
		return errors.New("mcp.path: must be an absolute HTTP path distinct from /, /api and /assets")
	}
	seen := map[string]bool{}
	for i, token := range c.MCP.Tokens {
		if strings.TrimSpace(token.Name) == "" || seen[token.Name] || hasControl(token.Name) {
			return fmt.Errorf("mcp.tokens[%d].name: name must be non-empty and unique", i)
		}
		seen[token.Name] = true
		if hash, err := hex.DecodeString(token.Hash); err != nil || len(hash) != sha256.Size {
			return fmt.Errorf("mcp.tokens[%d].hash: expected a SHA-256 hash encoded as 64 hexadecimal characters", i)
		}
	}
	for _, field := range []struct {
		name  string
		value time.Duration
	}{{"ssh.connect_timeout", c.SSH.ConnectTimeout}, {"ssh.keepalive_interval", c.SSH.KeepaliveInterval}, {"ssh.default_command_timeout", c.SSH.DefaultCommandTimeout}, {"ssh.max_command_timeout", c.SSH.MaxCommandTimeout}, {"monitor.interval", c.Monitor.Interval}} {
		if field.value <= 0 {
			return fmt.Errorf("%s: must be a positive duration", field.name)
		}
	}
	if c.SSH.DefaultCommandTimeout > c.SSH.MaxCommandTimeout {
		return errors.New("ssh.default_command_timeout: must not exceed ssh.max_command_timeout")
	}
	if c.SSH.MaxOutputBytes < 1024 {
		return errors.New("ssh.max_output_bytes: must be at least 1024")
	}
	if c.SSH.MaxSessionsPerHost < 1 || c.SSH.MaxSessionsPerHost > 256 {
		return errors.New("ssh.max_sessions_per_host: must be between 1 and 256")
	}
	if c.SSH.HostKeyPolicy != "tofu" {
		return errors.New("ssh.host_key_policy: only tofu is supported")
	}
	if c.Audit.RetentionDays < 1 || c.Audit.QueueSize < 1 {
		return errors.New("audit.retention_days and audit.queue_size: must be positive")
	}
	seen = map[string]bool{}
	for i, host := range c.Hosts {
		prefix := fmt.Sprintf("hosts[%d]", i)
		if strings.TrimSpace(host.Name) == "" || seen[host.Name] || strings.ContainsAny(host.Name, "/\\") || hasControl(host.Name) {
			return fmt.Errorf("%s.name: name must be non-empty, unique and contain no slash or control characters", prefix)
		}
		seen[host.Name] = true
		if strings.TrimSpace(host.Address) == "" || strings.ContainsAny(host.Address, " \t\r\n/\\\x00") {
			return fmt.Errorf("%s.address: expected an IP address or hostname", prefix)
		}
		if host.Port < 1 || host.Port > 65535 {
			return fmt.Errorf("%s.port: must be between 1 and 65535", prefix)
		}
		if strings.TrimSpace(host.Username) == "" || strings.ContainsAny(host.Username, "\r\n\x00") {
			return fmt.Errorf("%s.username: must be non-empty and contain no control characters", prefix)
		}
		if encrypted, err := base64.StdEncoding.DecodeString(host.PasswordEnc); err != nil || len(encrypted) < 28 {
			return fmt.Errorf("%s.password_enc: expected a base64 encrypted password; use tailgate host add or set-password", prefix)
		}
	}
	return nil
}

func hasControl(value string) bool {
	return strings.ContainsFunc(value, unicode.IsControl)
}

type Manager struct {
	mu     sync.RWMutex
	path   string
	config Config
}

func Load(path string) (*Manager, error) {
	cfg, err := read(path)
	if err != nil {
		return nil, err
	}
	return &Manager{path: path, config: cfg}, nil
}

func read(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration %s: %w", path, err)
	}
	cfg := Default()
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode configuration %s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("configuration %s: expected exactly one YAML document", path)
	}
	for i := range cfg.Hosts {
		if cfg.Hosts[i].Port == 0 {
			cfg.Hosts[i].Port = 22
		}
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("configuration %s: %w", path, err)
	}
	return cfg, nil
}

func (m *Manager) Path() string { return m.path }

func clone(cfg Config) Config {
	cfg.Server.AllowedCIDRs = append([]string(nil), cfg.Server.AllowedCIDRs...)
	cfg.MCP.Tokens = append([]Token(nil), cfg.MCP.Tokens...)
	cfg.Hosts = append([]Host(nil), cfg.Hosts...)
	for i := range cfg.Hosts {
		cfg.Hosts[i].Tags = append([]string(nil), cfg.Hosts[i].Tags...)
	}
	return cfg
}

func (m *Manager) Snapshot() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return clone(m.config)
}

func (m *Manager) Update(update func(*Config) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg := clone(m.config)
	if err := update(&cfg); err != nil {
		return err
	}
	if err := Save(m.path, cfg); err != nil {
		return err
	}
	m.config = clone(cfg)
	return nil
}

func (m *Manager) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, err := read(m.path)
	if err != nil {
		return err
	}
	m.config = cfg
	return nil
}

// Watch retains the last valid configuration when an external edit is invalid.
// onChange runs after the configuration is reloaded and outside the manager lock.
func (m *Manager) Watch(ctx context.Context, interval time.Duration, onChange func(Config)) {
	if interval <= 0 {
		interval = time.Second
	}
	// Load and Watch may be separated by service startup. Always inspect the
	// first observed file rather than silently baselining an intervening edit.
	var previous [sha256.Size]byte
	observed := false
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			data, err := os.ReadFile(m.path)
			if err != nil {
				slog.Warn("configuration watch could not read file", "error", err)
				continue
			}
			hash := sha256.Sum256(data)
			if observed && hash == previous {
				continue
			}
			previous = hash
			observed = true
			if err := m.Reload(); err != nil {
				slog.Warn("configuration reload rejected", "error", err)
				continue
			}
			if onChange != nil {
				onChange(m.Snapshot())
			}
		}
	}
}

func WriteDefault(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("configuration %s already exists", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check configuration: %w", err)
	}
	return Save(path, Default())
}

func Save(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	var document, template yaml.Node
	if err := document.Encode(cfg); err != nil {
		return fmt.Errorf("encode configuration: %w", err)
	}
	if err := yaml.Unmarshal([]byte(DefaultYAML), &template); err != nil {
		return fmt.Errorf("decode configuration comments: %w", err)
	}
	if len(template.Content) > 0 {
		copyComments(&document, template.Content[0])
	}
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return fmt.Errorf("encode configuration YAML: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("finish configuration YAML: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create configuration directory: %w", err)
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".tailgate-config-*")
	if err != nil {
		return fmt.Errorf("create temporary configuration: %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return fmt.Errorf("protect configuration: %w", err)
	}
	if _, err := file.Write(buffer.Bytes()); err != nil {
		file.Close()
		return fmt.Errorf("write configuration: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync configuration: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close configuration: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("replace configuration: %w", err)
	}
	return nil
}

func copyComments(destination, source *yaml.Node) {
	destination.HeadComment = source.HeadComment
	destination.LineComment = source.LineComment
	destination.FootComment = source.FootComment
	if destination.Kind != yaml.MappingNode || source.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(destination.Content); i += 2 {
		for j := 0; j+1 < len(source.Content); j += 2 {
			if destination.Content[i].Value == source.Content[j].Value {
				copyComments(destination.Content[i], source.Content[j])
				copyComments(destination.Content[i+1], source.Content[j+1])
				break
			}
		}
	}
}
