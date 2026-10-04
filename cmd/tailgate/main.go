package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"tailgate/internal/audit"
	"tailgate/internal/command"
	"time"

	"golang.org/x/term"
	"tailgate/internal/auth"
	"tailgate/internal/config"
	"tailgate/internal/secret"
	"tailgate/internal/service"
	"tailgate/internal/sshpool"
	"tailgate/internal/store"
)

var version = "dev"
var input = bufio.NewReader(os.Stdin)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := execute(ctx, os.Args[1:]); err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}
func defaultDir() string {
	if runtime.GOOS == "windows" {
		p := os.Getenv("ProgramData")
		if p == "" {
			p = `C:\ProgramData`
		}
		return filepath.Join(p, "Tailgate")
	}
	return "./data"
}
func parseArgs(args []string) (string, []string, error) {
	dir := defaultDir()
	out := []string{}
	for i := 0; i < len(args); i++ {
		if args[i] == "--data-dir" {
			i++
			if i == len(args) {
				return "", nil, errors.New("--data-dir needs a path")
			}
			dir = args[i]
		} else if strings.HasPrefix(args[i], "--data-dir=") {
			dir = strings.TrimPrefix(args[i], "--data-dir=")
		} else {
			out = append(out, args[i])
		}
	}
	abs, e := filepath.Abs(dir)
	return abs, out, e
}
func prompt(label string) (string, error) {
	fmt.Print(label + ": ")
	s, e := input.ReadString('\n')
	if e != nil {
		return "", fmt.Errorf("read %s: %w", label, e)
	}
	return strings.TrimSpace(s), nil
}
func password(label string) (string, error) {
	fmt.Print(label + ": ")
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("password input requires an interactive terminal (input is never echoed)")
	}
	b, e := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if e != nil {
		return "", e
	}
	if len(b) == 0 {
		return "", errors.New("password cannot be empty")
	}
	return string(b), nil
}
func newPassword() (string, error) {
	p, e := password("密码")
	if e != nil {
		return "", e
	}
	q, e := password("确认密码")
	if e != nil {
		return "", e
	}
	if p != q {
		return "", errors.New("passwords do not match")
	}
	return p, nil
}
func execute(ctx context.Context, args []string) error {
	dir, args, e := parseArgs(args)
	if e != nil {
		return e
	}
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "version":
		fmt.Println("Tailgate", version)
		return nil
	case "help", "--help", "-h":
		return usage()
	case "init":
		return initialize(ctx, dir)
	case "run":
		return run(ctx, dir)
	case "install", "uninstall", "start", "stop", "restart", "status":
		return serviceControl(ctx, dir, args[0])
	}
	m, e := config.Load(filepath.Join(dir, "config.yaml"))
	if e != nil {
		return fmt.Errorf("load config (run tailgate init first): %w", e)
	}
	return administrative(ctx, dir, m, args)
}

// Administrative CLI records contain operation metadata, never input secrets.
func administrative(ctx context.Context, dir string, m *config.Manager, args []string) (err error) {
	db, err := store.Open(ctx, filepath.Join(dir, "tailgate.db"))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	writer, err := audit.New(db, m.Snapshot().Audit)
	if err != nil {
		return err
	}
	defer func() {
		flushCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		err = errors.Join(err, writer.Close(flushCtx))
	}()
	actor := os.Getenv("USERNAME")
	if actor == "" {
		actor = os.Getenv("USER")
	}
	if actor == "" {
		actor = "local"
	}
	action := "cli." + args[0]
	if len(args) > 1 {
		action += "." + args[1]
	}
	event := audit.Event{Source: "web", Actor: "cli:" + actor, ClientIP: "local", Action: action}
	if args[0] == "host" && len(args) > 2 && args[1] != "add" {
		event.Host = args[2]
	}
	if args[0] == "host" && len(args) > 1 && args[1] == "test" {
		event.Command = sshpool.TestCommand
	}
	started := time.Now()
	begin := event
	begin.Action += ".started"
	if err = writer.Record(begin); err != nil {
		return err
	}
	defer func() {
		event.DurationMS = time.Since(started).Milliseconds()
		exit := 0
		if err != nil {
			exit = 1
			event.Error = err.Error()
		}
		event.ExitCode = &exit
		err = errors.Join(err, writer.Record(event))
	}()
	switch args[0] {
	case "host":
		return hostCommand(command.WithIdentity(ctx, command.Identity{Source: "web", Actor: event.Actor, ClientIP: "local"}), dir, m, args[1:], writer)
	case "token":
		return tokenCommand(m, args[1:])
	case "user":
		return userCommand(ctx, db, args[1:])
	case "firewall":
		return firewall(m.Snapshot())
	default:
		return fmt.Errorf("unknown command %q; use tailgate help", args[0])
	}
}

func usage() error {
	fmt.Println(`Tailgate — SSH 网关
  tailgate [--data-dir PATH] init | run | version
  tailgate host add | list | remove NAME | test NAME | test --all | set-password NAME
  tailgate user add NAME | passwd NAME | remove NAME
  tailgate token create NAME | list | revoke NAME
  tailgate install | uninstall | start | stop | restart | status
  tailgate firewall`)
	return nil
}
func initialize(ctx context.Context, dir string) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	if _, e := secret.New(dir); e != nil {
		return e
	}
	path := filepath.Join(dir, "config.yaml")
	if _, e := os.Stat(path); os.IsNotExist(e) {
		if e = config.WriteDefault(path); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	if _, e := config.Load(path); e != nil {
		return e
	}
	db, e := store.Open(ctx, filepath.Join(dir, "tailgate.db"))
	if e != nil {
		return e
	}
	defer db.Close()
	users, e := db.Users(ctx)
	if e != nil {
		return e
	}
	if len(users) == 0 {
		name, e := prompt("第一个管理员用户名")
		if e != nil {
			return e
		}
		p, e := newPassword()
		if e != nil {
			return e
		}
		if e = db.CreateUser(ctx, name, p, true); e != nil {
			return e
		}
	}
	fmt.Println("初始化完成：", dir)
	return nil
}
func tokenCommand(m *config.Manager, args []string) error {
	if len(args) == 0 {
		return errors.New("token expects create/list/revoke")
	}
	if args[0] == "list" {
		for _, t := range m.Snapshot().MCP.Tokens {
			fmt.Println(t.Name)
		}
		return nil
	}
	if len(args) != 2 {
		return errors.New("token create/revoke requires a name")
	}
	name := args[1]
	switch args[0] {
	case "create":
		token, e := auth.Generate()
		if e != nil {
			return e
		}
		e = m.Update(func(c *config.Config) error {
			for _, t := range c.MCP.Tokens {
				if t.Name == name {
					return errors.New("token name already exists")
				}
			}
			c.MCP.Tokens = append(c.MCP.Tokens, config.Token{Name: name, Hash: auth.Hash(token)})
			return nil
		})
		if e != nil {
			return e
		}
		fmt.Println("仅显示一次，请安全保存：", token)
		return nil
	case "revoke":
		return m.Update(func(c *config.Config) error {
			for i, t := range c.MCP.Tokens {
				if t.Name == name {
					c.MCP.Tokens = append(c.MCP.Tokens[:i], c.MCP.Tokens[i+1:]...)
					return nil
				}
			}
			return errors.New("token not found")
		})
	default:
		return errors.New("unknown token operation")
	}
}
func userCommand(ctx context.Context, db *store.Store, args []string) error {
	if len(args) != 2 {
		return errors.New("user add/passwd/remove requires a username")
	}
	switch args[0] {
	case "add":
		p, e := newPassword()
		if e != nil {
			return e
		}
		return db.CreateUser(ctx, args[1], p, true)
	case "passwd":
		p, e := newPassword()
		if e != nil {
			return e
		}
		return db.SetPassword(ctx, args[1], p)
	case "remove":
		return db.DeleteUser(ctx, args[1])
	default:
		return errors.New("unknown user operation")
	}
}
func hostCommand(ctx context.Context, dir string, m *config.Manager, args []string, writer *audit.Writer) error {
	if len(args) == 0 {
		return errors.New("host expects add/list/remove/test/set-password")
	}
	p, e := secret.New(dir)
	if e != nil {
		return e
	}
	switch args[0] {
	case "list":
		for _, h := range m.Snapshot().Hosts {
			fmt.Printf("%s\t%s:%d\t%s\t%s\n", h.Name, h.Address, h.Port, h.Username, strings.Join(h.Tags, ","))
		}
		return nil
	case "add":
		h := config.Host{Port: 22}
		if h.Name, e = prompt("主机名称"); e != nil {
			return e
		}
		if h.Address, e = prompt("Tailscale IP / MagicDNS"); e != nil {
			return e
		}
		port, e := prompt("SSH 端口（默认 22）")
		if e != nil {
			return e
		}
		if port != "" {
			h.Port, e = strconv.Atoi(port)
			if e != nil {
				return e
			}
		}
		if h.Username, e = prompt("SSH 用户名"); e != nil {
			return e
		}
		plain, e := password("SSH 密码")
		if e != nil {
			return e
		}
		h.PasswordEnc, e = p.Encrypt(plain)
		if e != nil {
			return e
		}
		tags, e := prompt("标签（逗号分隔）")
		if e != nil {
			return e
		}
		if tags != "" {
			for _, t := range strings.Split(tags, ",") {
				h.Tags = append(h.Tags, strings.TrimSpace(t))
			}
		}
		if h.Description, e = prompt("描述（可留空）"); e != nil {
			return e
		}
		sudo, e := prompt("自动注入 sudo 密码（y/N）")
		if e != nil {
			return e
		}
		h.SudoPasswordInject = strings.EqualFold(sudo, "y")
		return m.Update(func(c *config.Config) error {
			if _, ok := c.FindHost(h.Name); ok {
				return errors.New("host already exists")
			}
			c.Hosts = append(c.Hosts, h)
			return nil
		})
	case "remove", "set-password":
		if len(args) != 2 {
			return errors.New("host operation requires a name")
		}
		var enc string
		if args[0] == "set-password" {
			plain, e := password("SSH 新密码")
			if e != nil {
				return e
			}
			enc, e = p.Encrypt(plain)
			if e != nil {
				return e
			}
		}
		return m.Update(func(c *config.Config) error {
			for i, h := range c.Hosts {
				if h.Name == args[1] {
					if args[0] == "remove" {
						c.Hosts = append(c.Hosts[:i], c.Hosts[i+1:]...)
					} else {
						c.Hosts[i].PasswordEnc = enc
					}
					return nil
				}
			}
			return errors.New("host not found")
		})
	case "test":
		if len(args) != 2 {
			return errors.New("host test expects NAME or --all")
		}
		c := m.Snapshot()
		pool, e := sshpool.New(c.SSH, dir, p.Decrypt)
		if e != nil {
			return e
		}
		defer pool.Close()
		if e = pool.UpdateHosts(c.Hosts); e != nil {
			return e
		}
		names := []string{args[1]}
		if args[1] == "--all" {
			names = nil
			for _, h := range c.Hosts {
				names = append(names, h.Name)
			}
		}
		var failures []error
		for _, name := range names {
			identity := command.IdentityFrom(ctx)
			event := audit.Event{Source: "web", Actor: identity.Actor, ClientIP: "local", Host: name, Action: "host.test", Command: sshpool.TestCommand}
			begin := event
			begin.Action += ".started"
			if e := writer.Record(begin); e != nil {
				return e
			}
			started := time.Now()
			r, e := pool.Test(ctx, name)
			event.DurationMS = time.Since(started).Milliseconds()
			exit := 0
			if e != nil {
				exit = 1
				event.Error = e.Error()
			}
			event.ExitCode = &exit
			summary, _ := json.Marshal(r)
			event.OutputExcerpt = string(summary)
			e = errors.Join(e, writer.Record(event))
			b, _ := json.MarshalIndent(r, "", "  ")
			fmt.Println(string(b))
			if e != nil {
				failures = append(failures, fmt.Errorf("%s: %w", name, e))
			}
		}
		return errors.Join(failures...)
	default:
		return errors.New("unknown host operation")
	}
}

func run(ctx context.Context, dir string) error { return service.Run(ctx, dir, version) }
func serviceControl(ctx context.Context, dir, action string) error {
	return service.Control(ctx, dir, version, action)
}
func firewall(c config.Config) error {
	_, port, err := net.SplitHostPort(c.Server.Listen)
	if err != nil {
		return err
	}
	networks := make([]string, len(c.Server.AllowedCIDRs))
	for i, cidr := range c.Server.AllowedCIDRs {
		networks[i] = "'" + cidr + "'"
	}
	fmt.Printf("New-NetFirewallRule -DisplayName 'Tailgate LAN' -Direction Inbound -Action Allow -Protocol TCP -LocalPort %s -RemoteAddress @(%s)\n", port, strings.Join(networks, ", "))
	return nil
}
