package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tailgate/internal/audit"
	"tailgate/internal/auth"
	"tailgate/internal/config"
	"tailgate/internal/store"
)

func (s *Server) routes() {
	s.mux.HandleFunc("POST /api/login", s.login)
	s.mux.HandleFunc("GET /api/session", s.protected(false, false, "", func(w http.ResponseWriter, r *http.Request, session store.Session) error {
		writeJSON(w, http.StatusOK, session)
		return nil
	}))
	s.mux.HandleFunc("POST /api/logout", s.protected(false, true, "logout", s.logout))
	s.mux.HandleFunc("GET /api/hosts", s.protected(false, false, "", func(w http.ResponseWriter, r *http.Request, _ store.Session) error {
		result, err := s.options.Tools.Call(r.Context(), "list_hosts", map[string]any{"tag": r.URL.Query().Get("tag")})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, result)
		return nil
	}))
	s.mux.HandleFunc("GET /api/hosts/{host}", s.protected(false, false, "", func(w http.ResponseWriter, r *http.Request, _ store.Session) error {
		result, err := s.options.Tools.Call(r.Context(), "host_overview", map[string]any{"host": r.PathValue("host"), "refresh": r.URL.Query().Get("refresh") == "true"})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, result)
		return nil
	}))
	s.mux.HandleFunc("POST /api/tools/{tool}", s.protected(false, true, "", func(w http.ResponseWriter, r *http.Request, _ store.Session) error {
		var args map[string]any
		if !decode(w, r, &args) {
			return nil
		}
		result, err := s.options.Tools.Call(r.Context(), r.PathValue("tool"), args)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, result)
		return nil
	}))
	s.mux.HandleFunc("POST /api/hosts", s.protected(true, true, "host.add", s.addHost))
	s.mux.HandleFunc("PUT /api/hosts/{host}", s.protected(true, true, "host.update", s.updateHost))
	s.mux.HandleFunc("DELETE /api/hosts/{host}", s.protected(true, true, "host.remove", s.removeHost))
	s.mux.HandleFunc("POST /api/hosts/{host}/test", s.protected(true, true, "host.test", func(w http.ResponseWriter, r *http.Request, _ store.Session) error {
		result, err := s.options.Pool.Test(r.Context(), r.PathValue("host"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, result)
		return nil
	}))
	s.mux.HandleFunc("POST /api/hosts/{host}/key-confirm", s.protected(true, true, "host.key_confirm", func(w http.ResponseWriter, r *http.Request, _ store.Session) error {
		var input struct {
			Fingerprint string `json:"fingerprint"`
		}
		if !decode(w, r, &input) {
			return nil
		}
		if input.Fingerprint == "" {
			return errors.New("请提供已核对的主机指纹")
		}
		result, err := s.options.Pool.ConfirmHostKeyExpected(r.Context(), r.PathValue("host"), input.Fingerprint)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, result)
		return nil
	}))
	s.mux.HandleFunc("GET /api/settings", s.protected(true, false, "settings.view", s.settings))
	s.mux.HandleFunc("GET /api/host-keys", s.protected(true, false, "host_keys.list", func(w http.ResponseWriter, r *http.Request, _ store.Session) error {
		writeJSON(w, http.StatusOK, map[string]any{"host_keys": s.options.Pool.KnownHosts()})
		return nil
	}))
	s.mux.HandleFunc("GET /api/audit", s.protected(false, false, "audit.query", s.queryAudit))
	s.mux.HandleFunc("GET /api/tokens", s.protected(true, false, "tokens.list", func(w http.ResponseWriter, r *http.Request, _ store.Session) error {
		writeJSON(w, http.StatusOK, map[string]any{"tokens": s.options.Config.Snapshot().MCP.Tokens})
		return nil
	}))
	s.mux.HandleFunc("POST /api/tokens", s.protected(true, true, "token.create", s.createToken))
	s.mux.HandleFunc("DELETE /api/tokens/{name}", s.protected(true, true, "token.revoke", s.revokeToken))
	s.mux.HandleFunc("GET /api/users", s.protected(true, false, "users.list", func(w http.ResponseWriter, r *http.Request, _ store.Session) error {
		users, err := s.options.Store.Users(r.Context())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": users})
		return nil
	}))
	s.mux.HandleFunc("POST /api/users", s.protected(true, true, "user.add", s.addUser))
	s.mux.HandleFunc("POST /api/users/{name}/password", s.protected(true, true, "user.password", s.setUserPassword))
	s.mux.HandleFunc("DELETE /api/users/{name}", s.protected(true, true, "user.remove", s.removeUser))
	s.mux.HandleFunc("GET /ws/terminal", s.terminal)
	s.mux.HandleFunc("GET /ws/logs", s.logs)
	s.mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		fail(w, http.StatusNotFound, "not_found", "API 路径不存在")
	})
	if s.options.Assets != nil {
		s.mux.Handle("/", s.options.Assets)
	} else {
		s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	}
}

type hostInput struct {
	Name               string   `json:"name"`
	Address            string   `json:"address"`
	Port               int      `json:"port"`
	Username           string   `json:"username"`
	Password           string   `json:"password"`
	SudoPasswordInject bool     `json:"sudo_password_inject"`
	Tags               []string `json:"tags"`
	Description        string   `json:"description"`
}

func (s *Server) inputHost(input hostInput, existing config.Host) (config.Host, error) {
	if input.Port == 0 {
		input.Port = 22
	}
	if input.Name == "" {
		input.Name = existing.Name
	}
	password := existing.PasswordEnc
	if input.Password != "" {
		var err error
		password, err = s.options.Secrets.Encrypt(input.Password)
		if err != nil {
			return config.Host{}, err
		}
	}
	return config.Host{Name: input.Name, Address: input.Address, Port: input.Port, Username: input.Username, PasswordEnc: password, SudoPasswordInject: input.SudoPasswordInject, Tags: input.Tags, Description: input.Description}, nil
}

func (s *Server) addHost(w http.ResponseWriter, r *http.Request, _ store.Session) error {
	var input hostInput
	if !decode(w, r, &input) {
		return nil
	}
	host, err := s.inputHost(input, config.Host{})
	if err != nil {
		return err
	}
	if err := s.options.Config.Update(func(cfg *config.Config) error {
		if _, exists := cfg.FindHost(host.Name); exists {
			return fmt.Errorf("主机 %s 已存在", host.Name)
		}
		cfg.Hosts = append(cfg.Hosts, host)
		return nil
	}); err != nil {
		return err
	}
	if err := s.options.Pool.SyncConfig(s.options.Config); err != nil {
		return fmt.Errorf("配置已保存，但 SSH 主机同步失败: %w", err)
	}
	writeJSON(w, http.StatusCreated, host)
	return nil
}

func (s *Server) updateHost(w http.ResponseWriter, r *http.Request, _ store.Session) error {
	var input hostInput
	if !decode(w, r, &input) {
		return nil
	}
	name := r.PathValue("host")
	var host config.Host
	if err := s.options.Config.Update(func(cfg *config.Config) error {
		existing, ok := cfg.FindHost(name)
		if !ok {
			return store.ErrNotFound
		}
		var err error
		host, err = s.inputHost(input, existing)
		if err != nil {
			return err
		}
		for i, old := range cfg.Hosts {
			if old.Name == name {
				cfg.Hosts[i] = host
				return nil
			}
		}
		return store.ErrNotFound
	}); err != nil {
		return err
	}
	if err := s.options.Pool.SyncConfig(s.options.Config); err != nil {
		return fmt.Errorf("配置已保存，但 SSH 主机同步失败: %w", err)
	}
	writeJSON(w, http.StatusOK, host)
	return nil
}

func (s *Server) removeHost(w http.ResponseWriter, r *http.Request, _ store.Session) error {
	name := r.PathValue("host")
	if err := s.options.Config.Update(func(cfg *config.Config) error {
		for i, host := range cfg.Hosts {
			if host.Name == name {
				cfg.Hosts = append(cfg.Hosts[:i], cfg.Hosts[i+1:]...)
				return nil
			}
		}
		return store.ErrNotFound
	}); err != nil {
		return err
	}
	if err := s.options.Pool.SyncConfig(s.options.Config); err != nil {
		return fmt.Errorf("配置已保存，但 SSH 主机同步失败: %w", err)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request, _ store.Session) error {
	users, err := s.options.Store.Users(r.Context())
	if err != nil {
		return err
	}
	cfg := s.options.Config.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{"hosts": cfg.Hosts, "tokens": cfg.MCP.Tokens, "users": users, "host_keys": s.options.Pool.KnownHosts(), "server": cfg.Server})
	return nil
}

func (s *Server) queryAudit(w http.ResponseWriter, r *http.Request, _ store.Session) error {
	q := r.URL.Query()
	f := audit.Filter{Source: q.Get("source"), Host: q.Get("host"), Actor: q.Get("actor"), Keyword: q.Get("keyword")}
	for _, param := range []struct {
		name   string
		target *int
	}{{"limit", &f.Limit}, {"offset", &f.Offset}} {
		if raw := q.Get(param.name); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 0 {
				return fmt.Errorf("%s 必须为非负整数", param.name)
			}
			*param.target = value
		}
	}
	for _, param := range []struct {
		name   string
		target *time.Time
	}{{"since", &f.Since}, {"until", &f.Until}} {
		if raw := q.Get(param.name); raw != "" {
			value, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				return fmt.Errorf("%s 必须为带时区的 RFC3339 时间", param.name)
			}
			*param.target = value
		}
	}
	events, err := s.options.Audit.Query(r.Context(), f)
	if err != nil {
		return err
	}
	total, err := s.options.Audit.Count(r.Context(), f)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "total": total})
	return nil
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request, _ store.Session) error {
	var input struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &input) {
		return nil
	}
	token, err := auth.Generate()
	if err != nil {
		return err
	}
	if err := s.options.Config.Update(func(cfg *config.Config) error {
		for _, existing := range cfg.MCP.Tokens {
			if existing.Name == input.Name {
				return errors.New("token 名称已存在")
			}
		}
		cfg.MCP.Tokens = append(cfg.MCP.Tokens, config.Token{Name: strings.TrimSpace(input.Name), Hash: auth.Hash(token)})
		return nil
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]string{"name": strings.TrimSpace(input.Name), "token": token})
	return nil
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request, _ store.Session) error {
	if err := s.options.Config.Update(func(cfg *config.Config) error {
		for i, token := range cfg.MCP.Tokens {
			if token.Name == r.PathValue("name") {
				cfg.MCP.Tokens = append(cfg.MCP.Tokens[:i], cfg.MCP.Tokens[i+1:]...)
				return nil
			}
		}
		return store.ErrNotFound
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func (s *Server) addUser(w http.ResponseWriter, r *http.Request, _ store.Session) error {
	var input struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Admin    bool   `json:"admin"`
	}
	if !decode(w, r, &input) {
		return nil
	}
	if err := s.options.Store.CreateUser(r.Context(), input.Name, input.Password, input.Admin); err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]bool{"ok": true})
	return nil
}

func (s *Server) setUserPassword(w http.ResponseWriter, r *http.Request, _ store.Session) error {
	var input struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &input) {
		return nil
	}
	if err := s.options.Store.SetPassword(r.Context(), r.PathValue("name"), input.Password); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func (s *Server) removeUser(w http.ResponseWriter, r *http.Request, _ store.Session) error {
	if err := s.options.Store.DeleteUser(r.Context(), r.PathValue("name")); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}
