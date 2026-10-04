// Package web provides the authenticated human interface and live SSH streams.
package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"tailgate/internal/audit"
	"tailgate/internal/command"
	"tailgate/internal/config"
	"tailgate/internal/secret"
	"tailgate/internal/sshpool"
	"tailgate/internal/store"
)

type Options struct {
	Config  *config.Manager
	Store   *store.Store
	Pool    *sshpool.Pool
	Secrets *secret.Protector
	Audit   *audit.Writer
	Tools   *command.Service
	Assets  http.Handler
}

type Server struct {
	options     Options
	mux         *http.ServeMux
	ctx         context.Context
	cancel      context.CancelFunc
	rateMu      sync.Mutex
	attempts    map[string]loginWindow
	streamMu    sync.Mutex
	closing     bool
	streams     sync.WaitGroup
	cleanupDone chan struct{}
}

type loginWindow struct {
	attempts int
	start    time.Time
}

func New(options Options) (*Server, error) {
	if options.Config == nil || options.Store == nil || options.Pool == nil || options.Secrets == nil || options.Audit == nil || options.Tools == nil {
		return nil, errors.New("web config, store, pool, secrets, audit and tools are required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{options: options, mux: http.NewServeMux(), ctx: ctx, cancel: cancel, attempts: map[string]loginWindow{}, cleanupDone: make(chan struct{})}
	s.routes()
	go s.cleanupSessions()
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) cleanupSessions() {
	defer close(s.cleanupDone)
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
		if err := s.options.Store.CleanupSessions(ctx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Warn("expired session cleanup failed", "error", err)
		}
		cancel()
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) Close(ctx context.Context) error {
	s.streamMu.Lock()
	s.closing = true
	s.cancel()
	s.streamMu.Unlock()
	done := make(chan struct{})
	go func() { s.streams.Wait(); <-s.cleanupDone; close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("close live Web connections: %w", ctx.Err())
	}
}

// Wrap applies direct-source CIDR filtering and security headers to both Web and MCP.
// Forwarded headers are deliberately ignored: Tailgate is a direct LAN gateway.
func Wrap(manager *config.Manager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "" || strings.ContainsAny(r.Host, " \t\r\n;\"'<>/\\") {
			fail(w, http.StatusBadRequest, "invalid_host", "HTTP Host 无效")
			return
		}
		wsScheme := "ws"
		if r.TLS != nil {
			wsScheme = "wss"
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' "+wsScheme+"://"+r.Host+"; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		ip := net.ParseIP(clientIP(r))
		allowed := false
		for _, cidr := range manager.Snapshot().Server.AllowedCIDRs {
			_, network, err := net.ParseCIDR(cidr)
			if err == nil && ip != nil && network.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			fail(w, http.StatusForbidden, "source_denied", "来源 IP 不在允许网段内")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func sameOrigin(r *http.Request) bool {
	origin, err := url.Parse(r.Header.Get("Origin"))
	if err != nil || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.Path != "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return origin.Scheme == scheme && strings.EqualFold(origin.Host, r.Host)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func fail(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func report(w http.ResponseWriter, err error) {
	var ce *command.Error
	var se *sshpool.Error
	switch {
	case errors.As(err, &ce):
		status := http.StatusBadRequest
		if ce.Code == "audit_unavailable" {
			status = http.StatusServiceUnavailable
		}
		if ce.Code == "host_not_found" {
			status = http.StatusNotFound
		}
		fail(w, status, ce.Code, ce.Message)
	case errors.As(err, &se):
		fail(w, http.StatusBadGateway, se.Code, se.Error())
	case errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusNotFound, "not_found", "记录不存在")
	case errors.Is(err, store.ErrLastAdmin):
		fail(w, http.StatusConflict, "last_admin", "不能删除最后一个管理员")
	default:
		fail(w, http.StatusBadRequest, "operation_failed", err.Error())
	}
}

func decode(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		fail(w, http.StatusBadRequest, "invalid_json", "请求必须包含合法 JSON 参数")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		fail(w, http.StatusBadRequest, "invalid_json", "请求只能包含一个 JSON 对象")
		return false
	}
	return true
}

type protectedHandler func(http.ResponseWriter, *http.Request, store.Session) error

type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header { return b.header }
func (b *bufferedResponse) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}
func (b *bufferedResponse) Write(data []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(data)
}
func (b *bufferedResponse) commit(w http.ResponseWriter) {
	for key, values := range b.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	status := b.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(b.body.Bytes())
}

func (s *Server) protected(admin, csrf bool, action string, handler protectedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("tailgate_session")
		if err != nil {
			fail(w, http.StatusUnauthorized, "unauthorized", "请先登录")
			return
		}
		session, err := s.options.Store.GetSession(r.Context(), cookie.Value)
		if err != nil {
			fail(w, http.StatusUnauthorized, "unauthorized", "登录会话已失效")
			return
		}
		if admin && !session.User.Admin {
			fail(w, http.StatusForbidden, "admin_required", "此操作需要管理员权限")
			return
		}
		if csrf && (!sameOrigin(r) || !secureEqual(session.CSRF, r.Header.Get("X-CSRF-Token"))) {
			fail(w, http.StatusForbidden, "csrf_rejected", "请求来源或 CSRF 校验失败")
			return
		}
		ctx := command.WithIdentity(r.Context(), command.Identity{Source: "web", Actor: session.User.Name, ClientIP: clientIP(r)})
		r = r.WithContext(ctx)
		started := time.Now()
		var event audit.Event
		if action != "" {
			if err := s.options.Audit.Health(); err != nil {
				fail(w, http.StatusServiceUnavailable, "audit_unavailable", "审计存储不可用")
				return
			}
			event = audit.Event{Source: "web", Actor: session.User.Name, ClientIP: clientIP(r), Host: r.PathValue("host"), Action: action}
			if action == "host.test" {
				event.Command = sshpool.TestCommand
			}
			begin := event
			begin.Action += ".started"
			if err := s.options.Audit.Record(begin); err != nil {
				fail(w, http.StatusServiceUnavailable, "audit_unavailable", "审计存储不可用")
				return
			}
		}
		buffer := &bufferedResponse{header: make(http.Header)}
		err = handler(buffer, r, session)
		if action != "" {
			event.DurationMS = time.Since(started).Milliseconds()
			if action == "host.test" {
				code := 0
				if err != nil || buffer.status >= 400 {
					code = 1
				}
				event.ExitCode = &code
				if code == 0 {
					event.OutputExcerpt = audit.Excerpt(buffer.body.String(), "")
					event.OutputBytes = int64(buffer.body.Len())
				}
			}
			if err != nil {
				event.Error = err.Error()
			} else if buffer.status >= 400 {
				event.Error = fmt.Sprintf("HTTP %d", buffer.status)
			}
			if auditErr := s.options.Audit.Record(event); err == nil && auditErr != nil {
				err = &command.Error{Code: "audit_unavailable", Message: "操作完成后审计写入失败"}
			}
		}
		if err != nil {
			report(w, err)
		} else {
			buffer.commit(w)
		}
	}
}
