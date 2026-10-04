package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"

	"tailgate/internal/audit"
	"tailgate/internal/command"
	"tailgate/internal/sshpool"
	"tailgate/internal/store"
)

func (s *Server) socketSession(w http.ResponseWriter, r *http.Request) (store.Session, context.Context, func(), bool) {
	if !sameOrigin(r) {
		fail(w, http.StatusForbidden, "origin_rejected", "WebSocket 来源校验失败")
		return store.Session{}, nil, nil, false
	}
	cookie, err := r.Cookie("tailgate_session")
	if err != nil {
		fail(w, http.StatusUnauthorized, "unauthorized", "请先登录")
		return store.Session{}, nil, nil, false
	}
	session, err := s.options.Store.GetSession(r.Context(), cookie.Value)
	if err != nil {
		fail(w, http.StatusUnauthorized, "unauthorized", "登录会话已失效")
		return store.Session{}, nil, nil, false
	}
	if !secureEqual(session.CSRF, r.URL.Query().Get("csrf")) {
		fail(w, http.StatusForbidden, "csrf_rejected", "WebSocket CSRF 校验失败")
		return store.Session{}, nil, nil, false
	}
	if err := s.options.Audit.Health(); err != nil {
		fail(w, http.StatusServiceUnavailable, "audit_unavailable", "审计存储不可用")
		return store.Session{}, nil, nil, false
	}
	s.streamMu.Lock()
	if s.closing {
		s.streamMu.Unlock()
		fail(w, http.StatusServiceUnavailable, "server_stopping", "服务正在退出")
		return store.Session{}, nil, nil, false
	}
	s.streams.Add(1)
	s.streamMu.Unlock()
	ctx, cancel := context.WithDeadline(r.Context(), session.ExpiresAt)
	stop := context.AfterFunc(s.ctx, cancel)
	// An established socket cannot outlive logout, password rotation or expiry.
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := s.options.Store.GetSession(ctx, cookie.Value); err != nil {
					cancel()
					return
				}
			}
		}
	}()
	finish := func() { stop(); cancel(); <-watchDone; s.streams.Done() }
	return session, ctx, finish, true
}

func socketError(ctx context.Context, conn *websocket.Conn, err error) {
	code := "stream_failed"
	var ce *command.Error
	var se *sshpool.Error
	if errors.As(err, &ce) {
		code = ce.Code
	} else if errors.As(err, &se) {
		code = se.Code
	}
	payload, _ := json.Marshal(map[string]any{"type": "error", "error": map[string]string{"code": code, "message": err.Error()}})
	timeout, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_ = conn.Write(timeout, websocket.MessageText, payload)
}

type streamSummary struct {
	mu         sync.Mutex
	head, tail []byte
	total      int64
	capture    bool
}

func (s *streamSummary) add(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total += int64(len(data))
	if !s.capture {
		return
	}
	if len(s.head) < 4096 {
		count := 4096 - len(s.head)
		if count > len(data) {
			count = len(data)
		}
		s.head = append(s.head, data[:count]...)
	}
	s.tail = append(s.tail, data...)
	if len(s.tail) > 4096 {
		s.tail = append([]byte(nil), s.tail[len(s.tail)-4096:]...)
	}
}
func (s *streamSummary) event() (int64, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.capture {
		return s.total, ""
	}
	if s.total <= 4096 {
		return s.total, audit.Excerpt(string(s.head), "")
	}
	if s.total <= 8192 {
		overlap := 8192 - int(s.total)
		return s.total, audit.Excerpt(string(s.head)+string(s.tail[overlap:]), "")
	}
	return s.total, audit.Excerpt(string(s.head)+"\n[… stream output excerpt …]\n"+string(s.tail), "")
}

func binaryPump(ctx context.Context, conn *websocket.Conn, reader io.Reader, summary *streamSummary) error {
	buffer := make([]byte, 16384)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			summary.add(buffer[:n])
			writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			writeErr := conn.Write(writeCtx, websocket.MessageBinary, buffer[:n])
			cancel()
			if writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func (s *Server) beginStream(r *http.Request, session store.Session, source, action, host, cmd string) (audit.Event, error) {
	event := audit.Event{Source: source, Actor: session.User.Name, ClientIP: clientIP(r), Host: host, Action: action, Command: cmd}
	begin := event
	begin.Action += ".started"
	return event, s.options.Audit.Record(begin)
}

func (s *Server) finishStream(event audit.Event, started time.Time, summary *streamSummary, err error) {
	event.Action += ".ended"
	event.DurationMS = time.Since(started).Milliseconds()
	event.OutputBytes, event.OutputExcerpt = summary.event()
	if event.Source == "terminal" {
		event.OutputExcerpt = ""
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		event.Error = err.Error()
	}
	if auditErr := s.options.Audit.Record(event); auditErr != nil {
		slog.Error("stream completion audit could not be persisted", "error", auditErr, "host", event.Host, "action", event.Action)
	}
}

func dimensions(r *http.Request) (int, int, error) {
	cols, rows := 80, 24
	for _, field := range []struct {
		name string
		ptr  *int
	}{{"cols", &cols}, {"rows", &rows}} {
		if value := r.URL.Query().Get(field.name); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 1000 {
				return 0, 0, fmt.Errorf("%s 必须在 1 至 1000 之间", field.name)
			}
			*field.ptr = n
		}
	}
	return cols, rows, nil
}

func (s *Server) terminal(w http.ResponseWriter, r *http.Request) {
	session, parent, finish, ok := s.socketSession(w, r)
	if !ok {
		return
	}
	defer finish()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	cols, rows, err := dimensions(r)
	if err != nil {
		report(w, err)
		return
	}
	host := r.URL.Query().Get("host")
	if _, ok := s.options.Config.Snapshot().FindHost(host); !ok {
		fail(w, http.StatusNotFound, "host_not_found", "主机不存在")
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(64 * 1024)
	stop := context.AfterFunc(ctx, func() { _ = conn.CloseNow() })
	defer stop()
	started := time.Now()
	summary := &streamSummary{}
	event, err := s.beginStream(r, session, "terminal", "terminal", host, "")
	if err != nil {
		socketError(ctx, conn, err)
		return
	}
	defer func() { s.finishStream(event, started, summary, err) }()
	pty, err := s.options.Pool.OpenPTY(ctx, host, cols, rows)
	if err != nil {
		socketError(ctx, conn, err)
		return
	}
	defer pty.Close()
	done := make(chan error, 2)
	go func() { done <- binaryPump(ctx, conn, pty, summary) }()
	go func() {
		for {
			kind, data, readErr := conn.Read(ctx)
			if readErr != nil {
				done <- readErr
				return
			}
			if kind == websocket.MessageBinary {
				_, readErr = pty.Write(data)
			} else {
				var input struct {
					Type string `json:"type"`
					Data string `json:"data"`
					Cols int    `json:"cols"`
					Rows int    `json:"rows"`
				}
				if readErr = json.Unmarshal(data, &input); readErr == nil {
					switch input.Type {
					case "input":
						_, readErr = pty.Write([]byte(input.Data))
					case "resize":
						readErr = pty.Resize(input.Cols, input.Rows)
					default:
						readErr = errors.New("未知终端消息类型")
					}
				}
			}
			if readErr != nil {
				done <- readErr
				return
			}
		}
	}()
	err = <-done
	cancel()
	_ = pty.Close()
	_ = conn.CloseNow()
	<-done
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	session, parent, finish, ok := s.socketSession(w, r)
	if !ok {
		return
	}
	defer finish()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	q := r.URL.Query()
	host := q.Get("host")
	if _, ok := s.options.Config.Snapshot().FindHost(host); !ok {
		fail(w, http.StatusNotFound, "host_not_found", "主机不存在")
		return
	}
	cmd, err := command.FollowCommand(q.Get("path"), q.Get("unit"), q.Get("grep"), q.Get("ignore_case") == "true")
	if err != nil {
		report(w, err)
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(1024)
	stop := context.AfterFunc(ctx, func() { _ = conn.CloseNow() })
	defer stop()
	started := time.Now()
	summary := &streamSummary{capture: true}
	event, err := s.beginStream(r, session, "web", "logs", host, cmd)
	if err != nil {
		socketError(ctx, conn, err)
		return
	}
	defer func() { s.finishStream(event, started, summary, err) }()
	stream, err := s.options.Pool.Stream(ctx, host, cmd)
	if err != nil {
		socketError(ctx, conn, err)
		return
	}
	defer stream.Close()
	done := make(chan error, 3)
	go func() { done <- binaryPump(ctx, conn, stream.Stdout, summary) }()
	go func() { done <- binaryPump(ctx, conn, stream.Stderr, summary) }()
	go func() { _, _, readErr := conn.Read(ctx); done <- readErr }()
	err = <-done
	cancel()
	_ = stream.Close()
	_ = conn.CloseNow()
	<-done
	<-done
}
