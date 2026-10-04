package web

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"time"

	"tailgate/internal/audit"
	"tailgate/internal/store"
)

func secureEqual(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (s *Server) allowLogin(ip string) bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	now := time.Now()
	window := s.attempts[ip]
	if now.Sub(window.start) >= time.Minute {
		window = loginWindow{start: now}
	}
	if window.attempts >= 5 {
		return false
	}
	window.attempts++
	if len(s.attempts) > 4096 {
		for key, old := range s.attempts {
			if now.Sub(old.start) > time.Minute {
				delete(s.attempts, key)
			}
		}
	}
	s.attempts[ip] = window
	return true
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		fail(w, http.StatusForbidden, "origin_rejected", "登录请求来源校验失败")
		return
	}
	if !s.allowLogin(clientIP(r)) {
		w.Header().Set("Retry-After", "60")
		fail(w, http.StatusTooManyRequests, "login_limited", "登录尝试过于频繁，请一分钟后重试")
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &input) {
		return
	}
	if err := s.options.Audit.Health(); err != nil {
		fail(w, http.StatusServiceUnavailable, "audit_unavailable", "审计存储不可用")
		return
	}
	event := audit.Event{Source: "web", Actor: input.Username, ClientIP: clientIP(r), Action: "login"}
	user, err := s.options.Store.Authenticate(r.Context(), input.Username, input.Password)
	if err != nil {
		event.Error = "invalid credentials"
		if auditErr := s.options.Audit.Record(event); auditErr != nil {
			fail(w, http.StatusServiceUnavailable, "audit_unavailable", "审计存储不可用")
			return
		}
		if errors.Is(err, store.ErrInvalidCredentials) {
			fail(w, http.StatusUnauthorized, "invalid_credentials", "用户名或密码错误")
		} else {
			fail(w, http.StatusServiceUnavailable, "store_unavailable", "登录存储不可用")
		}
		return
	}
	session, err := s.options.Store.CreateSession(r.Context(), user, 12*time.Hour)
	if err != nil {
		report(w, err)
		return
	}
	if err := s.options.Audit.Record(event); err != nil {
		_ = s.options.Store.DeleteSession(r.Context(), session.Token)
		fail(w, http.StatusServiceUnavailable, "audit_unavailable", "审计存储不可用")
		return
	}
	s.rateMu.Lock()
	delete(s.attempts, clientIP(r))
	s.rateMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "tailgate_session", Value: session.Token, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: int((12 * time.Hour).Seconds())})
	writeJSON(w, http.StatusOK, session)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, _ store.Session) error {
	cookie, err := r.Cookie("tailgate_session")
	if err == nil {
		if err := s.options.Store.DeleteSession(r.Context(), cookie.Value); err != nil {
			return err
		}
	}
	http.SetCookie(w, &http.Cookie{Name: "tailgate_session", Value: "", Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}
