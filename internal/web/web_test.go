package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailgate/internal/audit"
	"tailgate/internal/auth"
	"tailgate/internal/command"
	"tailgate/internal/config"
	"tailgate/internal/secret"
	"tailgate/internal/sshpool"
	"tailgate/internal/store"
)

type fixture struct {
	s       *Server
	manager *config.Manager
	db      *store.Store
	auditor *audit.Writer
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := config.WriteDefault(path); err != nil {
		t.Fatal(err)
	}
	manager, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(context.Background(), filepath.Join(dir, "tailgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateUser(context.Background(), "admin", "correct-admin-password", true); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateUser(context.Background(), "operator", "correct-operator-password", false); err != nil {
		t.Fatal(err)
	}
	protector, err := secret.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := sshpool.New(manager.Snapshot().SSH, dir, protector.Decrypt)
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := audit.New(db, manager.Snapshot().Audit)
	if err != nil {
		t.Fatal(err)
	}
	tools := &command.Service{Config: manager, Pool: pool, Audit: auditor}
	s, err := New(Options{Config: manager, Store: db, Pool: pool, Secrets: protector, Audit: auditor, Tools: tools})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Close(ctx)
		_ = pool.Close()
		_ = auditor.Close(ctx)
		_ = db.Close()
	})
	return fixture{s: s, manager: manager, db: db, auditor: auditor}
}

func request(t *testing.T, f fixture, method, path, body string, cookie *http.Cookie, csrf, origin string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://tailgate.test"+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:12345"
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	f.s.Handler().ServeHTTP(w, r)
	return w
}

func loginAs(t *testing.T, f fixture, name, password string) (*http.Cookie, store.Session) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": name, "password": password})
	w := request(t, f, "POST", "/api/login", string(body), nil, "", "http://tailgate.test")
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	var session store.Session
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookie count: %d", len(cookies))
	}
	return cookies[0], session
}

func TestAuthenticationCSRFAndCredentialIsolation(t *testing.T) {
	f := newFixture(t)
	w := request(t, f, "POST", "/api/login", `{"username":"admin","password":"correct-admin-password"}`, nil, "", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("login without Origin: %d", w.Code)
	}
	cookie, session := loginAs(t, f, "admin", "correct-admin-password")
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Secure {
		t.Fatalf("cookie: %#v", cookie)
	}
	if session.CSRF == "" || session.User.Name != "admin" {
		t.Fatalf("session: %#v", session)
	}
	w = request(t, f, "POST", "/api/tokens", `{"name":"test-agent"}`, cookie, "", "http://tailgate.test")
	if w.Code != http.StatusForbidden {
		t.Fatalf("write without CSRF: %d", w.Code)
	}
	w = request(t, f, "POST", "/api/tokens", `{"name":"test-agent"}`, cookie, session.CSRF, "http://evil.test")
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign origin: %d", w.Code)
	}
	w = request(t, f, "POST", "/api/tokens", `{"name":"test-agent"}`, cookie, session.CSRF, "http://tailgate.test")
	if w.Code != http.StatusCreated {
		t.Fatalf("create token: %d %s", w.Code, w.Body.String())
	}
	var response struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	tokens := f.manager.Snapshot().MCP.Tokens
	if len(tokens) != 1 || !auth.Match(response.Token, tokens[0].Hash) {
		t.Fatal("token plaintext/hash mismatch")
	}
	r := httptest.NewRequest("GET", "http://tailgate.test/api/session", nil)
	r.Header.Set("Authorization", "Bearer "+response.Token)
	bearerOnly := httptest.NewRecorder()
	f.s.Handler().ServeHTTP(bearerOnly, r)
	if bearerOnly.Code != http.StatusUnauthorized {
		t.Fatal("MCP credential accepted as Web session")
	}
	if err := f.auditor.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	events, err := f.auditor.Query(context.Background(), audit.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(events)
	for _, sensitive := range []string{"correct-admin-password", response.Token, cookie.Value} {
		if strings.Contains(string(encoded), sensitive) {
			t.Fatal("authentication secret entered audit")
		}
	}
	w = request(t, f, "POST", "/api/logout", `{}`, cookie, session.CSRF, "http://tailgate.test")
	if w.Code != http.StatusOK {
		t.Fatalf("logout: %d", w.Code)
	}
	w = request(t, f, "GET", "/api/session", "", cookie, "", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatal("logout did not invalidate session")
	}
}

func TestAdminHostEncryptionAndLastAdmin(t *testing.T) {
	f := newFixture(t)
	operator, operatorSession := loginAs(t, f, "operator", "correct-operator-password")
	w := request(t, f, "GET", "/api/settings", "", operator, "", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("operator settings: %d", w.Code)
	}
	w = request(t, f, "POST", "/api/users", `{"name":"other","password":"good-password","admin":true}`, operator, operatorSession.CSRF, "http://tailgate.test")
	if w.Code != http.StatusForbidden {
		t.Fatal("operator created administrator")
	}
	admin, session := loginAs(t, f, "admin", "correct-admin-password")
	w = request(t, f, "POST", "/api/hosts", `{"name":"web-01","address":"100.1.2.3","username":"ubuntu","password":"ssh-secret-password","tags":["prod"],"sudo_password_inject":true}`, admin, session.CSRF, "http://tailgate.test")
	if w.Code != http.StatusCreated || strings.Contains(w.Body.String(), "ssh-secret-password") || strings.Contains(w.Body.String(), "password_enc") {
		t.Fatalf("host create: %d %s", w.Code, w.Body.String())
	}
	host, ok := f.manager.Snapshot().FindHost("web-01")
	if !ok || host.PasswordEnc == "" || host.PasswordEnc == "ssh-secret-password" {
		t.Fatal("host secret unprotected")
	}
	w = request(t, f, "DELETE", "/api/users/admin", "", admin, session.CSRF, "http://tailgate.test")
	if w.Code != http.StatusConflict {
		t.Fatalf("last admin: %d %s", w.Code, w.Body.String())
	}
}

func TestLoginRateLimitAndDirectCIDR(t *testing.T) {
	f := newFixture(t)
	for i := range 6 {
		w := request(t, f, "POST", "/api/login", `{"username":"admin","password":"bad-password"}`, nil, "", "http://tailgate.test")
		want := http.StatusUnauthorized
		if i == 5 {
			want = http.StatusTooManyRequests
		}
		if w.Code != want {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	r := httptest.NewRequest("GET", "http://tailgate.test/", nil)
	r.RemoteAddr = "203.0.113.1:12345"
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	w := httptest.NewRecorder()
	Wrap(f.manager, next).ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal("trusted spoofed forwarded IP")
	}
	r.RemoteAddr = "127.0.0.1:12345"
	w = httptest.NewRecorder()
	Wrap(f.manager, next).ServeHTTP(w, r)
	if w.Code != http.StatusNoContent || !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self'") || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("security headers: %#v", w.Header())
	}
}

func TestWebSocketOriginCSRFAndShutdownCancellation(t *testing.T) {
	f := newFixture(t)
	cookie, session := loginAs(t, f, "admin", "correct-admin-password")
	w := request(t, f, "GET", "/ws/terminal?host=missing&csrf="+session.CSRF, "", cookie, "", "http://evil.test")
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign WS origin: %d", w.Code)
	}
	w = request(t, f, "GET", "/ws/terminal?host=missing", "", cookie, "", "http://tailgate.test")
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing WS CSRF: %d", w.Code)
	}
	r := httptest.NewRequest("GET", "http://tailgate.test/ws/terminal?csrf="+session.CSRF, nil)
	r.AddCookie(cookie)
	r.Header.Set("Origin", "http://tailgate.test")
	_, ctx, finish, ok := f.s.socketSession(httptest.NewRecorder(), r)
	if !ok {
		t.Fatal("socket session rejected")
	}
	done := make(chan error, 1)
	go func() { done <- f.s.Close(context.Background()) }()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("server close did not cancel live socket")
	}
	finish()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTerminalAuditDoesNotRetainEchoedCredentials(t *testing.T) {
	terminal := &streamSummary{}
	terminal.add([]byte(strings.Repeat("typed-password", 1000)))
	count, excerpt := terminal.event()
	if count != 14000 || excerpt != "" || len(terminal.head) != 0 || len(terminal.tail) != 0 {
		t.Fatal("terminal audit retained echoed credentials")
	}
	logs := &streamSummary{capture: true}
	logs.add([]byte("first log line\n" + strings.Repeat("middle", 3000) + "\nlast log line"))
	_, excerpt = logs.event()
	if !strings.Contains(excerpt, "first log line") || !strings.Contains(excerpt, "last log line") || !strings.Contains(excerpt, "truncated") {
		t.Fatal("log summary did not preserve head and tail")
	}
}
