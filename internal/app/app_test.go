package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"strings"
	"tailgate/internal/auth"
	"tailgate/internal/config"
	"tailgate/internal/store"
	"tailgate/internal/transport"
	"testing"
	"time"
)

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func TestHTTPSRuntimeLoginCookieAndCSRF(t *testing.T) {
	dir := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	cfg := config.Default()
	cfg.Server.Listen = address
	cfg.Server.TLS.Enabled = true
	cfg.SSH.MaxCommandTimeout = 2 * time.Second
	cfg.SSH.DefaultCommandTimeout = time.Second
	if err := config.Save(filepath.Join(dir, "config.yaml"), cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(context.Background(), filepath.Join(dir, "tailgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateUser(context.Background(), "https-admin", "HTTPSFixture2026!", true); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	serverTLS, err := transport.TLS(dir, cfg.Server)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(serverTLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	httpTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer httpTransport.CloseIdleConnections()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: httpTransport, Jar: jar, Timeout: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, dir, "https-test") }()
	t.Cleanup(func() {
		cancel()
		httpTransport.CloseIdleConnections()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("HTTPS shutdown did not finish")
		}
	})
	base := "https://" + address
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, err := client.Get(base + "/")
		if err == nil {
			response.Body.Close()
			if response.TLS == nil || response.Header.Get("Strict-Transport-Security") == "" {
				t.Fatal("missing verified TLS or HSTS")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("HTTPS runtime did not start", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	request, err := http.NewRequest(http.MethodPost, base+"/api/login", strings.NewReader(`{"username":"https-admin","password":"HTTPSFixture2026!"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", base)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var session store.Session
	err = json.NewDecoder(response.Body).Decode(&session)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || session.CSRF == "" {
		t.Fatal("HTTPS login failed", response.StatusCode, err)
	}
	cookies := response.Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("session cookie protection missing", cookies)
	}
	for _, withCSRF := range []bool{false, true} {
		request, _ := http.NewRequest(http.MethodPost, base+"/api/logout", nil)
		request.Header.Set("Origin", base)
		if withCSRF {
			request.Header.Set("X-CSRF-Token", session.CSRF)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		want := http.StatusForbidden
		if withCSRF {
			want = http.StatusOK
		}
		if response.StatusCode != want {
			t.Fatal("CSRF check", withCSRF, response.StatusCode)
		}
	}
	response, err = client.Get(base + "/api/session")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("logout session still authorized", response.StatusCode)
	}
}

func TestRuntimeMCPAndGracefulAuditFlush(t *testing.T) {
	dir := t.TempDir()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	listener.Close()
	token, e := auth.Generate()
	if e != nil {
		t.Fatal(e)
	}
	cfg := config.Default()
	cfg.Server.Listen = address
	cfg.MCP.Tokens = []config.Token{{Name: "app-test", Hash: auth.Hash(token)}}
	cfg.SSH.MaxCommandTimeout = 2 * time.Second
	cfg.SSH.DefaultCommandTimeout = time.Second
	if e = config.Save(filepath.Join(dir, "config.yaml"), cfg); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, dir, "test") }()
	defer cancel()
	client := &http.Client{Timeout: time.Second}
	base := "http://" + address
	deadline := time.Now().Add(5 * time.Second)
	for {
		r, e := client.Get(base + "/")
		if e == nil {
			r.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("runtime did not start", e)
		}
		time.Sleep(20 * time.Millisecond)
	}
	response, e := client.Get(base + "/")
	if e != nil {
		t.Fatal(e)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if !strings.Contains(string(body), "Tailgate") || response.Header.Get("X-Frame-Options") == "" || response.Header.Get("Content-Security-Policy") == "" {
		t.Fatal("missing embedded UI or security headers")
	}
	response, e = client.Post(base+"/mcp", "application/json", strings.NewReader(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("MCP unauthenticated", response.StatusCode)
	}
	sdk := mcp.NewClient(&mcp.Implementation{Name: "runtime-test", Version: "1"}, nil)
	session, e := sdk.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: base + "/mcp", HTTPClient: &http.Client{Transport: bearerTransport{token}}}, nil)
	if e != nil {
		t.Fatal(e)
	}
	result, e := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_hosts", Arguments: map[string]any{}})
	if e != nil || result.IsError {
		t.Fatal(result, e)
	}
	session.Close()
	cancel()
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown did not finish")
	}
	db, e := store.Open(context.Background(), filepath.Join(dir, "tailgate.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	var count int
	if e = db.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE source='mcp' AND actor='app-test'`).Scan(&count); e != nil || count != 2 {
		t.Fatal("audit not flushed", count, e)
	}
}
