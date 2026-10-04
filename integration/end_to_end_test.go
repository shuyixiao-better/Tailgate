//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"tailgate/internal/audit"
	"tailgate/internal/auth"
	"tailgate/internal/command"
	"tailgate/internal/config"
	"tailgate/internal/hosts"
	"tailgate/internal/mcpserver"
	"tailgate/internal/secret"
	"tailgate/internal/sshpool"
	"tailgate/internal/store"
	webserver "tailgate/internal/web"
)

const (
	developmentPasswordOne = "Tailgate-dev-one-2026!"
	developmentPasswordTwo = "Tailgate-dev-two-2026!"
	developmentToken       = "tailgate-integration-token-never-for-production"
	developmentWebPassword = "tailgate-integration-admin-password"
	fixturesPath           = "/tmp/tailgate-fixtures"
)

type fixture struct {
	cfg     *config.Manager
	pool    *sshpool.Pool
	db      *store.Store
	audit   *audit.Writer
	monitor *hosts.Monitor
	tools   *command.Service
	website *webserver.Server
	http    *httptest.Server
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	for _, port := range []int{19721, 19722} {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err != nil {
			t.Fatalf("SSH integration container on port %d is unavailable; run docker compose up -d --build --wait: %v", port, err)
		}
		_ = conn.Close()
	}
	dir := t.TempDir()
	protector, err := secret.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	one, err := protector.Encrypt(developmentPasswordOne)
	if err != nil {
		t.Fatal(err)
	}
	two, err := protector.Encrypt(developmentPasswordTwo)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.SSH.ConnectTimeout = 3 * time.Second
	cfg.SSH.DefaultCommandTimeout = 10 * time.Second
	cfg.SSH.MaxCommandTimeout = 20 * time.Second
	cfg.SSH.MaxOutputBytes = 4096
	cfg.SSH.KeepaliveInterval = time.Second
	cfg.MCP.Tokens = []config.Token{{Name: "integration-agent", Hash: auth.Hash(developmentToken)}}
	cfg.Hosts = []config.Host{
		{Name: "ssh-one", Address: "127.0.0.1", Port: 19721, Username: "alice", PasswordEnc: one, SudoPasswordInject: true, Tags: []string{"integration", "one"}},
		{Name: "ssh-two", Address: "127.0.0.1", Port: 19722, Username: "bob", PasswordEnc: two, SudoPasswordInject: true, Tags: []string{"integration", "two"}},
	}
	path := filepath.Join(dir, "config.yaml")
	if err := config.Save(path, cfg); err != nil {
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
	if err := db.CreateUser(context.Background(), "admin", developmentWebPassword, true); err != nil {
		t.Fatal(err)
	}
	writer, err := audit.New(db, cfg.Audit)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := sshpool.New(cfg.SSH, dir, protector.Decrypt)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.UpdateHosts(cfg.Hosts); err != nil {
		t.Fatal(err)
	}
	monitor := hosts.New(manager, pool)
	monitor.SetAudit(writer)
	tools := &command.Service{Config: manager, Pool: pool, Audit: writer, OverviewProvider: monitor}
	website, err := webserver.New(webserver.Options{Config: manager, Store: db, Pool: pool, Secrets: protector, Audit: writer, Tools: tools})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", mcpserver.New(manager, tools, "integration"))
	mux.Handle("/", website.Handler())
	server := httptest.NewServer(webserver.Wrap(manager, mux))
	f := &fixture{cfg: manager, pool: pool, db: db, audit: writer, monitor: monitor, tools: tools, website: website, http: server}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = website.Close(ctx)
		server.Close()
		_ = pool.Close()
		_ = writer.Close(ctx)
		_ = db.Close()
	})
	return f
}

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	copy.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(copy)
}

func mcpClient(t *testing.T, f *fixture) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	client := mcp.NewClient(&mcp.Implementation{Name: "Tailgate-container-integration", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: f.http.URL + "/mcp", DisableStandaloneSSE: true, HTTPClient: &http.Client{Transport: bearerTransport{developmentToken}}}, &mcp.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func call(t *testing.T, client *mcp.ClientSession, name string, args map[string]any) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil || result.IsError {
		t.Fatalf("MCP %s failed: %+v %v", name, result, err)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func direct(t *testing.T, f *fixture, host, cmd string) sshpool.Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := f.pool.Execute(ctx, host, cmd, sshpool.ExecOptions{})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("SSH %s command failed: %+v %v", host, result, err)
	}
	return result
}

func TestDockerEndToEnd(t *testing.T) {
	f := newFixture(t)
	client := mcpClient(t, f)
	t.Run("SSH identities environment truncation timeout sudo", func(t *testing.T) {
		for host, user := range map[string]string{"ssh-one": "alice", "ssh-two": "bob"} {
			result := direct(t, f, host, "id -un; printf '%s\\n' \"$LANG/$TERM/$PAGER/$SYSTEMD_PAGER\"; printf error >&2")
			if result.Stdout != user+"\nC.UTF-8/dumb/cat/cat\n" || result.Stderr != "error" {
				t.Fatalf("SSH identity/environment %+v", result)
			}
		}
		result, err := f.pool.Execute(context.Background(), "ssh-one", "printf out; printf err >&2; exit 7", sshpool.ExecOptions{})
		if err != nil || result.ExitCode != 7 || result.Stdout != "out" || result.Stderr != "err" {
			t.Fatalf("exit capture %+v %v", result, err)
		}
		result = direct(t, f, "ssh-one", "printf HEAD; seq 1 10000; printf TAIL; printf '\\377' >&2")
		if !result.Truncated || len(result.Stdout)+len(result.Stderr) > 4096 || !utf8.ValidString(result.Stderr) || !strings.HasPrefix(result.Stdout, "HEAD") || !strings.HasSuffix(result.Stdout, "TAIL") {
			t.Fatalf("bounded UTF8 output %+v", result)
		}
		_, err = f.pool.Execute(context.Background(), "ssh-one", "sleep 30", sshpool.ExecOptions{Timeout: 100 * time.Millisecond})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("timeout missing: %v", err)
		}
		waitRemoteGone(t, f, "pgrep -f '[s]leep 30' || true")
		if result := direct(t, f, "ssh-one", "printf recovered"); result.Stdout != "recovered" {
			t.Fatal(result)
		}
		redacted := call(t, client, "run_command", map[string]any{"host": "ssh-one", "command": "sudo cat /run/tailgate-test-password"})
		if redacted["exit_code"] != float64(0) || !strings.Contains(redacted["stdout"].(string), "[REDACTED]") || strings.Contains(fmt.Sprint(redacted), developmentPasswordOne) {
			t.Fatalf("sudo authentication/redaction %+v", redacted)
		}
	})
	t.Run("all ten official MCP tools and parameter semantics", func(t *testing.T) {
		listed, err := client.ListTools(context.Background(), nil)
		if err != nil || len(listed.Tools) != 10 {
			t.Fatalf("tool list %+v %v", listed, err)
		}
		list := call(t, client, "list_hosts", map[string]any{"tag": "integration"})
		if len(list["hosts"].([]any)) != 2 {
			t.Fatal(list)
		}
		overview := call(t, client, "host_overview", map[string]any{"host": "ssh-one", "refresh": true})
		if overview["online"] != true || overview["memory"] == nil || overview["cpu_cores"] == nil {
			t.Fatal(overview)
		}
		run := call(t, client, "run_command", map[string]any{"host": "ssh-two", "command": "pwd", "workdir": fixturesPath})
		if run["stdout"] != fixturesPath+"\n" {
			t.Fatal(run)
		}
		started := time.Now()
		multi := call(t, client, "run_command_multi", map[string]any{"tag": "integration", "command": "sleep 1; id -un"})
		results := multi["results"].(map[string]any)
		if len(results) != 2 || results["ssh-one"].(map[string]any)["stdout"] != "alice\n" || results["ssh-two"].(map[string]any)["stdout"] != "bob\n" || time.Since(started) > 1750*time.Millisecond {
			t.Fatalf("parallel host selection %+v took %s", multi, time.Since(started))
		}
		read := call(t, client, "read_file", map[string]any{"host": "ssh-one", "path": fixturesPath + "/sample.log", "offset_line": 2, "max_lines": 2})
		if read["total_lines"] != float64(5) || read["content"] != "Beta ERROR\nplain\n" {
			t.Fatal(read)
		}
		tail := call(t, client, "tail_log", map[string]any{"host": "ssh-one", "path": fixturesPath + "/sample.log", "lines": 5, "grep": "error", "ignore_case": true})
		if tail["stdout"] != "Beta ERROR\nerror second\n" {
			t.Fatal(tail)
		}
		for name, args := range map[string]map[string]any{
			"journal":        {"host": "ssh-one", "unit": "nginx.service", "lines": 5},
			"service_status": {"host": "ssh-one", "unit": "nginx.service"},
		} {
			value := call(t, client, name, args)
			// These Alpine fixtures intentionally lack systemd; the tool must still
			// return a structured command result with an explicit failure status.
			if value["exit_code"] == float64(0) || value["stderr"] == "" {
				t.Fatalf("missing unavailable-systemd error: %+v", value)
			}
		}
		dir := call(t, client, "list_dir", map[string]any{"host": "ssh-one", "path": fixturesPath, "all": true})
		entries := dir["entries"].([]any)
		hidden, quoted := false, false
		for _, raw := range entries {
			entry := raw.(map[string]any)
			name := entry["name"].(string)
			hidden = hidden || name == ".hidden"
			quoted = quoted || strings.Contains(name, "quoted '")
			if entry["permissions"] == "" || entry["modified_unix"] == "" {
				t.Fatal(entry)
			}
		}
		if !hidden || !quoted {
			t.Fatal(dir)
		}
		search := call(t, client, "search_files", map[string]any{"host": "ssh-one", "path": fixturesPath, "pattern": "*.log", "content_grep": "ERROR", "max_results": 10})
		if len(search["paths"].([]any)) != 2 {
			t.Fatal(search)
		}
		literal := call(t, client, "read_file", map[string]any{"host": "ssh-one", "path": fixturesPath + "/quoted ' name;$(echo bad).log", "max_lines": 5})
		if literal["content"] != "ERROR literal filename\n" {
			t.Fatalf("literal shell quoting %+v", literal)
		}
		for _, args := range []map[string]any{
			{"host": "ssh-one", "path": fixturesPath + "/missing", "pattern": "*.log"},
			{"host": "ssh-one", "path": fixturesPath, "pattern": "*.log", "content_grep": "["},
		} {
			assertToolError(t, client, "search_files", args, "remote_command_failed")
		}
		empty := call(t, client, "search_files", map[string]any{"host": "ssh-one", "path": fixturesPath, "pattern": "*.log", "content_grep": "no such matching text"})
		if len(empty["paths"].([]any)) != 0 {
			t.Fatal(empty)
		}
		newlinePath := fixturesPath + "/newline\nfile.txt"
		call(t, client, "run_command", map[string]any{"host": "ssh-one", "command": "printf 'match newline\\n' > " + sshpool.ShellQuote(newlinePath)})
		for _, grep := range []string{"", "match newline"} {
			newline := call(t, client, "search_files", map[string]any{"host": "ssh-one", "path": fixturesPath, "pattern": "newline*.txt", "content_grep": grep})
			paths := newline["paths"].([]any)
			if len(paths) != 1 || paths[0] != newlinePath {
				t.Fatalf("newline filename changed: %+v", newline)
			}
		}
		call(t, client, "run_command", map[string]any{"host": "ssh-one", "command": "mkdir -p " + fixturesPath + "/large; for i in $(seq 1 200); do : > \"" + fixturesPath + "/large/entry_${i}_012345678901234567890123456789.txt\"; done"})
		assertToolError(t, client, "list_dir", map[string]any{"host": "ssh-one", "path": fixturesPath + "/large"}, "output_truncated")
		assertToolError(t, client, "search_files", map[string]any{"host": "ssh-one", "path": fixturesPath + "/large", "pattern": "*.txt", "max_results": 200}, "output_truncated")
	})
	t.Run("cached status samples", func(t *testing.T) {
		for _, host := range []string{"ssh-one", "ssh-two"} {
			first, err := f.monitor.Collect(context.Background(), host)
			if err != nil || !first.Online || first.Memory == nil {
				t.Fatalf("first sample %+v %v", first, err)
			}
			time.Sleep(30 * time.Millisecond)
			second, err := f.monitor.Collect(context.Background(), host)
			if err != nil || second.CPUUsagePercent == nil || *second.CPUUsagePercent < 0 || *second.CPUUsagePercent > 100 {
				t.Fatalf("second sample %+v %v", second, err)
			}
			if second.FailedServicesAvailable {
				t.Fatal("Alpine fixture claimed systemd available")
			}
		}
	})
	t.Run("web authentication CSRF PTY and follow cleanup", func(t *testing.T) { testWeb(t, f) })
	t.Run("offline host preserves last successful sample", func(t *testing.T) {
		previous, ok := f.monitor.Get("ssh-two")
		if !ok || previous.LastSuccess == nil {
			t.Fatal("missing online baseline")
		}
		compose(t, "stop", "ssh-two")
		defer compose(t, "up", "-d", "--wait", "ssh-two")
		status, err := f.monitor.Collect(context.Background(), "ssh-two")
		if err == nil || status.Online || status.LastError == "" || status.Memory == nil || !status.LastSuccess.Equal(*previous.LastSuccess) || status.OSVersion != previous.OSVersion {
			t.Fatalf("offline cache %+v %v", status, err)
		}
	})
	t.Run("audit actor lifecycle and credential absence", func(t *testing.T) {
		if err := f.audit.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
		events, err := f.audit.Query(context.Background(), audit.Filter{Limit: 1000})
		if err != nil {
			t.Fatal(err)
		}
		actions := map[string]int{}
		mcpCount := 0
		for _, event := range events {
			actions[event.Action]++
			if event.Source == "mcp" {
				if event.Actor != "integration-agent" || event.ClientIP != "127.0.0.1" {
					t.Fatalf("MCP identity %+v", event)
				}
				mcpCount++
			}
		}
		if mcpCount < 22 || actions["terminal.started"] != 1 || actions["terminal.ended"] != 1 || actions["logs.started"] != 1 || actions["logs.ended"] != 1 {
			t.Fatalf("missing lifecycle audit mcp=%d actions=%v", mcpCount, actions)
		}
		data, _ := json.Marshal(events)
		for _, credential := range []string{developmentPasswordOne, developmentPasswordTwo, developmentToken, developmentWebPassword} {
			if bytes.Contains(data, []byte(credential)) {
				t.Fatalf("credential leaked into audit: %d bytes", len(credential))
			}
		}
	})
}

func assertToolError(t *testing.T, client *mcp.ClientSession, name string, args map[string]any, code string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil || !result.IsError {
		t.Fatalf("expected %s from %s: %+v %v", code, name, result, err)
	}
	data, _ := json.Marshal(result.StructuredContent)
	var value struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &value); err != nil || value.Error.Code != code {
		t.Fatalf("wrong structured error: %s %v", data, err)
	}
}

func compose(t *testing.T, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	parameters := append([]string{"compose", "-f", "../docker-compose.yml", "-p", "tailgate-integration"}, args...)
	output, err := exec.CommandContext(ctx, "docker", parameters...).CombinedOutput()
	if err != nil {
		t.Fatalf("compose fixture lifecycle %v failed: %s %v", args, output, err)
	}
}

func webRequest(t *testing.T, f *fixture, method, path string, body any, cookie *http.Cookie, csrf, origin string) (*http.Response, map[string]any) {
	t.Helper()
	data, _ := json.Marshal(body)
	req, err := http.NewRequest(method, f.http.URL+path, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var value map[string]any
	if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
		t.Fatal(err)
	}
	return response, value
}

func testWeb(t *testing.T, f *fixture) {
	t.Helper()
	response, _ := webRequest(t, f, "GET", "/api/hosts", nil, nil, "", "")
	if response.StatusCode != 401 {
		t.Fatal("unauthenticated Web access accepted")
	}
	response, _ = webRequest(t, f, "POST", "/api/login", map[string]string{"username": "admin", "password": developmentWebPassword}, nil, "", "")
	if response.StatusCode != 403 {
		t.Fatal("login without Origin accepted")
	}
	response, login := webRequest(t, f, "POST", "/api/login", map[string]string{"username": "admin", "password": developmentWebPassword}, nil, "", f.http.URL)
	if response.StatusCode != 200 || len(response.Cookies()) != 1 {
		t.Fatal(login)
	}
	cookie := response.Cookies()[0]
	csrf := login["csrf"].(string)
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || csrf == "" {
		t.Fatal("session cookie flags")
	}
	tool := map[string]any{"host": "ssh-one", "command": "printf web-authenticated"}
	response, _ = webRequest(t, f, "POST", "/api/tools/run_command", tool, cookie, "", f.http.URL)
	if response.StatusCode != 403 {
		t.Fatal("mutation without CSRF accepted")
	}
	response, run := webRequest(t, f, "POST", "/api/tools/run_command", tool, cookie, csrf, f.http.URL)
	if response.StatusCode != 200 || run["stdout"] != "web-authenticated" {
		t.Fatal(run)
	}
	wsBase := "ws" + strings.TrimPrefix(f.http.URL, "http")
	wsHeaders := http.Header{"Origin": []string{f.http.URL}, "Cookie": []string{cookie.String()}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, rejected, err := websocket.Dial(ctx, wsBase+"/ws/terminal?host=ssh-one", &websocket.DialOptions{HTTPHeader: wsHeaders})
	if err == nil || rejected == nil || rejected.StatusCode != 403 {
		t.Fatal("WebSocket without CSRF accepted")
	}
	terminal, _, err := websocket.Dial(ctx, wsBase+"/ws/terminal?host=ssh-one&csrf="+url.QueryEscape(csrf), &websocket.DialOptions{HTTPHeader: wsHeaders})
	if err != nil {
		t.Fatal(err)
	}
	if err := terminal.Write(ctx, websocket.MessageText, []byte(`{"type":"resize","cols":100,"rows":30}`)); err != nil {
		t.Fatal(err)
	}
	if err := terminal.Write(ctx, websocket.MessageBinary, []byte("echo $$ > "+fixturesPath+"/pty.pid; printf 'PTY_READY\\n'; stty size\n")); err != nil {
		t.Fatal(err)
	}
	readUntil(t, ctx, terminal, "30 100")
	_ = terminal.CloseNow()
	waitRemoteGone(t, f, "if kill -0 \"$(cat "+fixturesPath+"/pty.pid)\" 2>/dev/null; then printf alive; fi")
	logs, _, err := websocket.Dial(ctx, wsBase+"/ws/logs?host=ssh-one&path="+url.QueryEscape(fixturesPath+"/live.log")+"&csrf="+url.QueryEscape(csrf), &websocket.DialOptions{HTTPHeader: wsHeaders})
	if err != nil {
		t.Fatal(err)
	}
	readUntil(t, ctx, logs, "live initial")
	_ = direct(t, f, "ssh-one", "printf 'live appended\\n' >> "+fixturesPath+"/live.log")
	readUntil(t, ctx, logs, "live appended")
	_ = logs.CloseNow()
	waitRemoteGone(t, f, "pgrep -f '[t]ail -F -n 200 -- "+fixturesPath+"/live.log' || true")
	response, _ = webRequest(t, f, "POST", "/api/logout", map[string]any{}, cookie, csrf, f.http.URL)
	if response.StatusCode != 200 {
		t.Fatal("logout failed")
	}
	response, _ = webRequest(t, f, "GET", "/api/session", nil, cookie, "", "")
	if response.StatusCode != 401 {
		t.Fatal("logout did not invalidate session")
	}
}

func readUntil(t *testing.T, ctx context.Context, conn *websocket.Conn, want string) {
	t.Helper()
	var output strings.Builder
	for !strings.Contains(output.String(), want) {
		kind, data, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("WebSocket closed before %q: %s %v", want, output.String(), err)
		}
		if kind == websocket.MessageText {
			t.Fatalf("WebSocket stream error: %s", data)
		}
		output.Write(data)
	}
}

func waitRemoteGone(t *testing.T, f *fixture, command string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if result := direct(t, f, "ssh-one", command); strings.TrimSpace(result.Stdout) == "" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("remote process survived WebSocket disconnect: %s", command)
}
