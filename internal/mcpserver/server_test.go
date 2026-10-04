package mcpserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"tailgate/internal/auth"
	"tailgate/internal/command"
	"tailgate/internal/config"
)

const testToken = "mcp-test-token-long-enough-for-a-fixture"

type callRecord struct {
	Name     string
	Args     map[string]any
	Identity command.Identity
}

type fakeCaller struct {
	mu         sync.Mutex
	calls      []callRecord
	rejections []callRecord
	block      bool
	started    chan struct{}
	cancelled  chan struct{}
}

func (f *fakeCaller) Call(ctx context.Context, name string, args map[string]any) (any, error) {
	f.mu.Lock()
	f.calls = append(f.calls, callRecord{Name: name, Args: args, Identity: command.IdentityFrom(ctx)})
	f.mu.Unlock()
	if f.block {
		close(f.started)
		<-ctx.Done()
		close(f.cancelled)
		return nil, &command.Error{Code: "cancelled", Message: "Command cancelled"}
	}
	for _, value := range args {
		if text, ok := value.(string); ok && strings.ContainsRune(text, 0) {
			return nil, &command.Error{Code: "invalid_arguments", Message: "Arguments cannot contain NUL", Host: "sample"}
		}
	}
	return map[string]any{"tool": name, "ok": true}, nil
}

func (f *fakeCaller) RecordRejected(ctx context.Context, name string, args map[string]any, _ error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejections = append(f.rejections, callRecord{Name: name, Args: args, Identity: command.IdentityFrom(ctx)})
	return nil
}

func testConfig(t *testing.T) *config.Manager {
	t.Helper()
	cfg := config.Default()
	cfg.MCP.Tokens = []config.Token{{Name: "mac-claude", Hash: auth.Hash(testToken)}}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	manager, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

type authTransport struct {
	token string
	base  http.RoundTripper
}

func (a authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	copy.Header.Set("Authorization", "Bearer "+a.token)
	copy.Header.Set("X-Forwarded-For", "203.0.113.123")
	return a.base.RoundTrip(copy)
}

func connectClient(t *testing.T, endpoint, protocol string) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	client := mcp.NewClient(&mcp.Implementation{Name: "Tailgate-test-client", Version: "1.0"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint: endpoint, DisableStandaloneSSE: true,
		HTTPClient: &http.Client{Transport: authTransport{token: testToken, base: http.DefaultTransport}},
	}
	session, err := client.Connect(ctx, transport, &mcp.ClientSessionOptions{ProtocolVersion: protocol})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func TestOfficialClientAllTools(t *testing.T) {
	for _, protocol := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(protocol, func(t *testing.T) {
			caller := &fakeCaller{}
			server := httptest.NewServer(New(testConfig(t), caller, "test"))
			defer server.Close()
			session := connectClient(t, server.URL, protocol)
			tools, err := session.ListTools(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(tools.Tools) != 10 {
				t.Fatalf("got %d tools, want 10", len(tools.Tools))
			}
			inputs := map[string]map[string]any{
				"list_hosts":        {"tag": "prod"},
				"host_overview":     {"host": "sample", "refresh": true},
				"run_command":       {"host": "sample", "command": "printf hello", "timeout_sec": 10, "workdir": "/tmp"},
				"run_command_multi": {"hosts": []string{"sample", "other"}, "command": "hostname"},
				"read_file":         {"host": "sample", "path": "/etc/os-release", "offset_line": 1, "max_lines": 20},
				"tail_log":          {"host": "sample", "path": "/var/log/syslog", "lines": 10, "grep": "error", "ignore_case": true},
				"journal":           {"host": "sample", "unit": "nginx", "since": "today", "until": "now", "priority": "err", "lines": 20, "grep": "failed"},
				"service_status":    {"host": "sample", "unit": "nginx"},
				"list_dir":          {"host": "sample", "path": "/tmp", "all": true},
				"search_files":      {"host": "sample", "path": "/var/log", "pattern": "*.log", "content_grep": "failed", "max_results": 10},
			}
			for _, tool := range tools.Tools {
				if tool.Description == "" {
					t.Fatalf("%s has no description", tool.Name)
				}
				encoded, _ := json.Marshal(tool.InputSchema)
				var schema struct {
					Type       string `json:"type"`
					Properties map[string]struct {
						Description string `json:"description"`
					} `json:"properties"`
				}
				if err := json.Unmarshal(encoded, &schema); err != nil || schema.Type != "object" {
					t.Fatalf("invalid schema for %s: %s", tool.Name, encoded)
				}
				for field, property := range schema.Properties {
					if property.Description == "" {
						t.Errorf("%s.%s has no parameter description", tool.Name, field)
					}
				}
				result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: tool.Name, Arguments: inputs[tool.Name]})
				if err != nil || result.IsError || result.StructuredContent == nil {
					t.Fatalf("call %s: result=%+v err=%v", tool.Name, result, err)
				}
			}
			caller.mu.Lock()
			defer caller.mu.Unlock()
			if len(caller.calls) != 10 {
				t.Fatalf("got %d calls", len(caller.calls))
			}
			for _, call := range caller.calls {
				if call.Identity != (command.Identity{Source: "mcp", Actor: "mac-claude", ClientIP: "127.0.0.1"}) {
					t.Errorf("wrong caller identity: %+v", call.Identity)
				}
			}
		})
	}
}

func TestAuthenticationRevocationOriginAndCIDR(t *testing.T) {
	manager := testConfig(t)
	handler := New(manager, &fakeCaller{}, "test")
	cases := []struct {
		name, authorization, remote, origin string
		status                              int
	}{
		{"missing", "", "127.0.0.1:1234", "", 401},
		{"invalid", "Bearer wrong", "127.0.0.1:1234", "", 401},
		{"extra", "Bearer " + testToken + " extra", "127.0.0.1:1234", "", 401},
		{"source", "Bearer " + testToken, "203.0.113.2:1234", "", 403},
		{"malformed-source", "Bearer " + testToken, "bad-address", "", 403},
		{"origin", "Bearer " + testToken, "127.0.0.1:1234", "https://evil.example", 403},
		{"origin-null", "Bearer " + testToken, "127.0.0.1:1234", "null", 403},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "http://gateway.example/mcp", strings.NewReader(`{}`))
			request.RemoteAddr = test.remote
			request.Header.Set("Authorization", test.authorization)
			request.Header.Set("Origin", test.origin)
			request.Header.Set("X-Forwarded-For", "127.0.0.1")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || !strings.Contains(response.Header().Get("Content-Type"), "application/json") {
				t.Fatalf("response %d %s", response.Code, response.Body)
			}
			if strings.Contains(response.Body.String(), testToken) || strings.Contains(response.Body.String(), test.authorization) && test.authorization != "" {
				t.Fatal("credential reflected in failure")
			}
		})
	}
	if err := manager.Update(func(c *config.Config) error { c.MCP.Tokens = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "http://gateway.example/mcp", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Authorization", "Bearer "+testToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token remained valid: %d", response.Code)
	}
}

func TestStructuredErrorsAndRejectionAudit(t *testing.T) {
	caller := &fakeCaller{}
	server := httptest.NewServer(New(testConfig(t), caller, "test"))
	defer server.Close()
	session := connectClient(t, server.URL, "2026-07-28")
	for _, args := range []map[string]any{{"host": "sample"}, {"host": 3, "command": "true"}, {"host": "sample", "command": "true", "unexpected": "value"}} {
		result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "run_command", Arguments: args})
		if err != nil || !result.IsError || result.StructuredContent == nil {
			t.Fatalf("invalid schema: %+v %v", result, err)
		}
	}
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "run_command", Arguments: map[string]any{"host": "sample", "command": "bad\x00command"}})
	if err != nil || !result.IsError || !strings.Contains(result.Content[0].(*mcp.TextContent).Text, "invalid_arguments") {
		t.Fatalf("NUL structured error: %+v %v", result, err)
	}
	caller.mu.Lock()
	defer caller.mu.Unlock()
	if len(caller.calls) != 1 || len(caller.rejections) != 3 {
		t.Fatalf("calls=%d rejections=%d", len(caller.calls), len(caller.rejections))
	}
	for _, rejection := range caller.rejections {
		if rejection.Identity.Actor != "mac-claude" || rejection.Identity.ClientIP != "127.0.0.1" {
			t.Errorf("bad rejection identity: %+v", rejection.Identity)
		}
	}
}

func TestHTTPDisconnectCancelsBothProtocolVersions(t *testing.T) {
	for _, protocol := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(protocol, func(t *testing.T) {
			caller := &fakeCaller{block: true, started: make(chan struct{}), cancelled: make(chan struct{})}
			server := httptest.NewServer(New(testConfig(t), caller, "test"))
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			meta := map[string]any{}
			if protocol == "2026-07-28" {
				meta[mcp.MetaKeyProtocolVersion] = protocol
				meta[mcp.MetaKeyClientCapabilities] = map[string]any{}
			}
			body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "run_command", "arguments": map[string]string{"host": "sample", "command": "sleep 30"}, "_meta": meta}})
			request, _ := http.NewRequestWithContext(ctx, "POST", server.URL, strings.NewReader(string(body)))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Accept", "application/json, text/event-stream")
			request.Header.Set("Authorization", "Bearer "+testToken)
			request.Header.Set("MCP-Protocol-Version", protocol)
			request.Header.Set("Mcp-Method", "tools/call")
			request.Header.Set("Mcp-Name", "run_command")
			done := make(chan struct{})
			go func() {
				defer close(done)
				response, err := http.DefaultClient.Do(request)
				if err == nil {
					_, _ = io.Copy(io.Discard, response.Body)
					_ = response.Body.Close()
				}
			}()
			select {
			case <-caller.started:
			case <-time.After(3 * time.Second):
				t.Fatal("tool did not start")
			}
			cancel()
			select {
			case <-caller.cancelled:
			case <-time.After(3 * time.Second):
				t.Fatal("HTTP disconnect did not cancel dispatcher")
			}
			<-done
		})
	}
}
