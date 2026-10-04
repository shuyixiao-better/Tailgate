package command

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"tailgate/internal/audit"
	"tailgate/internal/config"
	"tailgate/internal/sshpool"
	"tailgate/internal/store"
	"testing"
	"time"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	if e := config.WriteDefault(filepath.Join(dir, "config.yaml")); e != nil {
		t.Fatal(e)
	}
	cfg, e := config.Load(filepath.Join(dir, "config.yaml"))
	if e != nil {
		t.Fatal(e)
	}
	db, e := store.Open(context.Background(), filepath.Join(dir, "test.db"))
	if e != nil {
		t.Fatal(e)
	}
	a, e := audit.New(db, cfg.Snapshot().Audit)
	if e != nil {
		t.Fatal(e)
	}
	p, e := sshpool.New(cfg.Snapshot().SSH, dir, func(string) (string, error) { return "test", nil })
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, c := context.WithTimeout(context.Background(), time.Second)
		defer c()
		if e := a.Close(ctx); e != nil {
			t.Error(e)
		}
		p.Close()
		db.Close()
	})
	return &Service{Config: cfg, Pool: p, Audit: a}
}
func TestAuditsFailureAndIdentity(t *testing.T) {
	s := newTestService(t)
	ctx := WithIdentity(context.Background(), Identity{Source: "mcp", Actor: "test-token", ClientIP: "127.0.0.1"})
	_, e := s.Call(ctx, "run_command", map[string]any{"host": "missing", "command": "id"})
	if e == nil {
		t.Fatal("missing host accepted")
	}
	if e = s.Audit.Flush(ctx); e != nil {
		t.Fatal(e)
	}
	events, e := s.Audit.Query(ctx, audit.Filter{Source: "mcp", Limit: 10})
	if e != nil || len(events) != 2 {
		t.Fatal(events, e)
	}
	for _, event := range events {
		if event.Actor != "test-token" || event.ClientIP != "127.0.0.1" {
			t.Fatal(event)
		}
	}
	if events[0].Error == "" {
		t.Fatal("failed operation not audited")
	}
}
func TestReadFileLiteralPath(t *testing.T) {
	s := newTestService(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "log'; touch INJECTED;#.txt")
	if e := os.WriteFile(file, []byte("a\nb\nc"), 0600); e != nil {
		t.Fatal(e)
	}
	cmd, _, _, e := s.build("read_file", map[string]any{"path": file, "offset_line": float64(2), "max_lines": float64(1)})
	if e != nil {
		t.Fatal(e)
	}
	local := exec.Command("/bin/sh", "-c", cmd)
	local.Dir = dir
	output, e := local.CombinedOutput()
	if e != nil || string(output) != "__TAILGATE_LINES__=3\nb\n" {
		t.Fatal(string(output), e)
	}
	if _, e = os.Stat(filepath.Join(dir, "INJECTED")); !os.IsNotExist(e) {
		t.Fatal("shell parameter executed")
	}
}
func TestBuildersQuoteEveryParameter(t *testing.T) {
	s := newTestService(t)
	unsafe := "/tmp/x'$(touch evil);--option"
	for name, args := range map[string]map[string]any{"tail_log": {"path": unsafe, "grep": unsafe}, "journal": {"unit": unsafe, "since": unsafe, "until": unsafe, "priority": unsafe, "grep": unsafe}, "service_status": {"unit": unsafe}, "list_dir": {"path": unsafe}, "search_files": {"path": unsafe, "pattern": unsafe, "content_grep": unsafe}} {
		cmd, _, _, e := s.build(name, args)
		if e != nil {
			t.Fatal(name, e)
		}
		if name != "search_files" && !strings.Contains(cmd, quote(unsafe)) {
			t.Fatal(name, cmd)
		}
	}
	if cmd, _, _, e := s.build("list_dir", map[string]any{"path": "--help"}); e != nil || !strings.Contains(cmd, quote("./--help")) {
		t.Fatal(cmd, e)
	}
	if _, _, _, e := s.build("tail_log", map[string]any{"path": "/tmp/x", "lines": 1.5}); e == nil {
		t.Fatal("fractional lines accepted")
	}
	if _, e := FollowCommand("/x", "service", "", false); e == nil {
		t.Fatal("ambiguous log source")
	}
	if _, e := FollowCommand("/x\x00", "", "", false); e == nil {
		t.Fatal("NUL accepted")
	}
}

func TestSearchFilesPreservesProducerFailureNoMatchAndLiteralArguments(t *testing.T) {
	s := newTestService(t)
	dir := t.TempDir()
	name := "data'; touch INJECTED; #.log"
	content := "needle'; touch INJECTED; #"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	newlineName := "newline\nfile.log"
	if err := os.WriteFile(filepath.Join(dir, newlineName), []byte("match newline\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path, pattern, grep string
		max                       int
		wantFailure               bool
		want                      string
	}{
		{"literal nested quoting", dir, "*'; touch INJECTED; #.log", content, 10, false, filepath.Join(dir, name) + "\x00"},
		{"newline filename", dir, "newline*.log", "", 10, false, filepath.Join(dir, newlineName) + "\x00"},
		{"newline content match", dir, "newline*.log", "match newline", 10, false, filepath.Join(dir, newlineName) + "\x00"},
		{"missing directory", filepath.Join(dir, "missing"), "*.log", "", 10, true, ""},
		{"invalid regex", dir, "*.log", "[", 10, true, ""},
		{"no matches", dir, "*.log", "nothing matches", 10, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd, _, _, err := s.build("search_files", map[string]any{"path": tc.path, "pattern": tc.pattern, "content_grep": tc.grep, "max_results": tc.max})
			if err != nil {
				t.Fatal(err)
			}
			local := exec.Command("/bin/sh", "-c", cmd)
			local.Dir = dir
			output, err := local.CombinedOutput()
			if tc.wantFailure {
				if err == nil {
					t.Fatalf("producer failure masked: %s", output)
				}
			} else if err != nil || string(output) != tc.want {
				t.Fatalf("output=%q error=%v want=%q", output, err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(dir, "INJECTED")); !os.IsNotExist(err) {
				t.Fatal("shell parameter executed")
			}
		})
	}
	for i := range 20 {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("file-%02d.log", i)), []byte("match\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd, _, _, err := s.build("search_files", map[string]any{"path": dir, "pattern": "*.log", "max_results": 1})
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	if err != nil || strings.Count(string(output), "\x00") != 1 {
		t.Fatalf("limited result failed: %q %v", output, err)
	}
}

func TestDirectoryEntriesRejectsTruncatedOrInvalidMachineRecords(t *testing.T) {
	complete := "literal ' name\nwith newline\x00f\x0012\x001700000000.0\x00640\x00"
	entries, err := directoryEntries("host", sshpool.Result{Stdout: complete})
	if err != nil || len(entries) != 1 || entries[0]["size"] != int64(12) || entries[0]["name"] != "literal ' name\nwith newline" {
		t.Fatalf("valid record %+v %v", entries, err)
	}
	for _, result := range []sshpool.Result{
		{Stdout: complete[:15] + "\n… [truncated] …\n" + complete[len(complete)-20:], Truncated: true},
		{Stdout: strings.TrimSuffix(complete, "\x00")},
		{Stdout: "name\x00f\x00oops\x001700000000\x00644\x00"},
		{Stdout: "name\x00f\x001\x00NaN\x00644\x00"},
	} {
		entries, err := directoryEntries("host", result)
		if err == nil || len(entries) != 0 {
			t.Fatalf("parsed corrupt machine payload: %+v %v", entries, err)
		}
	}
}

func TestSearchPathsRejectsByteTruncationAndRemoteFailure(t *testing.T) {
	for _, tc := range []struct {
		result sshpool.Result
		code   string
	}{
		{sshpool.Result{Stdout: "/tmp/head-fragment\n… [truncated] …\n-tail-fragment", Truncated: true}, "output_truncated"},
		{sshpool.Result{ExitCode: 1, Stderr: "find: permission denied"}, "remote_command_failed"},
		{sshpool.Result{Stdout: "/tmp/missing-delimiter"}, "invalid_remote_output"},
		{sshpool.Result{Stdout: "/tmp/one\x00\x00"}, "invalid_remote_output"},
	} {
		paths, err := searchPaths("host", tc.result)
		var failure *Error
		if len(paths) != 0 || !errors.As(err, &failure) || failure.Code != tc.code {
			t.Fatalf("unsafe search result returned: %v %v", paths, err)
		}
	}
	paths, err := searchPaths("host", sshpool.Result{Stdout: "/tmp/one\x00/tmp/two\nwith newline\x00"})
	if err != nil || len(paths) != 2 || paths[1] != "/tmp/two\nwith newline" {
		t.Fatalf("valid paths %+v %v", paths, err)
	}
}
