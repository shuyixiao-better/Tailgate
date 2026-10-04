// Package command is the shared, audited tool layer for MCP and Web clients.
package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailgate/internal/audit"
	"tailgate/internal/config"
	"tailgate/internal/sshpool"
)

type OverviewProvider interface {
	Overview(context.Context, string, bool) (any, error)
}
type Service struct {
	Config           *config.Manager
	Pool             *sshpool.Pool
	Audit            *audit.Writer
	OverviewProvider OverviewProvider
}

func typedError(host string, err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	var se *sshpool.Error
	if errors.As(err, &se) {
		return &Error{Code: se.Code, Host: se.Host, Message: se.Error()}
	}
	code := "operation_failed"
	if errors.Is(err, context.DeadlineExceeded) {
		code = "timeout"
	}
	if errors.Is(err, context.Canceled) {
		code = "cancelled"
	}
	return &Error{Code: code, Host: host, Message: err.Error()}
}
func invalid(message string) error                 { return &Error{Code: "invalid_arguments", Message: message} }
func text(args map[string]any, key string) string  { v, _ := args[key].(string); return v }
func boolean(args map[string]any, key string) bool { v, _ := args[key].(bool); return v }
func number(args map[string]any, key string, def, min, max int) (int, error) {
	v, ok := args[key]
	if !ok {
		return def, nil
	}
	var n int
	switch x := v.(type) {
	case int:
		n = x
	case float64:
		n = int(x)
		if float64(n) != x {
			return 0, invalid(key + " must be an integer")
		}
	case json.Number:
		i, e := strconv.Atoi(string(x))
		if e != nil {
			return 0, invalid(key + " must be an integer")
		}
		n = i
	default:
		return 0, invalid(key + " must be an integer")
	}
	if n < min || n > max {
		return 0, invalid(fmt.Sprintf("%s must be between %d and %d", key, min, max))
	}
	return n, nil
}
func require(args map[string]any, keys ...string) error {
	for _, k := range keys {
		if strings.TrimSpace(text(args, k)) == "" {
			return invalid(k + " is required")
		}
	}
	return nil
}
func safePath(path string) string {
	if path != "" && !strings.HasPrefix(path, "/") {
		return "./" + path
	}
	return path
}

var quote = sshpool.ShellQuote

// Call records the requested action and a completion, including failed validation.
// No authentication material is included in either record.
func (s *Service) Call(ctx context.Context, name string, args map[string]any) (result any, err error) {
	id := IdentityFrom(ctx)
	if id.Source == "" {
		id.Source = "web"
	}
	host := text(args, "host")
	started := time.Now()
	event := audit.Event{Source: id.Source, Actor: id.Actor, ClientIP: id.ClientIP, Host: host, Action: name, Command: text(args, "command")}
	if s.Audit == nil {
		return nil, &Error{Code: "audit_unavailable", Message: "audit writer is unavailable"}
	}
	if e := s.Audit.Health(); e != nil {
		return nil, &Error{Code: "audit_unavailable", Message: e.Error()}
	}
	begin := event
	begin.Action = name + ".started"
	if e := s.Audit.Record(begin); e != nil {
		return nil, &Error{Code: "audit_unavailable", Message: e.Error()}
	}
	defer func() {
		event.DurationMS = time.Since(started).Milliseconds()
		if err != nil {
			err = typedError(host, err)
			event.Error = err.Error()
		}
		if e := s.Audit.Record(event); e != nil {
			err = &Error{Code: "audit_unavailable", Message: "operation finished but its completion audit could not be written: " + e.Error(), Host: host}
		}
	}()
	for k, v := range args {
		if str, ok := v.(string); ok && strings.ContainsRune(str, 0) {
			return nil, invalid(k + " must not contain NUL")
		}
	}
	switch name {
	case "list_hosts":
		list := []map[string]any{}
		for _, h := range s.Config.Snapshot().Hosts {
			if tag := text(args, "tag"); tag != "" && !hasTag(h, tag) {
				continue
			}
			row := map[string]any{"name": h.Name, "address": h.Address, "port": h.Port, "username": h.Username, "tags": h.Tags, "description": h.Description, "online": false}
			if s.OverviewProvider != nil {
				var status any
				var e error
				if cached, ok := s.OverviewProvider.(interface{ CachedOverview(string) (any, error) }); ok {
					status, e = cached.CachedOverview(h.Name)
				} else {
					status, e = s.OverviewProvider.Overview(ctx, h.Name, false)
				}
				if e == nil {
					row["status"] = status
					b, _ := json.Marshal(status)
					var summary map[string]any
					_ = json.Unmarshal(b, &summary)
					row["online"] = summary["online"]
				}
			}
			list = append(list, row)
		}
		return map[string]any{"hosts": list}, nil
	case "host_overview":
		if e := require(args, "host"); e != nil {
			return nil, e
		}
		if _, ok := s.Config.Snapshot().FindHost(host); !ok {
			return nil, &Error{Code: "host_not_found", Host: host, Message: "unknown host"}
		}
		if s.OverviewProvider != nil {
			return s.OverviewProvider.Overview(ctx, host, boolean(args, "refresh"))
		}
		return s.Pool.Test(ctx, host)
	case "run_command_multi":
		if e := require(args, "command"); e != nil {
			return nil, e
		}
		names, e := s.selectHosts(args)
		if e != nil {
			return nil, e
		}
		results := make(map[string]any, len(names))
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, h := range names {
			h := h
			wg.Add(1)
			go func() {
				defer wg.Done()
				child := map[string]any{"host": h, "command": text(args, "command")}
				if v, ok := args["timeout_sec"]; ok {
					child["timeout_sec"] = v
				}
				r, e := s.Call(ctx, "run_command", child)
				if e != nil {
					r = map[string]any{"error": typedError(h, e), "result": r}
				}
				mu.Lock()
				results[h] = r
				mu.Unlock()
			}()
		}
		wg.Wait()
		return map[string]any{"results": results}, nil
	default:
		if e := require(args, "host"); e != nil {
			return nil, e
		}
		cmd, timeout, workdir, e := s.build(name, args)
		if e != nil {
			return nil, e
		}
		event.Command = cmd
		r, e := s.Pool.Execute(ctx, host, cmd, sshpool.ExecOptions{Timeout: timeout, Workdir: workdir})
		event.ExitCode = &r.ExitCode
		event.OutputBytes = r.OutputBytes
		event.OutputExcerpt = audit.Excerpt(r.Stdout, r.Stderr)
		if e != nil {
			return r, e
		}
		switch name {
		case "read_file":
			if r.ExitCode != 0 {
				return r, &Error{Code: "remote_command_failed", Host: host, Message: r.Stderr}
			}
			first, content, ok := strings.Cut(r.Stdout, "\n")
			if !ok {
				return r, &Error{Code: "invalid_remote_output", Host: host, Message: "missing total line count"}
			}
			if !strings.HasPrefix(first, "__TAILGATE_LINES__=") {
				return r, &Error{Code: "invalid_remote_output", Host: host, Message: "missing total line count marker"}
			}
			total, e := strconv.ParseInt(strings.TrimPrefix(first, "__TAILGATE_LINES__="), 10, 64)
			if e != nil {
				return r, &Error{Code: "invalid_remote_output", Host: host, Message: "invalid total line count"}
			}
			return map[string]any{"content": content, "total_lines": total, "truncated": r.Truncated, "output_bytes": r.OutputBytes}, nil
		case "list_dir":
			if r.ExitCode != 0 {
				return r, &Error{Code: "remote_command_failed", Host: host, Message: r.Stderr}
			}
			entries, err := directoryEntries(host, r)
			if err != nil {
				return r, err
			}
			return map[string]any{"entries": entries, "truncated": r.Truncated}, nil
		case "search_files":
			paths, err := searchPaths(host, r)
			if err != nil {
				return r, err
			}
			return map[string]any{"paths": paths, "truncated": r.Truncated, "stderr": r.Stderr, "exit_code": r.ExitCode}, nil
		default:
			return r, nil
		}
	}
}

func searchPaths(host string, result sshpool.Result) ([]string, error) {
	if result.ExitCode != 0 {
		return nil, &Error{Code: "remote_command_failed", Host: host, Message: result.Stderr}
	}
	if result.Truncated {
		return nil, &Error{Code: "output_truncated", Host: host, Message: "File search exceeded ssh.max_output_bytes. Reduce max_results or choose a narrower directory."}
	}
	paths := []string{}
	if result.Stdout == "" {
		return paths, nil
	}
	if !strings.HasSuffix(result.Stdout, "\x00") {
		return nil, &Error{Code: "invalid_remote_output", Host: host, Message: "File search contains an incomplete path."}
	}
	for _, path := range strings.Split(strings.TrimSuffix(result.Stdout, "\x00"), "\x00") {
		if path == "" {
			return nil, &Error{Code: "invalid_remote_output", Host: host, Message: "File search contains an empty path."}
		}
		paths = append(paths, path)
	}
	return paths, nil
}

func directoryEntries(host string, result sshpool.Result) ([]map[string]any, error) {
	if result.Truncated {
		return nil, &Error{Code: "output_truncated", Host: host, Message: "Directory listing exceeded ssh.max_output_bytes. Choose a narrower directory or use run_command with an explicit limit."}
	}
	entries := []map[string]any{}
	if result.Stdout == "" {
		return entries, nil
	}
	if !strings.HasSuffix(result.Stdout, "\x00") {
		return nil, &Error{Code: "invalid_remote_output", Host: host, Message: "Directory listing contains an incomplete entry."}
	}
	fields := strings.Split(strings.TrimSuffix(result.Stdout, "\x00"), "\x00")
	if len(fields)%5 != 0 {
		return nil, &Error{Code: "invalid_remote_output", Host: host, Message: "Directory listing contains an incomplete entry."}
	}
	for i := 0; i < len(fields); i += 5 {
		size, sizeErr := strconv.ParseInt(fields[i+2], 10, 64)
		modified, timeErr := strconv.ParseFloat(fields[i+3], 64)
		permissions, modeErr := strconv.ParseUint(fields[i+4], 8, 16)
		if fields[i] == "" || len(fields[i+1]) != 1 || sizeErr != nil || size < 0 || timeErr != nil || math.IsNaN(modified) || math.IsInf(modified, 0) || modeErr != nil || permissions > 07777 {
			return nil, &Error{Code: "invalid_remote_output", Host: host, Message: "Directory listing contains invalid entry metadata."}
		}
		entries = append(entries, map[string]any{"name": fields[i], "type": fields[i+1], "size": size, "modified_unix": fields[i+3], "permissions": fields[i+4]})
	}
	return entries, nil
}
func hasTag(h config.Host, tag string) bool {
	for _, t := range h.Tags {
		if t == tag {
			return true
		}
	}
	return false
}
func (s *Service) selectHosts(args map[string]any) ([]string, error) {
	tag := text(args, "tag")
	raw, exists := args["hosts"]
	if exists && tag != "" {
		return nil, invalid("supply hosts or tag, not both")
	}
	names := []string{}
	if tag != "" {
		for _, h := range s.Config.Snapshot().Hosts {
			if hasTag(h, tag) {
				names = append(names, h.Name)
			}
		}
	} else {
		switch v := raw.(type) {
		case []string:
			names = v
		case []any:
			for _, n := range v {
				str, ok := n.(string)
				if !ok {
					return nil, invalid("hosts must be an array of names")
				}
				names = append(names, str)
			}
		default:
			return nil, invalid("hosts or tag is required")
		}
	}
	if len(names) == 0 {
		return nil, invalid("no matching hosts")
	}
	seen := map[string]bool{}
	unique := []string{}
	for _, n := range names {
		if n == "" {
			return nil, invalid("host names cannot be empty")
		}
		if !seen[n] {
			unique = append(unique, n)
			seen[n] = true
		}
	}
	return unique, nil
}
func (s *Service) build(name string, args map[string]any) (cmd string, timeout time.Duration, workdir string, err error) {
	settings := s.Config.Snapshot().SSH
	seconds, e := number(args, "timeout_sec", int(settings.DefaultCommandTimeout/time.Second), 1, int(settings.MaxCommandTimeout/time.Second))
	if e != nil {
		return "", 0, "", e
	}
	timeout = time.Duration(seconds) * time.Second
	path := safePath(text(args, "path"))
	lines := 200
	switch name {
	case "run_command":
		if e = require(args, "command"); e != nil {
			err = e
			return
		}
		cmd = text(args, "command")
		workdir = text(args, "workdir")
	case "read_file":
		if e = require(args, "path"); e != nil {
			err = e
			return
		}
		offset, e := number(args, "offset_line", 1, 1, 1000000000)
		if e != nil {
			err = e
			return
		}
		count, e := number(args, "max_lines", 500, 1, 10000)
		if e != nil {
			err = e
			return
		}
		cmd = "printf '__TAILGATE_LINES__='; awk 'END {print NR}' < " + quote(path) + " && sed -n " + quote(fmt.Sprintf("%d,%dp", offset, offset+count-1)) + " < " + quote(path)
	case "tail_log":
		if e = require(args, "path"); e != nil {
			err = e
			return
		}
		lines, e = number(args, "lines", 200, 1, 10000)
		if e != nil {
			err = e
			return
		}
		cmd = "tail -n " + strconv.Itoa(lines) + " -- " + quote(path)
		if filter := text(args, "grep"); filter != "" {
			cmd += " | grep -E "
			if boolean(args, "ignore_case") {
				cmd += "-i "
			}
			cmd += "-e " + quote(filter)
		}
	case "journal":
		lines, e = number(args, "lines", 200, 1, 10000)
		if e != nil {
			err = e
			return
		}
		cmd = "journalctl --no-pager -n " + strconv.Itoa(lines)
		for _, p := range []struct{ key, flag string }{{"unit", "--unit"}, {"since", "--since"}, {"until", "--until"}, {"priority", "--priority"}, {"grep", "--grep"}} {
			if value := text(args, p.key); value != "" {
				cmd += " " + p.flag + "=" + quote(value)
			}
		}
	case "service_status":
		if e = require(args, "unit"); e != nil {
			err = e
			return
		}
		unit := quote(text(args, "unit"))
		cmd = "systemctl --no-pager status -- " + unit + "; journalctl --no-pager -n 50 --unit=" + unit
	case "list_dir":
		if e = require(args, "path"); e != nil {
			err = e
			return
		}
		cmd = "find " + quote(path) + " -mindepth 1 -maxdepth 1 "
		if !boolean(args, "all") {
			cmd += "! -name '.*' "
		}
		cmd += "-printf '%f\\0%y\\0%s\\0%T@\\0%m\\0'"
	case "search_files":
		if e = require(args, "path", "pattern"); e != nil {
			err = e
			return
		}
		max, e := number(args, "max_results", 100, 1, 10000)
		if e != nil {
			err = e
			return
		}
		cmd = "find " + quote(path) + " -type f -name " + quote(text(args, "pattern"))
		if pattern := text(args, "content_grep"); pattern != "" {
			// No grep matches is a successful empty search; regex and I/O errors
			// must still make find fail and reach the structured error response.
			grepScript := "grep -l --null -E -e " + quote(pattern) + " -- \"$@\"; tailgate_grep_status=$?; if [ \"$tailgate_grep_status\" -eq 1 ]; then exit 0; fi; exit \"$tailgate_grep_status\""
			cmd += " -exec /bin/sh -c " + quote(grepScript) + " tailgate-grep {} +"
		} else {
			cmd += " -print0"
		}
		// Drain the producer even after the result cap; head can cause SIGPIPE
		// and obscures genuine find errors behind its own successful exit code.
		// Preserve legal filenames containing newlines by consuming NUL records.
		cmd += " | { tailgate_count=0; while IFS= read -r -d '' tailgate_path; do if [ \"$tailgate_count\" -lt " + strconv.Itoa(max) + " ]; then printf '%s\\0' \"$tailgate_path\"; tailgate_count=$((tailgate_count + 1)); fi; done; }"
		cmd = "BASH_ENV=/dev/null /bin/bash -o pipefail -c " + quote(cmd)
	default:
		err = &Error{Code: "tool_not_found", Message: "unknown tool " + name}
	}
	return
}

// FollowCommand produces a safely quoted long-running log command for WebSocket use.
func FollowCommand(path, unit, filter string, ignoreCase bool) (string, error) {
	for _, s := range []string{path, unit, filter} {
		if strings.ContainsRune(s, 0) {
			return "", invalid("log parameters must not contain NUL")
		}
	}
	if (path == "") == (unit == "") {
		return "", invalid("choose a file path or systemd unit")
	}
	cmd := ""
	if unit != "" {
		cmd = "journalctl --no-pager -f -n 200 --unit=" + quote(unit)
	} else {
		cmd = "tail -F -n 200 -- " + quote(safePath(path))
	}
	if filter != "" {
		cmd += " | grep --line-buffered -E "
		if ignoreCase {
			cmd += "-i "
		}
		cmd += "-e " + quote(filter)
	}
	return cmd, nil
}

// RecordRejected covers SDK schema errors that occur before business dispatch.
func (s *Service) RecordRejected(ctx context.Context, name string, args map[string]any, reason error) error {
	id := IdentityFrom(ctx)
	if id.Source == "" {
		id.Source = "mcp"
	}
	if s.Audit == nil {
		return errors.New("audit writer is unavailable")
	}
	return s.Audit.Record(audit.Event{Source: id.Source, Actor: id.Actor, ClientIP: id.ClientIP, Host: text(args, "host"), Action: name, Command: text(args, "command"), Error: reason.Error()})
}
