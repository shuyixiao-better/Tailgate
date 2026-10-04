// Package mcpserver exposes Tailgate tools through authenticated Streamable HTTP.
package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"tailgate/internal/auth"
	"tailgate/internal/command"
	"tailgate/internal/config"
)

const instructions = `Tailgate is an SSH gateway running on Windows. It reaches configured Ubuntu hosts through the Windows machine's Tailscale network. Call list_hosts first to discover accessible hosts, tags, and their recent status.
Use only non-interactive commands that terminate. Do not run vim, top, less, tail -f, or other interactive or endless commands. Use top -bn1, journalctl --no-pager -n 200, and tail -n 200 instead.
Limit line counts when reading large files and logs. Prefer targeted grep filters before requesting large output.
Before modifying or destructive operations, including deleting files, restarting services, or editing configuration, explain your intent to the user. SSH account permissions determine command access. Every tool operation is audited by Tailgate.`

type identityKey struct{}
type dispatchedKey struct{}

// RejectedRecorder records authenticated tool calls rejected by the SDK before
// the business dispatcher can validate or execute them.
type RejectedRecorder interface {
	RecordRejected(context.Context, string, map[string]any, error) error
}

// New authenticates every HTTP request using the current configuration. Each
// stateless server binds the requesting token's name and actual peer address.
func New(cfg *config.Manager, caller command.Caller, version string) http.Handler {
	schemas := mcp.NewSchemaCache()
	transport := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		id, ok := r.Context().Value(identityKey{}).(command.Identity)
		if !ok {
			return nil
		}
		return newServer(cfg.Snapshot(), caller, version, r.Context(), id, schemas)
	}, &mcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true, PropagateRequestCancellation: true,
		MaxRequestBodyBytes: 1 << 20,
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := cfg.Snapshot()
		if !current.MCP.Enabled {
			writeError(w, http.StatusNotFound, "not_found", "MCP is disabled")
			return
		}
		ip := peerIP(r.RemoteAddr)
		if !allowedIP(ip, current.Server.AllowedCIDRs) {
			writeError(w, http.StatusForbidden, "source_denied", "Source address is not allowed")
			return
		}
		if !sameOrigin(r) {
			writeError(w, http.StatusForbidden, "origin_denied", "Origin is not allowed")
			return
		}
		actor, ok := authenticate(r.Header.Get("Authorization"), current.MCP.Tokens)
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "unauthorized", "A valid MCP bearer token is required")
			return
		}
		id := command.Identity{Source: "mcp", Actor: actor, ClientIP: ip.String()}
		ctx := context.WithValue(r.Context(), identityKey{}, id)
		transport.ServeHTTP(w, r.WithContext(ctx))
	})
}

func peerIP(remote string) net.IP {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func allowedIP(ip net.IP, cidrs []string) bool {
	if ip == nil {
		return false
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return u.Scheme == scheme && strings.EqualFold(u.Host, r.Host)
}

func authenticate(header string, tokens []config.Token) (string, bool) {
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return "", false
	}
	actor := ""
	matched := false
	// Compare every configured hash even after a match, avoiding an early-return
	// timing distinction between credentials at different positions.
	for _, token := range tokens {
		if auth.Match(fields[1], token.Hash) {
			actor, matched = token.Name, true
		}
	}
	return actor, matched
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func newServer(cfg config.Config, caller command.Caller, version string, requestCtx context.Context, id command.Identity, schemas *mcp.SchemaCache) *mcp.Server {
	names := make([]string, 0, len(cfg.Hosts))
	for _, host := range cfg.Hosts {
		names = append(names, host.Name)
	}
	sort.Strings(names)
	server := mcp.NewServer(&mcp.Implementation{Name: "Tailgate", Version: version}, &mcp.ServerOptions{
		Instructions: instructions + "\nCurrently configured hosts: " + strings.Join(names, ", ") + ".",
		Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}},
		SchemaCache:  schemas,
	})
	register[listHostsInput](server, caller, requestCtx, id, "list_hosts", "List configured SSH hosts, tags, descriptions, online state, and their recent status summary. Optionally filter by tag.", true)
	register[overviewInput](server, caller, requestCtx, id, "host_overview", "Return complete cached host health including CPU, memory, swap, disks, failed services and top processes. Set refresh to collect a fresh sample.", true)
	register[runInput](server, caller, requestCtx, id, "run_command", "Execute a terminating non-interactive Linux command on one host. The command runs verbatim with SSH account permissions. Returns stdout, stderr, exit_code, duration_ms and truncation details. Explain changes to the user before modifying the host.", false)
	register[multiInput](server, caller, requestCtx, id, "run_command_multi", "Execute the same terminating non-interactive command concurrently on explicit hosts or hosts selected by a tag. Return a separate result or error for every host. Explain modifications to the user first.", false)
	register[readInput](server, caller, requestCtx, id, "read_file", "Read a bounded line range from a remote text file. Returns its content and total line count. Prefer narrow ranges for large files.", true)
	register[tailInput](server, caller, requestCtx, id, "tail_log", "Read the last lines of a log file, optionally filtering by a regular expression. This tool returns a finite result and never follows the log indefinitely.", true)
	register[journalInput](server, caller, requestCtx, id, "journal", "Read a bounded systemd journal with journalctl --no-pager. Optionally filter by unit, time interval, priority and regular expression.", true)
	register[serviceInput](server, caller, requestCtx, id, "service_status", "Read systemctl status and recent journal entries for a systemd unit without changing that service.", true)
	register[dirInput](server, caller, requestCtx, id, "list_dir", "List a remote directory with entry names, types, sizes, modification times and permissions. Optionally include hidden entries.", true)
	register[searchInput](server, caller, requestCtx, id, "search_files", "Find files by a filename glob below a remote directory. Optionally filter file contents by a regular expression and limit the number of results.", true)
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method != "tools/call" {
				return next(ctx, method, req)
			}
			dispatched := &atomic.Bool{}
			ctx = context.WithValue(ctx, dispatchedKey{}, dispatched)
			result, err := next(ctx, method, req)
			if dispatched.Load() {
				return result, err
			}
			failure := &command.Error{Code: "invalid_arguments", Message: "Tool arguments do not match a known tool schema"}
			if params, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok {
				var args map[string]any
				_ = json.Unmarshal(params.Arguments, &args)
				if recorder, ok := caller.(RejectedRecorder); ok {
					if recordErr := recorder.RecordRejected(command.WithIdentity(ctx, id), params.Name, args, failure); recordErr != nil {
						return toolError(&command.Error{Code: "audit_unavailable", Message: "Rejected tool call could not be audited"}), nil
					}
				}
			}
			return toolError(failure), nil
		}
	})
	return server
}

func register[Input any](server *mcp.Server, caller command.Caller, requestCtx context.Context, id command.Identity, name, description string, readOnly bool) {
	mcp.AddTool(server, &mcp.Tool{Name: name, Description: description, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: readOnly}},
		func(ctx context.Context, _ *mcp.CallToolRequest, input Input) (*mcp.CallToolResult, any, error) {
			if dispatched, ok := ctx.Value(dispatchedKey{}).(*atomic.Bool); ok {
				dispatched.Store(true)
			}
			// The legacy MCP transport detaches cancellation from HTTP requests.
			// Link both contexts so closing the request also cancels remote work.
			ctx, cancel := context.WithCancel(command.WithIdentity(ctx, id))
			stop := context.AfterFunc(requestCtx, cancel)
			defer stop()
			defer cancel()
			encoded, err := json.Marshal(input)
			if err != nil {
				return toolError(&command.Error{Code: "invalid_arguments", Message: "Tool arguments could not be encoded"}), nil, nil
			}
			var args map[string]any
			if err := json.Unmarshal(encoded, &args); err != nil {
				return toolError(&command.Error{Code: "invalid_arguments", Message: "Tool arguments could not be decoded"}), nil, nil
			}
			value, err := caller.Call(ctx, name, args)
			if err != nil {
				var failure *command.Error
				if !errors.As(err, &failure) {
					failure = &command.Error{Code: "operation_failed", Message: "The operation failed; inspect the Tailgate server log"}
				}
				return toolError(failure), nil, nil
			}
			return nil, value, nil
		})
}

func toolError(failure *command.Error) *mcp.CallToolResult {
	value := map[string]any{"error": failure}
	encoded, _ := json.Marshal(value)
	return &mcp.CallToolResult{IsError: true, StructuredContent: value, Content: []mcp.Content{&mcp.TextContent{Text: string(encoded)}}}
}
