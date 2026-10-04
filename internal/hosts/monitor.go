package hosts

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"tailgate/internal/audit"
	"tailgate/internal/config"
	"tailgate/internal/sshpool"
)

type executor interface {
	Execute(context.Context, string, string, sshpool.ExecOptions) (sshpool.Result, error)
}

type hostState struct {
	address    string
	port       int
	username   string
	collecting chan struct{}
	mu         sync.RWMutex
	status     Status
	collected  bool
	cpu        cpuSample
}

type Monitor struct {
	config  *config.Manager
	pool    executor
	mu      sync.RWMutex
	states  map[string]*hostState
	auditor *audit.Writer
}

func New(cfg *config.Manager, pool *sshpool.Pool) *Monitor {
	return &Monitor{config: cfg, pool: pool, states: map[string]*hostState{}}
}

// SetAudit is called before Run so background probes share the audit trail.
func (m *Monitor) SetAudit(writer *audit.Writer) { m.mu.Lock(); m.auditor = writer; m.mu.Unlock() }

func (m *Monitor) state(host config.Host) *hostState {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.states[host.Name]
	if state == nil || state.address != host.Address || state.port != host.Port || state.username != host.Username {
		state = &hostState{address: host.Address, port: host.Port, username: host.Username, collecting: make(chan struct{}, 1), status: emptyStatus(host.Name)}
		m.states[host.Name] = state
	}
	return state
}

func (m *Monitor) Get(name string) (Status, bool) {
	host, ok := m.config.Snapshot().FindHost(name)
	if !ok {
		return Status{}, false
	}
	state := m.state(host)
	state.mu.RLock()
	defer state.mu.RUnlock()
	return cloneStatus(state.status), state.collected
}

// CachedOverview is used by host lists so an uncollected offline host never
// blocks a page or MCP list request while awaiting a network timeout.
func (m *Monitor) CachedOverview(name string) (any, error) {
	host, ok := m.config.Snapshot().FindHost(name)
	if !ok {
		return nil, &sshpool.Error{Code: "host_not_found", Host: name, Err: errors.New("unknown host")}
	}
	state := m.state(host)
	state.mu.RLock()
	defer state.mu.RUnlock()
	return cloneStatus(state.status), nil
}

func (m *Monitor) Overview(ctx context.Context, name string, refresh bool) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cached, ok := m.Get(name); ok && !refresh {
		return cached, nil
	}
	status, err := m.Collect(ctx, name)
	if err == nil {
		return status, nil
	}
	var poolError *sshpool.Error
	if errors.As(err, &poolError) && poolError.Code != "host_not_found" && poolError.Code != "audit_unavailable" && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return status, nil
	}
	return status, err
}

func (m *Monitor) Collect(ctx context.Context, name string) (Status, error) {
	host, ok := m.config.Snapshot().FindHost(name)
	if !ok {
		return Status{}, &sshpool.Error{Code: "host_not_found", Host: name, Err: errors.New("unknown host")}
	}
	state := m.state(host)
	select {
	case state.collecting <- struct{}{}:
	case <-ctx.Done():
		return emptyStatus(name), ctx.Err()
	}
	defer func() { <-state.collecting }()
	if err := ctx.Err(); err != nil {
		return emptyStatus(name), err
	}
	m.mu.RLock()
	auditor := m.auditor
	m.mu.RUnlock()
	started := time.Now().UTC()
	event := audit.Event{TS: started, Source: "web", Actor: "monitor", Host: name, Action: "host.collect", Command: CollectionCommand}
	if auditor != nil {
		if err := auditor.Health(); err != nil {
			return emptyStatus(name), &sshpool.Error{Code: "audit_unavailable", Host: name, Err: err}
		}
		begin := event
		begin.Action = "host.collect.started"
		if err := auditor.Record(begin); err != nil {
			return emptyStatus(name), &sshpool.Error{Code: "audit_unavailable", Host: name, Err: err}
		}
	}
	result, err := m.pool.Execute(ctx, name, CollectionCommand, sshpool.ExecOptions{})
	if err == nil && result.ExitCode != 0 {
		err = &sshpool.Error{Code: "collection_failed", Host: name, Err: fmt.Errorf("status collection exited with code %d", result.ExitCode)}
	}
	now := time.Now().UTC()
	state.mu.Lock()
	var status Status
	if err != nil {
		status = cloneStatus(state.status)
		status.Online = false
		status.CollectedAt = now
		status.LastError = err.Error()
		status.SSHLatencyMS = result.DurationMS
	} else {
		var sample cpuSample
		status, sample = parseStatus(result.Stdout)
		status.Host = name
		status.Online = true
		status.CollectedAt = now
		status.LastSuccess = &now
		status.SSHLatencyMS = result.DurationMS
		status.CPUUsagePercent = cpuUsage(state.cpu, sample)
		if status.UptimeSeconds != nil && state.status.UptimeSeconds != nil && *status.UptimeSeconds < *state.status.UptimeSeconds {
			status.CPUUsagePercent = nil
		}
		state.cpu = sample
		if result.Truncated {
			status.Partial = true
			status.Warnings = append(status.Warnings, "status output exceeded ssh.max_output_bytes; some metrics may be unavailable")
		}
	}
	state.status = cloneStatus(status)
	state.collected = true
	state.mu.Unlock()
	if auditor != nil {
		event.DurationMS = time.Since(started).Milliseconds()
		event.OutputBytes = result.OutputBytes
		code := result.ExitCode
		event.ExitCode = &code
		event.OutputExcerpt = statusSummary(status)
		if err != nil {
			event.Error = err.Error()
		}
		if recordErr := auditor.Record(event); recordErr != nil {
			return status, &sshpool.Error{Code: "audit_unavailable", Host: name, Err: recordErr}
		}
	}
	return status, err
}

// Run samples immediately, then checks the current configuration every second.
// A fixed four-worker batch avoids unbounded goroutine growth on large tailnets.
func (m *Monitor) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastStarted := time.Time{}
	for {
		if ctx.Err() != nil {
			return
		}
		cfg := m.config.Snapshot()
		if lastStarted.IsZero() || time.Since(lastStarted) >= cfg.Monitor.Interval {
			lastStarted = time.Now()
			m.collectBatch(ctx, cfg.Hosts)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *Monitor) collectBatch(ctx context.Context, configured []config.Host) {
	keep := map[string]bool{}
	// A scheduled batch may contain an older snapshot. Only current hosts may
	// determine cache retention; pool synchronization belongs to config writers.
	for _, host := range m.config.Snapshot().Hosts {
		keep[host.Name] = true
	}
	m.mu.Lock()
	for name := range m.states {
		if !keep[name] {
			delete(m.states, name)
		}
	}
	m.mu.Unlock()
	workers := len(configured)
	if workers > 4 {
		workers = 4
	}
	jobs := make(chan string)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range jobs {
				if _, err := m.Collect(ctx, name); err != nil && ctx.Err() == nil {
					slog.Warn("host status collection failed", "host", name, "error", err)
				}
			}
		}()
	}
	for _, host := range configured {
		select {
		case jobs <- host.Name:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		}
	}
	close(jobs)
	wg.Wait()
}
