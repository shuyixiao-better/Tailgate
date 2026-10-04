package hosts

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailgate/internal/audit"
	"tailgate/internal/config"
	"tailgate/internal/sshpool"
	"tailgate/internal/store"
)

type fakeExecutor struct {
	mu      sync.Mutex
	output  string
	err     error
	count   atomic.Int32
	active  atomic.Int32
	maximum atomic.Int32
	delay   time.Duration
}

func (f *fakeExecutor) Execute(ctx context.Context, name, command string, _ sshpool.ExecOptions) (sshpool.Result, error) {
	if command != CollectionCommand {
		return sshpool.Result{}, errors.New("collector used more than its fixed composite command")
	}
	f.count.Add(1)
	active := f.active.Add(1)
	defer f.active.Add(-1)
	for previous := f.maximum.Load(); active > previous; previous = f.maximum.Load() {
		if f.maximum.CompareAndSwap(previous, active) {
			break
		}
	}
	if f.delay > 0 {
		timer := time.NewTimer(f.delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return sshpool.Result{ExitCode: -1}, ctx.Err()
		case <-timer.C:
		}
	}
	f.mu.Lock()
	output, err := f.output, f.err
	f.mu.Unlock()
	return sshpool.Result{Stdout: output, ExitCode: 0, DurationMS: 7, OutputBytes: int64(len(output))}, err
}

func newTestMonitor(t *testing.T, count int) (*Monitor, *fakeExecutor) {
	t.Helper()
	cfg := config.Default()
	for i := range count {
		cfg.Hosts = append(cfg.Hosts, config.Host{Name: fmt.Sprintf("host-%d", i), Address: "127.0.0.1", Port: 22, Username: "ubuntu", PasswordEnc: base64.StdEncoding.EncodeToString(make([]byte, 28))})
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	manager, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeExecutor{output: fixture(t)}
	monitor := &Monitor{config: manager, pool: fake, states: map[string]*hostState{}}
	return monitor, fake
}

func TestMonitorCachesDeltasPreservesSuccessAndClones(t *testing.T) {
	m, fake := newTestMonitor(t, 1)
	uncached, err := m.CachedOverview("host-0")
	if err != nil {
		t.Fatal(err)
	}
	if fake.count.Load() != 0 || uncached.(Status).Online {
		t.Fatal("cached list contacted SSH or invented online status")
	}
	first, err := m.Collect(context.Background(), "host-0")
	if err != nil {
		t.Fatal(err)
	}
	if !first.Online || first.LastSuccess == nil || first.CPUUsagePercent != nil {
		t.Fatalf("first sample %+v", first)
	}
	fake.mu.Lock()
	fake.output = strings.Replace(fake.output, "cpu  1000 20 500 8000 100 10 50 20 30 2", "cpu  1100 20 550 8200 120 10 70 30 40 2", 1)
	fake.mu.Unlock()
	second, err := m.Collect(context.Background(), "host-0")
	if err != nil {
		t.Fatal(err)
	}
	if second.CPUUsagePercent == nil || *second.CPUUsagePercent <= 0 || *second.CPUUsagePercent > 100 {
		t.Fatalf("missing sampled utilization %+v", second)
	}
	second.Disks[0].Mountpoint = "changed"
	second.Memory.TotalBytes = 1
	*second.CPUCores = 1
	cached, ok := m.Get("host-0")
	if !ok || cached.Disks[0].Mountpoint != "/" || cached.Memory.TotalBytes == 1 || *cached.CPUCores == 1 {
		t.Fatal("mutable result corrupted shared cache")
	}
	lastSuccess := *cached.LastSuccess
	fake.mu.Lock()
	fake.err = &sshpool.Error{Code: "connection_failed", Host: "host-0", Err: errors.New("unreachable")}
	fake.mu.Unlock()
	offline, err := m.Collect(context.Background(), "host-0")
	if err == nil || offline.Online || offline.LastError == "" || !offline.LastSuccess.Equal(lastSuccess) || offline.OSVersion != first.OSVersion || offline.Memory == nil {
		t.Fatalf("failure lost last success: %+v %v", offline, err)
	}
	before := fake.count.Load()
	overview, err := m.Overview(context.Background(), "host-0", false)
	if err != nil || overview.(Status).Online || fake.count.Load() != before {
		t.Fatal("cached offline status retried SSH")
	}
	refreshed, err := m.Overview(context.Background(), "host-0", true)
	if err != nil || refreshed.(Status).Online {
		t.Fatalf("offline overview missing: %+v %v", refreshed, err)
	}
}

func TestMonitorBatchLimitsConcurrencyAndPrunesRemovedHosts(t *testing.T) {
	m, fake := newTestMonitor(t, 12)
	fake.delay = 10 * time.Millisecond
	m.collectBatch(context.Background(), m.config.Snapshot().Hosts)
	if maximum := fake.maximum.Load(); maximum > 4 || maximum < 2 || fake.count.Load() != 12 {
		t.Fatalf("batch concurrency=%d calls=%d", maximum, fake.count.Load())
	}
	if err := m.config.Update(func(cfg *config.Config) error { cfg.Hosts = cfg.Hosts[:1]; return nil }); err != nil {
		t.Fatal(err)
	}
	m.collectBatch(context.Background(), m.config.Snapshot().Hosts)
	m.mu.RLock()
	size := len(m.states)
	m.mu.RUnlock()
	if size != 1 {
		t.Fatalf("stale cache hosts retained: %d", size)
	}
	if _, ok := m.Get("host-1"); ok {
		t.Fatal("removed host cached overview available")
	}
}

func TestMonitorStopsPendingBatchAndChangedAddressResetsCache(t *testing.T) {
	m, fake := newTestMonitor(t, 12)
	fake.delay = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	deadline := time.After(time.Second)
	for fake.active.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("monitor did not start")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("monitor failed to stop")
	}
	fake.delay = 0
	if _, err := m.Collect(context.Background(), "host-0"); err != nil {
		t.Fatal(err)
	}
	if err := m.config.Update(func(cfg *config.Config) error { cfg.Hosts[0].Address = "127.0.0.2"; return nil }); err != nil {
		t.Fatal(err)
	}
	status, ok := m.Get("host-0")
	if ok || status.Online || status.Memory != nil {
		t.Fatal("new SSH target inherited old host metrics")
	}
}

func TestMonitorAuditAndFailClosed(t *testing.T) {
	m, fake := newTestMonitor(t, 1)
	db, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	writer, err := audit.New(db, config.Audit{RetentionDays: 90, QueueSize: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close(context.Background())
	m.SetAudit(writer)
	if _, err := m.Collect(context.Background(), "host-0"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	events, err := writer.Query(context.Background(), audit.Filter{Actor: "monitor"})
	if err != nil || len(events) != 2 {
		t.Fatalf("missing collection audit %+v %v", events, err)
	}
	for _, event := range events {
		if event.Command != CollectionCommand || event.Source != "web" {
			t.Fatalf("collection audit lost actual command %+v", event)
		}
	}
	if _, err := db.DB.Exec("DROP TABLE audit_log"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Record(audit.Event{Source: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(context.Background()); err == nil {
		t.Fatal("expected audit failure")
	}
	before := fake.count.Load()
	_, err = m.Collect(context.Background(), "host-0")
	var poolErr *sshpool.Error
	if !errors.As(err, &poolErr) || poolErr.Code != "audit_unavailable" || fake.count.Load() != before {
		t.Fatalf("collector executed without audit: %v", err)
	}
}

func TestScheduledOldBatchCannotRevertUpdatedSSHTarget(t *testing.T) {
	m, _ := newTestMonitor(t, 1)
	oldBatch := m.config.Snapshot().Hosts
	pool, err := sshpool.New(m.config.Snapshot().SSH, t.TempDir(), func(string) (string, error) { return "fixture", nil })
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := pool.SyncConfig(m.config); err != nil {
		t.Fatal(err)
	}
	m = New(m.config, pool)
	if err := m.config.Update(func(c *config.Config) error {
		c.Hosts[0].Address = "127.0.0.2"
		c.Hosts[0].Username = "new-user"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := pool.SyncConfig(m.config); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.collectBatch(ctx, oldBatch)
	host, ok := pool.Host("host-0")
	if !ok || host.Address != "127.0.0.2" || host.Username != "new-user" {
		t.Fatalf("old monitor batch reverted current SSH target: %+v", host)
	}
}
