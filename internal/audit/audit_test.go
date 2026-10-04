package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"tailgate/internal/config"
	"tailgate/internal/store"
)

func TestConcurrentRecordsFlushAndFilters(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	w, err := New(db, config.Audit{RetentionDays: 90, QueueSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close(ctx)
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			code := 0
			if err := w.Record(Event{Source: "mcp", Actor: "test-token", Host: "web-01", Action: "run_command", Command: fmt.Sprintf("echo %d", index), ExitCode: &code}); err != nil {
				t.Errorf("record: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if err := w.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	count, err := w.Count(ctx, Filter{Source: "mcp", Host: "web-01"})
	if err != nil || count != 50 {
		t.Fatalf("expected every event persisted: count=%d error=%v", count, err)
	}
	events, err := w.Query(ctx, Filter{Keyword: "echo 17"})
	if err != nil || len(events) != 1 || events[0].Actor != "test-token" || events[0].ExitCode == nil {
		t.Fatalf("query: %#v %v", events, err)
	}
	if err := w.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.Record(Event{Source: "web"}); err == nil {
		t.Fatal("accepted record after close")
	}
}

func TestTimestampOrderingExcerptAndPersistenceFailure(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	w, err := New(db, config.Audit{RetentionDays: 90, QueueSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close(ctx)
	now := time.Now().UTC().Truncate(time.Second)
	for _, delta := range []time.Duration{0, 123 * time.Nanosecond, 1 * time.Nanosecond} {
		if err := w.Record(Event{Source: "web", TS: now.Add(delta)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	events, err := w.Query(ctx, Filter{})
	if err != nil || len(events) != 3 || !events[0].TS.Equal(now.Add(123*time.Nanosecond)) {
		t.Fatalf("timestamp ordering: %#v %v", events, err)
	}
	excerpt := Excerpt(strings.Repeat("中文", 4000), "error")
	if !utf8.ValidString(excerpt) || !strings.Contains(excerpt, "truncated") || !strings.HasSuffix(excerpt, "error") {
		t.Fatal("invalid or incomplete excerpt")
	}
	if _, err := db.DB.ExecContext(ctx, "DROP TABLE audit_log"); err != nil {
		t.Fatal(err)
	}
	if err := w.Record(Event{Source: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(ctx); err == nil {
		t.Fatal("persistence error was swallowed")
	}
	if err := w.Health(); err == nil {
		t.Fatal("unhealthy writer admitted further work")
	}
	if err := w.Record(Event{Source: "web"}); err == nil {
		t.Fatal("accepted record after persistence failure")
	}
}
