// Package audit asynchronously persists an append-only record of gateway actions.
package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"tailgate/internal/config"
	"tailgate/internal/store"
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

type Event struct {
	ID            int64     `json:"id"`
	TS            time.Time `json:"ts"`
	Source        string    `json:"source"`
	Actor         string    `json:"actor"`
	ClientIP      string    `json:"client_ip"`
	Host          string    `json:"host"`
	Action        string    `json:"action"`
	Command       string    `json:"command"`
	ExitCode      *int      `json:"exit_code"`
	DurationMS    int64     `json:"duration_ms"`
	OutputBytes   int64     `json:"output_bytes"`
	OutputExcerpt string    `json:"output_excerpt"`
	Error         string    `json:"error"`
}

type Filter struct {
	Source  string
	Host    string
	Actor   string
	Keyword string
	Since   time.Time
	Until   time.Time
	Limit   int
	Offset  int
}

type queued struct {
	event   *Event
	barrier chan struct{}
}

type Writer struct {
	db            *sql.DB
	retentionDays int
	queue         chan queued
	done          chan struct{}
	// admission protects shutdown and lets Flush wait for synchronous fallbacks.
	admission sync.RWMutex
	closed    bool
	writeMu   sync.Mutex
	failureMu sync.RWMutex
	failure   error
}

func New(database *store.Store, options config.Audit) (*Writer, error) {
	if database == nil || database.DB == nil {
		return nil, errors.New("audit database is required")
	}
	if options.QueueSize < 1 || options.RetentionDays < 1 {
		return nil, errors.New("audit queue size and retention days must be positive")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := database.DB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("initialize audit writer: %w", err)
	}
	w := &Writer{db: database.DB, retentionDays: options.RetentionDays, queue: make(chan queued, options.QueueSize), done: make(chan struct{})}
	go w.run()
	return w, nil
}

func (w *Writer) setFailure(err error) {
	w.failureMu.Lock()
	if w.failure == nil {
		w.failure = fmt.Errorf("audit persistence unavailable: %w", err)
		slog.Error("audit persistence failed; further operations must be refused", "error", err)
	}
	w.failureMu.Unlock()
}

// Health returns a permanent failure after an insert fails; restart is required
// after correcting storage. A gateway checks this before starting new actions.
func (w *Writer) Health() error {
	w.failureMu.RLock()
	defer w.failureMu.RUnlock()
	return w.failure
}

// Record never drops events. If the bounded queue fills, the caller performs a
// synchronous insert; this exceptional backpressure preserves the audit trail.
func (w *Writer) Record(event Event) error {
	w.admission.RLock()
	defer w.admission.RUnlock()
	if w.closed {
		return errors.New("audit writer is closed")
	}
	if err := w.Health(); err != nil {
		return err
	}
	if event.Source != "mcp" && event.Source != "web" && event.Source != "terminal" {
		return fmt.Errorf("invalid audit source %q", event.Source)
	}
	if event.TS.IsZero() {
		event.TS = time.Now().UTC()
	}
	event.OutputExcerpt = trimExcerpt(event.OutputExcerpt)
	if event.ExitCode != nil {
		value := *event.ExitCode
		event.ExitCode = &value
	}
	select {
	case w.queue <- queued{event: &event}:
		return nil
	default:
		return w.write(event)
	}
}

func (w *Writer) write(event Event) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := w.db.ExecContext(ctx, `INSERT INTO audit_log(ts,source,actor,client_ip,host,action,command,exit_code,duration_ms,output_bytes,output_excerpt,error) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, event.TS.UTC().Format(timestampLayout), event.Source, event.Actor, event.ClientIP, event.Host, event.Action, event.Command, event.ExitCode, event.DurationMS, event.OutputBytes, event.OutputExcerpt, event.Error)
	if err != nil {
		w.setFailure(err)
		return fmt.Errorf("write audit event: %w", err)
	}
	return nil
}

func (w *Writer) run() {
	defer close(w.done)
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	w.cleanup()
	for {
		select {
		case record, ok := <-w.queue:
			if !ok {
				return
			}
			if record.event != nil {
				_ = w.write(*record.event)
			}
			if record.barrier != nil {
				close(record.barrier)
			}
		case <-ticker.C:
			w.cleanup()
		}
	}
}

func (w *Writer) cleanup() {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := w.db.ExecContext(ctx, `DELETE FROM audit_log WHERE ts<?`, time.Now().UTC().AddDate(0, 0, -w.retentionDays).Format(timestampLayout)); err != nil {
		slog.Warn("audit retention cleanup failed", "error", err)
	}
}

// Flush waits until all records admitted before this call have been persisted.
func (w *Writer) Flush(ctx context.Context) error {
	w.admission.Lock()
	if w.closed {
		w.admission.Unlock()
		select {
		case <-w.done:
			return w.Health()
		case <-ctx.Done():
			return fmt.Errorf("flush closed audit writer: %w", ctx.Err())
		}
	}
	barrier := make(chan struct{})
	select {
	case w.queue <- queued{barrier: barrier}:
		w.admission.Unlock()
	case <-ctx.Done():
		w.admission.Unlock()
		return fmt.Errorf("enqueue audit flush: %w", ctx.Err())
	}
	select {
	case <-barrier:
		return w.Health()
	case <-ctx.Done():
		return fmt.Errorf("flush audit writer: %w", ctx.Err())
	}
}

// Close stops admission and drains all accepted records. The database remains
// owned by the caller and must be closed only after this method succeeds.
func (w *Writer) Close(ctx context.Context) error {
	w.admission.Lock()
	if !w.closed {
		w.closed = true
		close(w.queue)
	}
	w.admission.Unlock()
	select {
	case <-w.done:
		return w.Health()
	case <-ctx.Done():
		return fmt.Errorf("drain audit writer: %w", ctx.Err())
	}
}

func filterSQL(filter Filter) (string, []any, error) {
	where := []string{"1=1"}
	args := []any{}
	if filter.Source != "" {
		if filter.Source != "mcp" && filter.Source != "web" && filter.Source != "terminal" {
			return "", nil, errors.New("audit source must be mcp, web or terminal")
		}
		where = append(where, "source=?")
		args = append(args, filter.Source)
	}
	for _, field := range []struct{ column, value string }{{"host", filter.Host}, {"actor", filter.Actor}} {
		if field.value != "" {
			where = append(where, field.column+"=?")
			args = append(args, field.value)
		}
	}
	if !filter.Since.IsZero() {
		where = append(where, "ts>=?")
		args = append(args, filter.Since.UTC().Format(timestampLayout))
	}
	if !filter.Until.IsZero() {
		where = append(where, "ts<=?")
		args = append(args, filter.Until.UTC().Format(timestampLayout))
	}
	if filter.Keyword != "" {
		where = append(where, "(instr(lower(command),lower(?))>0 OR instr(lower(output_excerpt),lower(?))>0 OR instr(lower(actor),lower(?))>0 OR instr(lower(error),lower(?))>0)")
		for range 4 {
			args = append(args, filter.Keyword)
		}
	}
	return strings.Join(where, " AND "), args, nil
}

func (w *Writer) Query(ctx context.Context, filter Filter) ([]Event, error) {
	where, args, err := filterSQL(filter)
	if err != nil {
		return nil, err
	}
	limit := filter.Limit
	if limit < 1 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	if filter.Offset < 0 {
		return nil, errors.New("audit offset must not be negative")
	}
	args = append(args, limit, filter.Offset)
	rows, err := w.db.QueryContext(ctx, `SELECT id,ts,source,actor,client_ip,host,action,command,exit_code,duration_ms,output_bytes,output_excerpt,error FROM audit_log WHERE `+where+` ORDER BY ts DESC,id DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	defer rows.Close()
	events := []Event{}
	for rows.Next() {
		var event Event
		var timestamp string
		var exit sql.NullInt64
		if err := rows.Scan(&event.ID, &timestamp, &event.Source, &event.Actor, &event.ClientIP, &event.Host, &event.Action, &event.Command, &exit, &event.DurationMS, &event.OutputBytes, &event.OutputExcerpt, &event.Error); err != nil {
			return nil, fmt.Errorf("read audit event: %w", err)
		}
		parsed, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return nil, fmt.Errorf("parse audit timestamp: %w", err)
		}
		event.TS = parsed
		if exit.Valid {
			value := int(exit.Int64)
			event.ExitCode = &value
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}
	return events, nil
}

func (w *Writer) Count(ctx context.Context, filter Filter) (int, error) {
	where, args, err := filterSQL(filter)
	if err != nil {
		return 0, err
	}
	var count int
	if err := w.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE `+where, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count audit events: %w", err)
	}
	return count, nil
}

func Excerpt(stdout, stderr string) string {
	output := stdout
	if stderr != "" {
		output += "\n[stderr]\n" + stderr
	}
	return trimExcerpt(output)
}

func trimExcerpt(output string) string {
	const part = 4096
	if len(output) > part*2 {
		output = output[:part] + "\n[… output excerpt truncated …]\n" + output[len(output)-part:]
	}
	return strings.ToValidUTF8(output, "�")
}
