// Package sshpool manages reusable SSH connections and bounded command sessions.
package sshpool

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"tailgate/internal/config"
)

type Error struct {
	Code string `json:"code"`
	Host string `json:"host,omitempty"`
	Err  error  `json:"-"`
}

func (e *Error) Error() string { return fmt.Sprintf("%s for host %q: %v", e.Code, e.Host, e.Err) }
func (e *Error) Unwrap() error { return e.Err }

func classify(host, code string, err error) error {
	if err == nil {
		return nil
	}
	var poolErr *Error
	if errors.As(err, &poolErr) {
		return poolErr
	}
	if errors.Is(err, context.DeadlineExceeded) {
		code = "timeout"
	}
	if errors.Is(err, context.Canceled) {
		code = "cancelled"
	}
	if strings.Contains(err.Error(), "unable to authenticate") {
		code = "authentication_failed"
	}
	return &Error{Code: code, Host: host, Err: err}
}

type Pool struct {
	settings       config.SSH
	decrypt        func(string) (string, error)
	mu             sync.RWMutex
	entries        map[string]*hostEntry
	closed         bool
	keysMu         sync.Mutex
	knownHostsPath string
	keys           map[string]HostKeyStatus
}

type hostEntry struct {
	host       config.Host
	slots      chan struct{}
	connecting chan struct{}
	mu         sync.Mutex
	client     *ssh.Client
	closed     chan struct{}
	closeOnce  sync.Once
	failures   int
	nextRetry  time.Time
}

func New(settings config.SSH, dataDir string, decrypt func(string) (string, error)) (*Pool, error) {
	if decrypt == nil {
		return nil, fmt.Errorf("SSH password decryptor is required")
	}
	if settings.HostKeyPolicy != "tofu" {
		return nil, fmt.Errorf("SSH host_key_policy must be tofu")
	}
	if settings.ConnectTimeout <= 0 || settings.KeepaliveInterval <= 0 || settings.DefaultCommandTimeout <= 0 || settings.MaxCommandTimeout < settings.DefaultCommandTimeout || settings.MaxOutputBytes <= 0 || settings.MaxSessionsPerHost <= 0 {
		return nil, fmt.Errorf("invalid SSH settings: durations, output limit and session limit must be positive")
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create SSH data directory: %w", err)
	}
	path := filepath.Join(dataDir, "known_hosts")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("create known_hosts: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close known_hosts: %w", err)
	}
	return &Pool{settings: settings, decrypt: decrypt, entries: make(map[string]*hostEntry), knownHostsPath: path, keys: make(map[string]HostKeyStatus)}, nil
}

// UpdateHosts swaps changed host entries and closes stale authenticated clients.
func (p *Pool) UpdateHosts(hosts []config.Host) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.updateHostsLocked(hosts)
}

// SyncConfig serializes the fresh snapshot and pool update so concurrent Web
// edits and file-watch callbacks cannot apply an older host list last.
func (p *Pool) SyncConfig(manager *config.Manager) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.updateHostsLocked(manager.Snapshot().Hosts)
}

func (p *Pool) updateHostsLocked(hosts []config.Host) error {
	if p.closed {
		return &Error{Code: "pool_closed", Err: errors.New("SSH pool is closed")}
	}
	next := make(map[string]*hostEntry, len(hosts))
	for _, host := range hosts {
		if _, exists := next[host.Name]; exists {
			return fmt.Errorf("duplicate SSH host %q", host.Name)
		}
		if current, exists := p.entries[host.Name]; exists && reflect.DeepEqual(current.host, host) {
			next[host.Name] = current
			continue
		}
		host.Tags = append([]string(nil), host.Tags...)
		next[host.Name] = &hostEntry{host: host, slots: make(chan struct{}, p.settings.MaxSessionsPerHost), connecting: make(chan struct{}, 1), closed: make(chan struct{})}
	}
	for name, current := range p.entries {
		if next[name] != current {
			current.close()
		}
	}
	p.entries = next
	return nil
}

func (p *Pool) Host(name string) (config.Host, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	e, ok := p.entries[name]
	if !ok {
		return config.Host{}, false
	}
	host := e.host
	host.Tags = append([]string(nil), host.Tags...)
	return host, true
}

func (p *Pool) entry(name string) (*hostEntry, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, &Error{Code: "pool_closed", Host: name, Err: errors.New("SSH pool is closed")}
	}
	e, ok := p.entries[name]
	if !ok {
		return nil, &Error{Code: "host_not_found", Host: name, Err: errors.New("unknown host")}
	}
	return e, nil
}

func (p *Pool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	for _, e := range p.entries {
		e.close()
	}
	return nil
}

func (e *hostEntry) close() {
	e.closeOnce.Do(func() { close(e.closed); e.disconnect(nil) })
}

func (e *hostEntry) disconnect(expected *ssh.Client) {
	e.mu.Lock()
	client := e.client
	if expected != nil && client != expected {
		e.mu.Unlock()
		return
	}
	e.client = nil
	e.mu.Unlock()
	if client != nil {
		_ = client.Close()
	}
}

func acquire(ctx context.Context, semaphore chan struct{}, closed <-chan struct{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-closed:
		return errors.New("SSH host configuration changed or pool closed")
	case semaphore <- struct{}{}:
		select {
		case <-ctx.Done():
			<-semaphore
			return ctx.Err()
		case <-closed:
			<-semaphore
			return errors.New("SSH host configuration changed or pool closed")
		default:
			return nil
		}
	}
}

func hostAddress(host config.Host) string {
	return net.JoinHostPort(host.Address, fmt.Sprint(host.Port))
}

func (p *Pool) client(ctx context.Context, e *hostEntry) (*ssh.Client, error) {
	if err := acquire(ctx, e.connecting, e.closed); err != nil {
		return nil, classify(e.host.Name, "connection_failed", err)
	}
	defer func() { <-e.connecting }()
	e.mu.Lock()
	client, nextRetry := e.client, e.nextRetry
	e.mu.Unlock()
	if client != nil {
		return client, nil
	}
	if delay := time.Until(nextRetry); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, classify(e.host.Name, "connection_failed", ctx.Err())
		case <-e.closed:
			return nil, classify(e.host.Name, "connection_failed", errors.New("SSH host closed"))
		case <-timer.C:
		}
	}
	connectCtx, cancel := context.WithTimeout(ctx, p.settings.ConnectTimeout)
	defer cancel()
	password, err := p.decrypt(e.host.PasswordEnc)
	if err != nil {
		return nil, classify(e.host.Name, "secret_decryption_failed", err)
	}
	config := &ssh.ClientConfig{
		User: e.host.Username,
		Auth: []ssh.AuthMethod{ssh.Password(password), ssh.KeyboardInteractive(func(_ string, _ string, questions []string, _ []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range answers {
				answers[i] = password
			}
			return answers, nil
		})},
		HostKeyCallback: p.hostKeyCallback(e.host.Name),
		Timeout:         p.settings.ConnectTimeout,
	}
	address := hostAddress(e.host)
	conn, err := (&net.Dialer{}).DialContext(connectCtx, "tcp", address)
	if err == nil {
		_ = conn.SetDeadline(deadlineFor(connectCtx, p.settings.ConnectTimeout))
		stopWatch := watchConn(connectCtx, conn)
		sshConn, channels, requests, handshakeErr := ssh.NewClientConn(conn, address, config)
		stopWatch()
		if handshakeErr != nil {
			_ = conn.Close()
			err = handshakeErr
		} else {
			_ = conn.SetDeadline(time.Time{})
			client = ssh.NewClient(sshConn, channels, requests)
		}
	}
	if err != nil {
		if connectCtx.Err() != nil {
			err = connectCtx.Err()
		}
		e.mu.Lock()
		e.failures++
		shift := e.failures - 1
		if shift > 7 {
			shift = 7
		}
		backoff := 250 * time.Millisecond * time.Duration(1<<shift)
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
		e.nextRetry = time.Now().Add(backoff)
		e.mu.Unlock()
		return nil, classify(e.host.Name, "connection_failed", err)
	}
	select {
	case <-e.closed:
		_ = client.Close()
		return nil, classify(e.host.Name, "connection_failed", errors.New("SSH host closed during connection"))
	case <-connectCtx.Done():
		_ = client.Close()
		return nil, classify(e.host.Name, "connection_failed", connectCtx.Err())
	default:
	}
	e.mu.Lock()
	select {
	case <-e.closed:
		e.mu.Unlock()
		_ = client.Close()
		return nil, classify(e.host.Name, "connection_failed", errors.New("SSH host closed during connection"))
	default:
	}
	e.client, e.failures, e.nextRetry = client, 0, time.Time{}
	e.mu.Unlock()
	go p.keepalive(e, client)
	go func() { _ = client.Wait(); e.disconnect(client) }()
	return client, nil
}

func deadlineFor(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}

func watchConn(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	return func() { close(done); <-exited }
}

func (p *Pool) keepalive(e *hostEntry, client *ssh.Client) {
	ticker := time.NewTicker(p.settings.KeepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-e.closed:
			return
		case <-ticker.C:
			e.mu.Lock()
			active := e.client == client
			e.mu.Unlock()
			if !active {
				return
			}
			done := make(chan error, 1)
			go func() { _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); done <- err }()
			timer := time.NewTimer(p.settings.ConnectTimeout)
			select {
			case err := <-done:
				timer.Stop()
				if err != nil {
					e.disconnect(client)
					return
				}
			case <-timer.C:
				e.disconnect(client)
				return
			case <-e.closed:
				timer.Stop()
				return
			}
		}
	}
}

type ownedSession struct {
	*ssh.Session
	client *ssh.Client
}

func (p *Pool) session(ctx context.Context, e *hostEntry) (*ownedSession, func(), error) {
	if err := acquire(ctx, e.slots, e.closed); err != nil {
		return nil, nil, classify(e.host.Name, "session_failed", err)
	}
	release := func() { <-e.slots }
	type answer struct {
		session *ssh.Session
		err     error
	}
	for attempt := 0; attempt < 2; attempt++ {
		client, err := p.client(ctx, e)
		if err != nil {
			release()
			return nil, nil, err
		}
		done := make(chan answer)
		go func() {
			session, err := client.NewSession()
			select {
			case done <- answer{session, err}:
			case <-ctx.Done():
				if session != nil {
					_ = session.Close()
				}
			}
		}()
		select {
		case <-ctx.Done():
			e.disconnect(client)
			release()
			return nil, nil, classify(e.host.Name, "session_failed", ctx.Err())
		case result := <-done:
			if result.err != nil {
				var openError *ssh.OpenChannelError
				// A peer's explicit session refusal is not a dead connection.
				if errors.As(result.err, &openError) {
					release()
					return nil, nil, classify(e.host.Name, "session_failed", result.err)
				}
				e.disconnect(client)
				if attempt == 0 {
					continue
				}
				release()
				return nil, nil, classify(e.host.Name, "session_failed", result.err)
			}
			if err := ctx.Err(); err != nil {
				_ = result.session.Close()
				release()
				return nil, nil, classify(e.host.Name, "session_failed", err)
			}
			return &ownedSession{Session: result.session, client: client}, release, nil
		}
	}
	panic("unreachable session retry")
}
