package sshpool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Terminal owns a PTY session until Close or cancellation of its context.
type Terminal struct {
	reader    io.Reader
	writer    io.WriteCloser
	session   *ownedSession
	entry     *hostEntry
	release   func()
	closeOnce sync.Once
	closed    chan struct{}
}

func (t *Terminal) Read(p []byte) (int, error)  { return t.reader.Read(p) }
func (t *Terminal) Write(p []byte) (int, error) { return t.writer.Write(p) }
func (t *Terminal) Resize(cols, rows int) error {
	if cols < 1 || cols > 1000 || rows < 1 || rows > 1000 {
		return fmt.Errorf("terminal dimensions must be between 1 and 1000")
	}
	return t.session.WindowChange(rows, cols)
}
func (t *Terminal) Close() error {
	t.closeOnce.Do(func() { close(t.closed); stopSession(t.session, t.entry); t.release() })
	return nil
}

func (p *Pool) OpenPTY(ctx context.Context, name string, cols, rows int) (*Terminal, error) {
	if cols < 1 || cols > 1000 || rows < 1 || rows > 1000 {
		return nil, classify(name, "invalid_arguments", fmt.Errorf("terminal dimensions must be between 1 and 1000"))
	}
	e, err := p.entry(name)
	if err != nil {
		return nil, err
	}
	session, release, err := p.session(ctx, e)
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = session.Close(); release() }
	stdin, err := session.StdinPipe()
	if err != nil {
		cleanup()
		return nil, classify(name, "session_failed", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		cleanup()
		return nil, classify(name, "session_failed", err)
	}
	// A PTY merges stderr into stdout on OpenSSH. Drain separate stderr on peers
	// that do not merge it so their channel cannot deadlock under output pressure.
	session.Stderr = io.Discard
	done := make(chan error, 1)
	go func() {
		err := session.RequestPty("xterm-256color", rows, cols, ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400})
		if err == nil {
			err = session.Shell()
		}
		done <- err
	}()
	select {
	case <-ctx.Done():
		stopSession(session, e)
		cleanup()
		return nil, classify(name, "session_failed", ctx.Err())
	case err := <-done:
		if err != nil {
			cleanup()
			return nil, classify(name, "session_failed", err)
		}
	}
	t := &Terminal{reader: stdout, writer: stdin, session: session, entry: e, release: release, closed: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			_ = t.Close()
		case <-t.closed:
		}
	}()
	go func() { _ = session.Wait(); _ = t.Close() }()
	return t, nil
}

// Stream is an unbounded live command output stream for authenticated humans.
// The consumer must drain both readers and call Close when its browser closes.
type Stream struct {
	Stdout    io.Reader
	Stderr    io.Reader
	session   *ownedSession
	entry     *hostEntry
	release   func()
	closeOnce sync.Once
	closed    chan struct{}
	waitDone  chan struct{}
	waitErr   error
}

func (s *Stream) Close() error {
	s.closeOnce.Do(func() { close(s.closed); stopSession(s.session, s.entry); s.release() })
	return nil
}
func (s *Stream) Wait() error { <-s.waitDone; return s.waitErr }

func (p *Pool) Stream(ctx context.Context, name, command string) (*Stream, error) {
	e, err := p.entry(name)
	if err != nil {
		return nil, err
	}
	rewritten, inject := RewriteSudo(command, e.host.SudoPasswordInject)
	prepared, err := prepareCommand(rewritten, "")
	if err != nil {
		return nil, classify(name, "invalid_arguments", err)
	}
	session, release, err := p.session(ctx, e)
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = session.Close(); release() }
	password := ""
	if inject {
		password, err = p.decrypt(e.host.PasswordEnc)
		if err != nil {
			cleanup()
			return nil, classify(name, "secret_decryption_failed", err)
		}
		session.Stdin = strings.NewReader(password + "\n")
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		cleanup()
		return nil, err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		cleanup()
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- session.Start(prepared) }()
	select {
	case <-ctx.Done():
		stopSession(session, e)
		cleanup()
		return nil, classify(name, "session_failed", ctx.Err())
	case err := <-done:
		if err != nil {
			cleanup()
			return nil, classify(name, "session_failed", err)
		}
	}
	s := &Stream{Stdout: newRedactingReader(stdout, password), Stderr: newRedactingReader(stderr, password), session: session, entry: e, release: release, closed: make(chan struct{}), waitDone: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-s.closed:
		}
	}()
	go func() {
		s.waitErr = session.Wait()
		if ctx.Err() != nil {
			s.waitErr = ctx.Err()
		}
		close(s.waitDone)
		_ = s.Close()
	}()
	return s, nil
}

// IsTimeout identifies either a queue, connection, or command deadline.
func IsTimeout(err error) bool { return errors.Is(err, context.DeadlineExceeded) }
