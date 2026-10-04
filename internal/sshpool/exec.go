package sshpool

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type ExecOptions struct {
	Timeout time.Duration
	Workdir string
}

type Result struct {
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
	ExitCode    int    `json:"exit_code"`
	DurationMS  int64  `json:"duration_ms"`
	Truncated   bool   `json:"truncated"`
	OutputBytes int64  `json:"output_bytes"`
	StdoutBytes int64  `json:"stdout_bytes"`
	StderrBytes int64  `json:"stderr_bytes"`
}

func (p *Pool) commandContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc, error) {
	if timeout < 0 {
		return nil, nil, fmt.Errorf("command timeout must be positive")
	}
	if timeout == 0 {
		timeout = p.settings.DefaultCommandTimeout
	}
	if timeout > p.settings.MaxCommandTimeout {
		timeout = p.settings.MaxCommandTimeout
	}
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	return commandCtx, cancel, nil
}

func (p *Pool) Execute(ctx context.Context, name, command string, opts ExecOptions) (Result, error) {
	started := time.Now()
	result := Result{ExitCode: -1}
	ctx, cancel, err := p.commandContext(ctx, opts.Timeout)
	if err != nil {
		return result, classify(name, "invalid_arguments", err)
	}
	defer cancel()
	e, err := p.entry(name)
	if err != nil {
		return result, err
	}
	rewritten, inject := RewriteSudo(command, e.host.SudoPasswordInject)
	prepared, err := prepareCommand(rewritten, opts.Workdir)
	if err != nil {
		return result, classify(name, "invalid_arguments", err)
	}
	session, release, err := p.session(ctx, e)
	if err != nil {
		result.DurationMS = time.Since(started).Milliseconds()
		return result, err
	}
	defer release()
	defer session.Close()
	password := ""
	if inject {
		password, err = p.decrypt(e.host.PasswordEnc)
		if err != nil {
			return result, classify(name, "secret_decryption_failed", err)
		}
		session.Stdin = strings.NewReader(password + "\n")
	}
	stdout, stderr := newHeadTailBuffer(p.settings.MaxOutputBytes), newHeadTailBuffer(p.settings.MaxOutputBytes)
	outWriter := &redactingWriter{target: stdout, secret: []byte(password)}
	errWriter := &redactingWriter{target: stderr, secret: []byte(password)}
	session.Stdout, session.Stderr = outWriter, errWriter
	done := make(chan error, 1)
	go func() { done <- session.Run(prepared) }()
	select {
	case err = <-done:
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	case <-ctx.Done():
		stopSession(session, e)
		// Closing the session also stops the SDK's stdout/stderr copy goroutines.
		select {
		case <-done:
		case <-time.After(time.Second):
			e.disconnect(session.client)
			<-done
		}
		err = ctx.Err()
	}
	flushErr := errors.Join(outWriter.flush(), errWriter.flush())
	if err == nil {
		err = flushErr
	}
	result.Stdout, result.Stderr, result.Truncated = renderOutput(stdout, stderr, p.settings.MaxOutputBytes)
	result.StdoutBytes, result.StderrBytes = outWriter.total, errWriter.total
	result.OutputBytes = result.StdoutBytes + result.StderrBytes
	result.DurationMS = time.Since(started).Milliseconds()
	if err == nil {
		result.ExitCode = 0
		return result, nil
	}
	var exitError *ssh.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitStatus()
		return result, nil
	}
	return result, classify(name, "command_failed", err)
}

// stopSession first asks the peer to kill the process, then closes its channel.
// A stuck peer must not prevent context cancellation from making progress.
func stopSession(session *ownedSession, e *hostEntry) {
	// Preserve wire order: closing concurrently can reject the signal before
	// it reaches OpenSSH and leave a non-PTY process such as sleep running.
	signalSent := make(chan struct{})
	go func() { _ = session.Signal(ssh.SIGKILL); close(signalSent) }()
	select {
	case <-signalSent:
	case <-time.After(250 * time.Millisecond):
		e.disconnect(session.client)
		return
	}
	done := make(chan struct{})
	go func() { _ = session.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		e.disconnect(session.client)
	}
}

type TestResult struct {
	Host          string `json:"host"`
	LatencyMS     int64  `json:"latency_ms"`
	Fingerprint   string `json:"fingerprint"`
	SystemVersion string `json:"system_version"`
	Hostname      string `json:"hostname"`
}

const TestCommand = "hostname; if [ -r /etc/os-release ]; then . /etc/os-release; printf '%s\\n' \"$PRETTY_NAME\"; else uname -sr; fi"

func (p *Pool) Test(ctx context.Context, name string) (TestResult, error) {
	started := time.Now()
	result, err := p.Execute(ctx, name, TestCommand, ExecOptions{Timeout: p.settings.ConnectTimeout + p.settings.DefaultCommandTimeout})
	if err != nil {
		return TestResult{}, err
	}
	if result.ExitCode != 0 {
		return TestResult{}, classify(name, "command_failed", fmt.Errorf("host test exited with status %d: %s", result.ExitCode, result.Stderr))
	}
	lines := strings.Split(strings.TrimSpace(result.Stdout), "\n")
	test := TestResult{Host: name, LatencyMS: time.Since(started).Milliseconds()}
	if len(lines) > 0 {
		test.Hostname = lines[0]
	}
	if len(lines) > 1 {
		test.SystemVersion = lines[1]
	}
	p.keysMu.Lock()
	test.Fingerprint = p.keys[name].Fingerprint
	p.keysMu.Unlock()
	return test, nil
}
