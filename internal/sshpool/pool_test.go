//go:build !windows

package sshpool

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"tailgate/internal/config"
)

type testSSHServer struct {
	listener    net.Listener
	signer      ssh.Signer
	connections atomic.Int32
	started     chan string
	mu          sync.Mutex
	clients     []net.Conn
	wg          sync.WaitGroup
}

func newTestSSHServer(t *testing.T, address string, keyboardOnly bool) *testSSHServer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	s := &testSSHServer{listener: listener, signer: signer, started: make(chan string, 20)}
	serverConfig := &ssh.ServerConfig{}
	if !keyboardOnly {
		serverConfig.PasswordCallback = func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if metadata.User() != "ubuntu" || string(password) != "s3cr'et!" {
				return nil, errors.New("password rejected")
			}
			return nil, nil
		}
	}
	serverConfig.KeyboardInteractiveCallback = func(metadata ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		answers, err := challenge(metadata.User(), "", []string{"Password:"}, []bool{false})
		if err != nil {
			return nil, err
		}
		if metadata.User() != "ubuntu" || len(answers) != 1 || answers[0] != "s3cr'et!" {
			return nil, errors.New("keyboard password rejected")
		}
		return nil, nil
	}
	serverConfig.AddHostKey(signer)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.clients = append(s.clients, conn)
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer conn.Close()
				serverConn, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
				if err != nil {
					return
				}
				defer serverConn.Close()
				s.connections.Add(1)
				go func() {
					for req := range requests {
						_ = req.Reply(false, nil)
					}
				}()
				for newChannel := range channels {
					if newChannel.ChannelType() != "session" {
						_ = newChannel.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					channel, requests, err := newChannel.Accept()
					if err != nil {
						continue
					}
					go s.handleSession(channel, requests)
				}
			}()
		}
	}()
	t.Cleanup(s.Close)
	return s
}

func (s *testSSHServer) Close() {
	_ = s.listener.Close()
	s.mu.Lock()
	for _, client := range s.clients {
		_ = client.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *testSSHServer) handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer channel.Close()
	completed := make(chan struct{})
	started := false
	for {
		select {
		case <-completed:
			return
		case req, ok := <-requests:
			if !ok {
				return
			}
			switch req.Type {
			case "exec":
				var payload struct{ Command string }
				if err := ssh.Unmarshal(req.Payload, &payload); err != nil || started {
					_ = req.Reply(false, nil)
					continue
				}
				started = true
				_ = req.Reply(true, nil)
				select {
				case s.started <- payload.Command:
				default:
				}
				go func(command string) {
					code := uint32(0)
					if strings.Contains(command, "sudo -S -p") {
						password, _ := bufio.NewReader(channel).ReadString('\n')
						_, _ = io.WriteString(channel, "echoed: "+password)
						_, _ = io.WriteString(channel.Stderr(), "echoed: "+password)
					} else {
						cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
						cmd.Stdout = channel
						cmd.Stderr = channel.Stderr()
						if err := cmd.Run(); err != nil {
							var exitErr *exec.ExitError
							if errors.As(err, &exitErr) {
								code = uint32(exitErr.ExitCode())
							} else {
								code = 255
							}
						}
					}
					_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
					close(completed)
				}(payload.Command)
			case "signal":
				cancel()
				_ = req.Reply(true, nil)
			default:
				_ = req.Reply(false, nil)
			}
		}
	}
}

func poolSettings() config.SSH {
	return config.SSH{ConnectTimeout: time.Second, KeepaliveInterval: 50 * time.Millisecond, DefaultCommandTimeout: time.Second, MaxCommandTimeout: 3 * time.Second, MaxOutputBytes: 1024, MaxSessionsPerHost: 1, HostKeyPolicy: "tofu"}
}

func testPool(t *testing.T, server *testSSHServer, dataDir string, sudo bool) *Pool {
	t.Helper()
	p, err := New(poolSettings(), dataDir, func(ciphertext string) (string, error) {
		if ciphertext != "encrypted" {
			return "", errors.New("invalid ciphertext")
		}
		return "s3cr'et!", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	address, portString, err := net.SplitHostPort(server.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscan(portString, &port); err != nil {
		t.Fatal(err)
	}
	if err := p.UpdateHosts([]config.Host{{Name: "test", Address: address, Port: port, Username: "ubuntu", PasswordEnc: "encrypted", SudoPasswordInject: sudo}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func TestPoolPasswordAndKeyboardAuthenticationReuse(t *testing.T) {
	for _, keyboardOnly := range []bool{false, true} {
		t.Run(fmt.Sprint(keyboardOnly), func(t *testing.T) {
			server := newTestSSHServer(t, "127.0.0.1:0", keyboardOnly)
			p := testPool(t, server, t.TempDir(), false)
			for range 2 {
				result, err := p.Execute(context.Background(), "test", "printf '%s' \"$LANG/$TERM/$PAGER/$SYSTEMD_PAGER\"; printf error >&2; exit 7", ExecOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if result.Stdout != "C.UTF-8/dumb/cat/cat" || result.Stderr != "error" || result.ExitCode != 7 {
					t.Fatalf("result %+v", result)
				}
			}
			if got := server.connections.Load(); got != 1 {
				t.Fatalf("expected one reused connection, got %d", got)
			}
		})
	}
}

func TestPoolQueueDeadlineAndCommandCancellation(t *testing.T) {
	server := newTestSSHServer(t, "127.0.0.1:0", false)
	p := testPool(t, server, t.TempDir(), false)
	firstDone := make(chan error, 1)
	go func() {
		_, err := p.Execute(context.Background(), "test", "sleep 0.15; printf done", ExecOptions{})
		firstDone <- err
	}()
	select {
	case <-server.started:
	case <-time.After(time.Second):
		t.Fatal("first command did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := p.Execute(ctx, "test", "printf should-not-run", ExecOptions{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected queue deadline, got %v", err)
	}
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	_, err = p.Execute(context.Background(), "test", "sleep 2", ExecOptions{Timeout: 30 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected execution deadline, got %v", err)
	}
	result, err := p.Execute(context.Background(), "test", "printf recovered", ExecOptions{})
	if err != nil || result.Stdout != "recovered" {
		t.Fatalf("pool unusable after cancellation: %+v %v", result, err)
	}
}

func TestPoolReconnectsDeadReusedConnectionBeforeExecution(t *testing.T) {
	server := newTestSSHServer(t, "127.0.0.1:0", false)
	p := testPool(t, server, t.TempDir(), false)
	if _, err := p.Execute(context.Background(), "test", "printf first", ExecOptions{}); err != nil {
		t.Fatal(err)
	}
	e, err := p.entry("test")
	if err != nil {
		t.Fatal(err)
	}
	// Keep a closed client in the entry to deterministically exercise the race
	// between a reused connection and the asynchronous disconnect watcher.
	e.mu.Lock()
	client := e.client
	if err := client.Close(); err != nil {
		e.mu.Unlock()
		t.Fatal(err)
	}
	_, err = client.NewSession()
	if err == nil {
		e.mu.Unlock()
		t.Fatal("test connection did not close")
	}
	e.mu.Unlock()
	// The watcher may clear it before this assignment. Reinstall the dead
	// pointer to model the exact instant before the watcher runs.
	e.mu.Lock()
	e.client = client
	e.mu.Unlock()
	result, err := p.Execute(context.Background(), "test", "printf recovered", ExecOptions{})
	if err != nil || result.Stdout != "recovered" {
		t.Fatalf("did not reconnect safely: %+v %v", result, err)
	}
	if server.connections.Load() != 2 {
		t.Fatalf("expected one reconnect, got %d connections", server.connections.Load())
	}
	if len(server.started) != 2 {
		t.Fatalf("command duplicated while reconnecting: %d executions", len(server.started))
	}
}

func TestPoolSudoDoesNotExposePassword(t *testing.T) {
	server := newTestSSHServer(t, "127.0.0.1:0", false)
	p := testPool(t, server, t.TempDir(), true)
	result, err := p.Execute(context.Background(), "test", "sudo id", ExecOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.Stdout, "s3cr'et!") || strings.Contains(result.Stderr, "s3cr'et!") {
		t.Fatal("password exposed")
	}
	if !strings.Contains(result.Stdout, "[REDACTED]") || !strings.Contains(result.Stderr, "[REDACTED]") {
		t.Fatalf("redaction missing %+v", result)
	}
	command := <-server.started
	if strings.Contains(command, "s3cr") {
		t.Fatal("password sent in command")
	}
}

func TestStreamSudoRedaction(t *testing.T) {
	server := newTestSSHServer(t, "127.0.0.1:0", false)
	p := testPool(t, server, t.TempDir(), true)
	stream, err := p.Stream(context.Background(), "test", "sudo id")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	stderrDone := make(chan []byte, 1)
	go func() { data, _ := io.ReadAll(stream.Stderr); stderrDone <- data }()
	out, err := io.ReadAll(stream.Stdout)
	if err != nil {
		t.Fatal(err)
	}
	errOut := <-stderrDone
	if err := stream.Wait(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "s3cr'et!") || strings.Contains(string(errOut), "s3cr'et!") || !strings.Contains(string(out), "[REDACTED]") {
		t.Fatalf("stream exposed password: %q %q", out, errOut)
	}
}

func TestPoolTOFURefusesChangeAndExplicitConfirmation(t *testing.T) {
	dir := t.TempDir()
	server := newTestSSHServer(t, "127.0.0.1:0", false)
	address := server.listener.Addr().String()
	p := testPool(t, server, dir, false)
	if _, err := p.Execute(context.Background(), "test", "true", ExecOptions{}); err != nil {
		t.Fatal(err)
	}
	_ = p.Close()
	server.Close()
	// Validate updates against hashed known_hosts entries too.
	line := knownhosts.Line([]string{address}, server.signer.PublicKey())
	fields := strings.Fields(line)
	fields[0] = knownhosts.HashHostname(knownhosts.Normalize(address))
	if err := os.WriteFile(filepath.Join(dir, "known_hosts"), []byte(strings.Join(fields, " ")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	second := newTestSSHServer(t, address, false)
	p2 := testPool(t, second, dir, false)
	_, err := p2.Execute(context.Background(), "test", "true", ExecOptions{})
	var poolErr *Error
	if !errors.As(err, &poolErr) || poolErr.Code != "host_key_changed" {
		t.Fatalf("expected changed fingerprint, got %v", err)
	}
	statuses := p2.KnownHosts()
	if len(statuses) != 1 || !statuses[0].Changed {
		t.Fatalf("missing key alert %+v", statuses)
	}
	before, err := os.ReadFile(filepath.Join(dir, "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p2.ConfirmHostKeyExpected(context.Background(), "test", ssh.FingerprintSHA256(server.signer.PublicKey())); err == nil {
		t.Fatal("accepted fingerprint differing from reviewed key")
	}
	after, err := os.ReadFile(filepath.Join(dir, "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("failed key confirmation modified trust file")
	}
	status, err := p2.ConfirmHostKeyExpected(context.Background(), "test", ssh.FingerprintSHA256(second.signer.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	if status.Changed || status.Fingerprint != ssh.FingerprintSHA256(second.signer.PublicKey()) {
		t.Fatalf("wrong confirmation %+v", status)
	}
	if _, err := p2.Execute(context.Background(), "test", "true", ExecOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestPoolUnknownHostAndWorkdirEscaping(t *testing.T) {
	server := newTestSSHServer(t, "127.0.0.1:0", false)
	p := testPool(t, server, t.TempDir(), false)
	_, err := p.Execute(context.Background(), "missing", "true", ExecOptions{})
	var poolErr *Error
	if !errors.As(err, &poolErr) || poolErr.Code != "host_not_found" {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "space ' quote")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	result, err := p.Execute(context.Background(), "test", "pwd", ExecOptions{Workdir: dir})
	if err != nil || strings.TrimSpace(result.Stdout) != dir {
		t.Fatalf("workdir escaping failed: %+v %v", result, err)
	}
}
