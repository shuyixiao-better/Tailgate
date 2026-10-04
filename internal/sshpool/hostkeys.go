package sshpool

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type HostKeyStatus struct {
	Host                string    `json:"host"`
	Address             string    `json:"address"`
	Fingerprint         string    `json:"fingerprint,omitempty"`
	PreviousFingerprint string    `json:"previous_fingerprint,omitempty"`
	Changed             bool      `json:"changed"`
	LastSeen            time.Time `json:"last_seen,omitempty"`
}

func (p *Pool) hostKeyCallback(name string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		p.keysMu.Lock()
		defer p.keysMu.Unlock()
		callback, err := knownhosts.New(p.knownHostsPath)
		if err != nil {
			return fmt.Errorf("load known_hosts: %w", err)
		}
		status := HostKeyStatus{Host: name, Address: hostname, Fingerprint: ssh.FingerprintSHA256(key), LastSeen: time.Now().UTC()}
		err = callback(hostname, remote, key)
		if err == nil {
			p.keys[name] = status
			return nil
		}
		var keyError *knownhosts.KeyError
		if !errors.As(err, &keyError) {
			return fmt.Errorf("verify host key: %w", err)
		}
		if len(keyError.Want) != 0 {
			status.Changed = true
			status.PreviousFingerprint = ssh.FingerprintSHA256(keyError.Want[0].Key)
			p.keys[name] = status
			slog.Error("SSH host key changed; connection refused", "host", name, "address", hostname, "expected", status.PreviousFingerprint, "presented", status.Fingerprint)
			return &Error{Code: "host_key_changed", Host: name, Err: fmt.Errorf("host fingerprint changed from %s to %s; administrator confirmation is required", status.PreviousFingerprint, status.Fingerprint)}
		}
		file, err := os.OpenFile(p.knownHostsPath, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("open known_hosts for TOFU: %w", err)
		}
		_, writeErr := fmt.Fprintln(file, knownhosts.Line([]string{hostname}, key))
		syncErr := file.Sync()
		closeErr := file.Close()
		if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
			return fmt.Errorf("save first host fingerprint: %w", err)
		}
		p.keys[name] = status
		slog.Info("SSH host fingerprint trusted on first connection", "host", name, "address", hostname, "fingerprint", status.Fingerprint)
		return nil
	}
}

func (p *Pool) KnownHosts() []HostKeyStatus {
	p.keysMu.Lock()
	defer p.keysMu.Unlock()
	statuses := make([]HostKeyStatus, 0, len(p.keys))
	for _, status := range p.keys {
		statuses = append(statuses, status)
	}
	return statuses
}

// ConfirmHostKey fetches a fresh key and explicitly replaces the trusted key.
// The caller must restrict this operation to an authenticated administrator.
func (p *Pool) ConfirmHostKey(ctx context.Context, name string) (HostKeyStatus, error) {
	return p.confirmHostKey(ctx, name, "")
}

// ConfirmHostKeyExpected refuses replacement if the fresh key differs from the
// fingerprint the administrator reviewed, avoiding blind trust across a race.
func (p *Pool) ConfirmHostKeyExpected(ctx context.Context, name, expected string) (HostKeyStatus, error) {
	if expected == "" {
		return HostKeyStatus{}, &Error{Code: "invalid_arguments", Host: name, Err: errors.New("reviewed fingerprint is required")}
	}
	return p.confirmHostKey(ctx, name, expected)
}

func (p *Pool) confirmHostKey(ctx context.Context, name, expected string) (HostKeyStatus, error) {
	e, err := p.entry(name)
	if err != nil {
		return HostKeyStatus{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, p.settings.ConnectTimeout)
	defer cancel()
	address := hostAddress(e.host)
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return HostKeyStatus{}, classify(name, "connection_failed", err)
	}
	defer conn.Close()
	stopWatch := watchConn(ctx, conn)
	defer stopWatch()
	_ = conn.SetDeadline(deadlineFor(ctx, p.settings.ConnectTimeout))
	var key ssh.PublicKey
	probeDone := errors.New("host key probe completed")
	_, _, _, handshakeErr := ssh.NewClientConn(conn, address, &ssh.ClientConfig{
		User:            e.host.Username,
		HostKeyCallback: func(_ string, _ net.Addr, presented ssh.PublicKey) error { key = presented; return probeDone },
	})
	if key == nil {
		return HostKeyStatus{}, classify(name, "connection_failed", handshakeErr)
	}
	if ctx.Err() != nil {
		return HostKeyStatus{}, classify(name, "timeout", ctx.Err())
	}
	if expected != "" && ssh.FingerprintSHA256(key) != expected {
		status := HostKeyStatus{Host: name, Address: address, Fingerprint: ssh.FingerprintSHA256(key), Changed: true, LastSeen: time.Now().UTC()}
		p.keysMu.Lock()
		previous := p.keys[name]
		status.PreviousFingerprint = previous.PreviousFingerprint
		if status.PreviousFingerprint == "" {
			status.PreviousFingerprint = previous.Fingerprint
		}
		p.keys[name] = status
		p.keysMu.Unlock()
		return status, &Error{Code: "host_key_changed", Host: name, Err: fmt.Errorf("host fingerprint changed since review: expected %s, now %s; review the current key before confirming", expected, status.Fingerprint)}
	}
	p.keysMu.Lock()
	defer p.keysMu.Unlock()
	contents, err := os.ReadFile(p.knownHostsPath)
	if err != nil {
		return HostKeyStatus{}, fmt.Errorf("read known_hosts for replacement: %w", err)
	}
	var updated bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			fmt.Fprintln(&updated, line)
			continue
		}
		_, hostnames, _, _, _, parseErr := ssh.ParseKnownHosts([]byte(line))
		if parseErr != nil {
			return HostKeyStatus{}, fmt.Errorf("parse known_hosts for replacement: %w", parseErr)
		}
		var retained []string
		for _, hostname := range hostnames {
			if !matchesHost(hostname, knownhosts.Normalize(address)) {
				retained = append(retained, hostname)
			}
		}
		if len(retained) == len(hostnames) {
			fmt.Fprintln(&updated, line)
		} else if len(retained) > 0 {
			fields := strings.Fields(line)
			index := 0
			if strings.HasPrefix(fields[0], "@") {
				index = 1
			}
			fields[index] = strings.Join(retained, ",")
			fmt.Fprintln(&updated, strings.Join(fields, " "))
		}
	}
	if err := scanner.Err(); err != nil {
		return HostKeyStatus{}, fmt.Errorf("scan known_hosts for replacement: %w", err)
	}
	fmt.Fprintln(&updated, knownhosts.Line([]string{address}, key))
	if err := replaceKnownHosts(p.knownHostsPath, updated.Bytes()); err != nil {
		return HostKeyStatus{}, err
	}
	status := HostKeyStatus{Host: name, Address: address, Fingerprint: ssh.FingerprintSHA256(key), LastSeen: time.Now().UTC()}
	p.keys[name] = status
	e.disconnect(nil)
	slog.Warn("SSH host fingerprint explicitly updated by administrator", "host", name, "fingerprint", status.Fingerprint)
	return status, nil
}

func matchesHost(pattern, hostname string) bool {
	if pattern == hostname {
		return true
	}
	if strings.HasPrefix(pattern, "|1|") {
		parts := strings.Split(pattern, "|")
		if len(parts) != 4 {
			return false
		}
		salt, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			return false
		}
		digest, err := base64.StdEncoding.DecodeString(parts[3])
		if err != nil {
			return false
		}
		h := hmac.New(sha1.New, salt)
		_, _ = h.Write([]byte(hostname))
		return hmac.Equal(h.Sum(nil), digest)
	}
	// Tailgate writes exact hostnames. Existing wildcard entries cannot safely be
	// edited for a single host; retain them so a conflicting rule still refuses.
	return false
}

func replaceKnownHosts(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".known_hosts-")
	if err != nil {
		return fmt.Errorf("create replacement known_hosts: %w", err)
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return fmt.Errorf("secure replacement known_hosts: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write replacement known_hosts: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync replacement known_hosts: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close replacement known_hosts: %w", err)
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("replace known_hosts: %w", err)
	}
	return nil
}
