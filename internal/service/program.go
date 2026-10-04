// Package service connects the gateway lifecycle to Windows Service Control Manager.
package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	kservice "github.com/kardianos/service"
)

const Name = "Tailgate"

type program struct {
	run          func(context.Context) error
	timeout      time.Duration
	onUnexpected func(error)
	mu           sync.Mutex
	cancel       context.CancelFunc
	done         chan struct{}
	err          error
	stopping     bool
}

// Start returns promptly as required by Service Control Manager. The gateway
// owns its graceful shutdown and returns only after its audit and DB resources close.
func (p *program) Start(_ kservice.Service) error {
	p.mu.Lock()
	if p.done != nil {
		p.mu.Unlock()
		return errors.New("service runtime is already started")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan struct{})
	p.mu.Unlock()
	go func() {
		err := p.run(ctx)
		p.mu.Lock()
		p.err = err
		unexpected := !p.stopping
		close(p.done)
		p.mu.Unlock()
		if unexpected {
			if err == nil {
				err = errors.New("gateway stopped without a service stop request")
			}
			p.onUnexpected(err)
		}
	}()
	return nil
}

func (p *program) Stop(_ kservice.Service) error {
	p.mu.Lock()
	if p.done == nil {
		p.mu.Unlock()
		return nil
	}
	p.stopping = true
	p.cancel()
	done := p.done
	p.mu.Unlock()
	timeout := p.timeout
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	select {
	case <-done:
		p.mu.Lock()
		err := p.err
		p.mu.Unlock()
		return err
	case <-ctx.Done():
		return fmt.Errorf("service gateway shutdown exceeded %s: %w", timeout, ctx.Err())
	}
}

func (p *program) Shutdown(s kservice.Service) error { return p.Stop(s) }

func serviceConfig(dataDir string) (*kservice.Config, error) {
	dir, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("resolve service data directory: %w", err)
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve service executable: %w", err)
	}
	return &kservice.Config{Name: Name, DisplayName: "Tailgate SSH Gateway", Description: "LAN gateway for audited MCP and Web access to Tailscale SSH hosts", Executable: executable, Arguments: []string{"--data-dir", dir, "run"}, WorkingDirectory: filepath.Dir(executable), Option: kservice.KeyValue{"StartType": "automatic", "DelayedAutoStart": true, "OnFailure": "restart", "OnFailureDelayDuration": "5s", "OnFailureResetPeriod": 86400}}, nil
}
