package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestProgramGracefulStopAndUnexpectedFailure(t *testing.T) {
	unexpected := make(chan error, 1)
	started := make(chan struct{})
	p := &program{timeout: time.Second, onUnexpected: func(err error) { unexpected <- err }, run: func(ctx context.Context) error { close(started); <-ctx.Done(); return nil }}
	if err := p.Start(nil); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := p.Stop(nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-unexpected:
		t.Fatalf("normal stop treated as failure: %v", err)
	default:
	}
	if err := p.Stop(nil); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("gateway failed")
	p = &program{timeout: time.Second, onUnexpected: func(err error) { unexpected <- err }, run: func(context.Context) error { return failure }}
	if err := p.Start(nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-unexpected:
		if !errors.Is(err, failure) {
			t.Fatalf("failure: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("unexpected failure not propagated")
	}
}

func TestServiceConfiguration(t *testing.T) {
	dir := t.TempDir()
	cfg, err := serviceConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Name != "Tailgate" || !filepath.IsAbs(cfg.Executable) || !filepath.IsAbs(cfg.WorkingDirectory) || len(cfg.Arguments) != 3 || cfg.Arguments[1] != dir || cfg.Option["OnFailure"] != "restart" || cfg.Option["StartType"] != "automatic" {
		t.Fatalf("configuration: %#v", cfg)
	}
}
