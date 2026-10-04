// Package app owns the gateway lifecycle and graceful resource shutdown.
package app

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/natefinch/lumberjack.v2"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"tailgate/internal/audit"
	"tailgate/internal/command"
	"tailgate/internal/config"
	"tailgate/internal/hosts"
	"tailgate/internal/mcpserver"
	"tailgate/internal/secret"
	"tailgate/internal/sshpool"
	"tailgate/internal/store"
	"tailgate/internal/transport"
	webserver "tailgate/internal/web"
	webassets "tailgate/web"
	"time"
)

func Run(ctx context.Context, dataDir, version string) (err error) {
	protector, err := secret.New(dataDir)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Join(dataDir, "logs"), 0700); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}
	rolling := &lumberjack.Logger{Filename: filepath.Join(dataDir, "logs", "tailgate.log"), MaxSize: 10, MaxBackups: 5, MaxAge: 30, Compress: true}
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(io.MultiWriter(rolling, os.Stderr), nil)))
	defer func() {
		if err != nil {
			slog.Error("gateway stopped with error", "error", err)
		}
		slog.SetDefault(previousLogger)
		err = errors.Join(err, rolling.Close())
	}()
	cfg, err := config.Load(filepath.Join(dataDir, "config.yaml"))
	if err != nil {
		return err
	}
	settings := cfg.Snapshot()
	tlsConfig, err := transport.TLS(dataDir, settings.Server)
	if err != nil {
		return err
	}
	db, err := store.Open(ctx, filepath.Join(dataDir, "tailgate.db"))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	auditor, err := audit.New(db, settings.Audit)
	if err != nil {
		return err
	}
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = errors.Join(err, auditor.Close(flushCtx))
	}()
	pool, err := sshpool.New(settings.SSH, dataDir, protector.Decrypt)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, pool.Close()) }()
	if err = pool.SyncConfig(cfg); err != nil {
		return err
	}
	monitor := hosts.New(cfg, pool)
	monitor.SetAudit(auditor)
	tools := &command.Service{Config: cfg, Pool: pool, Audit: auditor, OverviewProvider: monitor}
	website, err := webserver.New(webserver.Options{Config: cfg, Store: db, Pool: pool, Secrets: protector, Audit: auditor, Tools: tools, Assets: webassets.Handler()})
	if err != nil {
		return err
	}
	defer func() {
		closeCtx, c := context.WithTimeout(context.Background(), 15*time.Second)
		defer c()
		err = errors.Join(err, website.Close(closeCtx))
	}()
	mux := http.NewServeMux()
	mux.Handle(settings.MCP.Path, mcpserver.New(cfg, tools, version))
	mux.Handle("/", website.Handler())
	server := &http.Server{Handler: webserver.Wrap(cfg, mux), TLSConfig: tlsConfig, ReadTimeout: 15 * time.Second, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20}
	listener, err := net.Listen("tcp", settings.Server.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", settings.Server.Listen, err)
	}
	background, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); monitor.Run(background) }()
	go func() {
		defer workers.Done()
		cfg.Watch(background, time.Second, func(_ config.Config) {
			if e := pool.SyncConfig(cfg); e != nil {
				slog.Error("reload SSH hosts", "error", e)
			}
		})
	}()
	defer func() { cancel(); workers.Wait() }()
	done := make(chan error, 1)
	go func() {
		if tlsConfig != nil {
			done <- server.ServeTLS(listener, "", "")
		} else {
			done <- server.Serve(listener)
		}
	}()
	slog.Info("Tailgate listening", "address", listener.Addr(), "version", version)
	select {
	case <-ctx.Done():
	case err = <-done:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	}
	cancel()
	shutdownCtx, stop := context.WithTimeout(context.Background(), settings.SSH.MaxCommandTimeout+15*time.Second)
	defer stop()
	draining := make(chan error, 1)
	go func() { draining <- server.Shutdown(shutdownCtx) }()
	websocketCtx, webStop := context.WithTimeout(context.Background(), 15*time.Second)
	err = errors.Join(err, website.Close(websocketCtx))
	webStop()
	if e := <-draining; e != nil {
		err = errors.Join(err, e, server.Close())
	}
	return err
}
