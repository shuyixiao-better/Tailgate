//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	kservice "github.com/kardianos/service"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"tailgate/internal/app"
	"tailgate/internal/config"
	"tailgate/internal/secret"
)

func fatalRuntime(err error) {
	slog.Error("service gateway failed; exiting for Windows recovery restart", "error", err)
	// app.Run has already unwound all resources. Exiting with a nonzero process
	// code activates SCM crash-recovery actions instead of leaving a dead service.
	os.Exit(1)
}

func stopTimeout(dataDir string, requireConfig bool) (time.Duration, error) {
	cfg, err := config.Load(filepath.Join(dataDir, "config.yaml"))
	if err != nil {
		if requireConfig {
			return 0, fmt.Errorf("initialize Tailgate before installing or running the service: %w", err)
		}
		return config.Default().SSH.MaxCommandTimeout + 45*time.Second, nil
	}
	maximum := cfg.Snapshot().SSH.MaxCommandTimeout
	const maxDuration = time.Duration(1<<63 - 1)
	if maximum > maxDuration-45*time.Second {
		return maxDuration, nil
	}
	return maximum + 45*time.Second, nil
}

func Run(ctx context.Context, dataDir, version string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if kservice.Interactive() {
		return app.Run(ctx, dataDir, version)
	}
	timeout, err := stopTimeout(dataDir, true)
	if err != nil {
		return err
	}
	configuration, err := serviceConfig(dataDir)
	if err != nil {
		return err
	}
	p := &program{timeout: timeout, run: func(runCtx context.Context) error { return app.Run(runCtx, dataDir, version) }, onUnexpected: fatalRuntime}
	systemService, err := kservice.New(p, configuration)
	if err != nil {
		return fmt.Errorf("create Windows service runtime: %w", err)
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		if err := requestStop(); err != nil {
			slog.Error("request Windows service stop after context cancellation", "error", err)
		}
	})
	defer stopCancellation()
	return systemService.Run()
}

func Control(ctx context.Context, dataDir, version, action string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timeout, err := stopTimeout(dataDir, action == "install")
	if err != nil {
		return err
	}
	configuration, err := serviceConfig(dataDir)
	if err != nil {
		return err
	}
	p := &program{timeout: timeout, run: func(runCtx context.Context) error { return app.Run(runCtx, dataDir, version) }, onUnexpected: fatalRuntime}
	systemService, err := kservice.New(p, configuration)
	if err != nil {
		return fmt.Errorf("create Windows service controller: %w", err)
	}
	if action == "install" {
		if _, err := secret.New(dataDir); err != nil {
			return fmt.Errorf("protect service data directory before installation: %w", err)
		}
		if err := systemService.Install(); err != nil {
			return fmt.Errorf("install Tailgate Windows service (Administrator required): %w", err)
		}
		if err := configureRecovery(); err != nil {
			return errors.Join(err, systemService.Uninstall())
		}
		fmt.Println("Tailgate 服务已安装（LocalSystem、自动延迟启动、失败后 5 秒重启）。")
		return nil
	}
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to Windows Service Control Manager (Administrator required): %w", err)
	}
	defer manager.Disconnect()
	installed, err := manager.OpenService(Name)
	if err != nil {
		return fmt.Errorf("open Tailgate Windows service: %w", err)
	}
	defer installed.Close()
	if action == "status" {
		status, err := installed.Query()
		if err != nil {
			return fmt.Errorf("query Tailgate service status: %w", err)
		}
		fmt.Printf("Tailgate: %s\n", stateName(status.State))
		return nil
	}
	controlTimeout := timeout
	if controlTimeout < time.Duration(1<<63-1)-5*time.Second {
		controlTimeout += 5 * time.Second
	}
	controlCtx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	switch action {
	case "start":
		err = start(controlCtx, installed)
	case "stop":
		err = stop(controlCtx, installed)
	case "restart":
		if err = stop(controlCtx, installed); err == nil {
			err = start(controlCtx, installed)
		}
	case "uninstall":
		if err = stop(controlCtx, installed); err == nil {
			err = systemService.Uninstall()
		}
	default:
		return fmt.Errorf("unknown service action %q", action)
	}
	if err != nil {
		return fmt.Errorf("%s Tailgate Windows service: %w", action, err)
	}
	fmt.Printf("Tailgate 服务操作完成：%s\n", action)
	return nil
}

func requestStop() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	installed, err := manager.OpenService(Name)
	if err != nil {
		return err
	}
	defer installed.Close()
	status, err := installed.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped || status.State == svc.StopPending {
		return nil
	}
	if status.State == svc.StartPending {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := waitState(ctx, installed, svc.Running); err != nil {
			return err
		}
	}
	_, err = installed.Control(svc.Stop)
	return err
}

func configureRecovery() error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to configure recovery: %w", err)
	}
	defer manager.Disconnect()
	installed, err := manager.OpenService(Name)
	if err != nil {
		return fmt.Errorf("open service to configure recovery: %w", err)
	}
	defer installed.Close()
	// The library configures restart actions; include service-specific nonzero
	// stop codes as failures as well as process crashes.
	if err := installed.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("enable service failure recovery: %w", err)
	}
	return nil
}

func start(ctx context.Context, installed *mgr.Service) error {
	status, err := installed.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Running {
		return nil
	}
	if status.State == svc.StopPending {
		if err := waitState(ctx, installed, svc.Stopped); err != nil {
			return err
		}
		status.State = svc.Stopped
	}
	if status.State != svc.StartPending {
		if err := installed.Start(); err != nil {
			return err
		}
	}
	return waitState(ctx, installed, svc.Running)
}

func stop(ctx context.Context, installed *mgr.Service) error {
	status, err := installed.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped {
		return nil
	}
	if status.State == svc.StartPending {
		if err := waitState(ctx, installed, svc.Running); err != nil {
			return err
		}
	}
	if status.State != svc.StopPending {
		if _, err := installed.Control(svc.Stop); err != nil {
			return err
		}
	}
	return waitState(ctx, installed, svc.Stopped)
}

func waitState(ctx context.Context, installed *mgr.Service, want svc.State) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		status, err := installed.Query()
		if err != nil {
			return err
		}
		if status.State == want {
			return nil
		}
		if want == svc.Running && status.State == svc.Stopped {
			return fmt.Errorf("service stopped before reaching Running (Windows exit code %d, service exit code %d)", status.Win32ExitCode, status.ServiceSpecificExitCode)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func stateName(state svc.State) string {
	switch state {
	case svc.Running:
		return "运行中"
	case svc.Stopped:
		return "已停止"
	case svc.StartPending:
		return "启动中"
	case svc.StopPending:
		return "停止中"
	case svc.Paused:
		return "已暂停"
	default:
		slog.Warn("unrecognized Windows service state", "state", state)
		return fmt.Sprintf("未知状态 (%d)", state)
	}
}
