//go:build !windows

package service

import (
	"context"
	"fmt"

	"tailgate/internal/app"
)

func Run(ctx context.Context, dataDir, version string) error { return app.Run(ctx, dataDir, version) }

func Control(ctx context.Context, _ string, _ string, action string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fmt.Errorf("service operation %s is available only on Windows; use tailgate run for development", action)
}
