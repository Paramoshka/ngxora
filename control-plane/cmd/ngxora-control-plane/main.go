package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/paramoshka/ngxora/control-plane/internal/config"
	cpcontroller "github.com/paramoshka/ngxora/control-plane/internal/controller"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg, err := config.FromEnv()
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	mgr, err := cpcontroller.NewManager(cfg, logger)
	if err != nil {
		logger.Error("failed to build controller manager", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("starting control-plane", "namespace", cfg.WatchNamespace, "uds", cfg.SocketPath)

	if err := mgr.Start(ctx); err != nil {
		logger.Error("controller manager stopped with error", "error", err)
		os.Exit(1)
	}
}
