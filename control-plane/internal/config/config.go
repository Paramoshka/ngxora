package config

import (
	"fmt"
	"os"
	"time"
)

type Config struct {
	SocketPath       string
	WatchNamespace   string
	ApplyTimeout     time.Duration
	ReconcileTimeout time.Duration
}

func FromEnv() (Config, error) {
	cfg := Config{
		SocketPath:       envOrDefault("NGXORA_SOCKET_PATH", "/tmp/ngxora-control.sock"),
		WatchNamespace:   envOrDefault("NGXORA_WATCH_NAMESPACE", "default"),
		ApplyTimeout:     5 * time.Second,
		ReconcileTimeout: 10 * time.Second,
	}

	if raw := os.Getenv("NGXORA_APPLY_TIMEOUT"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("parse NGXORA_APPLY_TIMEOUT: %w", err)
		}
		cfg.ApplyTimeout = d
	}

	if raw := os.Getenv("NGXORA_RECONCILE_TIMEOUT"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("parse NGXORA_RECONCILE_TIMEOUT: %w", err)
		}
		cfg.ReconcileTimeout = d
	}

	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
