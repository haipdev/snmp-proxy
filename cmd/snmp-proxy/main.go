package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/snmp-proxy/internal/gateway"
)

var (
	version   = "unknown"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	cfg, err := gateway.LoadConfig(os.Args[1:], os.Getenv)
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLevel(cfg.LogLevel)}))
	if cfg.WriteTimeout < cfg.DefaultSNMPTimeout*time.Duration(cfg.DefaultSNMPRetries+1) {
		logger.Warn("HTTP write timeout may be shorter than SNMP execution budget")
	}
	if err := gateway.EnsureTLSMaterial(cfg); err != nil {
		logger.Error("prepare TLS material", "error", err)
		os.Exit(1)
	}

	app := gateway.NewServer(cfg, logger, gateway.GoSNMPExecutor{MaxVarbinds: cfg.MaxVarbindsPerOperation}, version, commit, buildTime)
	httpServer := app.HTTPServer()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app.StartStatsLoop(ctx)

	errCh := make(chan error, 1)
	go func() {
		if cfg.TLSEnabled {
			errCh <- httpServer.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath)
			return
		}
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped", "error", err)
			os.Exit(1)
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := gateway.ShutdownHTTP(shutdownCtx, httpServer); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
}

func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
