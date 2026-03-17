package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bigtcze/pve-exporter/collector"
	"github.com/bigtcze/pve-exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// CLI flags
	showVersion := flag.Bool("version", false, "Print version and exit")
	selfUpdate := flag.Bool("selfupdate", false, "Update to latest version and restart")
	configFile := flag.String("config", "", "Path to configuration file")
	flag.Parse()

	// Handle --version
	if *showVersion {
		fmt.Printf("pve-exporter version=%s commit=%s date=%s\n", version, commit, date)
		os.Exit(0)
	}

	// Handle --selfupdate
	if *selfUpdate {
		if err := SelfUpdate(version); err != nil {
			slog.Error("self-update failed", "error", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	slog.Info("starting pve-exporter", "version", version, "commit", commit, "date", date)

	// Load configuration
	cfg, err := config.LoadFromFile(*configFile)
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	if cfg.Proxmox.InsecureSkipVerify {
		slog.Warn("TLS certificate verification is disabled, this is insecure for production use")
	}

	collector.SetBuildInfo(version, commit)

	slog.Info("connecting to Proxmox", "host", cfg.Proxmox.Host, "port", cfg.Proxmox.Port)

	// Create Prometheus registry
	registry := prometheus.NewRegistry()

	// Register Proxmox collector
	proxmoxCollector := collector.NewProxmoxCollector(&cfg.Proxmox, slog.Default())
	registry.MustRegister(proxmoxCollector)

	// Setup HTTP server
	mux := http.NewServeMux()

	// Metrics endpoint
	mux.Handle(cfg.Server.MetricsPath, promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		ErrorLog:      log.New(os.Stderr, "", log.LstdFlags),
		ErrorHandling: promhttp.ContinueOnError,
	}))

	// Health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "OK\n")
	})

	// Root endpoint with info
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<html>
<head><title>Proxmox Exporter</title></head>
<body>
<h1>Proxmox Exporter</h1>
<p>Version: %s</p>
<p>Commit: %s</p>
<p>Build Date: %s</p>
<p><a href="%s">Metrics</a></p>
<p><a href="/health">Health</a></p>
</body>
</html>`, version, commit, date, cfg.Server.MetricsPath)
	})

	// Start HTTP server
	server := &http.Server{
		Addr:         cfg.Server.ListenAddress,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		slog.Info("shutting down gracefully", "timeout", "15s")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown error", "error", err)
		}
	}()

	slog.Info("starting HTTP server", "address", cfg.Server.ListenAddress)
	slog.Info("metrics available", "path", cfg.Server.MetricsPath)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("HTTP server failed", "error", err)
		os.Exit(1)
	}

	slog.Info("exporter stopped")
}
