package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/vgrusdev/sap_metrics_exporter/api"
	"github.com/vgrusdev/sap_metrics_exporter/cache"
	"github.com/vgrusdev/sap_metrics_exporter/config"
	"github.com/vgrusdev/sap_metrics_exporter/metrics"
	"github.com/vgrusdev/sap_metrics_exporter/scrape"
	"github.com/vgrusdev/sap_metrics_exporter/utils"
)

var (
	version          = "0.1.0-development"
	buildDate string = "December 2025"
)

func main() {
	// Parse command line flags
	configFile := flag.String("config", "", "Configuration file path")
	versionFlag := flag.Bool("version", false, "Show version")
	flag.Parse()

	if *versionFlag {
		showVersion()
	}

	// Initialize logger
	logger := utils.NewLogger("main")

	// Load configuration
	//cfg, err := config.Load(*configFile)
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		logger.Fatal("Failed to load configuration", "error", err)
	}

	logger.Debug("Config %s", cfg)
	logger.Info("Starting SAP Metrics Exporter",
		"version", version,
		"primary_instance", cfg.PrimaryInstance,
		"host", cfg.Host,
		"port", cfg.Port,
	)

	// Initialize components
	cacheMgr := cache.NewManager(cfg.CacheTTL)
	metricsReg := metrics.NewRegistry()

	// Initialize scrape manager
	scrapeMgr, err := scrape.NewManager(cfg, cacheMgr, metricsReg)
	if err != nil {
		logger.Fatal("Failed to create scrape manager", "error", err)
	}

	// Start background scraping
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scrapeMgr.Start(ctx)

	// Initialize HTTP server
	server := api.NewServer(cfg, scrapeMgr, cacheMgr, metricsReg)

	// Start HTTP server
	go func() {
		logger.Info("Starting HTTP server", "address", cfg.ListenAddress)
		if err := server.Start(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("HTTP server failed", "error", err)
		}
	}()

	// Wait for shutdown signal
	waitForShutdown(logger, server, scrapeMgr)
}

func waitForShutdown(logger *utils.Logger, server *api.Server, scrapeMgr *scrape.Manager) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	logger.Info("Shutdown signal received")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop HTTP server
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("HTTP server shutdown error", "error", err)
	}

	// Stop scrape manager
	scrapeMgr.Stop()

	logger.Info("Shutdown completed")
}
func showVersion() {
	fmt.Printf("SAP_Metrics_Exporter, %s version\nbuilt with %s %s/%s %s\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH, buildDate)
	os.Exit(0)
}
