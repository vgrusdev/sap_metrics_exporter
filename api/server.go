package api

import (
	"context"
	"net/http"
	"time"

	"github.com/vgrusdev/sap_metrics_exporter/cache"
	"github.com/vgrusdev/sap_metrics_exporter/config"
	"github.com/vgrusdev/sap_metrics_exporter/metrics"
	"github.com/vgrusdev/sap_metrics_exporter/scrape"
)

type Server struct {
	config   *config.Config
	server   *http.Server
	handlers *Handlers
}

func NewServer(cfg *config.Config, scrapeMgr *scrape.Manager, cacheMgr *cache.Manager, metrics *metrics.Registry) *Server {
	handlers := NewHandlers(cfg, scrapeMgr, cacheMgr, metrics)

	mux := http.NewServeMux()
	handlers.RegisterRoutes(mux)

	// Add middleware
	handler := loggingMiddleware(mux)
	handler = recoveryMiddleware(handler)

	return &Server{
		config: cfg,
		server: &http.Server{
			Addr:         cfg.ListenAddress,
			Handler:      handler,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
		handlers: handlers,
	}
}

func (s *Server) Start() error {
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
