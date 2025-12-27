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

func NewServer(cfg *config.Config, scrapeMgr *scrape.Manager, cacheMgr *cache.Manager, metricsReg *metrics.Registry) *Server {
	handlers := NewHandlers(cfg, scrapeMgr, cacheMgr, metricsReg)

	mux := http.NewServeMux()
	handlers.RegisterRoutes(mux)

	// Chain middlewares in order (last middleware is executed first)
	handler := ChainMiddleware(mux,
		// Recovery should be first to catch panics from other middlewares
		recoveryMiddleware,
		// Security headers
		SecurityHeadersMiddleware,
		// CORS
		CORSMiddleware,
		// Request ID for tracing
		RequestIDMiddleware,
		// Compression
		CompressionMiddleware,
		// Metrics collection
		//func(next http.Handler) http.Handler {
		//	return MetricsMiddleware(metricsReg, next)
		//},
		// Rate limiting (optional, based on config)
		//func(next http.Handler) http.Handler {
		//	if cfg.RateLimit > 0 {
		//		return RateLimitMiddleware(cfg.RateLimit, next)
		//	}
		//	return next
		//},
		// Authentication (optional, based on config)
		// 	type APIAuthConfig struct {
		//		Username string `json:"username"`
		//		Password string `json:"password"`
		//		Enabled  bool   `json:"enabled"`
		//	}
		func(next http.Handler) http.Handler {
			if cfg.API.Enabled && cfg.API.Username != "" {
				return AuthMiddleware(cfg.API.Username, cfg.API.Password, next)
			}
			return next
		},
		// Timeout (optional, based on config)
		func(next http.Handler) http.Handler {
			if cfg.RequestTimeout > 0 {
				return TimeoutMiddleware(cfg.RequestTimeout, next)
			}
			return next
		},
		// Logging should be last to capture everything
		loggingMiddleware,
	)

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
