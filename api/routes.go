package api

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func (h *Handlers) RegisterRoutes(mux *http.ServeMux) {
	// Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())

	// API endpoints
	mux.HandleFunc("/health", h.Health)
	mux.HandleFunc("/api/v1/instances", h.Instances)
	mux.HandleFunc("/api/v1/dispatcher/", h.Dispatcher)
	mux.HandleFunc("/api/v1/refresh", h.Refresh)
	mux.HandleFunc("/api/v1/status", h.Status)

	// Root endpoint
	mux.HandleFunc("/", h.Root)
}

func (h *Handlers) Root(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	html := `<!DOCTYPE html>
<html>
<head>
    <title>SAP Monitor Exporter</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        .container { max-width: 1200px; margin: 0 auto; }
        .endpoints { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .endpoint { margin: 10px 0; padding: 10px; background: white; border-left: 4px solid #4CAF50; }
    </style>
</head>
<body>
    <div class="container">
        <h1>SAP Monitor Exporter</h1>
        <p>Monitoring SAP instances with detailed dispatcher and enqueue metrics.</p>
        
        <div class="endpoints">
            <h2>Endpoints</h2>
            <div class="endpoint">
                <strong><a href="/metrics">/metrics</a></strong> - Prometheus metrics
            </div>
            <div class="endpoint">
                <strong><a href="/health">/health</a></strong> - Health check
            </div>
            <div class="endpoint">
                <strong><a href="/api/v1/instances">/api/v1/instances</a></strong> - List all instances
            </div>
            <div class="endpoint">
                <strong><a href="/api/v1/status">/api/v1/status</a></strong> - Exporter status
            </div>
        </div>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
