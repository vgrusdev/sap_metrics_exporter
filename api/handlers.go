package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/vgrusdev/sap_metrics_exporter/cache"
	"github.com/vgrusdev/sap_metrics_exporter/config"
	"github.com/vgrusdev/sap_metrics_exporter/metrics"
	"github.com/vgrusdev/sap_metrics_exporter/scrape"
	"github.com/vgrusdev/sap_metrics_exporter/utils"
)

type Handlers struct {
	config    *config.Config
	scrapeMgr *scrape.Manager
	cacheMgr  *cache.Manager
	metrics   *metrics.Registry
	logger    *utils.Logger
}

func NewHandlers(cfg *config.Config, scrapeMgr *scrape.Manager, cacheMgr *cache.Manager, metrics *metrics.Registry) *Handlers {
	return &Handlers{
		config:    cfg,
		scrapeMgr: scrapeMgr,
		cacheMgr:  cacheMgr,
		metrics:   metrics,
		logger:    utils.NewLogger("api"),
	}
}

func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	cacheStats := h.cacheMgr.GetStats()

	status := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"cache":     cacheStats,
		"version":   "1.0.0",
	}

	h.respondJSON(w, status)
}

func (h *Handlers) Instances(w http.ResponseWriter, r *http.Request) {
	instances := h.cacheMgr.GetInstances()

	instancesData := make([]map[string]interface{}, len(instances))
	for i, inst := range instances {
		instancesData[i] = map[string]interface{}{
			"instance":        inst.InstanceNr,
			"hostname":        inst.Hostname,
			"system_id":       inst.SystemID,
			"status":          inst.Dispstatus,
			"status_text":     inst.StatusText,
			"dispatcher_port": inst.DispatcherPort,
			"enqueue_port":    inst.EnqueuePort,
			"last_scrape":     inst.LastScrape.Format(time.RFC3339),
			"scrape_success":  inst.ScrapeSuccess,
			"is_primary":      inst.IsPrimary,
			"last_error":      inst.LastError,
		}
	}

	response := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"count":     len(instances),
		"instances": instancesData,
	}

	h.respondJSON(w, response)
}

func (h *Handlers) Dispatcher(w http.ResponseWriter, r *http.Request) {
	instance := strings.TrimPrefix(r.URL.Path, "/api/v1/dispatcher/")
	if instance == "" {
		instance = r.URL.Query().Get("instance")
		if instance == "" {
			instance = h.config.PrimaryInstance
		}
	}

	inst := h.cacheMgr.GetInstance(instance)
	if inst == nil {
		h.respondError(w, "Instance not found", http.StatusNotFound)
		return
	}

	// In production, you would fetch fresh data here
	// For now, return cached metrics
	data := map[string]interface{}{
		"instance":    inst.InstanceNr,
		"hostname":    inst.Hostname,
		"last_update": inst.Metrics.LastCollection.Format(time.RFC3339),
		"metrics":     inst.Metrics,
	}

	h.respondJSON(w, data)
}

func (h *Handlers) Refresh(w http.ResponseWriter, r *http.Request) {
	h.cacheMgr.Clear()

	h.respondJSON(w, map[string]string{
		"status":    "cache_refreshed",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	cacheStats := h.cacheMgr.GetStats()

	status := map[string]interface{}{
		"timestamp":        time.Now().Format(time.RFC3339),
		"cache":            cacheStats,
		"detailed_metrics": h.config.DetailedMetrics,
		"scrape_interval":  h.config.ScrapeInterval.String(),
		"primary_instance": h.config.PrimaryInstance,
	}

	h.respondJSON(w, status)
}

func (h *Handlers) Metrics(w http.ResponseWriter, r *http.Request) {
	// This would be handled by promhttp.Handler()
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (h *Handlers) respondJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *Handlers) respondError(w http.ResponseWriter, message string, status int) {
	h.respondJSON(w, map[string]interface{}{
		"error":     message,
		"timestamp": time.Now().Format(time.RFC3339),
		"status":    status,
	})
	w.WriteHeader(status)
}
