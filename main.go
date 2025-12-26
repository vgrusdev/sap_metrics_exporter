package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hooklift/gowsdl/soap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Command line flags
var (
	instanceFlag   = flag.String("instance", "00", "Primary SAP instance number")
	ipFlag         = flag.String("ip", "localhost", "SAP system IP address")
	portFlag       = flag.String("port", "50014", "SAP system port")
	listenAddr     = flag.String("listen", ":2112", "Metrics server listen address")
	scrapeInterval = flag.Duration("interval", 30*time.Second, "Scrape interval")
	timeoutFlag    = flag.Duration("timeout", 15*time.Second, "HTTP timeout")
	enableDetailed = flag.Bool("detailed", true, "Enable detailed dispatcher/enqueue metrics")
	cacheTTL       = flag.Duration("cache-ttl", 5*time.Minute, "Instance cache TTL")
	maxConcurrency = flag.Int("max-concurrency", 5, "Maximum concurrent scrapes per instance")
	logLevel       = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	configFile     = flag.String("config", "", "Configuration file path")
)

// Configuration structure
type Config struct {
	PrimaryInstance string        `json:"primary_instance"`
	Host            string        `json:"host"`
	Port            string        `json:"port"`
	ListenAddress   string        `json:"listen_address"`
	ScrapeInterval  time.Duration `json:"scrape_interval"`
	Timeout         time.Duration `json:"timeout"`
	DetailedMetrics bool          `json:"detailed_metrics"`
	CacheTTL        time.Duration `json:"cache_ttl"`
	MaxConcurrency  int           `json:"max_concurrency"`
	Auth            *AuthConfig   `json:"auth,omitempty"`
}

type AuthConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	UseSSL   bool   `json:"use_ssl"`
}

// SOAP Response structures
type GetSystemInstanceList struct {
	XMLName xml.Name `xml:"urn:SAPControl GetSystemInstanceList"`
}

type SAPInstanceList struct {
	XMLName  xml.Name      `xml:"urn:SAPControl"`
	Instance []SAPInstance `xml:"instance"`
}

type SAPInstance struct {
	Hostname      string `xml:"hostname"`
	InstanceNr    string `xml:"instanceNr"`
	SystemID      string `xml:"systemId"`
	HttpPort      string `xml:"httpPort"`
	HttpsPort     string `xml:"httpsPort"`
	StartPriority string `xml:"startPriority"`
	Features      string `xml:"features"`
	Dispstatus    string `xml:"dispstatus"`
	Sapstatus     string `xml:"sapstatus"`
	StatusText    string `xml:"statustext"`
}

type InstanceInfo struct {
	SAPInstance                    // Embedded base instance
	DispatcherPort string          `json:"dispatcher_port"`
	EnqueuePort    string          `json:"enqueue_port"`
	LastScrape     time.Time       `json:"last_scrape"`
	LastError      string          `json:"last_error,omitempty"`
	ScrapeSuccess  bool            `json:"scrape_success"`
	IsPrimary      bool            `json:"is_primary"`
	Metrics        InstanceMetrics `json:"metrics,omitempty"`
}

type InstanceMetrics struct {
	WorkProcesses  map[string]int `json:"work_processes,omitempty"`
	QueueStats     map[string]int `json:"queue_stats,omitempty"`
	EnqueueLocks   map[string]int `json:"enqueue_locks,omitempty"`
	LastCollection time.Time      `json:"last_collection"`
}

// Dispatcher structures
type GetWPTable struct {
	XMLName xml.Name `xml:"urn:SAPControl GetWPTable"`
}

type WPTable struct {
	XMLName     xml.Name      `xml:"urn:SAPControl"`
	Workprocess []WorkProcess `xml:"workprocess"`
}

type WorkProcess struct {
	No      string `xml:"No"`
	Type    string `xml:"Typ"`
	Pid     string `xml:"Pid"`
	Status  string `xml:"Status"`
	Reason  string `xml:"Reason"`
	Start   string `xml:"Start"`
	Err     string `xml:"Err"`
	Sem     string `xml:"Sem"`
	Cpu     string `xml:"Cpu"`
	Time    string `xml:"Time"`
	Program string `xml:"Program"`
	Client  string `xml:"Client"`
	User    string `xml:"User"`
	Action  string `xml:"Action"`
	Table   string `xml:"Table"`
}

type GetQueueStatistic struct {
	XMLName xml.Name `xml:"urn:SAPControl GetQueueStatistic"`
}

type QueueStatistic struct {
	XMLName xml.Name     `xml:"urn:SAPControl"`
	Queue   []QueueEntry `xml:"queue"`
}

type QueueEntry struct {
	Typ    string `xml:"Typ"`
	Now    int    `xml:"Now"`
	High   int    `xml:"High"`
	Max    int    `xml:"Max"`
	Writes int    `xml:"Writes"`
	Reads  int    `xml:"Reads"`
}

// Enqueue structures
type GetEnqTable struct {
	XMLName xml.Name `xml:"urn:SAPControl GetEnqTable"`
}

type EnqTable struct {
	XMLName xml.Name   `xml:"urn:SAPControl"`
	Lock    []EnqLock  `xml:"lock"`
	Summary EnqSummary `xml:"summary"`
}

type EnqLock struct {
	LockName    string `xml:"LockName"`
	TableName   string `xml:"TableName"`
	Client      string `xml:"Client"`
	User        string `xml:"User"`
	Transaction string `xml:"Transaction"`
	Obj         string `xml:"Obj"`
	Mode        string `xml:"Mode"`
	Owner       string `xml:"Owner"`
	OwnerVb     string `xml:"OwnerVb"`
	Count       string `xml:"Count"`
	Backup      string `xml:"Backup"`
}

type EnqSummary struct {
	Locks   int `xml:"Locks"`
	Owners  int `xml:"Owners"`
	Entries int `xml:"Entries"`
	Used    int `xml:"Used"`
	Max     int `xml:"Max"`
}

type GetEnqStatistic struct {
	XMLName xml.Name `xml:"urn:SAPControl GetEnqStatistic"`
}

type EnqStatistic struct {
	XMLName   xml.Name       `xml:"urn:SAPControl"`
	Statistic []EnqStatEntry `xml:"statistic"`
}

type EnqStatEntry struct {
	Client      string `xml:"Client"`
	User        string `xml:"User"`
	Transaction string `xml:"Transaction"`
	Object      string `xml:"Object"`
	Mode        string `xml:"Mode"`
	Count       int    `xml:"Count"`
	CumCount    int    `xml:"CumCount"`
	CumTime     int    `xml:"CumTime"`
}

// Prometheus metrics
var (
	// Instance status metrics
	sapInstanceStatus = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sap_instance_status",
			Help: "Status of SAP instance (1=GREEN/RUNNING, 0.5=YELLOW, 0=GRAY/RED)",
		},
		[]string{"instance", "hostname", "sid", "type", "status_text"},
	)

	sapInstanceInfo = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sap_instance_info",
			Help: "SAP instance information",
		},
		[]string{"instance", "hostname", "sid", "features", "http_port", "https_port"},
	)

	// Dispatcher metrics
	sapDispatcherWorkProcesses = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sap_dispatcher_work_processes",
			Help: "Dispatcher work process counts by type and status",
		},
		[]string{"instance", "hostname", "wp_type", "status"},
	)

	sapDispatcherQueue = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sap_dispatcher_queue",
			Help: "Dispatcher queue statistics",
		},
		[]string{"instance", "hostname", "queue_type", "metric"},
	)

	sapDispatcherQueueWrites = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sap_dispatcher_queue_writes_total",
			Help: "Total writes to dispatcher queues",
		},
		[]string{"instance", "hostname", "queue_type"},
	)

	sapDispatcherQueueReads = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sap_dispatcher_queue_reads_total",
			Help: "Total reads from dispatcher queues",
		},
		[]string{"instance", "hostname", "queue_type"},
	)

	// Enqueue metrics
	sapEnqueueLocks = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sap_enqueue_locks",
			Help: "Enqueue server lock statistics",
		},
		[]string{"instance", "hostname", "lock_type", "status"},
	)

	sapEnqueueTableUsage = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sap_enqueue_table_usage",
			Help: "Enqueue table usage statistics",
		},
		[]string{"instance", "hostname", "metric"},
	)

	sapEnqueueRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sap_enqueue_requests_total",
			Help: "Total enqueue server requests",
		},
		[]string{"instance", "hostname", "request_type"},
	)

	// Process metrics
	sapProcessStatus = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sap_process_status",
			Help: "Status of SAP process",
		},
		[]string{"instance", "hostname", "pid", "name", "type", "description", "client", "user"},
	)

	sapProcessCPU = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sap_process_cpu_percent",
			Help: "CPU usage percentage of SAP process",
		},
		[]string{"instance", "hostname", "pid", "name", "type"},
	)

	sapProcessMemory = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sap_process_memory_kb",
			Help: "Memory usage of SAP process in KB",
		},
		[]string{"instance", "hostname", "pid", "name", "type"},
	)

	sapProcessElapsedTime = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sap_process_elapsed_time_seconds",
			Help: "Elapsed time of SAP process in seconds",
		},
		[]string{"instance", "hostname", "pid", "name", "type"},
	)

	// Scraper metrics
	sapScrapeDuration = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sap_scrape_duration_seconds",
			Help: "Duration of SAP scrape operations",
		},
		[]string{"operation", "instance"},
	)

	sapScrapeErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sap_scrape_errors_total",
			Help: "Total number of SAP scrape errors",
		},
		[]string{"operation", "instance", "error_type"},
	)

	sapScrapeSuccess = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sap_scrape_success",
			Help: "Success of last scrape (1=success, 0=failure)",
		},
		[]string{"operation", "instance"},
	)

	sapInstancesDiscovered = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sap_instances_discovered",
			Help: "Number of SAP instances discovered",
		},
	)

	sapLastSuccessfulScrape = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sap_last_successful_scrape_timestamp",
			Help: "Timestamp of last successful scrape",
		},
		[]string{"instance"},
	)
)

// Global variables
var (
	config          Config
	instancesCache  []InstanceInfo
	cacheMutex      sync.RWMutex
	scrapeMutex     sync.Mutex
	scrapeSemaphore chan struct{}
	httpClient      *http.Client
	logger          *log.Logger
)

// Custom error types
type SAPError struct {
	Operation string
	Instance  string
	Message   string
	Err       error
}

func (e *SAPError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s for instance %s: %s (%v)", e.Operation, e.Instance, e.Message, e.Err)
	}
	return fmt.Sprintf("%s for instance %s: %s", e.Operation, e.Instance, e.Message)
}

func init() {
	// Initialize logger
	logger = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)
}

func main() {
	flag.Parse()

	// Load configuration
	if err := loadConfig(); err != nil {
		logger.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize HTTP client
	httpClient = &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// Initialize semaphore for concurrency control
	scrapeSemaphore = make(chan struct{}, config.MaxConcurrency)

	logger.Printf("Starting SAP Monitor Exporter v1.0")
	logger.Printf("Primary instance: %s at %s:%s", config.PrimaryInstance, config.Host, config.Port)
	logger.Printf("Listen address: %s", config.ListenAddress)
	logger.Printf("Scrape interval: %v", config.ScrapeInterval)
	logger.Printf("Detailed metrics: %v", config.DetailedMetrics)

	// Start background scraper
	go startBackgroundScraper()

	// Register HTTP handlers
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/v1/instances", instancesAPIHandler)
	mux.HandleFunc("/api/v1/dispatcher/", dispatcherAPIHandler)
	mux.HandleFunc("/api/v1/enqueue/", enqueueAPIHandler)
	mux.HandleFunc("/api/v1/refresh", refreshCacheHandler)
	mux.HandleFunc("/api/v1/status", statusHandler)
	mux.HandleFunc("/", rootHandler)

	// Add middleware
	handler := loggingMiddleware(mux)
	handler = recoveryMiddleware(handler)

	// Start HTTP server
	server := &http.Server{
		Addr:         config.ListenAddress,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	logger.Printf("Server listening on %s", config.ListenAddress)

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	// signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Server failed: %v", err)
		}
	}()

	<-stop
	logger.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Printf("Server shutdown error: %v", err)
	}

	logger.Println("Server stopped")
}

// Configuration loading
func loadConfig() error {
	// Default configuration
	config = Config{
		PrimaryInstance: *instanceFlag,
		Host:            *ipFlag,
		Port:            *portFlag,
		ListenAddress:   *listenAddr,
		ScrapeInterval:  *scrapeInterval,
		Timeout:         *timeoutFlag,
		DetailedMetrics: *enableDetailed,
		CacheTTL:        *cacheTTL,
		MaxConcurrency:  *maxConcurrency,
	}

	// Load from file if specified
	if *configFile != "" {
		data, err := os.ReadFile(*configFile)
		if err != nil {
			return fmt.Errorf("failed to read config file: %w", err)
		}

		if err := json.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	return nil
}

// HTTP Handlers
func healthHandler(w http.ResponseWriter, r *http.Request) {
	cacheMutex.RLock()
	healthy := len(instancesCache) > 0
	cacheMutex.RUnlock()

	status := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"instances": len(instancesCache),
		"version":   "1.0.0",
	}

	if !healthy {
		status["status"] = "unhealthy"
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func instancesAPIHandler(w http.ResponseWriter, r *http.Request) {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	instances := make([]map[string]interface{}, len(instancesCache))
	for i, inst := range instancesCache {
		instances[i] = map[string]interface{}{
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
		}
	}

	response := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"count":     len(instances),
		"instances": instances,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func dispatcherAPIHandler(w http.ResponseWriter, r *http.Request) {
	instance := strings.TrimPrefix(r.URL.Path, "/api/v1/dispatcher/")
	if instance == "" {
		instance = r.URL.Query().Get("instance")
		if instance == "" {
			instance = config.PrimaryInstance
		}
	}

	cacheMutex.RLock()
	var instanceInfo *InstanceInfo
	for i := range instancesCache {
		if instancesCache[i].InstanceNr == instance {
			instanceInfo = &instancesCache[i]
			break
		}
	}
	cacheMutex.RUnlock()

	if instanceInfo == nil {
		http.Error(w, "Instance not found", http.StatusNotFound)
		return
	}

	metrics, err := fetchDispatcherMetricsForAPI(instanceInfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

func enqueueAPIHandler(w http.ResponseWriter, r *http.Request) {
	instance := strings.TrimPrefix(r.URL.Path, "/api/v1/enqueue/")
	if instance == "" {
		instance = r.URL.Query().Get("instance")
		if instance == "" {
			instance = config.PrimaryInstance
		}
	}

	cacheMutex.RLock()
	var instanceInfo *InstanceInfo
	for i := range instancesCache {
		if instancesCache[i].InstanceNr == instance {
			instanceInfo = &instancesCache[i]
			break
		}
	}
	cacheMutex.RUnlock()

	if instanceInfo == nil {
		http.Error(w, "Instance not found", http.StatusNotFound)
		return
	}

	metrics, err := fetchEnqueueMetricsForAPI(instanceInfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

func refreshCacheHandler(w http.ResponseWriter, r *http.Request) {
	cacheMutex.Lock()
	instancesCache = nil
	cacheMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "cache_refreshed",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	status := map[string]interface{}{
		"timestamp":          time.Now().Format(time.RFC3339),
		"cache_size":         len(instancesCache),
		"cache_age":          "",
		"detailed_metrics":   config.DetailedMetrics,
		"scrape_interval":    config.ScrapeInterval.String(),
		"concurrent_scrapes": len(scrapeSemaphore),
	}

	if len(instancesCache) > 0 {
		oldest := time.Now()
		for _, inst := range instancesCache {
			if inst.LastScrape.Before(oldest) {
				oldest = inst.LastScrape
			}
		}
		status["cache_age"] = time.Since(oldest).String()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
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
        .metric { font-family: monospace; background: #f0f0f0; padding: 2px 4px; }
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
        
        <h2>Metrics Examples</h2>
        <ul>
            <li><span class="metric">sap_instance_status</span> - Instance health status</li>
            <li><span class="metric">sap_dispatcher_work_processes</span> - Work process counts</li>
            <li><span class="metric">sap_dispatcher_queue</span> - Queue statistics</li>
            <li><span class="metric">sap_enqueue_locks</span> - Lock statistics</li>
            <li><span class="metric">sap_enqueue_table_usage</span> - Table usage</li>
        </ul>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Middleware
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		logger.Printf("HTTP %s %s %s", r.Method, r.URL.Path, r.RemoteAddr)

		next.ServeHTTP(w, r)

		logger.Printf("HTTP %s %s completed in %v", r.Method, r.URL.Path, time.Since(start))
	})
}

func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				logger.Printf("PANIC recovered: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Background scraper
func startBackgroundScraper() {
	// Initial scrape
	logger.Println("Performing initial scrape...")
	if err := performScrape(); err != nil {
		logger.Printf("Initial scrape failed: %v", err)
	}

	ticker := time.NewTicker(config.ScrapeInterval)
	defer ticker.Stop()

	for range ticker.C {
		logger.Println("Starting scheduled scrape...")
		if err := performScrape(); err != nil {
			logger.Printf("Scheduled scrape failed: %v", err)
		}
	}
}

func performScrape() error {
	scrapeMutex.Lock()
	defer scrapeMutex.Unlock()

	start := time.Now()
	logger.Println("Performing full system scrape...")

	// Reset metrics that need to be re-populated
	sapInstanceStatus.Reset()
	sapDispatcherWorkProcesses.Reset()
	sapDispatcherQueue.Reset()
	sapEnqueueLocks.Reset()
	sapEnqueueTableUsage.Reset()

	// Discover instances
	instances, err := discoverInstances()
	if err != nil {
		sapScrapeErrors.WithLabelValues("discovery", "", "connection").Inc()
		return &SAPError{Operation: "discovery", Message: "failed to discover instances", Err: err}
	}

	sapInstancesDiscovered.Set(float64(len(instances)))

	// Update cache with discovered instances
	var instanceInfos []InstanceInfo
	for _, inst := range instances {
		info := InstanceInfo{
			SAPInstance:    inst,
			DispatcherPort: detectDispatcherPort(inst),
			EnqueuePort:    detectEnqueuePort(inst),
			LastScrape:     time.Now(),
			IsPrimary:      inst.InstanceNr == config.PrimaryInstance,
			Metrics: InstanceMetrics{
				WorkProcesses: make(map[string]int),
				QueueStats:    make(map[string]int),
				EnqueueLocks:  make(map[string]int),
			},
		}
		instanceInfos = append(instanceInfos, info)
	}

	// Scrape each instance concurrently with semaphore
	var wg sync.WaitGroup
	scrapeErrors := make(chan error, len(instanceInfos))

	for i := range instanceInfos {
		wg.Add(1)
		go func(info *InstanceInfo) {
			defer wg.Done()

			// Acquire semaphore
			scrapeSemaphore <- struct{}{}
			defer func() { <-scrapeSemaphore }()

			if err := scrapeSingleInstance(info); err != nil {
				scrapeErrors <- err
				info.LastError = err.Error()
				info.ScrapeSuccess = false
				sapScrapeSuccess.WithLabelValues("instance_scrape", info.InstanceNr).Set(0)
			} else {
				info.LastError = ""
				info.ScrapeSuccess = true
				sapScrapeSuccess.WithLabelValues("instance_scrape", info.InstanceNr).Set(1)
				sapLastSuccessfulScrape.WithLabelValues(info.InstanceNr).Set(float64(time.Now().Unix()))
			}
		}(&instanceInfos[i])
	}

	wg.Wait()
	close(scrapeErrors)

	// Update cache
	cacheMutex.Lock()
	instancesCache = instanceInfos
	cacheMutex.Unlock()

	// Check for errors
	var errors []string
	for err := range scrapeErrors {
		errors = append(errors, err.Error())
	}

	duration := time.Since(start).Seconds()
	sapScrapeDuration.WithLabelValues("full_scrape", "").Set(duration)

	if len(errors) > 0 {
		logger.Printf("Scrape completed with %d errors in %.2f seconds", len(errors), duration)
		return fmt.Errorf("scrape completed with errors: %v", errors)
	}

	logger.Printf("Scrape completed successfully in %.2f seconds", duration)
	return nil
}

func discoverInstances() ([]SAPInstance, error) {
	start := time.Now()

	// Try multiple endpoints
	endpoints := []string{
		fmt.Sprintf("http://%s:%s/sap/bc/soap/rfc", config.Host, config.Port),
		fmt.Sprintf("http://%s:%s/SAPControl.cgi", config.Host, config.Port),
		fmt.Sprintf("http://%s:%s/sap/bc/webdynpro/sap/dba_control", config.Host, config.Port),
	}

	var lastErr error
	for _, endpoint := range endpoints {
		client := soap.NewClient(endpoint)

		// Add authentication if configured
		if config.Auth != nil && config.Auth.Username != "" {
			client.AddHeader(soap.NewWSSecurityHeader(config.Auth.Username, config.Auth.Password))
		}

		request := &GetSystemInstanceList{}
		response := &SAPInstanceList{}

		ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
		defer cancel()

		if err := client.CallContext(ctx, "GetSystemInstanceList", request, response); err != nil {
			lastErr = err
			logger.Printf("Failed to connect to %s: %v", endpoint, err)
			continue
		}

		if len(response.Instance) == 0 {
			lastErr = fmt.Errorf("no instances found at %s", endpoint)
			continue
		}

		sapScrapeDuration.WithLabelValues("discovery", "").Set(time.Since(start).Seconds())
		logger.Printf("Discovered %d instances from %s", len(response.Instance), endpoint)

		return response.Instance, nil
	}

	return nil, fmt.Errorf("failed to discover instances from any endpoint: %v", lastErr)
}

func detectDispatcherPort(instance SAPInstance) string {
	// Try instance-specific ports first
	if instance.HttpPort != "" && instance.HttpPort != "0" {
		return instance.HttpPort
	}

	// Default SAP dispatcher ports based on instance number
	instanceNum, err := strconv.Atoi(instance.InstanceNr)
	if err == nil {
		return strconv.Itoa(3200 + instanceNum)
	}

	// Fallback
	return config.Port
}

func detectEnqueuePort(instance SAPInstance) string {
	dispatcherPort := detectDispatcherPort(instance)
	if port, err := strconv.Atoi(dispatcherPort); err == nil {
		return strconv.Itoa(port + 1) // Enqueue is typically dispatcher+1
	}
	return config.Port
}

func scrapeSingleInstance(info *InstanceInfo) error {
	start := time.Now()
	logger.Printf("Scraping instance %s on %s", info.InstanceNr, info.Hostname)

	// Set instance info metric
	instanceType := "ABAP"
	if strings.Contains(info.Features, "J2EE") {
		instanceType = "JAVA"
	}

	sapInstanceInfo.WithLabelValues(
		info.InstanceNr,
		info.Hostname,
		info.SystemID,
		info.Features,
		info.HttpPort,
		info.HttpsPort,
	).Set(1)

	// Set instance status
	statusValue := 0.0
	statusText := info.Dispstatus
	if info.StatusText != "" {
		statusText = info.StatusText
	}

	switch strings.ToUpper(info.Dispstatus) {
	case "GREEN", "RUNNING":
		statusValue = 1.0
	case "YELLOW", "WARNING", "STARTING":
		statusValue = 0.5
	case "GRAY", "RED", "STOPPED":
		statusValue = 0.0
	}

	sapInstanceStatus.WithLabelValues(
		info.InstanceNr,
		info.Hostname,
		info.SystemID,
		instanceType,
		statusText,
	).Set(statusValue)

	// Scrape dispatcher metrics
	if err := scrapeDispatcherMetrics(info); err != nil {
		sapScrapeErrors.WithLabelValues("dispatcher", info.InstanceNr, "connection").Inc()
		logger.Printf("Failed to scrape dispatcher for instance %s: %v", info.InstanceNr, err)
		// Continue with other metrics
	}

	// Scrape enqueue metrics
	if err := scrapeEnqueueMetrics(info); err != nil {
		sapScrapeErrors.WithLabelValues("enqueue", info.InstanceNr, "connection").Inc()
		logger.Printf("Failed to scrape enqueue for instance %s: %v", info.InstanceNr, err)
		// Continue with other metrics
	}

	// Update instance metrics
	info.LastScrape = time.Now()

	duration := time.Since(start).Seconds()
	sapScrapeDuration.WithLabelValues("instance_scrape", info.InstanceNr).Set(duration)

	logger.Printf("Completed scraping instance %s in %.2f seconds", info.InstanceNr, duration)
	return nil
}

func scrapeDispatcherMetrics(info *InstanceInfo) error {
	start := time.Now()

	client := soap.NewClient(fmt.Sprintf("http://%s:%s/sap/bc/soap/rfc",
		info.Hostname, info.DispatcherPort))

	// Add authentication if configured
	if config.Auth != nil && config.Auth.Username != "" {
		client.AddHeader(soap.NewWSSecurityHeader(config.Auth.Username, config.Auth.Password))
	}

	// Get work process table
	wpRequest := &GetWPTable{}
	wpResponse := &WPTable{}

	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	if err := client.CallContext(ctx, "GetWPTable", wpRequest, wpResponse); err != nil {
		return fmt.Errorf("GetWPTable failed: %w", err)
	}

	// Process work processes
	wpCounts := make(map[string]map[string]int)
	for _, wp := range wpResponse.Workprocess {
		wpType := wp.Type
		status := wp.Status

		if wpCounts[wpType] == nil {
			wpCounts[wpType] = make(map[string]int)
		}
		wpCounts[wpType][status]++

		// Store in instance metrics
		info.Metrics.WorkProcesses[fmt.Sprintf("%s_%s", wpType, status)]++

		// Set detailed process metrics
		setWorkProcessMetrics(info, wp)
	}

	// Update aggregated metrics
	for wpType, statusCounts := range wpCounts {
		for status, count := range statusCounts {
			sapDispatcherWorkProcesses.WithLabelValues(
				info.InstanceNr,
				info.Hostname,
				wpType,
				status,
			).Set(float64(count))
		}
	}

	// Get queue statistics
	queueRequest := &GetQueueStatistic{}
	queueResponse := &QueueStatistic{}

	ctx2, cancel2 := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel2()

	if err := client.CallContext(ctx2, "GetQueueStatistic", queueRequest, queueResponse); err != nil {
		return fmt.Errorf("GetQueueStatistic failed: %w", err)
	}

	// Process queue statistics
	for _, queue := range queueResponse.Queue {
		queueType := queue.Typ

		// Store in instance metrics
		info.Metrics.QueueStats[fmt.Sprintf("%s_current", queueType)] = queue.Now
		info.Metrics.QueueStats[fmt.Sprintf("%s_max", queueType)] = queue.Max

		// Current queue length
		sapDispatcherQueue.WithLabelValues(
			info.InstanceNr,
			info.Hostname,
			queueType,
			"current",
		).Set(float64(queue.Now))

		// Maximum queue length
		sapDispatcherQueue.WithLabelValues(
			info.InstanceNr,
			info.Hostname,
			queueType,
			"max",
		).Set(float64(queue.Max))

		// High watermark
		sapDispatcherQueue.WithLabelValues(
			info.InstanceNr,
			info.Hostname,
			queueType,
			"high",
		).Set(float64(queue.High))

		// Request counters
		sapDispatcherQueueWrites.WithLabelValues(
			info.InstanceNr,
			info.Hostname,
			queueType,
		).Add(float64(queue.Writes))

		sapDispatcherQueueReads.WithLabelValues(
			info.InstanceNr,
			info.Hostname,
			queueType,
		).Add(float64(queue.Reads))
	}

	info.Metrics.LastCollection = time.Now()

	sapScrapeDuration.WithLabelValues("dispatcher", info.InstanceNr).Set(time.Since(start).Seconds())
	return nil
}

func setWorkProcessMetrics(info *InstanceInfo, wp WorkProcess) {
	// Work process CPU
	if cpu, err := strconv.ParseFloat(wp.Cpu, 64); err == nil {
		sapProcessCPU.WithLabelValues(
			info.InstanceNr,
			info.Hostname,
			wp.Pid,
			fmt.Sprintf("WP-%s", wp.No),
			wp.Type,
		).Set(cpu)
	}

	// Work process status
	statusValue := 0.0
	switch wp.Status {
	case "Running":
		statusValue = 1.0
	case "Waiting":
		statusValue = 0.5
	default:
		statusValue = 0.0
	}

	sapProcessStatus.WithLabelValues(
		info.InstanceNr,
		info.Hostname,
		wp.Pid,
		fmt.Sprintf("WP-%s", wp.No),
		wp.Type,
		wp.Reason,
		wp.Client,
		wp.User,
	).Set(statusValue)

	// Elapsed time
	if elapsed, err := strconv.ParseFloat(wp.Time, 64); err == nil {
		sapProcessElapsedTime.WithLabelValues(
			info.InstanceNr,
			info.Hostname,
			wp.Pid,
			fmt.Sprintf("WP-%s", wp.No),
			wp.Type,
		).Set(elapsed)
	}
}

func scrapeEnqueueMetrics(info *InstanceInfo) error {
	start := time.Now()

	client := soap.NewClient(fmt.Sprintf("http://%s:%s/sap/bc/soap/rfc",
		info.Hostname, info.EnqueuePort))

	// Add authentication if configured
	if config.Auth != nil && config.Auth.Username != "" {
		client.AddHeader(soap.NewWSSecurityHeader(config.Auth.Username, config.Auth.Password))
	}

	// Get enqueue table
	enqRequest := &GetEnqTable{}
	enqResponse := &EnqTable{}

	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	if err := client.CallContext(ctx, "GetEnqTable", enqRequest, enqResponse); err != nil {
		return fmt.Errorf("GetEnqTable failed: %w", err)
	}

	// Process locks
	lockCounts := make(map[string]int)
	ownedLocks := 0
	waitingLocks := 0

	for _, lock := range enqResponse.Lock {
		lockType := lock.Mode
		lockCounts[lockType]++

		if lock.Owner != "" {
			ownedLocks++
		} else {
			waitingLocks++
		}
	}

	// Store in instance metrics
	for lockType, count := range lockCounts {
		info.Metrics.EnqueueLocks[lockType] = count
	}

	// Update lock type metrics
	for lockType, count := range lockCounts {
		sapEnqueueLocks.WithLabelValues(
			info.InstanceNr,
			info.Hostname,
			lockType,
			"total",
		).Set(float64(count))
	}

	// Update lock status metrics
	sapEnqueueLocks.WithLabelValues(
		info.InstanceNr,
		info.Hostname,
		"all",
		"owned",
	).Set(float64(ownedLocks))

	sapEnqueueLocks.WithLabelValues(
		info.InstanceNr,
		info.Hostname,
		"all",
		"waiting",
	).Set(float64(waitingLocks))

	// Update table usage metrics
	if enqResponse.Summary.Max > 0 {
		usagePercent := (float64(enqResponse.Summary.Used) / float64(enqResponse.Summary.Max)) * 100

		sapEnqueueTableUsage.WithLabelValues(
			info.InstanceNr,
			info.Hostname,
			"percent",
		).Set(usagePercent)

		sapEnqueueTableUsage.WithLabelValues(
			info.InstanceNr,
			info.Hostname,
			"used",
		).Set(float64(enqResponse.Summary.Used))

		sapEnqueueTableUsage.WithLabelValues(
			info.InstanceNr,
			info.Hostname,
			"max",
		).Set(float64(enqResponse.Summary.Max))

		sapEnqueueTableUsage.WithLabelValues(
			info.InstanceNr,
			info.Hostname,
			"entries",
		).Set(float64(enqResponse.Summary.Entries))
	}

	// Get enqueue statistics if available
	statRequest := &GetEnqStatistic{}
	statResponse := &EnqStatistic{}

	ctx2, cancel2 := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel2()

	if err := client.CallContext(ctx2, "GetEnqStatistic", statRequest, statResponse); err == nil {
		// Process statistics
		for _, stat := range statResponse.Statistic {
			sapEnqueueRequests.WithLabelValues(
				info.InstanceNr,
				info.Hostname,
				stat.Mode,
			).Add(float64(stat.CumCount))
		}
	} else {
		logger.Printf("GetEnqStatistic not available for instance %s: %v", info.InstanceNr, err)
	}

	sapScrapeDuration.WithLabelValues("enqueue", info.InstanceNr).Set(time.Since(start).Seconds())
	return nil
}

func fetchDispatcherMetricsForAPI(info *InstanceInfo) (map[string]interface{}, error) {
	client := soap.NewClient(fmt.Sprintf("http://%s:%s/sap/bc/soap/rfc",
		info.Hostname, info.DispatcherPort))

	if config.Auth != nil && config.Auth.Username != "" {
		client.AddHeader(soap.NewWSSecurityHeader(config.Auth.Username, config.Auth.Password))
	}

	result := make(map[string]interface{})

	// Get work process table
	wpRequest := &GetWPTable{}
	wpResponse := &WPTable{}

	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	if err := client.CallContext(ctx, "GetWPTable", wpRequest, wpResponse); err != nil {
		return nil, err
	}

	result["work_processes"] = wpResponse.Workprocess

	// Get queue statistics
	queueRequest := &GetQueueStatistic{}
	queueResponse := &QueueStatistic{}

	ctx2, cancel2 := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel2()

	if err := client.CallContext(ctx2, "GetQueueStatistic", queueRequest, queueResponse); err != nil {
		// Return partial data
		result["queues"] = nil
	} else {
		result["queues"] = queueResponse.Queue
	}

	result["timestamp"] = time.Now().Format(time.RFC3339)
	result["instance"] = info.InstanceNr
	result["hostname"] = info.Hostname

	return result, nil
}

func fetchEnqueueMetricsForAPI(info *InstanceInfo) (map[string]interface{}, error) {
	client := soap.NewClient(fmt.Sprintf("http://%s:%s/sap/bc/soap/rfc",
		info.Hostname, info.EnqueuePort))

	if config.Auth != nil && config.Auth.Username != "" {
		client.AddHeader(soap.NewWSSecurityHeader(config.Auth.Username, config.Auth.Password))
	}

	result := make(map[string]interface{})

	// Get enqueue table
	enqRequest := &GetEnqTable{}
	enqResponse := &EnqTable{}

	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	if err := client.CallContext(ctx, "GetEnqTable", enqRequest, enqResponse); err != nil {
		return nil, err
	}

	result["lock_table"] = enqResponse.Lock
	result["summary"] = enqResponse.Summary
	result["timestamp"] = time.Now().Format(time.RFC3339)
	result["instance"] = info.InstanceNr
	result["hostname"] = info.Hostname

	return result, nil
}
