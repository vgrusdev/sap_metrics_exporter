package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Registry struct {
	// Instance metrics
	InstanceStatus *prometheus.GaugeVec
	InstanceInfo   *prometheus.GaugeVec

	// Dispatcher metrics
	DispatcherWorkProcesses *prometheus.GaugeVec
	DispatcherQueue         *prometheus.GaugeVec
	DispatcherQueueWrites   *prometheus.CounterVec
	DispatcherQueueReads    *prometheus.CounterVec

	// Enqueue metrics
	EnqueueLocks      *prometheus.GaugeVec
	EnqueueTableUsage *prometheus.GaugeVec
	EnqueueRequests   *prometheus.CounterVec

	// Process metrics
	ProcessStatus      *prometheus.GaugeVec
	ProcessCPU         *prometheus.GaugeVec
	ProcessMemory      *prometheus.GaugeVec
	ProcessElapsedTime *prometheus.GaugeVec

	// Scraper metrics
	ScrapeDuration       *prometheus.GaugeVec
	ScrapeErrors         *prometheus.CounterVec
	ScrapeSuccess        *prometheus.GaugeVec
	InstancesDiscovered  *prometheus.Gauge
	LastSuccessfulScrape *prometheus.GaugeVec
}

func NewRegistry() *Registry {
	return &Registry{
		InstanceStatus: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sap_instance_status",
				Help: "Status of SAP instance (1=GREEN/RUNNING, 0.5=YELLOW, 0=GRAY/RED)",
			},
			[]string{"instance", "hostname", "sid", "type", "status_text"},
		),

		InstanceInfo: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sap_instance_info",
				Help: "SAP instance information",
			},
			[]string{"instance", "hostname", "sid", "features", "http_port", "https_port"},
		),

		DispatcherWorkProcesses: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sap_dispatcher_work_processes",
				Help: "Dispatcher work process counts by type and status",
			},
			[]string{"instance", "hostname", "wp_type", "status"},
		),

		DispatcherQueue: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sap_dispatcher_queue",
				Help: "Dispatcher queue statistics",
			},
			[]string{"instance", "hostname", "queue_type", "metric"},
		),

		DispatcherQueueWrites: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "sap_dispatcher_queue_writes_total",
				Help: "Total writes to dispatcher queues",
			},
			[]string{"instance", "hostname", "queue_type"},
		),

		DispatcherQueueReads: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "sap_dispatcher_queue_reads_total",
				Help: "Total reads from dispatcher queues",
			},
			[]string{"instance", "hostname", "queue_type"},
		),

		EnqueueLocks: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sap_enqueue_locks",
				Help: "Enqueue server lock statistics",
			},
			[]string{"instance", "hostname", "lock_type", "status"},
		),

		EnqueueTableUsage: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sap_enqueue_table_usage",
				Help: "Enqueue table usage statistics",
			},
			[]string{"instance", "hostname", "metric"},
		),

		EnqueueRequests: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "sap_enqueue_requests_total",
				Help: "Total enqueue server requests",
			},
			[]string{"instance", "hostname", "request_type"},
		),

		ProcessStatus: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sap_process_status",
				Help: "Status of SAP process",
			},
			[]string{"instance", "hostname", "pid", "name", "type", "description", "client", "user"},
		),

		ProcessCPU: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sap_process_cpu_percent",
				Help: "CPU usage percentage of SAP process",
			},
			[]string{"instance", "hostname", "pid", "name", "type"},
		),

		ProcessMemory: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sap_process_memory_kb",
				Help: "Memory usage of SAP process in KB",
			},
			[]string{"instance", "hostname", "pid", "name", "type"},
		),

		ProcessElapsedTime: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sap_process_elapsed_time_seconds",
				Help: "Elapsed time of SAP process in seconds",
			},
			[]string{"instance", "hostname", "pid", "name", "type"},
		),

		ScrapeDuration: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sap_scrape_duration_seconds",
				Help: "Duration of SAP scrape operations",
			},
			[]string{"operation", "instance"},
		),

		ScrapeErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "sap_scrape_errors_total",
				Help: "Total number of SAP scrape errors",
			},
			[]string{"operation", "instance", "error_type"},
		),

		ScrapeSuccess: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sap_scrape_success",
				Help: "Success of last scrape (1=success, 0=failure)",
			},
			[]string{"operation", "instance"},
		),

		InstancesDiscovered: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "sap_instances_discovered",
				Help: "Number of SAP instances discovered",
			},
		),

		LastSuccessfulScrape: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sap_last_successful_scrape_timestamp",
				Help: "Timestamp of last successful scrape",
			},
			[]string{"instance"},
		),
	}
}

func (r *Registry) Reset() {
	r.InstanceStatus.Reset()
	r.DispatcherWorkProcesses.Reset()
	r.DispatcherQueue.Reset()
	r.EnqueueLocks.Reset()
	r.EnqueueTableUsage.Reset()
	r.ProcessStatus.Reset()
	r.ProcessCPU.Reset()
	r.ProcessMemory.Reset()
	r.ProcessElapsedTime.Reset()
}
