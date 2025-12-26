package cache

import (
	"time"

	"github.com/vgrusdev/sap_metrics_exporter/soap"
)

type InstanceInfo struct {
	soap.SAPInstance                 // Embedded base instance
	DispatcherPort   string          `json:"dispatcher_port"`
	EnqueuePort      string          `json:"enqueue_port"`
	LastScrape       time.Time       `json:"last_scrape"`
	LastError        string          `json:"last_error,omitempty"`
	ScrapeSuccess    bool            `json:"scrape_success"`
	IsPrimary        bool            `json:"is_primary"`
	Metrics          InstanceMetrics `json:"metrics,omitempty"`
}

type InstanceMetrics struct {
	WorkProcesses  map[string]int `json:"work_processes,omitempty"`
	QueueStats     map[string]int `json:"queue_stats,omitempty"`
	EnqueueLocks   map[string]int `json:"enqueue_locks,omitempty"`
	LastCollection time.Time      `json:"last_collection"`
}
