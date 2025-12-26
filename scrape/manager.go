package scrape

import (
	"context"
	"sync"
	"time"

	"github.com/vgrusdev/sap_metrics_exporter/cache"
	"github.com/vgrusdev/sap_metrics_exporter/collectors"
	"github.com/vgrusdev/sap_metrics_exporter/config"
	"github.com/vgrusdev/sap_metrics_exporter/metrics"
	"github.com/vgrusdev/sap_metrics_exporter/soap"
	"github.com/vgrusdev/sap_metrics_exporter/utils"
)

type Manager struct {
	config              *config.Config
	cacheMgr            *cache.Manager
	metrics             *metrics.Registry
	soapClient          *soap.Client
	instanceCollector   *collectors.InstanceCollector
	dispatcherCollector *collectors.DispatcherCollector
	enqueueCollector    *collectors.EnqueueCollector
	logger              *utils.Logger
	scrapeSemaphore     chan struct{}
	scrapeMutex         sync.Mutex
	stopChan            chan struct{}
	running             bool
}

func NewManager(cfg *config.Config, cacheMgr *cache.Manager, metrics *metrics.Registry) (*Manager, error) {
	soapClient := soap.NewClient(cfg)

	return &Manager{
		config:              cfg,
		cacheMgr:            cacheMgr,
		metrics:             metrics,
		soapClient:          soapClient,
		instanceCollector:   collectors.NewInstanceCollector(cfg, soapClient, metrics),
		dispatcherCollector: collectors.NewDispatcherCollector(cfg, soapClient, metrics),
		enqueueCollector:    collectors.NewEnqueueCollector(cfg, soapClient, metrics),
		logger:              utils.NewLogger("scrape"),
		scrapeSemaphore:     make(chan struct{}, cfg.MaxConcurrency),
		stopChan:            make(chan struct{}),
	}, nil
}

func (m *Manager) Start(ctx context.Context) {
	m.scrapeMutex.Lock()
	if m.running {
		m.scrapeMutex.Unlock()
		return
	}
	m.running = true
	m.scrapeMutex.Unlock()

	// Initial scrape
	m.logger.Info("Starting scrape manager")
	if err := m.Scrape(ctx); err != nil {
		m.logger.Error("Initial scrape failed", "error", err)
	}

	// Start scheduled scraping
	go m.startScheduler(ctx)
}

func (m *Manager) Stop() {
	m.scrapeMutex.Lock()
	defer m.scrapeMutex.Unlock()

	if !m.running {
		return
	}

	m.logger.Info("Stopping scrape manager")
	close(m.stopChan)
	m.running = false
}

func (m *Manager) Scrape(ctx context.Context) error {
	m.scrapeMutex.Lock()
	defer m.scrapeMutex.Unlock()

	start := time.Now()
	m.logger.Info("Starting full scrape")

	// Reset metrics
	m.metrics.Reset()

	// Discover instances
	instances, err := m.instanceCollector.Collect(ctx)
	if err != nil {
		m.metrics.ScrapeErrors.WithLabelValues("discovery", "", "connection").Inc()
		return err
	}

	// Update cache
	m.cacheMgr.SetInstances(instances)

	// Scrape each instance concurrently
	var wg sync.WaitGroup
	scrapeErrors := make(chan error, len(instances))

	for i := range instances {
		wg.Add(1)
		go func(instance *cache.InstanceInfo) {
			defer wg.Done()

			// Acquire semaphore
			m.scrapeSemaphore <- struct{}{}
			defer func() { <-m.scrapeSemaphore }()

			if err := m.scrapeInstance(ctx, instance); err != nil {
				scrapeErrors <- err
				instance.LastError = err.Error()
				instance.ScrapeSuccess = false
				m.metrics.ScrapeSuccess.WithLabelValues("instance_scrape", instance.InstanceNr).Set(0)
			} else {
				instance.LastError = ""
				instance.ScrapeSuccess = true
				m.metrics.ScrapeSuccess.WithLabelValues("instance_scrape", instance.InstanceNr).Set(1)
				m.metrics.LastSuccessfulScrape.WithLabelValues(instance.InstanceNr).Set(float64(time.Now().Unix()))
			}
		}(&instances[i])
	}

	wg.Wait()
	close(scrapeErrors)

	// Update cache with scraped instances
	m.cacheMgr.SetInstances(instances)

	// Check for errors
	var errors []string
	for err := range scrapeErrors {
		errors = append(errors, err.Error())
	}

	duration := time.Since(start).Seconds()
	m.metrics.ScrapeDuration.WithLabelValues("full_scrape", "").Set(duration)

	if len(errors) > 0 {
		m.logger.Warn("Scrape completed with errors",
			"error_count", len(errors),
			"duration", duration,
		)
		return nil // Return nil to allow partial success
	}

	m.logger.Info("Scrape completed successfully", "duration", duration)
	return nil
}

func (m *Manager) scrapeInstance(ctx context.Context, instance *cache.InstanceInfo) error {
	start := time.Now()

	// Scrape dispatcher metrics
	if m.config.DetailedMetrics {
		if err := m.dispatcherCollector.Collect(ctx, instance); err != nil {
			m.metrics.ScrapeErrors.WithLabelValues("dispatcher", instance.InstanceNr, "connection").Inc()
			m.logger.Warn("Failed to scrape dispatcher",
				"instance", instance.InstanceNr,
				"error", err,
			)
			// Continue with enqueue
		}

		// Scrape enqueue metrics
		if err := m.enqueueCollector.Collect(ctx, instance); err != nil {
			m.metrics.ScrapeErrors.WithLabelValues("enqueue", instance.InstanceNr, "connection").Inc()
			m.logger.Warn("Failed to scrape enqueue",
				"instance", instance.InstanceNr,
				"error", err,
			)
		}
	}

	duration := time.Since(start).Seconds()
	m.metrics.ScrapeDuration.WithLabelValues("instance_scrape", instance.InstanceNr).Set(duration)

	return nil
}

func (m *Manager) startScheduler(ctx context.Context) {
	ticker := time.NewTicker(m.config.ScrapeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.logger.Debug("Starting scheduled scrape")
			if err := m.Scrape(ctx); err != nil {
				m.logger.Error("Scheduled scrape failed", "error", err)
			}

		case <-m.stopChan:
			m.logger.Debug("Stopping scheduler")
			return

		case <-ctx.Done():
			m.logger.Debug("Context cancelled, stopping scheduler")
			return
		}
	}
}
