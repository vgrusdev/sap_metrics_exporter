package collectors

import (
	"context"
	"fmt"
	"time"

	"github.com/vgrusdev/sap_metrics_exporter/cache"
	"github.com/vgrusdev/sap_metrics_exporter/config"
	"github.com/vgrusdev/sap_metrics_exporter/metrics"
	"github.com/vgrusdev/sap_metrics_exporter/soap"
)

type InstanceCollector struct {
	*BaseCollector
	metrics *metrics.Registry
}

func NewInstanceCollector(cfg *config.Config, soapClient *soap.Client, metrics *metrics.Registry) *InstanceCollector {
	return &InstanceCollector{
		BaseCollector: NewBaseCollector(cfg, soapClient),
		metrics:       metrics,
	}
}

func (c *InstanceCollector) Collect(ctx context.Context) ([]cache.InstanceInfo, error) {
	start := time.Now()
	c.logger.Debug("Starting instance collection")

	// Get instances from SAP
	instanceList, err := c.soapClient.GetSystemInstanceList(ctx, c.config.Host, c.config.Port)
	if err != nil {
		c.metrics.ScrapeErrors.WithLabelValues("discovery", "", "connection").Inc()
		return nil, fmt.Errorf("failed to discover instances: %w", err)
	}

	c.metrics.InstancesDiscovered.Set(float64(len(instanceList.Instance)))

	// Convert to cache instances
	instances := make([]cache.InstanceInfo, 0, len(instanceList.Instance))
	for _, sapInst := range instanceList.Instance {
		dispatcherPort, enqueuePort := c.DetectPorts(sapInst)

		instance := cache.InstanceInfo{
			SAPInstance:    sapInst,
			DispatcherPort: dispatcherPort,
			EnqueuePort:    enqueuePort,
			LastScrape:     time.Now(),
			IsPrimary:      sapInst.InstanceNr == c.config.PrimaryInstance,
			Metrics: cache.InstanceMetrics{
				WorkProcesses: make(map[string]int),
				QueueStats:    make(map[string]int),
				EnqueueLocks:  make(map[string]int),
			},
		}

		// Set metrics for this instance
		c.setInstanceMetrics(&instance)
		instances = append(instances, instance)
	}

	duration := time.Since(start).Seconds()
	c.metrics.ScrapeDuration.WithLabelValues("discovery", "").Set(duration)
	c.logger.Debug("Instance collection completed", "duration", duration, "instances", len(instances))

	return instances, nil
}

func (c *InstanceCollector) setInstanceMetrics(instance *cache.InstanceInfo) {
	instanceType := c.GetInstanceType(instance.Features)
	statusValue, statusText := c.GetStatusValue(instance.Dispstatus, instance.StatusText)

	// Set instance info metric
	c.metrics.InstanceInfo.WithLabelValues(
		instance.InstanceNr,
		instance.Hostname,
		instance.SystemID,
		instance.Features,
		instance.HttpPort,
		instance.HttpsPort,
	).Set(1)

	// Set instance status metric
	c.metrics.InstanceStatus.WithLabelValues(
		instance.InstanceNr,
		instance.Hostname,
		instance.SystemID,
		instanceType,
		statusText,
	).Set(statusValue)
}
