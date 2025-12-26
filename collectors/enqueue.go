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

type EnqueueCollector struct {
	*BaseCollector
	metrics *metrics.Registry
}

func NewEnqueueCollector(cfg *config.Config, soapClient *soap.Client, metrics *metrics.Registry) *EnqueueCollector {
	return &EnqueueCollector{
		BaseCollector: NewBaseCollector(cfg, soapClient),
		metrics:       metrics,
	}
}

func (c *EnqueueCollector) Collect(ctx context.Context, instance *cache.InstanceInfo) error {
	start := time.Now()
	c.logger.Debug("Collecting enqueue metrics", "instance", instance.InstanceNr)

	// Get enqueue table
	enqTable, err := c.soapClient.GetEnqTable(ctx, instance.Hostname, instance.EnqueuePort)
	if err != nil {
		return fmt.Errorf("failed to get enqueue table: %w", err)
	}

	// Process locks
	lockCounts := make(map[string]int)
	ownedLocks := 0
	waitingLocks := 0

	for _, lock := range enqTable.Lock {
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
		instance.Metrics.EnqueueLocks[lockType] = count
	}

	// Update lock type metrics
	for lockType, count := range lockCounts {
		c.metrics.EnqueueLocks.WithLabelValues(
			instance.InstanceNr,
			instance.Hostname,
			lockType,
			"total",
		).Set(float64(count))
	}

	// Update lock status metrics
	c.metrics.EnqueueLocks.WithLabelValues(
		instance.InstanceNr,
		instance.Hostname,
		"all",
		"owned",
	).Set(float64(ownedLocks))

	c.metrics.EnqueueLocks.WithLabelValues(
		instance.InstanceNr,
		instance.Hostname,
		"all",
		"waiting",
	).Set(float64(waitingLocks))

	// Update table usage metrics
	if enqTable.Summary.Max > 0 {
		usagePercent := (float64(enqTable.Summary.Used) / float64(enqTable.Summary.Max)) * 100

		c.metrics.EnqueueTableUsage.WithLabelValues(
			instance.InstanceNr,
			instance.Hostname,
			"percent",
		).Set(usagePercent)

		c.metrics.EnqueueTableUsage.WithLabelValues(
			instance.InstanceNr,
			instance.Hostname,
			"used",
		).Set(float64(enqTable.Summary.Used))

		c.metrics.EnqueueTableUsage.WithLabelValues(
			instance.InstanceNr,
			instance.Hostname,
			"max",
		).Set(float64(enqTable.Summary.Max))

		c.metrics.EnqueueTableUsage.WithLabelValues(
			instance.InstanceNr,
			instance.Hostname,
			"entries",
		).Set(float64(enqTable.Summary.Entries))
	}

	duration := time.Since(start).Seconds()
	c.metrics.ScrapeDuration.WithLabelValues("enqueue", instance.InstanceNr).Set(duration)
	c.logger.Debug("Enqueue collection completed",
		"instance", instance.InstanceNr,
		"duration", duration,
	)

	return nil
}
