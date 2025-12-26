package collectors

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/vgrusdev/sap_metrics_exporter/cache"
	"github.com/vgrusdev/sap_metrics_exporter/config"
	"github.com/vgrusdev/sap_metrics_exporter/metrics"
	"github.com/vgrusdev/sap_metrics_exporter/soap"
)

type DispatcherCollector struct {
	*BaseCollector
	metrics *metrics.Registry
}

func NewDispatcherCollector(cfg *config.Config, soapClient *soap.Client, metrics *metrics.Registry) *DispatcherCollector {
	return &DispatcherCollector{
		BaseCollector: NewBaseCollector(cfg, soapClient),
		metrics:       metrics,
	}
}

func (c *DispatcherCollector) Collect(ctx context.Context, instance *cache.InstanceInfo) error {
	start := time.Now()
	c.logger.Debug("Collecting dispatcher metrics", "instance", instance.InstanceNr)

	// Get work process table
	wpTable, err := c.soapClient.GetWPTable(ctx, instance.Hostname, instance.DispatcherPort)
	if err != nil {
		return fmt.Errorf("failed to get work process table: %w", err)
	}

	// Process work processes
	wpCounts := make(map[string]map[string]int)
	for _, wp := range wpTable.Workprocess {
		wpType := wp.Type
		status := wp.Status

		if wpCounts[wpType] == nil {
			wpCounts[wpType] = make(map[string]int)
		}
		wpCounts[wpType][status]++

		// Store in instance metrics
		instance.Metrics.WorkProcesses[fmt.Sprintf("%s_%s", wpType, status)]++

		// Set detailed process metrics
		c.setWorkProcessMetrics(instance, wp)
	}

	// Update aggregated metrics
	for wpType, statusCounts := range wpCounts {
		for status, count := range statusCounts {
			c.metrics.DispatcherWorkProcesses.WithLabelValues(
				instance.InstanceNr,
				instance.Hostname,
				wpType,
				status,
			).Set(float64(count))
		}
	}

	// Get queue statistics
	queueStats, err := c.soapClient.GetQueueStatistic(ctx, instance.Hostname, instance.DispatcherPort)
	if err != nil {
		return fmt.Errorf("failed to get queue statistics: %w", err)
	}

	// Process queue statistics
	for _, queue := range queueStats.Queue {
		queueType := queue.Typ

		// Store in instance metrics
		instance.Metrics.QueueStats[fmt.Sprintf("%s_current", queueType)] = queue.Now
		instance.Metrics.QueueStats[fmt.Sprintf("%s_max", queueType)] = queue.Max

		// Current queue length
		c.metrics.DispatcherQueue.WithLabelValues(
			instance.InstanceNr,
			instance.Hostname,
			queueType,
			"current",
		).Set(float64(queue.Now))

		// Maximum queue length
		c.metrics.DispatcherQueue.WithLabelValues(
			instance.InstanceNr,
			instance.Hostname,
			queueType,
			"max",
		).Set(float64(queue.Max))

		// High watermark
		c.metrics.DispatcherQueue.WithLabelValues(
			instance.InstanceNr,
			instance.Hostname,
			queueType,
			"high",
		).Set(float64(queue.High))

		// Request counters
		c.metrics.DispatcherQueueWrites.WithLabelValues(
			instance.InstanceNr,
			instance.Hostname,
			queueType,
		).Add(float64(queue.Writes))

		c.metrics.DispatcherQueueReads.WithLabelValues(
			instance.InstanceNr,
			instance.Hostname,
			queueType,
		).Add(float64(queue.Reads))
	}

	instance.Metrics.LastCollection = time.Now()

	duration := time.Since(start).Seconds()
	c.metrics.ScrapeDuration.WithLabelValues("dispatcher", instance.InstanceNr).Set(duration)
	c.logger.Debug("Dispatcher collection completed",
		"instance", instance.InstanceNr,
		"duration", duration,
	)

	return nil
}

func (c *DispatcherCollector) setWorkProcessMetrics(instance *cache.InstanceInfo, wp soap.WorkProcess) {
	// Work process CPU
	if cpu, err := strconv.ParseFloat(wp.Cpu, 64); err == nil {
		c.metrics.ProcessCPU.WithLabelValues(
			instance.InstanceNr,
			instance.Hostname,
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

	c.metrics.ProcessStatus.WithLabelValues(
		instance.InstanceNr,
		instance.Hostname,
		wp.Pid,
		fmt.Sprintf("WP-%s", wp.No),
		wp.Type,
		wp.Reason,
		wp.Client,
		wp.User,
	).Set(statusValue)

	// Elapsed time
	if elapsed, err := strconv.ParseFloat(wp.Time, 64); err == nil {
		c.metrics.ProcessElapsedTime.WithLabelValues(
			instance.InstanceNr,
			instance.Hostname,
			wp.Pid,
			fmt.Sprintf("WP-%s", wp.No),
			wp.Type,
		).Set(elapsed)
	}
}
