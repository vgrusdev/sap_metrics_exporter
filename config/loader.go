package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

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
)

func Load(configFile string) (*Config, error) {
	cfg := DefaultConfig()

	// Load from file if specified
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// Override with command line flags
	if *instanceFlag != "" {
		cfg.PrimaryInstance = *instanceFlag
	}
	if *ipFlag != "" {
		cfg.Host = *ipFlag
	}
	if *portFlag != "" {
		cfg.Port = *portFlag
	}
	if *listenAddr != "" {
		cfg.ListenAddress = *listenAddr
	}
	if *scrapeInterval > 0 {
		cfg.ScrapeInterval = *scrapeInterval
	}
	if *timeoutFlag > 0 {
		cfg.Timeout = *timeoutFlag
	}
	cfg.DetailedMetrics = *enableDetailed
	if *cacheTTL > 0 {
		cfg.CacheTTL = *cacheTTL
	}
	if *maxConcurrency > 0 {
		cfg.MaxConcurrency = *maxConcurrency
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}

	return cfg, nil
}
