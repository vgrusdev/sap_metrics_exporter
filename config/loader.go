package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
	"github.com/vgrusdev/sap_metrics_exporter/utils"
)

var (
	instanceFlag   = flag.String("instance", "00", "Primary SAP instance number")
	ipFlag         = flag.String("ip", "localhost", "SAP system IP host/address")
	portFlag       = flag.String("port", "50014", "SAP system port")
	listenAddr     = flag.String("listen", ":2112", "API server listen address")
	scrapeInterval = flag.Duration("interval", 30*time.Second, "Scrape interval")
	timeoutFlag    = flag.Duration("timeout", 15*time.Second, "Scrape timeout")
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
	if !cfg.Auth.UseSSL && cfg.Auth.TLSSkipVfy {
		cfg.Auth.TLSSkipVfy = false
	}
	return cfg, nil
}

// LoadConfig loads configuration from file and environment variables
func LoadConfig(configPath string) (*Config, error) {
	log := utils.NewLogger("config")
	var config Config

	// Initialize Viper
	v := viper.New()

	// Set default values
	setDefaults(v)

	// Read from config file if provided
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		log.Info("Using config file: %s", v.ConfigFileUsed())
	} else {
		// Look for config in default locations
		v.SetConfigName("config") // name of config file (without extension)
		v.SetConfigType("yaml")   // or json, toml, etc.
		v.AddConfigPath(".")
		v.AddConfigPath("./config")
		v.AddConfigPath("/etc/your-app/")

		if err := v.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				log.Warn("No config file found, using defaults and environment variables")
			} else {
				return nil, fmt.Errorf("error reading config file: %w", err)
			}
		}
	}

	// Enable environment variable support
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Bind environment variables
	bindEnvVars(v)

	// Unmarshal into struct
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("unable to decode config into struct: %w", err)
	}

	return &config, nil
}
