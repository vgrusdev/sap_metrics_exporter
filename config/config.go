package config

import (
	"time"
)

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
	LogLevel        string        `json:"log_level"`
	Auth            *AuthConfig   `json:"auth,omitempty"`
}

type AuthConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	UseSSL   bool   `json:"use_ssl"`
}

func DefaultConfig() *Config {
	return &Config{
		PrimaryInstance: "00",
		Host:            "localhost",
		Port:            "50014",
		ListenAddress:   ":2112",
		ScrapeInterval:  30 * time.Second,
		Timeout:         15 * time.Second,
		DetailedMetrics: true,
		CacheTTL:        5 * time.Minute,
		MaxConcurrency:  5,
		LogLevel:        "info",
	}
}
