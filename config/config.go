package config

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	PrimaryInstance  string         `json:"primary_instance"`
	Host             string         `json:"host"`
	Port             string         `json:"port"`
	SAPControlURL    string         `json:"sap_control_url"`
	SAPControlDomain string         `json:"sap_control_domain"`
	ListenAddress    string         `json:"listen_address"`
	ScrapeInterval   time.Duration  `json:"scrape_interval"`
	Timeout          time.Duration  `json:"scrape_timeout"`
	DetailedMetrics  bool           `json:"detailed_metrics"`
	CacheTTL         time.Duration  `json:"cache_ttl"`
	MaxConcurrency   int            `json:"max_concurrency"`
	LogLevel         string         `json:"log_level"`
	Auth             *AuthConfig    `json:"sap_auth,omitempty"`
	RequestTimeout   time.Duration  `json:"api_request_timeout"` // HTTP request timeout
	API              *APIAuthConfig `json:"api_auth,omitempty"`  // API Authentication
}

type AuthConfig struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	UseSSL     bool   `json:"use_ssl"`
	TLSSkipVfy bool   `json:"tls_skip_verify"`
}

type APIAuthConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Enabled  bool   `json:"enabled"`
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
		Auth: &AuthConfig{
			UseSSL:     true,
			TLSSkipVfy: false,
		},
		RequestTimeout: 30 * time.Second,
		API: &APIAuthConfig{
			Enabled: false,
		},
	}
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("primary_instance", "")
	v.SetDefault("host", "localhost")
	v.SetDefault("port", "50014")
	v.SetDefault("sap_control_url", "https://localhost:50014")
	v.SetDefault("sap_control_domain", "")
	v.SetDefault("listen_address", ":8080")
	v.SetDefault("scrape_interval", "60s")
	v.SetDefault("scrape_timeout", "20s")
	v.SetDefault("detailed_metrics", false)
	v.SetDefault("cache_ttl", "5m")
	v.SetDefault("max_concurrency", 10)
	v.SetDefault("log_level", "info")
	v.SetDefault("api_request_timeout", "30s")

	// Nested defaults
	v.SetDefault("sap_auth.use_ssl", true)
	v.SetDefault("sap_auth.tls_skip_verify", false)
	v.SetDefault("api_auth.enabled", false)
}

func bindEnvVars(v *viper.Viper) {
	// Bind each field to environment variable
	v.BindEnv("primary_instance", "PRIMARY_INSTANCE")
	v.BindEnv("host", "HOST")
	v.BindEnv("port", "PORT")
	v.BindEnv("sap_control_url", "SAP_CONTROL_URL")
	v.BindEnv("sap_control_domain", "SAP_CONTROL_DOMAIN")
	v.BindEnv("listen_address", "LISTEN_ADDRESS")
	v.BindEnv("scrape_interval", "SCRAPE_INTERVAL")
	v.BindEnv("scrape_timeout", "SCRAPE_TIMEOUT")
	v.BindEnv("detailed_metrics", "DETAILED_METRICS")
	v.BindEnv("cache_ttl", "CACHE_TTL")
	v.BindEnv("max_concurrency", "MAX_CONCURRENCY")
	v.BindEnv("log_level", "LOG_LEVEL")
	v.BindEnv("api_request_timeout", "API_REQUEST_TIMEOUT")

	// Nested struct environment variables
	v.BindEnv("sap_auth.username", "SAP_AUTH_USERNAME")
	v.BindEnv("sap_auth.password", "SAP_AUTH_PASSWORD")
	v.BindEnv("sap_auth.use_ssl", "SAP_AUTH_USE_SSL")
	v.BindEnv("sap_auth.tls_skip_verify", "SAP_AUTH_TLS_SKIP_VERIFY")

	v.BindEnv("api_auth.username", "API_AUTH_USERNAME")
	v.BindEnv("api_auth.password", "API_AUTH_PASSWORD")
	v.BindEnv("api_auth.enabled", "API_AUTH_ENABLED")
}
