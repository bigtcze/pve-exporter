package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the application configuration
type Config struct {
	Proxmox ProxmoxConfig `yaml:"proxmox"`
	Server  ServerConfig  `yaml:"server"`
}

// ProxmoxConfig holds Proxmox API configuration
type ProxmoxConfig struct {
	Host               string        `yaml:"host"`
	Port               int           `yaml:"port"`
	User               string        `yaml:"user"`
	Password           string        `yaml:"password"`
	TokenID            string        `yaml:"token_id"`
	TokenSecret        string        `yaml:"token_secret"`
	Realm              string        `yaml:"realm"`
	InsecureSkipVerify bool          `yaml:"insecure_skip_verify"`
	Timeout            time.Duration `yaml:"timeout"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	ListenAddress string `yaml:"listen_address"`
	MetricsPath   string `yaml:"metrics_path"`
}

// LoadFromFile loads configuration from file and environment variables
func LoadFromFile(configFile string) (*Config, error) {

	// Default configuration
	cfg := &Config{
		Proxmox: ProxmoxConfig{
			Host:               getEnv("PVE_HOST", "localhost"),
			Port:               8006,
			User:               getEnv("PVE_USER", "root@pam"),
			Password:           getEnv("PVE_PASSWORD", ""),
			TokenID:            getEnv("PVE_TOKEN_ID", ""),
			TokenSecret:        getEnv("PVE_TOKEN_SECRET", ""),
			Realm:              getEnv("PVE_REALM", "pam"),
			InsecureSkipVerify: getEnvBool("PVE_INSECURE_SKIP_VERIFY", true),
			Timeout:            30 * time.Second,
		},
		Server: ServerConfig{
			ListenAddress: getEnv("LISTEN_ADDRESS", ":9221"),
			MetricsPath:   getEnv("METRICS_PATH", "/metrics"),
		},
	}

	// Load from file if specified
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}

		// Warn if config file is world-readable
		info, err := os.Stat(configFile)
		if err == nil {
			mode := info.Mode().Perm()
			if mode&0o007 != 0 {
				slog.Warn("config file is world-readable, consider chmod 640", "file", configFile, "mode", fmt.Sprintf("%o", mode))
			}
		}
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Proxmox.Host == "" {
		return fmt.Errorf("proxmox host is required")
	}

	// Port range validation
	if c.Proxmox.Port < 1 || c.Proxmox.Port > 65535 {
		return fmt.Errorf("proxmox port must be between 1 and 65535, got %d", c.Proxmox.Port)
	}

	// Timeout auto-fix (don't error, just reset to default)
	if c.Proxmox.Timeout < 1*time.Second {
		c.Proxmox.Timeout = 30 * time.Second
	}

	// MetricsPath must start with /
	if c.Server.MetricsPath != "" && !strings.HasPrefix(c.Server.MetricsPath, "/") {
		return fmt.Errorf("server metrics_path must start with '/', got %q", c.Server.MetricsPath)
	}

	// TokenID format: must contain '!' if set
	if c.Proxmox.TokenID != "" && !strings.Contains(c.Proxmox.TokenID, "!") {
		return fmt.Errorf("proxmox token_id must be in format 'user@realm!tokenname', got %q", c.Proxmox.TokenID)
	}

	// Check authentication method
	hasPassword := c.Proxmox.Password != ""
	hasToken := c.Proxmox.TokenID != "" && c.Proxmox.TokenSecret != ""

	if !hasPassword && !hasToken {
		return fmt.Errorf("either password or token authentication must be configured")
	}

	return nil
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvBool gets a boolean environment variable or returns a default value
func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1" || value == "yes"
	}
	return defaultValue
}
