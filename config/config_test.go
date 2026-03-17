package config

import (
	"os"
	"testing"
)

func TestLoadFromFile(t *testing.T) {
	content := []byte(`
proxmox:
  host: "test.proxmox.com"
  port: 8006
  user: "test@pam"
  password: "password123"
  insecure_skip_verify: true

server:
  listen_address: ":9090"
  metrics_path: "/test-metrics"
`)
	tmpfile, err := os.CreateTemp("", "config-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	if _, err := tmpfile.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFromFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	if cfg.Proxmox.Host != "test.proxmox.com" {
		t.Errorf("expected host 'test.proxmox.com', got '%s'", cfg.Proxmox.Host)
	}
	if cfg.Proxmox.User != "test@pam" {
		t.Errorf("expected user 'test@pam', got '%s'", cfg.Proxmox.User)
	}
	if cfg.Server.ListenAddress != ":9090" {
		t.Errorf("expected listen address ':9090', got '%s'", cfg.Server.ListenAddress)
	}
}

func TestLoadFromEnv(t *testing.T) {
	_ = os.Setenv("PVE_HOST", "env.proxmox.com")
	_ = os.Setenv("PVE_USER", "env@pam")
	_ = os.Setenv("PVE_PASSWORD", "envpass")
	_ = os.Setenv("LISTEN_ADDRESS", ":9111")
	defer func() {
		_ = os.Unsetenv("PVE_HOST")
		_ = os.Unsetenv("PVE_USER")
		_ = os.Unsetenv("PVE_PASSWORD")
		_ = os.Unsetenv("LISTEN_ADDRESS")
	}()

	cfg, err := LoadFromFile("")
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	if cfg.Proxmox.Host != "env.proxmox.com" {
		t.Errorf("expected host 'env.proxmox.com', got '%s'", cfg.Proxmox.Host)
	}
	if cfg.Proxmox.User != "env@pam" {
		t.Errorf("expected user 'env@pam', got '%s'", cfg.Proxmox.User)
	}
	if cfg.Server.ListenAddress != ":9111" {
		t.Errorf("expected listen address ':9111', got '%s'", cfg.Server.ListenAddress)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid password auth",
			cfg: Config{
				Proxmox: ProxmoxConfig{
					Host:     "localhost",
					Port:     8006,
					User:     "root@pam",
					Password: "password",
				},
			},
			wantErr: false,
		},
		{
			name: "valid token auth",
			cfg: Config{
				Proxmox: ProxmoxConfig{
					Host:        "localhost",
					Port:        8006,
					TokenID:     "user@pam!token",
					TokenSecret: "secret",
				},
			},
			wantErr: false,
		},
		{
			name: "missing host",
			cfg: Config{
				Proxmox: ProxmoxConfig{
					Host:     "",
					Port:     8006,
					User:     "root@pam",
					Password: "password",
				},
			},
			wantErr: true,
		},
		{
			name: "missing auth",
			cfg: Config{
				Proxmox: ProxmoxConfig{
					Host: "localhost",
					Port: 8006,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid port too low",
			cfg: Config{
				Proxmox: ProxmoxConfig{
					Host:     "localhost",
					Port:     0,
					Password: "x",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid port too high",
			cfg: Config{
				Proxmox: ProxmoxConfig{
					Host:     "localhost",
					Port:     70000,
					Password: "x",
				},
			},
			wantErr: true,
		},
		{
			name: "valid port",
			cfg: Config{
				Proxmox: ProxmoxConfig{
					Host:     "localhost",
					Port:     8006,
					Password: "x",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid metrics path",
			cfg: Config{
				Proxmox: ProxmoxConfig{
					Host:     "localhost",
					Port:     8006,
					Password: "x",
				},
				Server: ServerConfig{MetricsPath: "metrics"},
			},
			wantErr: true,
		},
		{
			name: "invalid token format",
			cfg: Config{
				Proxmox: ProxmoxConfig{
					Host:        "localhost",
					Port:        8006,
					TokenID:     "badformat",
					TokenSecret: "secret",
				},
			},
			wantErr: true,
		},
		{
			name: "valid token format",
			cfg: Config{
				Proxmox: ProxmoxConfig{
					Host:        "localhost",
					Port:        8006,
					TokenID:     "user@pam!token",
					TokenSecret: "secret",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetEnvBool(t *testing.T) {
	_ = os.Setenv("TEST_BOOL_TRUE", "true")
	_ = os.Setenv("TEST_BOOL_1", "1")
	_ = os.Setenv("TEST_BOOL_FALSE", "false")
	defer func() {
		_ = os.Unsetenv("TEST_BOOL_TRUE")
		_ = os.Unsetenv("TEST_BOOL_1")
		_ = os.Unsetenv("TEST_BOOL_FALSE")
	}()

	if !getEnvBool("TEST_BOOL_TRUE", false) {
		t.Error("expected true for 'true'")
	}
	if !getEnvBool("TEST_BOOL_1", false) {
		t.Error("expected true for '1'")
	}
	if getEnvBool("TEST_BOOL_FALSE", true) {
		t.Error("expected false for 'false'")
	}
	if !getEnvBool("NON_EXISTENT", true) {
		t.Error("expected default value true")
	}
}
