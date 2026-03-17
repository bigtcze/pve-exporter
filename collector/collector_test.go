package collector

import (
	"io"
	"log/slog"
	"testing"

	"github.com/bigtcze/pve-exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestNewProxmoxCollector(t *testing.T) {
	cfg := &config.ProxmoxConfig{
		Host: "localhost",
		User: "root@pam",
	}

	c := NewProxmoxCollector(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if c == nil {
		t.Fatal("NewProxmoxCollector returned nil")
	}
}

func TestDescribe(t *testing.T) {
	cfg := &config.ProxmoxConfig{
		Host: "localhost",
		User: "root@pam",
	}

	c := NewProxmoxCollector(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ch := make(chan *prometheus.Desc)

	go func() {
		for range ch {
		}
	}()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Describe panicked: %v", r)
		}
	}()

	c.Describe(ch)
	close(ch)
}

func findMetricValue(metrics []*dto.MetricFamily, name string, labels map[string]string) (float64, bool) {
	for _, mf := range metrics {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			match := true
			for k, v := range labels {
				found := false
				for _, l := range m.GetLabel() {
					if l.GetName() == k && l.GetValue() == v {
						found = true
						break
					}
				}
				if !found {
					match = false
					break
				}
			}
			if match {
				if m.GetGauge() != nil {
					return m.GetGauge().GetValue(), true
				}
				if m.GetCounter() != nil {
					return m.GetCounter().GetValue(), true
				}
			}
		}
	}
	return 0, false
}

func gatherMetrics(t *testing.T, c *ProxmoxCollector) []*dto.MetricFamily {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	metrics, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather failed: %v", err)
	}
	return metrics
}

func TestCollect(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	c := newTestCollector(t, server)

	metrics := gatherMetrics(t, c)
	if len(metrics) == 0 {
		t.Fatal("expected metrics, got none")
	}
}

func TestCollectNodeMetrics(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	c := newTestCollector(t, server)
	metrics := gatherMetrics(t, c)

	nodeLabels := map[string]string{"node": "pve1"}

	tests := []struct {
		name  string
		value float64
	}{
		{"pve_node_up", 1},
		{"pve_node_uptime_seconds", 1234567},
		{"pve_node_cpu_load", 0.15},
		{"pve_node_cpus_total", 16},
		{"pve_node_memory_total_bytes", 68719476736},
		{"pve_node_memory_used_bytes", 34359738368},
	}

	for _, tt := range tests {
		val, ok := findMetricValue(metrics, tt.name, nodeLabels)
		if !ok {
			t.Errorf("metric %s not found", tt.name)
			continue
		}
		if val != tt.value {
			t.Errorf("%s = %v, want %v", tt.name, val, tt.value)
		}
	}
}

func TestCollectVMMetrics(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	c := newTestCollector(t, server)
	metrics := gatherMetrics(t, c)

	runningLabels := map[string]string{"node": "pve1", "vmid": "100", "name": "web-server"}
	stoppedLabels := map[string]string{"node": "pve1", "vmid": "101", "name": "db-server"}

	val, ok := findMetricValue(metrics, "pve_vm_status", runningLabels)
	if !ok {
		t.Error("pve_vm_status for running VM not found")
	} else if val != 1 {
		t.Errorf("pve_vm_status running = %v, want 1", val)
	}

	val, ok = findMetricValue(metrics, "pve_vm_status", stoppedLabels)
	if !ok {
		t.Error("pve_vm_status for stopped VM not found")
	} else if val != 0 {
		t.Errorf("pve_vm_status stopped = %v, want 0", val)
	}

	val, ok = findMetricValue(metrics, "pve_vm_cpu_usage", runningLabels)
	if !ok {
		t.Error("pve_vm_cpu_usage not found")
	} else if val != 0.25 {
		t.Errorf("pve_vm_cpu_usage = %v, want 0.25", val)
	}
}

func TestCollectLXCMetrics(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	c := newTestCollector(t, server)
	metrics := gatherMetrics(t, c)

	lxcLabels := map[string]string{"node": "pve1", "vmid": "200", "name": "proxy-ct"}

	val, ok := findMetricValue(metrics, "pve_lxc_status", lxcLabels)
	if !ok {
		t.Error("pve_lxc_status not found")
	} else if val != 1 {
		t.Errorf("pve_lxc_status = %v, want 1", val)
	}

	val, ok = findMetricValue(metrics, "pve_lxc_uptime_seconds", lxcLabels)
	if !ok {
		t.Error("pve_lxc_uptime_seconds not found")
	} else if val != 172800 {
		t.Errorf("pve_lxc_uptime_seconds = %v, want 172800", val)
	}
}

func TestCollectStorageMetrics(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	c := newTestCollector(t, server)
	metrics := gatherMetrics(t, c)

	localLabels := map[string]string{"node": "pve1", "storage": "local", "type": "dir"}

	val, ok := findMetricValue(metrics, "pve_storage_total_bytes", localLabels)
	if !ok {
		t.Error("pve_storage_total_bytes not found")
	} else if val != 536870912000 {
		t.Errorf("pve_storage_total_bytes = %v, want 536870912000", val)
	}

	val, ok = findMetricValue(metrics, "pve_storage_used_fraction", localLabels)
	if !ok {
		t.Error("pve_storage_used_fraction not found")
	} else if val != 0.2 {
		t.Errorf("pve_storage_used_fraction = %v, want 0.2", val)
	}
}

func TestCollectClusterMetrics(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	c := newTestCollector(t, server)
	metrics := gatherMetrics(t, c)

	val, ok := findMetricValue(metrics, "pve_cluster_quorate", nil)
	if !ok {
		t.Error("pve_cluster_quorate not found")
	} else if val != 1 {
		t.Errorf("pve_cluster_quorate = %v, want 1", val)
	}

	val, ok = findMetricValue(metrics, "pve_cluster_nodes_online", nil)
	if !ok {
		t.Error("pve_cluster_nodes_online not found")
	} else if val != 1 {
		t.Errorf("pve_cluster_nodes_online = %v, want 1", val)
	}
}

func TestCollectZFSPoolMetrics(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	c := newTestCollector(t, server)
	metrics := gatherMetrics(t, c)

	zfsLabels := map[string]string{"node": "pve1", "pool": "rpool"}

	val, ok := findMetricValue(metrics, "pve_zfs_pool_health_status", zfsLabels)
	if !ok {
		t.Error("pve_zfs_pool_health_status not found")
	} else if val != 1 {
		t.Errorf("pve_zfs_pool_health_status = %v, want 1", val)
	}
}

func TestCollectBackupMetrics(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	c := newTestCollector(t, server)
	metrics := gatherMetrics(t, c)

	backupLabels := map[string]string{"node": "pve1", "vmid": "100", "name": "web-server"}

	val, ok := findMetricValue(metrics, "pve_vm_last_backup_timestamp", backupLabels)
	if !ok {
		t.Error("pve_vm_last_backup_timestamp not found")
	} else if val != 1710000000 {
		t.Errorf("pve_vm_last_backup_timestamp = %v, want 1710000000", val)
	}
}

func TestCollectReplicationMetrics(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	c := newTestCollector(t, server)
	metrics := gatherMetrics(t, c)

	repLabels := map[string]string{"guest": "100", "job": "100-0"}

	val, ok := findMetricValue(metrics, "pve_replication_status", repLabels)
	if !ok {
		t.Error("pve_replication_status not found")
	} else if val != 1 {
		t.Errorf("pve_replication_status = %v, want 1", val)
	}
}
