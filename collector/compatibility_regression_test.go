package collector

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bigtcze/pve-exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

func TestCompatibilityGuestScenarios(t *testing.T) {
	for _, resType := range []string{"qemu", "lxc"} {
		for _, scenario := range []string{"empty-details", "failed-details", "malformed-details", "stopped", "string-psi", "list403"} {
			if scenario == "string-psi" && resType != "lxc" {
				continue
			}
			t.Run(resType+"/"+scenario, func(t *testing.T) {
				var detailRequests atomic.Int32
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/api2/json/nodes/node1/"+resType {
						if scenario == "list403" {
							http.Error(w, "Forbidden", http.StatusForbidden)
							return
						}
						status := "running"
						if scenario == "stopped" {
							status = "stopped"
						}
						_, _ = fmt.Fprintf(w, `{"data":[{"vmid":100,"name":"guest","status":%q,"diskread":111,"diskwrite":222}]}`, status)
						return
					}
					detailRequests.Add(1)
					switch scenario {
					case "failed-details":
						http.NotFound(w, r)
					case "malformed-details":
						_, _ = io.WriteString(w, `{"data":`)
					case "string-psi":
						_, _ = io.WriteString(w, `{"data":{"diskread":999,"diskwrite":888,"swap":12,"maxswap":24,"pressurecpufull":"0.25"}}`)
					default:
						_, _ = io.WriteString(w, `{"data":{}}`)
					}
				}))
				defer server.Close()
				c := apiTestCollector(t, server, &config.ProxmoxConfig{TokenID: "user@pam!metrics", TokenSecret: "secret"})

				if scenario == "list403" {
					metrics := collectMetrics(func(ch chan<- prometheus.Metric) {
						c.collectVMMetricsWithNodes(ch, []string{"node1"})
					})
					countName := "pve_node_vm_count"
					if resType == "lxc" {
						countName = "pve_node_lxc_count"
					}
					if got, ok := metricValue(metrics, countName, nil); !ok || got != 0 {
						t.Errorf("%s = %v, found %v; want 0", countName, got, ok)
					}
					return
				}

				metrics := collectMetrics(func(ch chan<- prometheus.Metric) { c.collectResourceMetrics(ch, "node1", resType) })
				prefix := "pve_vm_"
				detailName := "balloon_bytes"
				if resType == "lxc" {
					prefix = "pve_lxc_"
					detailName = "swap_used_bytes"
				}
				wants := map[string]float64{"memory_used_bytes": 0, "disk_read_bytes_total": 111, "disk_write_bytes_total": 222}
				if scenario == "empty-details" {
					wants["disk_read_bytes_total"] = 0
					wants["disk_write_bytes_total"] = 0
					wants[detailName] = 0
				}
				if scenario == "string-psi" {
					wants[detailName] = 12
					wants["swap_max_bytes"] = 24
					wants["pressure_cpu_full"] = 0.25
				}
				for name, want := range wants {
					if got, ok := metricValue(metrics, prefix+name, nil); !ok || got != want {
						t.Errorf("%s = %v, found %v; want %v", prefix+name, got, ok, want)
					}
				}
				if scenario == "failed-details" || scenario == "malformed-details" || scenario == "stopped" {
					if _, ok := metricValue(metrics, prefix+detailName, nil); ok {
						t.Errorf("unexpected %s%s after %s", prefix, detailName, scenario)
					}
				}
				wantRequests := int32(1)
				if scenario == "stopped" || scenario == "list403" {
					wantRequests = 0
				}
				if got := detailRequests.Load(); got != wantRequests {
					t.Errorf("detail requests = %d, want %d", got, wantRequests)
				}
			})
		}
	}
}

func TestCompatibilityHAErrorZeros(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api2/json/cluster/status" {
			_, _ = io.WriteString(w, `{"data":[]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	c := apiTestCollector(t, server, &config.ProxmoxConfig{TokenID: "user@pam!metrics", TokenSecret: "secret"})
	metrics := collectMetrics(c.collectClusterMetrics)
	for _, name := range []string{"pve_ha_resources_total", "pve_ha_resources_active"} {
		if got, ok := metricValue(metrics, name, nil); !ok || got != 0 {
			t.Errorf("%s = %v, found %v; want emitted zero", name, got, ok)
		}
	}
}

func TestCompatibilityEmptyNodes(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":[]}`)
	}))
	defer server.Close()
	c := apiTestCollector(t, server, &config.ProxmoxConfig{TokenID: "user@pam!metrics", TokenSecret: "secret"})
	metrics := gatherMetrics(t, c)
	if got, ok := findMetricValue(metrics, "pve_exporter_up", nil); !ok || got != 1 {
		t.Errorf("pve_exporter_up = %v, found %v; want 1", got, ok)
	}
	if _, ok := findMetricValue(metrics, "pve_exporter_scrape_duration_seconds", nil); !ok {
		t.Error("missing duration")
	}
}

func TestCompatibilityBackupRequestLimits(t *testing.T) {
	var tasksRequests, logRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api2/json/nodes/node1/tasks" {
			tasksRequests.Add(1)
			if r.URL.RawQuery != "typefilter=vzdump&limit=50" {
				t.Errorf("task query = %q", r.URL.RawQuery)
			}
			_, _ = io.WriteString(w, `{"data":[`+
				`{"status":"OK","id":"300","endtime":99},`+
				`{"status":"OK","upid":"batch0"},{"status":"OK","upid":"batch1"},`+
				`{"status":"OK","upid":"batch2"},{"status":"OK","upid":"batch3"},`+
				`{"status":"OK","upid":"batch4"},{"status":"OK","upid":"batch5"}]}`)
			return
		}
		logRequests.Add(1)
		if !strings.HasSuffix(r.URL.Path, "/log") || strings.Contains(r.URL.Path, "/batch5/") || r.URL.RawQuery != "limit=1000000" {
			t.Errorf("unexpected log request: %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		_, _ = io.WriteString(w, `{"data":[]}`)
	}))
	defer server.Close()
	c := apiTestCollector(t, server, &config.ProxmoxConfig{TokenID: "user@pam!metrics", TokenSecret: "secret"})
	backups := make(map[string]int64)
	var mu sync.Mutex
	c.collectNodeBackups("node1", 2, backups, &mu)
	if got := tasksRequests.Load(); got != 1 {
		t.Errorf("task requests = %d, want 1", got)
	}
	if got := logRequests.Load(); got != 5 {
		t.Errorf("log requests = %d, want 5", got)
	}
	if got := backups["300"]; got != 99 {
		t.Errorf("direct task timestamp = %d, want 99", got)
	}
}

func TestBackupSharedMapDeterministic(t *testing.T) {
	seedTime, _ := time.Parse("2006-01-02 15:04:05", "2024-01-02 01:00:00")
	wantTime, _ := time.Parse("2006-01-02 15:04:05", "2024-01-03 01:00:00")
	for _, concurrent := range []bool{false, true} {
		t.Run(fmt.Sprintf("concurrent=%v", concurrent), func(t *testing.T) {
			seedReady := make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/seed/log") {
					_, _ = io.WriteString(w, `{"data":[{"t":"Finished Backup of VM 100"},{"t":"Backup finished at 2024-01-02 01:00:00"}]}`)
					return
				}
				if !waitForTestBarrier(r, seedReady) {
					http.Error(w, "seed barrier timeout", http.StatusInternalServerError)
					return
				}
				_, _ = io.WriteString(w, `{"data":[`+
					`{"t":"Finished Backup of VM 100"},{"t":"Backup finished at 2024-01-01 01:00:00"},`+
					`{"t":"Finished Backup of VM 200"},{"t":"Backup finished at 2024-01-01 01:00:00"},`+
					`{"t":"Finished Backup of VM 100"},{"t":"Backup finished at 2024-01-03 01:00:00"}]}`)
			}))
			defer server.Close()
			c := apiTestCollector(t, server, &config.ProxmoxConfig{TokenID: "user@pam!metrics", TokenSecret: "secret"})
			backups := make(map[string]int64)
			var mu sync.Mutex
			if concurrent {
				done := make(chan struct{})
				go func() {
					c.parseBackupLog("node1", "main", 2, backups, &mu)
					close(done)
				}()
				c.parseBackupLog("node1", "seed", 2, backups, &mu)
				close(seedReady)
				<-done
			} else {
				backups["100"] = seedTime.Unix()
				close(seedReady)
				c.parseBackupLog("node1", "main", 2, backups, &mu)
			}
			if got := backups["100"]; got != wantTime.Unix() {
				t.Errorf("VM 100 timestamp = %d (%s), want %d (%s)", got, time.Unix(got, 0).UTC(), wantTime.Unix(), wantTime)
			}
		})
	}
}
