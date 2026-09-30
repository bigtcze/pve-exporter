package collector

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bigtcze/pve-exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func metricValue(metrics []prometheus.Metric, name string, labels map[string]string) (float64, bool) {
	for _, metric := range metrics {
		if !strings.Contains(metric.Desc().String(), `fqName: "`+name+`"`) {
			continue
		}
		var value dto.Metric
		if err := metric.Write(&value); err != nil {
			continue
		}
		matched := true
		for labelName, labelValue := range labels {
			found := false
			for _, label := range value.Label {
				if label.GetName() == labelName && label.GetValue() == labelValue {
					found = true
					break
				}
			}
			if !found {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		if value.Gauge != nil {
			return value.Gauge.GetValue(), true
		}
		if value.Counter != nil {
			return value.Counter.GetValue(), true
		}
	}
	return 0, false
}

func collectMetrics(run func(chan<- prometheus.Metric)) []prometheus.Metric {
	ch := make(chan prometheus.Metric, 2048)
	run(ch)
	close(ch)
	metrics := make([]prometheus.Metric, 0, len(ch))
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	return metrics
}

func TestConcurrentRunningGuestDetailsRetainMetrics(t *testing.T) {
	for _, resourceType := range []string{"qemu", "lxc"} {
		t.Run(resourceType, func(t *testing.T) {
			const guestCount = 4
			var detailRequests atomic.Int32
			allDetails := make(chan struct{})
			var allDetailsOnce sync.Once

			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api2/json/nodes/node1/"+resourceType {
					_, _ = io.WriteString(w, `{"data":[`+
						`{"vmid":100,"name":"guest-100","status":"running","diskread":1,"diskwrite":2},`+
						`{"vmid":101,"name":"guest-101","status":"running","diskread":1,"diskwrite":2},`+
						`{"vmid":102,"name":"guest-102","status":"running","diskread":1,"diskwrite":2},`+
						`{"vmid":103,"name":"guest-103","status":"running","diskread":1,"diskwrite":2}]}`)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/status/current") {
					if detailRequests.Add(1) == guestCount {
						allDetailsOnce.Do(func() { close(allDetails) })
					}
					if !waitForTestBarrier(r, allDetails) {
						http.Error(w, "detail barrier timeout", http.StatusInternalServerError)
						return
					}
					parts := strings.Split(r.URL.Path, "/")
					vmid, _ := strconv.Atoi(parts[6])
					_, _ = fmt.Fprintf(w, `{"data":{"diskread":%d,"diskwrite":%d}}`, vmid+1000, vmid+2000)
					return
				}
				http.NotFound(w, r)
			}))
			t.Cleanup(server.Close)
			t.Cleanup(func() { allDetailsOnce.Do(func() { close(allDetails) }) })

			c := apiTestCollector(t, server, &config.ProxmoxConfig{TokenID: "user@pam!metrics", TokenSecret: "secret"})
			metrics := collectMetrics(func(ch chan<- prometheus.Metric) {
				if got := c.collectResourceMetrics(ch, "node1", resourceType); got != guestCount {
					t.Fatalf("resource count = %d, want %d", got, guestCount)
				}
			})

			metricName := "pve_vm_disk_read_bytes_total"
			if resourceType == "lxc" {
				metricName = "pve_lxc_disk_read_bytes_total"
			}
			for vmid := 100; vmid < 100+guestCount; vmid++ {
				labels := map[string]string{"node": "node1", "vmid": strconv.Itoa(vmid), "name": "guest-" + strconv.Itoa(vmid)}
				value, ok := metricValue(metrics, metricName, labels)
				if !ok || value != float64(vmid+1000) {
					t.Errorf("%s for VM %d = %v, found %v; want %d", metricName, vmid, value, ok, vmid+1000)
				}
			}
		})
	}
}

func TestClusterNodeTotalFallback(t *testing.T) {
	tests := []struct {
		name       string
		statusBody string
		wantTotal  float64
		wantOnline float64
		wantQuorum float64
	}{
		{
			name:       "node entries without cluster entry",
			statusBody: `{"data":[{"type":"node","name":"n1","online":1},{"type":"node","name":"n2","online":0},{"type":"node","name":"n3","online":1}]}`,
			wantTotal:  3,
			wantOnline: 2,
			wantQuorum: 1,
		},
		{
			name:       "cluster entry remains authoritative",
			statusBody: `{"data":[{"type":"node","name":"n1","online":1},{"type":"cluster","nodes":5,"quorate":0},{"type":"node","name":"n2","online":1}]}`,
			wantTotal:  5,
			wantOnline: 2,
			wantQuorum: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api2/json/cluster/status":
					_, _ = io.WriteString(w, tt.statusBody)
				case "/api2/json/cluster/ha/resources":
					_, _ = io.WriteString(w, `{"data":[]}`)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			c := apiTestCollector(t, server, &config.ProxmoxConfig{TokenID: "user@pam!metrics", TokenSecret: "secret"})
			metrics := collectMetrics(c.collectClusterMetrics)

			for name, want := range map[string]float64{
				"pve_cluster_nodes_total":  tt.wantTotal,
				"pve_cluster_nodes_online": tt.wantOnline,
				"pve_cluster_quorate":      tt.wantQuorum,
			} {
				if got, ok := metricValue(metrics, name, nil); !ok || got != want {
					t.Errorf("%s = %v, found %v; want %v", name, got, ok, want)
				}
			}
		})
	}
}

func TestMalformedNodesCompletesFailedScrapeOnce(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api2/json/nodes" {
			_, _ = io.WriteString(w, `{"data":`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	c := apiTestCollector(t, server, &config.ProxmoxConfig{TokenID: "user@pam!metrics", TokenSecret: "secret"})

	metrics := gatherMetrics(t, c)
	if up, ok := findMetricValue(metrics, "pve_exporter_up", nil); !ok || up != 0 {
		t.Fatalf("pve_exporter_up = %v, found %v; want 0", up, ok)
	}
	for _, name := range []string{"pve_exporter_up", "pve_exporter_scrape_duration_seconds"} {
		found := false
		for _, family := range metrics {
			if family.GetName() == name {
				found = true
				if got := len(family.Metric); got != 1 {
					t.Fatalf("%s metric count = %d, want 1", name, got)
				}
			}
		}
		if !found {
			t.Fatalf("metric family %s not found", name)
		}
	}
}

func TestBackupLogEarlyStopCountsDistinctVMIDs(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":[`+
			`{"n":1,"t":"Finished Backup of VM 100"},`+
			`{"n":2,"t":"Backup finished at 2024-01-01 01:00:00"},`+
			`{"n":3,"t":"Finished Backup of VM 100"},`+
			`{"n":4,"t":"Backup finished at 2024-01-02 01:00:00"},`+
			`{"n":5,"t":"Finished Backup of VM 200"},`+
			`{"n":6,"t":"Backup finished at 2024-01-03 01:00:00"}]}`)
	}))
	defer server.Close()
	c := apiTestCollector(t, server, &config.ProxmoxConfig{TokenID: "user@pam!metrics", TokenSecret: "secret"})

	backups := make(map[string]int64)
	var mu sync.Mutex
	c.parseBackupLog("node1", "UPID:test", 2, backups, &mu)
	for vmid, date := range map[string]string{"100": "2024-01-02 01:00:00", "200": "2024-01-03 01:00:00"} {
		want, err := time.Parse("2006-01-02 15:04:05", date)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := backups[vmid]; !ok || got != want.Unix() {
			t.Errorf("backup %s = %d, found %v; want %d", vmid, got, ok, want.Unix())
		}
	}
}

type errorAfterDataReader struct {
	data []byte
}

func (r *errorAfterDataReader) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	return 0, errors.New("injected scanner failure")
}

func TestInternalFailuresAreLogged(t *testing.T) {
	var logs bytes.Buffer
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api2/json/nodes/node1/qemu":
			_, _ = io.WriteString(w, `{"data":[{"vmid":100,"name":"request-error","status":"running"},{"vmid":101,"name":"decode-error","status":"running"}]}`)
		case strings.Contains(r.URL.Path, "/qemu/100/"):
			http.NotFound(w, r)
		case strings.Contains(r.URL.Path, "/qemu/101/"):
			_, _ = io.WriteString(w, `{"data":{"diskread":2,"pressurecpufull":"invalid-number"}}`)
		case r.URL.Path == "/api2/json/nodes/node1/tasks/bad/log":
			_, _ = io.WriteString(w, "private malformed body marker")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	c := apiTestCollector(t, server, &config.ProxmoxConfig{TokenID: "user@pam!metrics", TokenSecret: "secret"})
	c.logger = slog.New(slog.NewJSONHandler(&logs, nil))

	_ = collectMetrics(func(ch chan<- prometheus.Metric) { c.collectResourceMetrics(ch, "node1", "qemu") })
	_ = collectMetrics(c.collectReplicationMetrics)
	_ = collectMetrics(func(ch chan<- prometheus.Metric) { c.collectZFSPoolMetricsWithNodes(ch, []string{"node1"}) })
	backups := make(map[string]int64)
	var mu sync.Mutex
	c.collectNodeBackups("node1", 1, backups, &mu)
	c.parseBackupLog("node1", "missing", 1, backups, &mu)
	c.parseBackupLog("node1", "bad", 1, backups, &mu)
	_ = collectMetrics(func(ch chan<- prometheus.Metric) {
		c.collectZFSARCFromReader(ch, &errorAfterDataReader{data: []byte("hits 4 1\n")}, "node1")
	})

	output := logs.String()
	for _, message := range []string{
		"failed to fetch resource details",
		"failed to decode VM details",
		"failed to fetch replication status",
		"failed to fetch ZFS pools",
		"failed to fetch backup tasks",
		"failed to fetch backup task log",
		"failed to decode backup task log",
		"failed to scan ZFS ARC stats",
	} {
		if !strings.Contains(output, message) {
			t.Errorf("log message %q not found in %s", message, output)
		}
	}
	if strings.Contains(output, "private malformed body marker") || strings.Contains(output, "secret") {
		t.Fatalf("logs contain response body or credential: %s", output)
	}
}

func TestBackupLogSeededRegression(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":[`+
			`{"n":1,"t":"Finished Backup of VM 100"},`+
			`{"n":2,"t":"Backup finished at 2024-01-01 01:00:00"},`+
			`{"n":3,"t":"Finished Backup of VM 200"},`+
			`{"n":4,"t":"Backup finished at 2024-01-01 02:00:00"},`+
			`{"n":5,"t":"Finished Backup of VM 100"},`+
			`{"n":6,"t":"Backup finished at 2024-01-03 01:00:00"}]}`)
	}))
	defer server.Close()
	c := apiTestCollector(t, server, &config.ProxmoxConfig{TokenID: "user@pam!metrics", TokenSecret: "secret"})

	backups := make(map[string]int64)
	jan2, _ := time.Parse("2006-01-02 15:04:05", "2024-01-02 01:00:00")
	backups["100"] = jan2.Unix()

	var mu sync.Mutex
	c.parseBackupLog("node1", "UPID:test", 2, backups, &mu)

	wantJan3, _ := time.Parse("2006-01-02 15:04:05", "2024-01-03 01:00:00")
	if got, ok := backups["100"]; !ok || got != wantJan3.Unix() {
		t.Errorf("backup 100 = %d, found %v; want %d", got, ok, wantJan3.Unix())
	}
}

func TestConcurrentBackupLogBatch(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "UPID:slow") {
			_, _ = io.WriteString(w, `{"data":[`+
				`{"n":1,"t":"Finished Backup of VM 100"},`+
				`{"n":2,"t":"Backup finished at 2024-01-01 01:00:00"},`+
				`{"n":3,"t":"Finished Backup of VM 200"},`+
				`{"n":4,"t":"Backup finished at 2024-01-01 02:00:00"},`+
				`{"n":5,"t":"Finished Backup of VM 100"},`+
				`{"n":6,"t":"Backup finished at 2024-01-03 01:00:00"}]}`)
		} else if strings.Contains(r.URL.Path, "UPID:fast") {
			_, _ = io.WriteString(w, `{"data":[`+
				`{"n":1,"t":"Finished Backup of VM 100"},`+
				`{"n":2,"t":"Backup finished at 2024-01-02 01:00:00"}]}`)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	c := apiTestCollector(t, server, &config.ProxmoxConfig{TokenID: "user@pam!metrics", TokenSecret: "secret"})

	jobs := []batchJob{
		{UPID: "UPID:slow"},
		{UPID: "UPID:fast"},
	}
	backups := make(map[string]int64)
	var mu sync.Mutex
	c.processBatchBackupJobs("node1", jobs, 10, backups, &mu)

	wantJan3, _ := time.Parse("2006-01-02 15:04:05", "2024-01-03 01:00:00")
	if got, ok := backups["100"]; !ok || got != wantJan3.Unix() {
		t.Errorf("backup 100 = %d, found %v; want %d", got, ok, wantJan3.Unix())
	}
}

func TestCompatibilityCharacterizations(t *testing.T) {
	var requestedTasksURL string
	var logRequests int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api2/json/nodes/node1/qemu":
			http.Error(w, "Forbidden", http.StatusForbidden)
		case r.URL.Path == "/api2/json/nodes/node1/lxc":
			_, _ = io.WriteString(w, `{"data":[{"vmid":200,"name":"lxc1","status":"running","diskread":500}]}`)
		case r.URL.Path == "/api2/json/nodes/node1/lxc/200/status/current":
			// string PSI and missing numeric fields
			_, _ = io.WriteString(w, `{"data":{"swap":123,"pressurecpufull":"string-value"}}`)
		case r.URL.Path == "/api2/json/cluster/ha/resources":
			http.Error(w, "Error", http.StatusInternalServerError)
		case r.URL.Path == "/api2/json/nodes":
			_, _ = io.WriteString(w, `{"data":[]}`)
		case strings.Contains(r.URL.Path, "/tasks"):
			if strings.HasSuffix(r.URL.Path, "/tasks") {
				requestedTasksURL = r.URL.String()
				_, _ = io.WriteString(w, `{"data":[`+
					`{"status":"OK","upid":"1","endtime":1},`+
					`{"status":"OK","upid":"2","endtime":2},`+
					`{"status":"OK","upid":"3","endtime":3},`+
					`{"status":"OK","upid":"4","endtime":4},`+
					`{"status":"OK","upid":"5","endtime":5},`+
					`{"status":"OK","upid":"6","endtime":6}]}`)
			} else if strings.HasSuffix(r.URL.Path, "/log") {
				atomic.AddInt32(&logRequests, 1)
				_, _ = io.WriteString(w, `{"data":[]}`)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	c := apiTestCollector(t, server, &config.ProxmoxConfig{TokenID: "token", TokenSecret: "secret"})

	metrics := collectMetrics(func(ch chan<- prometheus.Metric) {
		c.collectResourceMetrics(ch, "node1", "qemu")
		c.collectResourceMetrics(ch, "node1", "lxc")
		c.collectClusterMetrics(ch)
		c.collectNodeBackups("node1", 1, make(map[string]int64), &sync.Mutex{})
	})

	if val, ok := metricValue(metrics, "pve_lxc_disk_read_bytes_total", nil); !ok || val != 500 {
		t.Errorf("expected LXC string PSI disk fallback to use aggregate 500, got %v (ok=%v)", val, ok)
	}
	if val, ok := metricValue(metrics, "pve_lxc_swap_used_bytes", nil); !ok || val != 123 {
		t.Errorf("expected LXC detail swap=123, got %v (ok=%v)", val, ok)
	}

	metricsNodes := gatherMetrics(t, c)
	if up, ok := findMetricValue(metricsNodes, "pve_exporter_up", nil); !ok || up != 1 {
		t.Errorf("expected empty /nodes to be up=1, got %v", up)
	}

	if !strings.Contains(requestedTasksURL, "limit=50") {
		t.Errorf("expected tasks query to have limit=50, got %s", requestedTasksURL)
	}
	if atomic.LoadInt32(&logRequests) != 5 {
		t.Errorf("expected maximum 5 log requests, got %d", atomic.LoadInt32(&logRequests))
	}
}
