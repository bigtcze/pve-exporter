package collector

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bigtcze/pve-exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// newLocalCollector builds a collector without any Proxmox connection, for
// tests of local-host sources only.
func newLocalCollector(t *testing.T) *ProxmoxCollector {
	t.Helper()
	cfg := &config.ProxmoxConfig{Host: "localhost", Port: 8006, Timeout: time.Second}
	return NewProxmoxCollector(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// overrideString sets a package-level path for the test duration.
func overrideString(t *testing.T, target *string, value string) {
	t.Helper()
	orig := *target
	*target = value
	t.Cleanup(func() { *target = orig })
}

func writeTestFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// metricSeries is one emitted series reduced to what tests assert on.
type metricSeries struct {
	name   string
	typ    dto.MetricType
	labels map[string]string
	value  float64
}

func readSeries(t *testing.T, metrics []prometheus.Metric) []metricSeries {
	t.Helper()
	out := make([]metricSeries, 0, len(metrics))
	for _, m := range metrics {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		desc := m.Desc().String()
		name := between(desc, `fqName: "`, `"`)
		s := metricSeries{name: name, labels: map[string]string{}}
		for _, l := range pb.Label {
			s.labels[l.GetName()] = l.GetValue()
		}
		switch {
		case pb.Gauge != nil:
			s.typ, s.value = dto.MetricType_GAUGE, pb.Gauge.GetValue()
		case pb.Counter != nil:
			s.typ, s.value = dto.MetricType_COUNTER, pb.Counter.GetValue()
		}
		out = append(out, s)
	}
	return out
}

func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	s = s[i+len(start):]
	j := strings.Index(s, end)
	if j < 0 {
		return s
	}
	return s[:j]
}

// findSeries returns the single series matching name and all labels; it fails
// the test when none or more than one matches.
func findSeries(t *testing.T, series []metricSeries, name string, labels map[string]string) metricSeries {
	t.Helper()
	var matches []metricSeries
	for _, s := range series {
		if s.name != name {
			continue
		}
		ok := true
		for k, v := range labels {
			if s.labels[k] != v {
				ok = false
				break
			}
		}
		if ok {
			matches = append(matches, s)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("%s %v: got %d matches, want 1", name, labels, len(matches))
	}
	return matches[0]
}

func countFamily(series []metricSeries, name string) int {
	n := 0
	for _, s := range series {
		if s.name == name {
			n++
		}
	}
	return n
}

// ---- lm-sensors ----

const sensorsFixture = `{
  "coretemp-isa-0000": {
    "Adapter": "ISA adapter",
    "Package id 0": {
      "temp1_input": 45.5,
      "temp1_max": 100.0
    },
    "Core 0": {
      "temp2_input": 43.0
    }
  },
  "nct6798-isa-0290": {
    "Adapter": "ISA adapter",
    "fan1": {
      "fan1_input": 1200.0,
      "fan1_min": 300.0
    },
    "in0": {
      "in0_input": 1.104
    },
    "power1": {
      "power1_input": 65.0,
      "power1_average": 60.0
    }
  },
  "amdgpu-pci-0300": {
    "Adapter": "PCI adapter",
    "power1": {
      "power1_average": 12.5
    }
  },
  "broken-chip": "not-an-object"
}`

func TestCollectSensorsMetricsFromFixture(t *testing.T) {
	orig := sensorsCommand
	t.Cleanup(func() { sensorsCommand = orig })
	sensorsCommand = func() ([]byte, error) { return []byte(sensorsFixture), nil }

	c := newLocalCollector(t)
	series := readSeries(t, collectMetrics(func(ch chan<- prometheus.Metric) { c.collectSensorsMetrics(ch) }))

	host := getHostname()
	cases := []struct {
		name   string
		labels map[string]string
		value  float64
		typ    dto.MetricType
	}{
		// Priority *_input wins over other readings in the same sensor group.
		{"pve_sensor_temperature_celsius", map[string]string{"node": host, "chip": "coretemp-isa-0000", "adapter": "ISA adapter", "sensor": "Package id 0"}, 45.5, dto.MetricType_GAUGE},
		{"pve_sensor_temperature_celsius", map[string]string{"node": host, "chip": "coretemp-isa-0000", "adapter": "ISA adapter", "sensor": "Core 0"}, 43.0, dto.MetricType_GAUGE},
		{"pve_sensor_fan_rpm", map[string]string{"node": host, "chip": "nct6798-isa-0290", "adapter": "ISA adapter", "sensor": "fan1"}, 1200, dto.MetricType_GAUGE},
		{"pve_sensor_voltage_volts", map[string]string{"node": host, "chip": "nct6798-isa-0290", "adapter": "ISA adapter", "sensor": "in0"}, 1.104, dto.MetricType_GAUGE},
		// power_input has priority over power_average in the same group.
		{"pve_sensor_power_watts", map[string]string{"node": host, "chip": "nct6798-isa-0290", "adapter": "ISA adapter", "sensor": "power1"}, 65, dto.MetricType_GAUGE},
		// Only the fallback average exists: it is still exported.
		{"pve_sensor_power_watts", map[string]string{"node": host, "chip": "amdgpu-pci-0300", "adapter": "PCI adapter", "sensor": "power1"}, 12.5, dto.MetricType_GAUGE},
	}
	for _, tc := range cases {
		got := findSeries(t, series, tc.name, tc.labels)
		if got.value != tc.value || got.typ != tc.typ {
			t.Errorf("%s %v = %v (%v), want %v (%v)", tc.name, tc.labels, got.value, got.typ, tc.value, tc.typ)
		}
	}

	// Only one temperature per sensor group, no max/min leakage.
	if n := countFamily(series, "pve_sensor_temperature_celsius"); n != 2 {
		t.Errorf("temperature series = %d, want 2", n)
	}
	if n := countFamily(series, "pve_sensor_fan_rpm"); n != 1 {
		t.Errorf("fan series = %d, want 1 (fan1_min must be ignored)", n)
	}
	// power1 in nct6798 must not emit the average as a second series.
	if n := countFamily(series, "pve_sensor_power_watts"); n != 2 {
		t.Errorf("power series = %d, want 2", n)
	}
}

func TestCollectSensorsMalformedJSONEmitsNothing(t *testing.T) {
	orig := sensorsCommand
	t.Cleanup(func() { sensorsCommand = orig })
	sensorsCommand = func() ([]byte, error) { return []byte(`{"coretemp": {"temp1_input": `), nil }

	c := newLocalCollector(t)
	metrics := collectMetrics(func(ch chan<- prometheus.Metric) { c.collectSensorsMetrics(ch) })
	if len(metrics) != 0 {
		t.Fatalf("malformed JSON emitted %d metrics", len(metrics))
	}
}

func TestCollectSensorsCommandFailureEmitsNothing(t *testing.T) {
	orig := sensorsCommand
	t.Cleanup(func() { sensorsCommand = orig })
	sensorsCommand = func() ([]byte, error) { return nil, errors.New("sensors: not found") }

	c := newLocalCollector(t)
	metrics := collectMetrics(func(ch chan<- prometheus.Metric) { c.collectSensorsMetrics(ch) })
	if len(metrics) != 0 {
		t.Fatalf("failed command emitted %d metrics, want none (no fabricated zeros)", len(metrics))
	}
}

func TestProcessSensorPriority(t *testing.T) {
	got := processSensor(map[string]interface{}{
		"temp1_input":    40.0,
		"temp1_max":      90.0, // not a recognised key
		"power1_average": 5.0,
		"power1_input":   9.0,
		"fan1_input":     "not-a-number",
	})
	if got["temp"] != 40 || got["power"] != 9 {
		t.Fatalf("readings = %v", got)
	}
	if _, ok := got["fan"]; ok {
		t.Fatal("non-numeric value must be skipped")
	}
}

// ---- SMART JSON and diskstats ----

const smartFixture = `{
  "hostname": "pve1",
  "timestamp": 0,
  "disks": [
    {"device": "nvme0n1", "model": "Samsung SSD 980", "serial": "S64ANX0R123", "type": "nvme",
     "healthy": 1, "temperature": 41, "power_on_hours": 12345,
     "data_written_bytes": 2.5e12, "available_spare_percent": 100, "percentage_used": 3},
    {"device": "sda", "model": "WDC WD40EFRX", "serial": "WD-ABC", "type": "sata",
     "healthy": 0, "temperature": 0, "power_on_hours": 0}
  ]
}`

func setSmartPaths(t *testing.T, smartPath, diskstats string) {
	t.Helper()
	overrideString(t, &smartDataPath, smartPath)
	overrideString(t, &diskstatsPath, diskstats)
}

func TestSmartMissingFileIsSilent(t *testing.T) {
	setSmartPaths(t, filepath.Join(t.TempDir(), "absent.json"), filepath.Join(t.TempDir(), "absent"))
	c := newLocalCollector(t)
	metrics := collectMetrics(func(ch chan<- prometheus.Metric) { c.collectSmartMetrics(ch) })
	if len(metrics) != 0 {
		t.Fatalf("missing SMART file emitted %d metrics", len(metrics))
	}
}

func TestSmartStaleFileIsSkipped(t *testing.T) {
	path := writeTestFile(t, "smart.json", smartFixture)
	old := time.Now().Add(-2 * smartDataMaxAge)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	setSmartPaths(t, path, filepath.Join(t.TempDir(), "absent"))
	c := newLocalCollector(t)
	metrics := collectMetrics(func(ch chan<- prometheus.Metric) { c.collectSmartMetrics(ch) })
	if len(metrics) != 0 {
		t.Fatalf("stale SMART file emitted %d metrics", len(metrics))
	}
}

func TestSmartMalformedJSONEmitsNothing(t *testing.T) {
	path := writeTestFile(t, "smart.json", `{"hostname": "pve1", "disks": [`)
	setSmartPaths(t, path, filepath.Join(t.TempDir(), "absent"))
	c := newLocalCollector(t)
	metrics := collectMetrics(func(ch chan<- prometheus.Metric) { c.collectSmartMetrics(ch) })
	if len(metrics) != 0 {
		t.Fatalf("malformed SMART emitted %d metrics", len(metrics))
	}
}

func TestSmartFixtureMetricsAndOmission(t *testing.T) {
	path := writeTestFile(t, "smart.json", smartFixture)
	setSmartPaths(t, path, filepath.Join(t.TempDir(), "absent"))
	c := newLocalCollector(t)
	series := readSeries(t, collectMetrics(func(ch chan<- prometheus.Metric) { c.collectSmartMetrics(ch) }))

	nvme := map[string]string{"node": "pve1", "device": "nvme0n1", "model": "Samsung SSD 980", "serial": "S64ANX0R123", "type": "nvme"}
	sata := map[string]string{"node": "pve1", "device": "sda", "model": "WDC WD40EFRX", "serial": "WD-ABC", "type": "sata"}

	checks := []struct {
		name   string
		labels map[string]string
		value  float64
		typ    dto.MetricType
	}{
		{"pve_disk_health_status", nvme, 1, dto.MetricType_GAUGE},
		{"pve_disk_temperature_celsius", nvme, 41, dto.MetricType_GAUGE},
		{"pve_disk_power_on_hours", nvme, 12345, dto.MetricType_GAUGE},
		{"pve_disk_data_written_bytes", nvme, 2.5e12, dto.MetricType_COUNTER},
		{"pve_disk_available_spare_percent", nvme, 100, dto.MetricType_GAUGE},
		{"pve_disk_percentage_used", nvme, 3, dto.MetricType_GAUGE},
		{"pve_disk_health_status", sata, 0, dto.MetricType_GAUGE},
	}
	for _, ck := range checks {
		got := findSeries(t, series, ck.name, ck.labels)
		if got.value != ck.value || got.typ != ck.typ {
			t.Errorf("%s %v = %v (%v), want %v (%v)", ck.name, ck.labels, got.value, got.typ, ck.value, ck.typ)
		}
	}

	// Omission rules: a SATA disk reporting zero temperature/hours, and no
	// NVMe-only fields, must not produce series (no fabricated zeros).
	for _, name := range []string{"pve_disk_temperature_celsius", "pve_disk_power_on_hours", "pve_disk_data_written_bytes", "pve_disk_available_spare_percent", "pve_disk_percentage_used"} {
		for _, s := range series {
			if s.name == name && s.labels["device"] == "sda" {
				t.Errorf("%s emitted for sda, must be omitted", name)
			}
		}
	}
	if n := countFamily(series, "pve_disk_health_status"); n != 2 {
		t.Errorf("health series = %d, want 2", n)
	}
}

const diskstatsFixture = `   8       0 sda 1000 0 2048 300 500 0 4096 700 0 900 1000
   8       1 sda1 10 0 20 3 5 0 40 7 0 9 10
 259       0 nvme0n1 200 0 4096 50 100 0 8192 70 0 120 150
   7       0 loop0 1 0 8 0 0 0 0 0 0 0 0
 252       0 dm-0 1 0 8 0 0 0 0 0 0 0 0
   8      16 sdb short
`

func TestDiskIOFromDiskstatsFixture(t *testing.T) {
	path := writeTestFile(t, "diskstats", diskstatsFixture)
	setSmartPaths(t, filepath.Join(t.TempDir(), "absent.json"), path)
	c := newLocalCollector(t)
	host := getHostname()
	series := readSeries(t, collectMetrics(func(ch chan<- prometheus.Metric) {
		c.collectDiskIOMetrics(ch, host)
	}))

	sda := map[string]string{"node": host, "device": "sda"}
	// 2048 sectors * 512 bytes; 4096 sectors written; io time 900 ms -> 0.9 s.
	checks := []struct {
		name  string
		value float64
	}{
		{"pve_disk_read_bytes_total", 2048 * 512},
		{"pve_disk_write_bytes_total", 4096 * 512},
		{"pve_disk_reads_completed_total", 1000},
		{"pve_disk_writes_completed_total", 500},
		{"pve_disk_io_time_seconds_total", 0.9},
	}
	for _, ck := range checks {
		got := findSeries(t, series, ck.name, sda)
		if got.value != ck.value || got.typ != dto.MetricType_COUNTER {
			t.Errorf("%s = %v (%v), want %v counter", ck.name, got.value, got.typ, ck.value)
		}
	}

	// Partitions, loop/dm devices and short lines are omitted.
	for _, s := range series {
		if d := s.labels["device"]; d == "sda1" || d == "loop0" || d == "dm-0" || d == "sdb" {
			t.Fatalf("unexpected device %q emitted as %s", d, s.name)
		}
	}
	nvme := map[string]string{"node": host, "device": "nvme0n1"}
	if got := findSeries(t, series, "pve_disk_read_bytes_total", nvme); got.value != 4096*512 {
		t.Fatalf("nvme read bytes = %v", got.value)
	}
}

func TestDiskIOMissingDiskstatsEmitsNothing(t *testing.T) {
	setSmartPaths(t, filepath.Join(t.TempDir(), "absent.json"), filepath.Join(t.TempDir(), "absent"))
	c := newLocalCollector(t)
	metrics := collectMetrics(func(ch chan<- prometheus.Metric) { c.collectDiskIOMetrics(ch, "pve1") })
	if len(metrics) != 0 {
		t.Fatalf("missing diskstats emitted %d metrics", len(metrics))
	}
}

func TestCollectDiskMetricsCombinesSources(t *testing.T) {
	setSmartPaths(t, writeTestFile(t, "smart.json", smartFixture), writeTestFile(t, "diskstats", diskstatsFixture))
	c := newLocalCollector(t)
	series := readSeries(t, collectMetrics(func(ch chan<- prometheus.Metric) { c.collectDiskMetrics(ch) }))
	if countFamily(series, "pve_disk_health_status") == 0 || countFamily(series, "pve_disk_read_bytes_total") == 0 {
		t.Fatal("collectDiskMetrics must emit both SMART and diskstats families")
	}
}

// ---- ZFS ARC ----

const arcstatsFixture = `13 1 0x01 91 4368 3898528 1426006524
name                            type data
hits                            4    12000
misses                          4    3000
size                            4    8589934592
c_min                           4    1073741824
c_max                           4    17179869184
c                               4    9663676416
l2_hits                         4    500
l2_misses                       4    250
l2_size                         4    2147483648
l2_hdr_size                     4    41943040
memory_throttle_count           4    0
`

func TestZFSARCFromFixture(t *testing.T) {
	overrideString(t, &arcStatsPath, writeTestFile(t, "arcstats", arcstatsFixture))
	c := newLocalCollector(t)
	host := getHostname()
	series := readSeries(t, collectMetrics(func(ch chan<- prometheus.Metric) { c.collectZFSARCMetrics(ch) }))

	node := map[string]string{"node": host}
	checks := []struct {
		name  string
		value float64
		typ   dto.MetricType
	}{
		{"pve_zfs_arc_size_bytes", 8589934592, dto.MetricType_GAUGE},
		{"pve_zfs_arc_min_size_bytes", 1073741824, dto.MetricType_GAUGE},
		{"pve_zfs_arc_max_size_bytes", 17179869184, dto.MetricType_GAUGE},
		{"pve_zfs_arc_hits_total", 12000, dto.MetricType_COUNTER},
		{"pve_zfs_arc_misses_total", 3000, dto.MetricType_COUNTER},
		{"pve_zfs_arc_target_size_bytes", 9663676416, dto.MetricType_GAUGE},
		{"pve_zfs_arc_l2_hits_total", 500, dto.MetricType_COUNTER},
		{"pve_zfs_arc_l2_misses_total", 250, dto.MetricType_COUNTER},
		{"pve_zfs_arc_l2_size_bytes", 2147483648, dto.MetricType_GAUGE},
		{"pve_zfs_arc_l2_header_size_bytes", 41943040, dto.MetricType_GAUGE},
		// hits / (hits + misses) * 100 = 12000 / 15000 * 100 = 80
		{"pve_zfs_arc_hit_ratio_percent", 80, dto.MetricType_GAUGE},
	}
	for _, ck := range checks {
		got := findSeries(t, series, ck.name, node)
		if got.value != ck.value || got.typ != ck.typ {
			t.Errorf("%s = %v (%v), want %v (%v)", ck.name, got.value, got.typ, ck.value, ck.typ)
		}
	}
	// Unrecognised kstat rows are ignored.
	if n := countFamily(series, "pve_zfs_arc_size_bytes"); n != 1 {
		t.Errorf("arc size series = %d, want 1", n)
	}
}

func TestZFSARCMissingFileEmitsNothing(t *testing.T) {
	overrideString(t, &arcStatsPath, filepath.Join(t.TempDir(), "absent"))
	c := newLocalCollector(t)
	metrics := collectMetrics(func(ch chan<- prometheus.Metric) { c.collectZFSARCMetrics(ch) })
	if len(metrics) != 0 {
		t.Fatalf("missing arcstats emitted %d metrics", len(metrics))
	}
}

func TestZFSARCNoAccessesOmitsHitRatio(t *testing.T) {
	overrideString(t, &arcStatsPath, writeTestFile(t, "arcstats", "hits 4 0\nmisses 4 0\nsize 4 1024\n"))
	c := newLocalCollector(t)
	series := readSeries(t, collectMetrics(func(ch chan<- prometheus.Metric) { c.collectZFSARCMetrics(ch) }))
	if countFamily(series, "pve_zfs_arc_hit_ratio_percent") != 0 {
		t.Fatal("hit ratio must be omitted when there were no accesses, not reported as 0")
	}
}
