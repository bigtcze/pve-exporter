package collector

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	percentMultiplier = 100
)

// collectZFSMetricsWithNodes collects ZFS metrics using pre-fetched nodes list
func (c *ProxmoxCollector) collectZFSMetricsWithNodes(ch chan<- prometheus.Metric, nodes []string) {
	c.collectZFSPoolMetricsWithNodes(ch, nodes)
	c.collectZFSARCMetrics(ch)
}

// collectZFSPoolMetricsWithNodes collects ZFS pool metrics using pre-fetched nodes list
func (c *ProxmoxCollector) collectZFSPoolMetricsWithNodes(ch chan<- prometheus.Metric, nodes []string) {
	var wg sync.WaitGroup
	for _, node := range nodes {
		wg.Add(1)
		go func(nodeName string) {
			defer wg.Done()

			result, err := fetchJSON[zfsPoolResponse](c, apiPathf("/nodes/%s/disks/zfs", nodeName))
			if err != nil {
				return
			}

			for _, pool := range result.Data {
				health := 0.0
				if pool.Health == "ONLINE" {
					health = 1.0
				}

				ch <- prometheus.MustNewConstMetric(c.zfsPoolHealth, prometheus.GaugeValue, health, nodeName, pool.Name)
				ch <- prometheus.MustNewConstMetric(c.zfsPoolSize, prometheus.GaugeValue, pool.Size, nodeName, pool.Name)
				ch <- prometheus.MustNewConstMetric(c.zfsPoolAlloc, prometheus.GaugeValue, pool.Alloc, nodeName, pool.Name)
				ch <- prometheus.MustNewConstMetric(c.zfsPoolFree, prometheus.GaugeValue, pool.Free, nodeName, pool.Name)
				ch <- prometheus.MustNewConstMetric(c.zfsPoolFrag, prometheus.GaugeValue, pool.Frag, nodeName, pool.Name)
			}
		}(node)
	}
	wg.Wait()
}

// arcMetricHandler defines how to handle a specific ARC metric
type arcMetricHandler struct {
	metric      *prometheus.Desc
	valueType   prometheus.ValueType
	trackHits   bool // if true, also store value in hits variable
	trackMisses bool // if true, also store value in misses variable
}

// collectZFSARCMetrics collects ZFS ARC metrics from /proc/spl/kstat/zfs/arcstats
func (c *ProxmoxCollector) collectZFSARCMetrics(ch chan<- prometheus.Metric) {
	file, err := os.Open("/proc/spl/kstat/zfs/arcstats")
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	hostname := getHostname()

	// Map metric names to their handlers
	handlers := map[string]arcMetricHandler{
		"size":        {c.zfsARCSize, prometheus.GaugeValue, false, false},
		"c_min":       {c.zfsARCMinSize, prometheus.GaugeValue, false, false},
		"c_max":       {c.zfsARCMaxSize, prometheus.GaugeValue, false, false},
		"hits":        {c.zfsARCHits, prometheus.CounterValue, true, false},
		"misses":      {c.zfsARCMisses, prometheus.CounterValue, false, true},
		"c":           {c.zfsARCTargetSize, prometheus.GaugeValue, false, false},
		"l2_hits":     {c.zfsARCL2Hits, prometheus.CounterValue, false, false},
		"l2_misses":   {c.zfsARCL2Misses, prometheus.CounterValue, false, false},
		"l2_size":     {c.zfsARCL2Size, prometheus.GaugeValue, false, false},
		"l2_hdr_size": {c.zfsARCL2HeaderSize, prometheus.GaugeValue, false, false},
	}

	var hits, misses float64

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		name := fields[0]
		value, err := strconv.ParseFloat(fields[2], 64)
		if err != nil {
			continue
		}

		if handler, ok := handlers[name]; ok {
			ch <- prometheus.MustNewConstMetric(handler.metric, handler.valueType, value, hostname)
			if handler.trackHits {
				hits = value
			}
			if handler.trackMisses {
				misses = value
			}
		}
	}

	// Calculate and emit hit ratio percent
	total := hits + misses
	if total > 0 {
		hitRatioPercent := (hits / total) * percentMultiplier
		ch <- prometheus.MustNewConstMetric(c.zfsARCHitRatio, prometheus.GaugeValue, hitRatioPercent, hostname)
	}
}
