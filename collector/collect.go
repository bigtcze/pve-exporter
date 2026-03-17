package collector

import (
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func (c *ProxmoxCollector) Collect(ch chan<- prometheus.Metric) {
	scrapeStart := time.Now()

	ch <- prometheus.MustNewConstMetric(c.exporterBuildInfo, prometheus.GaugeValue, 1,
		version, commit, runtime.Version())

	if err := c.authenticate(); err != nil {
		c.logger.Error("failed to authenticate", "error", err)
		ch <- prometheus.MustNewConstMetric(c.exporterUp, prometheus.GaugeValue, 0)
		ch <- prometheus.MustNewConstMetric(c.exporterScrapeDuration, prometheus.GaugeValue, time.Since(scrapeStart).Seconds())
		return
	}

	nodesData, err := c.apiRequest("/nodes")
	if err != nil {
		c.logger.Error("failed to fetch nodes", "error", err)
		ch <- prometheus.MustNewConstMetric(c.exporterUp, prometheus.GaugeValue, 0)
		ch <- prometheus.MustNewConstMetric(c.exporterScrapeDuration, prometheus.GaugeValue, time.Since(scrapeStart).Seconds())
		return
	}

	ch <- prometheus.MustNewConstMetric(c.exporterUp, prometheus.GaugeValue, 1)

	var nodesResult nodesOnlyResponse
	if err := unmarshalJSON(nodesData, &nodesResult); err != nil {
		c.logger.Error("failed to unmarshal nodes", "error", err)
		return
	}

	nodes := make([]string, len(nodesResult.Data))
	for i, n := range nodesResult.Data {
		nodes[i] = n.Node
	}

	guests := make(map[string]GuestInfo)
	resourcesResult, err := fetchJSON[clusterResourcesResponse](c, "/cluster/resources?type=vm")
	if err == nil {
		for _, res := range resourcesResult.Data {
			vmid := strconv.FormatInt(res.VMID, 10)
			guests[vmid] = GuestInfo{Node: res.Node, Name: res.Name, Type: res.Type}
		}
	}

	var wg sync.WaitGroup

	wg.Add(10)

	go func() {
		defer wg.Done()
		c.collectNodeMetricsWithNodes(ch, nodesData)
	}()

	go func() {
		defer wg.Done()
		c.collectVMMetricsWithNodes(ch, nodes)
	}()

	go func() {
		defer wg.Done()
		c.collectStorageMetrics(ch, nodes)
	}()

	go func() {
		defer wg.Done()
		c.collectZFSMetricsWithNodes(ch, nodes)
	}()

	go func() {
		defer wg.Done()
		c.collectSensorsMetrics(ch)
	}()

	go func() {
		defer wg.Done()
		c.collectDiskMetrics(ch)
	}()

	go func() {
		defer wg.Done()
		c.collectBackupMetricsWithGuests(ch, nodes, guests)
	}()

	go func() {
		defer wg.Done()
		c.collectClusterMetrics(ch)
	}()

	go func() {
		defer wg.Done()
		c.collectReplicationMetrics(ch)
	}()

	go func() {
		defer wg.Done()
		c.collectCertificateMetrics(ch, nodes)
	}()

	wg.Wait()

	ch <- prometheus.MustNewConstMetric(c.exporterScrapeDuration, prometheus.GaugeValue, time.Since(scrapeStart).Seconds())
}
