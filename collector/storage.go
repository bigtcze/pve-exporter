package collector

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

func (c *ProxmoxCollector) collectStorageMetrics(ch chan<- prometheus.Metric, nodes []string) {
	var wg sync.WaitGroup
	for _, node := range nodes {
		wg.Add(1)
		go func(nodeName string) {
			defer wg.Done()

			result, err := fetchJSON[storageResponse](c, apiPathf("/nodes/%s/storage", nodeName))
			if err != nil {
				c.logger.Error("failed to fetch storage", "node", nodeName, "error", err)
				return
			}

			for _, storage := range result.Data {
				labels := []string{nodeName, storage.Storage, storage.Type}
				ch <- prometheus.MustNewConstMetric(c.storageTotal, prometheus.GaugeValue, storage.Total, labels...)
				ch <- prometheus.MustNewConstMetric(c.storageUsed, prometheus.GaugeValue, storage.Used, labels...)
				ch <- prometheus.MustNewConstMetric(c.storageAvail, prometheus.GaugeValue, storage.Avail, labels...)
				ch <- prometheus.MustNewConstMetric(c.storageActive, prometheus.GaugeValue, float64(storage.Active), labels...)
				ch <- prometheus.MustNewConstMetric(c.storageEnabled, prometheus.GaugeValue, float64(storage.Enabled), labels...)
				ch <- prometheus.MustNewConstMetric(c.storageShared, prometheus.GaugeValue, float64(storage.Shared), labels...)
				ch <- prometheus.MustNewConstMetric(c.storageUsedFraction, prometheus.GaugeValue, storage.UsedFraction, labels...)
			}
		}(node)
	}
	wg.Wait()
}
