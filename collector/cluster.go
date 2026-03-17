package collector

import (
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func (c *ProxmoxCollector) collectClusterMetrics(ch chan<- prometheus.Metric) {
	result, err := fetchJSON[clusterStatusResponse](c, "/cluster/status")
	if err != nil {
		c.logger.Error("failed to fetch cluster status", "error", err)
		return
	}

	var nodesTotal, nodesOnline int
	var hasClusterEntry bool
	for _, item := range result.Data {
		switch item.Type {
		case "cluster":
			ch <- prometheus.MustNewConstMetric(c.clusterQuorate, prometheus.GaugeValue, float64(item.Quorate))
			nodesTotal = item.Nodes
			hasClusterEntry = true
		case "node":
			if nodesTotal == 0 {
				nodesTotal++
			}
			if item.Online == 1 {
				nodesOnline++
			}
		}
	}

	if !hasClusterEntry {
		ch <- prometheus.MustNewConstMetric(c.clusterQuorate, prometheus.GaugeValue, 1)
	}

	ch <- prometheus.MustNewConstMetric(c.clusterNodesTotal, prometheus.GaugeValue, float64(nodesTotal))
	ch <- prometheus.MustNewConstMetric(c.clusterNodesOnline, prometheus.GaugeValue, float64(nodesOnline))

	haResult, err := fetchJSON[haResourcesResponse](c, "/cluster/ha/resources")
	if err != nil {
		ch <- prometheus.MustNewConstMetric(c.haResourcesTotal, prometheus.GaugeValue, 0)
		ch <- prometheus.MustNewConstMetric(c.haResourcesActive, prometheus.GaugeValue, 0)
		return
	}

	var haTotal, haActive int
	for _, res := range haResult.Data {
		haTotal++
		if res.State == "started" {
			haActive++
		}
	}

	ch <- prometheus.MustNewConstMetric(c.haResourcesTotal, prometheus.GaugeValue, float64(haTotal))
	ch <- prometheus.MustNewConstMetric(c.haResourcesActive, prometheus.GaugeValue, float64(haActive))
}

func (c *ProxmoxCollector) collectReplicationMetrics(ch chan<- prometheus.Metric) {
	result, err := fetchJSON[replicationResponse](c, "/cluster/replication")
	if err != nil {
		return
	}

	for _, job := range result.Data {
		guest := strconv.FormatInt(job.Guest, 10)
		jobID := job.ID

		if job.LastSync > 0 {
			ch <- prometheus.MustNewConstMetric(c.replicationLastSync, prometheus.GaugeValue, float64(job.LastSync), guest, jobID)
		}

		ch <- prometheus.MustNewConstMetric(c.replicationDuration, prometheus.GaugeValue, job.Duration, guest, jobID)

		status := 1.0
		if job.FailCount > 0 || job.Error != "" {
			status = 0
		}
		ch <- prometheus.MustNewConstMetric(c.replicationStatus, prometheus.GaugeValue, status, guest, jobID)
	}
}

func (c *ProxmoxCollector) collectCertificateMetrics(ch chan<- prometheus.Metric, nodes []string) {
	var wg sync.WaitGroup
	for _, node := range nodes {
		wg.Add(1)
		go func(nodeName string) {
			defer wg.Done()

			result, err := fetchJSON[certificatesResponse](c, apiPathf("/nodes/%s/certificates/info", nodeName))
			if err != nil {
				c.logger.Error("failed to fetch certificates", "node", nodeName, "error", err)
				return
			}

			now := time.Now().Unix()
			for _, cert := range result.Data {
				if cert.Filename == "pveproxy-ssl.pem" || cert.Filename == "pve-ssl.pem" {
					expirySeconds := float64(cert.NotAfter - now)
					ch <- prometheus.MustNewConstMetric(c.certificateExpiry, prometheus.GaugeValue, expirySeconds, nodeName)
					return
				}
			}

			if len(result.Data) > 0 {
				expirySeconds := float64(result.Data[0].NotAfter - now)
				ch <- prometheus.MustNewConstMetric(c.certificateExpiry, prometheus.GaugeValue, expirySeconds, nodeName)
			}
		}(node)
	}
	wg.Wait()
}
