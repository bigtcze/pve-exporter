package collector

import (
	"encoding/json"
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

func (c *ProxmoxCollector) collectNodeMetricsWithNodes(ch chan<- prometheus.Metric, data []byte) {
	var result nodesListResponse
	if err := json.Unmarshal(data, &result); err != nil {
		c.logger.Error("failed to unmarshal nodes data", "error", err)
		return
	}

	var wg sync.WaitGroup
	for _, node := range result.Data {
		up := 0.0
		if node.Status == "online" {
			up = 1.0
		}

		ch <- prometheus.MustNewConstMetric(c.nodeUp, prometheus.GaugeValue, up, node.Node)
		ch <- prometheus.MustNewConstMetric(c.nodeUptime, prometheus.GaugeValue, node.Uptime, node.Node)
		ch <- prometheus.MustNewConstMetric(c.nodeCPULoad, prometheus.GaugeValue, node.CPU, node.Node)
		ch <- prometheus.MustNewConstMetric(c.nodeCPUs, prometheus.GaugeValue, node.MaxCPU, node.Node)
		ch <- prometheus.MustNewConstMetric(c.nodeMemoryTotal, prometheus.GaugeValue, node.MaxMem, node.Node)
		ch <- prometheus.MustNewConstMetric(c.nodeMemoryUsed, prometheus.GaugeValue, node.Mem, node.Node)
		ch <- prometheus.MustNewConstMetric(c.nodeMemoryFree, prometheus.GaugeValue, node.MaxMem-node.Mem, node.Node)

		wg.Add(1)
		go func(nodeName string) {
			defer wg.Done()
			c.collectNodeDetailedMetrics(ch, nodeName)
		}(node.Node)
	}
	wg.Wait()
}

func (c *ProxmoxCollector) collectNodeDetailedMetrics(ch chan<- prometheus.Metric, nodeName string) {
	result, err := fetchJSON[nodeStatusResponse](c, apiPathf("/nodes/%s/status", nodeName))
	if err != nil {
		c.logger.Error("failed to fetch node status", "node", nodeName, "error", err)
		return
	}

	d := result.Data

	if len(d.LoadAvg) >= 3 {
		if load1, err := strconv.ParseFloat(d.LoadAvg[0], 64); err == nil {
			ch <- prometheus.MustNewConstMetric(c.nodeLoad1, prometheus.GaugeValue, load1, nodeName)
		}
		if load5, err := strconv.ParseFloat(d.LoadAvg[1], 64); err == nil {
			ch <- prometheus.MustNewConstMetric(c.nodeLoad5, prometheus.GaugeValue, load5, nodeName)
		}
		if load15, err := strconv.ParseFloat(d.LoadAvg[2], 64); err == nil {
			ch <- prometheus.MustNewConstMetric(c.nodeLoad15, prometheus.GaugeValue, load15, nodeName)
		}
	}

	ch <- prometheus.MustNewConstMetric(c.nodeIOWait, prometheus.GaugeValue, d.Wait, nodeName)
	ch <- prometheus.MustNewConstMetric(c.nodeIdle, prometheus.GaugeValue, d.Idle, nodeName)

	if mhz, err := strconv.ParseFloat(d.CPUInfo.Mhz, 64); err == nil {
		ch <- prometheus.MustNewConstMetric(c.nodeCPUMhz, prometheus.GaugeValue, mhz, nodeName)
	}

	ch <- prometheus.MustNewConstMetric(c.nodeRootfsTotal, prometheus.GaugeValue, d.Rootfs.Total, nodeName)
	ch <- prometheus.MustNewConstMetric(c.nodeRootfsUsed, prometheus.GaugeValue, d.Rootfs.Used, nodeName)
	ch <- prometheus.MustNewConstMetric(c.nodeRootfsFree, prometheus.GaugeValue, d.Rootfs.Free, nodeName)
	ch <- prometheus.MustNewConstMetric(c.nodeCPUCores, prometheus.GaugeValue, d.CPUInfo.Cores, nodeName)
	ch <- prometheus.MustNewConstMetric(c.nodeCPUSockets, prometheus.GaugeValue, d.CPUInfo.Sockets, nodeName)
	ch <- prometheus.MustNewConstMetric(c.nodeKSMShared, prometheus.GaugeValue, d.KSM.Shared, nodeName)
	ch <- prometheus.MustNewConstMetric(c.nodeSwapTotal, prometheus.GaugeValue, d.Swap.Total, nodeName)
	ch <- prometheus.MustNewConstMetric(c.nodeSwapUsed, prometheus.GaugeValue, d.Swap.Used, nodeName)
	ch <- prometheus.MustNewConstMetric(c.nodeSwapFree, prometheus.GaugeValue, d.Swap.Free, nodeName)
}
