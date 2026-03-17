package collector

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

func (c *ProxmoxCollector) collectVMMetricsWithNodes(ch chan<- prometheus.Metric, nodes []string) {
	var wg sync.WaitGroup
	for _, node := range nodes {
		wg.Add(1)
		go func(nodeName string) {
			defer wg.Done()
			vmCount := c.collectResourceMetrics(ch, nodeName, "qemu")
			ch <- prometheus.MustNewConstMetric(c.nodeVMCount, prometheus.GaugeValue, float64(vmCount), nodeName)

			lxcCount := c.collectResourceMetrics(ch, nodeName, "lxc")
			ch <- prometheus.MustNewConstMetric(c.nodeLXCCount, prometheus.GaugeValue, float64(lxcCount), nodeName)
		}(node)
	}
	wg.Wait()
}

func (c *ProxmoxCollector) collectResourceMetrics(ch chan<- prometheus.Metric, node, resType string) int {
	result, err := fetchJSON[resourceListResponse](c, apiPathf("/nodes/%s/%s", node, resType))
	if err != nil {
		c.logger.Error("failed to fetch resources", "type", resType, "node", node, "error", err)
		return 0
	}

	var wg sync.WaitGroup
	for _, vm := range result.Data {
		wg.Add(1)
		go func(vm resourceEntry) {
			defer wg.Done()

			status := 0.0
			if vm.Status == "running" {
				status = 1.0
			}

			labels := []string{node, fmt.Sprintf("%d", vm.VMID), vm.Name}

			diskRead := vm.DiskRead
			diskWrite := vm.DiskWrite
			var detailData []byte
			if vm.Status == "running" {
				detailPath := apiPathf("/nodes/%s/%s/%d/status/current", node, resType, vm.VMID)
				detailData, err = c.apiRequest(detailPath)
				if err == nil {
					var detailResult vmDetailResponse
					if json.Unmarshal(detailData, &detailResult) == nil {
						diskRead = detailResult.Data.DiskRead
						diskWrite = detailResult.Data.DiskWrite
					}
				}
			}

			if resType == "lxc" {
				ch <- prometheus.MustNewConstMetric(c.lxcStatus, prometheus.GaugeValue, status, labels...)
				ch <- prometheus.MustNewConstMetric(c.lxcUptime, prometheus.GaugeValue, vm.Uptime, labels...)
				ch <- prometheus.MustNewConstMetric(c.lxcCPU, prometheus.GaugeValue, vm.CPU, labels...)
				ch <- prometheus.MustNewConstMetric(c.lxcCPUs, prometheus.GaugeValue, vm.CPUs, labels...)
				ch <- prometheus.MustNewConstMetric(c.lxcMemory, prometheus.GaugeValue, vm.Mem, labels...)
				ch <- prometheus.MustNewConstMetric(c.lxcMaxMemory, prometheus.GaugeValue, vm.MaxMem, labels...)
				ch <- prometheus.MustNewConstMetric(c.lxcDisk, prometheus.GaugeValue, vm.Disk, labels...)
				ch <- prometheus.MustNewConstMetric(c.lxcMaxDisk, prometheus.GaugeValue, vm.MaxDisk, labels...)
				ch <- prometheus.MustNewConstMetric(c.lxcNetIn, prometheus.CounterValue, vm.NetIn, labels...)
				ch <- prometheus.MustNewConstMetric(c.lxcNetOut, prometheus.CounterValue, vm.NetOut, labels...)
				ch <- prometheus.MustNewConstMetric(c.lxcDiskRead, prometheus.CounterValue, diskRead, labels...)
				ch <- prometheus.MustNewConstMetric(c.lxcDiskWrite, prometheus.CounterValue, diskWrite, labels...)
				c.collectLXCSwapMetricsFromData(ch, detailData, labels)
			} else {
				ch <- prometheus.MustNewConstMetric(c.vmStatus, prometheus.GaugeValue, status, labels...)
				ch <- prometheus.MustNewConstMetric(c.vmUptime, prometheus.GaugeValue, vm.Uptime, labels...)
				ch <- prometheus.MustNewConstMetric(c.vmCPU, prometheus.GaugeValue, vm.CPU, labels...)
				ch <- prometheus.MustNewConstMetric(c.vmCPUs, prometheus.GaugeValue, vm.CPUs, labels...)
				ch <- prometheus.MustNewConstMetric(c.vmMemory, prometheus.GaugeValue, vm.Mem, labels...)
				ch <- prometheus.MustNewConstMetric(c.vmMaxMemory, prometheus.GaugeValue, vm.MaxMem, labels...)
				ch <- prometheus.MustNewConstMetric(c.vmMaxDisk, prometheus.GaugeValue, vm.MaxDisk, labels...)
				ch <- prometheus.MustNewConstMetric(c.vmNetIn, prometheus.CounterValue, vm.NetIn, labels...)
				ch <- prometheus.MustNewConstMetric(c.vmNetOut, prometheus.CounterValue, vm.NetOut, labels...)
				ch <- prometheus.MustNewConstMetric(c.vmDiskRead, prometheus.CounterValue, diskRead, labels...)
				ch <- prometheus.MustNewConstMetric(c.vmDiskWrite, prometheus.CounterValue, diskWrite, labels...)
				c.collectVMDetailedMetricsFromData(ch, detailData, labels)
			}
		}(vm)
	}

	wg.Wait()
	return len(result.Data)
}

func (c *ProxmoxCollector) collectLXCSwapMetricsFromData(ch chan<- prometheus.Metric, data []byte, labels []string) {
	if data == nil {
		return
	}

	var result lxcDetailResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return
	}

	d := result.Data
	ch <- prometheus.MustNewConstMetric(c.lxcSwap, prometheus.GaugeValue, d.Swap, labels...)
	ch <- prometheus.MustNewConstMetric(c.lxcMaxSwap, prometheus.GaugeValue, d.MaxSwap, labels...)
	ch <- prometheus.MustNewConstMetric(c.lxcHAManaged, prometheus.GaugeValue, float64(d.HA.Managed), labels...)
	ch <- prometheus.MustNewConstMetric(c.lxcPID, prometheus.GaugeValue, d.PID, labels...)

	if cpuFull, err := strconv.ParseFloat(d.PressureCPUFull, 64); err == nil {
		ch <- prometheus.MustNewConstMetric(c.lxcPressureCPUFull, prometheus.GaugeValue, cpuFull, labels...)
	}
	if cpuSome, err := strconv.ParseFloat(d.PressureCPUSome, 64); err == nil {
		ch <- prometheus.MustNewConstMetric(c.lxcPressureCPUSome, prometheus.GaugeValue, cpuSome, labels...)
	}
	if ioFull, err := strconv.ParseFloat(d.PressureIOFull, 64); err == nil {
		ch <- prometheus.MustNewConstMetric(c.lxcPressureIOFull, prometheus.GaugeValue, ioFull, labels...)
	}
	if ioSome, err := strconv.ParseFloat(d.PressureIOSome, 64); err == nil {
		ch <- prometheus.MustNewConstMetric(c.lxcPressureIOSome, prometheus.GaugeValue, ioSome, labels...)
	}
	if memFull, err := strconv.ParseFloat(d.PressureMemoryFull, 64); err == nil {
		ch <- prometheus.MustNewConstMetric(c.lxcPressureMemoryFull, prometheus.GaugeValue, memFull, labels...)
	}
	if memSome, err := strconv.ParseFloat(d.PressureMemorySome, 64); err == nil {
		ch <- prometheus.MustNewConstMetric(c.lxcPressureMemorySome, prometheus.GaugeValue, memSome, labels...)
	}
}

func (c *ProxmoxCollector) collectVMDetailedMetricsFromData(ch chan<- prometheus.Metric, data []byte, labels []string) {
	if data == nil {
		return
	}

	var result vmDetailResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return
	}

	d := result.Data
	ch <- prometheus.MustNewConstMetric(c.vmBalloon, prometheus.GaugeValue, d.Balloon, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmFreeMem, prometheus.GaugeValue, d.FreeMem, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmHAManaged, prometheus.GaugeValue, float64(d.HA.Managed), labels...)
	ch <- prometheus.MustNewConstMetric(c.vmPID, prometheus.GaugeValue, d.PID, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmMemHost, prometheus.GaugeValue, d.MemHost, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmPressureCPUFull, prometheus.GaugeValue, d.PressureCPUFull, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmPressureCPUSome, prometheus.GaugeValue, d.PressureCPUSome, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmPressureIOFull, prometheus.GaugeValue, d.PressureIOFull, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmPressureIOSome, prometheus.GaugeValue, d.PressureIOSome, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmPressureMemoryFull, prometheus.GaugeValue, d.PressureMemoryFull, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmPressureMemorySome, prometheus.GaugeValue, d.PressureMemorySome, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmBalloonActual, prometheus.GaugeValue, d.BalloonInfo.Actual, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmBalloonMaxMem, prometheus.GaugeValue, d.BalloonInfo.MaxMem, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmBalloonTotalMem, prometheus.GaugeValue, d.BalloonInfo.TotalMem, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmBalloonMajorFaults, prometheus.CounterValue, d.BalloonInfo.MajorPageFaults, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmBalloonMinorFaults, prometheus.CounterValue, d.BalloonInfo.MinorPageFaults, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmBalloonMemSwappedIn, prometheus.GaugeValue, d.BalloonInfo.MemSwappedIn, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmBalloonMemSwappedOut, prometheus.GaugeValue, d.BalloonInfo.MemSwappedOut, labels...)

	for device, stats := range d.BlockStat {
		deviceLabels := append(labels, device)
		ch <- prometheus.MustNewConstMetric(c.vmBlockReadBytes, prometheus.CounterValue, stats.RdBytes, deviceLabels...)
		ch <- prometheus.MustNewConstMetric(c.vmBlockWriteBytes, prometheus.CounterValue, stats.WrBytes, deviceLabels...)
		ch <- prometheus.MustNewConstMetric(c.vmBlockReadOps, prometheus.CounterValue, stats.RdOps, deviceLabels...)
		ch <- prometheus.MustNewConstMetric(c.vmBlockWriteOps, prometheus.CounterValue, stats.WrOps, deviceLabels...)
		ch <- prometheus.MustNewConstMetric(c.vmBlockFailedRead, prometheus.CounterValue, stats.FailedRdOps, deviceLabels...)
		ch <- prometheus.MustNewConstMetric(c.vmBlockFailedWrite, prometheus.CounterValue, stats.FailedWrOps, deviceLabels...)
		ch <- prometheus.MustNewConstMetric(c.vmBlockFlushOps, prometheus.CounterValue, stats.FlushOps, deviceLabels...)
	}

	for iface, stats := range d.NICS {
		nicLabels := append(labels, iface)
		ch <- prometheus.MustNewConstMetric(c.vmNICNetIn, prometheus.CounterValue, stats.NetIn, nicLabels...)
		ch <- prometheus.MustNewConstMetric(c.vmNICNetOut, prometheus.CounterValue, stats.NetOut, nicLabels...)
	}
}
