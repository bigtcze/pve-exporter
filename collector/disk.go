package collector

import (
	"bufio"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// Default path for SMART data JSON file
	smartDataPath = "/var/lib/pve-exporter/smart.json"
	// Maximum age of SMART data file before considering it stale (10 minutes = 2x cron interval)
	smartDataMaxAge = 10 * time.Minute
	// Path to diskstats
	diskstatsPath = "/proc/diskstats"
	// Sector size in bytes (standard Linux sector size)
	sectorSizeBytes = 512
	// Milliseconds per second
	msPerSecond = 1000
)

// SmartData represents the JSON structure from pve-smart-collector.sh
type SmartData struct {
	Hostname  string     `json:"hostname"`
	Timestamp int64      `json:"timestamp"`
	Disks     []DiskInfo `json:"disks"`
}

// DiskInfo represents a single disk's SMART data
type DiskInfo struct {
	Device                string  `json:"device"`
	Model                 string  `json:"model"`
	Serial                string  `json:"serial"`
	Type                  string  `json:"type"`
	Healthy               int     `json:"healthy"`
	Temperature           float64 `json:"temperature,omitempty"`
	PowerOnHours          float64 `json:"power_on_hours,omitempty"`
	DataWrittenBytes      float64 `json:"data_written_bytes,omitempty"`
	AvailableSparePercent float64 `json:"available_spare_percent,omitempty"`
	PercentageUsed        float64 `json:"percentage_used,omitempty"`
}

// collectDiskMetrics reads SMART data from JSON file and disk I/O from /proc/diskstats
func (c *ProxmoxCollector) collectDiskMetrics(ch chan<- prometheus.Metric) {
	hostname := getHostname()

	// Collect SMART metrics from JSON file (if available)
	c.collectSmartMetrics(ch)

	// Collect disk I/O metrics from /proc/diskstats (always available, no root needed)
	c.collectDiskIOMetrics(ch, hostname)
}

// collectSmartMetrics reads SMART data from JSON file
func (c *ProxmoxCollector) collectSmartMetrics(ch chan<- prometheus.Metric) {
	// Check if file exists
	info, err := os.Stat(smartDataPath)
	if os.IsNotExist(err) {
		// File doesn't exist - SMART collector not configured, skip silently
		return
	}
	if err != nil {
		c.logger.Error("failed to check SMART data file", "error", err)
		return
	}

	// Check if file is too old
	if time.Since(info.ModTime()) > smartDataMaxAge {
		c.logger.Warn("SMART data file is stale, skipping", "max_age", smartDataMaxAge)
		return
	}

	// Read file
	data, err := os.ReadFile(smartDataPath)
	if err != nil {
		c.logger.Error("failed to read SMART data file", "error", err)
		return
	}

	// Parse JSON
	var smartData SmartData
	if err := json.Unmarshal(data, &smartData); err != nil {
		c.logger.Error("failed to parse SMART data JSON", "error", err)
		return
	}

	// Export metrics for each disk
	for _, disk := range smartData.Disks {
		labels := []string{smartData.Hostname, disk.Device, disk.Model, disk.Serial, disk.Type}

		// Health status (always present)
		ch <- prometheus.MustNewConstMetric(c.diskHealth, prometheus.GaugeValue, float64(disk.Healthy), labels...)

		// Temperature (if available)
		if disk.Temperature > 0 {
			ch <- prometheus.MustNewConstMetric(c.diskTemperature, prometheus.GaugeValue, disk.Temperature, labels...)
		}

		// Power on hours (if available)
		if disk.PowerOnHours > 0 {
			ch <- prometheus.MustNewConstMetric(c.diskPowerOnHours, prometheus.GaugeValue, disk.PowerOnHours, labels...)
		}

		// NVMe specific metrics
		if disk.DataWrittenBytes > 0 {
			ch <- prometheus.MustNewConstMetric(c.diskDataWritten, prometheus.CounterValue, disk.DataWrittenBytes, labels...)
		}

		if disk.AvailableSparePercent > 0 {
			ch <- prometheus.MustNewConstMetric(c.diskAvailableSpare, prometheus.GaugeValue, disk.AvailableSparePercent, labels...)
		}

		if disk.PercentageUsed >= 0 && disk.Type == "nvme" {
			ch <- prometheus.MustNewConstMetric(c.diskPercentageUsed, prometheus.GaugeValue, disk.PercentageUsed, labels...)
		}
	}
}

// collectDiskIOMetrics reads disk I/O stats from /proc/diskstats
func (c *ProxmoxCollector) collectDiskIOMetrics(ch chan<- prometheus.Metric, hostname string) {
	file, err := os.Open(diskstatsPath)
	if err != nil {
		// /proc/diskstats not available (e.g., not Linux)
		return
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 14 {
			continue
		}

		device := fields[2]

		// Skip partitions (only whole disks) - partitions have numbers at the end after letters
		// e.g., sda1, nvme0n1p1 are partitions; sda, nvme0n1 are disks
		if isPartition(device) {
			continue
		}

		// Skip virtual devices
		if strings.HasPrefix(device, "loop") || strings.HasPrefix(device, "ram") ||
			strings.HasPrefix(device, "zd") || strings.HasPrefix(device, "dm-") {
			continue
		}

		// Parse diskstats fields (Linux kernel documentation)
		// Field 1: reads completed successfully
		// Field 2: reads merged
		// Field 3: sectors read
		// Field 4: time spent reading (ms)
		// Field 5: writes completed successfully
		// Field 6: writes merged
		// Field 7: sectors written
		// Field 8: time spent writing (ms)
		// Field 9: I/Os currently in progress
		// Field 10: time spent doing I/Os (ms)
		// Field 11: weighted time spent doing I/Os (ms)

		readsCompleted, _ := strconv.ParseFloat(fields[3], 64)
		sectorsRead, _ := strconv.ParseFloat(fields[5], 64)
		writesCompleted, _ := strconv.ParseFloat(fields[7], 64)
		sectorsWritten, _ := strconv.ParseFloat(fields[9], 64)
		ioTimeMs, _ := strconv.ParseFloat(fields[12], 64)

	// Each sector is 512 bytes
	readBytes := sectorsRead * sectorSizeBytes
	writeBytes := sectorsWritten * sectorSizeBytes
	ioTimeSeconds := ioTimeMs / msPerSecond

		labels := []string{hostname, device}

		ch <- prometheus.MustNewConstMetric(c.diskReadBytes, prometheus.CounterValue, readBytes, labels...)
		ch <- prometheus.MustNewConstMetric(c.diskWriteBytes, prometheus.CounterValue, writeBytes, labels...)
		ch <- prometheus.MustNewConstMetric(c.diskReadsCompleted, prometheus.CounterValue, readsCompleted, labels...)
		ch <- prometheus.MustNewConstMetric(c.diskWritesCompleted, prometheus.CounterValue, writesCompleted, labels...)
		ch <- prometheus.MustNewConstMetric(c.diskIOTime, prometheus.CounterValue, ioTimeSeconds, labels...)
	}
}

// isPartition checks if a device name is a partition
func isPartition(device string) bool {
	// NVMe partitions: nvme0n1p1, nvme0n1p2, etc.
	if strings.Contains(device, "nvme") && strings.Contains(device, "p") {
		parts := strings.Split(device, "p")
		if len(parts) >= 2 {
			// Check if the last part is a number
			_, err := strconv.Atoi(parts[len(parts)-1])
			return err == nil
		}
	}

	// SATA/SCSI partitions: sda1, sdb2, etc.
	if len(device) > 0 {
		lastChar := device[len(device)-1]
		if lastChar >= '0' && lastChar <= '9' {
			// Check if not nvme (handled above)
			if !strings.HasPrefix(device, "nvme") {
				return true
			}
		}
	}

	return false
}
