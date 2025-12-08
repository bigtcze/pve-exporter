package collector

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// collectDiskMetrics collects disk SMART metrics using smartctl
func (c *ProxmoxCollector) collectDiskMetrics(ch chan<- prometheus.Metric) {
	hostname := getHostname()

	// Discover physical disks using lsblk
	disks := discoverDisks()
	if len(disks) == 0 {
		return
	}

	// Collect SMART data in parallel for all disks
	var wg sync.WaitGroup
	for _, disk := range disks {
		wg.Add(1)
		go func(diskName string) {
			defer wg.Done()
			c.collectDiskSMART(ch, hostname, diskName)
		}(disk)
	}
	wg.Wait()
}

// discoverDisks returns a list of physical disk device names (e.g., sda, nvme0n1)
func discoverDisks() []string {
	cmd := exec.Command("lsblk", "-d", "-n", "-o", "NAME,TYPE")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var disks []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		name, diskType := fields[0], fields[1]
		// Only include disk type, exclude loop, zd (zvol), rom, etc.
		if diskType == "disk" && !strings.HasPrefix(name, "zd") && !strings.HasPrefix(name, "loop") {
			disks = append(disks, name)
		}
	}
	return disks
}

// collectDiskSMART collects SMART data for a single disk
func (c *ProxmoxCollector) collectDiskSMART(ch chan<- prometheus.Metric, hostname, diskName string) {
	devicePath := "/dev/" + diskName

	// Run smartctl with JSON output
	// Use sudo -n (non-interactive) because smartctl requires root access
	// Use full paths to avoid PATH issues in systemd services
	// Requires: echo "Defaults:pve-exporter !syslog" > /etc/sudoers.d/pve-exporter
	//           echo "pve-exporter ALL=(root) NOPASSWD: /usr/sbin/smartctl" >> /etc/sudoers.d/pve-exporter
	cmd := exec.Command("/usr/bin/sudo", "-n", "/usr/sbin/smartctl", "-j", "-a", devicePath)

	// Capture stdout - smartctl returns non-zero exit codes for various
	// conditions but still outputs valid JSON
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Run() // Ignore error - we check output instead

	output := stdout.Bytes()
	if len(output) == 0 {
		return
	}

	var smartData map[string]interface{}
	if err := json.Unmarshal(output, &smartData); err != nil {
		log.Printf("Error parsing smartctl JSON for %s: %v", diskName, err)
		return
	}

	// Check if SMART status is available - virtual disks won't have this
	smartStatus, hasSmartStatus := smartData["smart_status"].(map[string]interface{})
	if !hasSmartStatus {
		// No SMART status = virtual disk or unsupported, skip silently
		return
	}

	// Determine disk type (nvme or sat/ata)
	diskType := "unknown"
	if device, ok := smartData["device"].(map[string]interface{}); ok {
		if dt, ok := device["type"].(string); ok {
			diskType = dt
		}
		// Also check protocol for more accurate detection
		if proto, ok := device["protocol"].(string); ok {
			if proto == "NVMe" {
				diskType = "nvme"
			} else if proto == "ATA" {
				diskType = "sata"
			}
		}
	}

	// Get model - try multiple field names
	model := getStringField(smartData, "model_name")
	if model == "" {
		model = getStringField(smartData, "model_family")
	}

	// Get serial
	serial := getStringField(smartData, "serial_number")

	labels := []string{hostname, diskName, model, serial, diskType}

	// Get health status (we verified smart_status exists above)
	health := 0.0
	if passed, ok := smartStatus["passed"].(bool); ok && passed {
		health = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.diskHealth, prometheus.GaugeValue, health, labels...)

	// Parse based on device type
	if diskType == "nvme" {
		c.parseNVMeMetrics(ch, smartData, labels)
	} else {
		c.parseATAMetrics(ch, smartData, labels)
	}
}

// parseNVMeMetrics extracts metrics from NVMe SMART data
func (c *ProxmoxCollector) parseNVMeMetrics(ch chan<- prometheus.Metric, data map[string]interface{}, labels []string) {
	nvmeLog, ok := data["nvme_smart_health_information_log"].(map[string]interface{})
	if !ok {
		return
	}

	// Temperature
	if temp, ok := nvmeLog["temperature"].(float64); ok {
		ch <- prometheus.MustNewConstMetric(c.diskTemperature, prometheus.GaugeValue, temp, labels...)
	}

	// Power on hours
	if hours, ok := nvmeLog["power_on_hours"].(float64); ok {
		ch <- prometheus.MustNewConstMetric(c.diskPowerOnHours, prometheus.GaugeValue, hours, labels...)
	}

	// Data units written (1 unit = 512 * 1000 bytes = 512KB)
	if unitsWritten, ok := nvmeLog["data_units_written"].(float64); ok {
		bytesWritten := unitsWritten * 512 * 1000
		ch <- prometheus.MustNewConstMetric(c.diskDataWritten, prometheus.CounterValue, bytesWritten, labels...)
	}

	// Available spare percentage
	if spare, ok := nvmeLog["available_spare"].(float64); ok {
		ch <- prometheus.MustNewConstMetric(c.diskAvailableSpare, prometheus.GaugeValue, spare, labels...)
	}

	// Percentage used
	if used, ok := nvmeLog["percentage_used"].(float64); ok {
		ch <- prometheus.MustNewConstMetric(c.diskPercentageUsed, prometheus.GaugeValue, used, labels...)
	}
}

// extractRawValue extracts the raw value from a SMART attribute
func extractRawValue(rawMap map[string]interface{}) (float64, bool) {
	if rawValue, ok := rawMap["value"].(float64); ok {
		return rawValue, true
	}
	// Try string value
	if rawStr, ok := rawMap["string"].(string); ok {
		fields := strings.Fields(rawStr)
		if len(fields) > 0 {
			if v, err := strconv.ParseFloat(fields[0], 64); err == nil {
				return v, true
			}
		}
	}
	return 0, false
}

// getTemperatureFromRoot extracts temperature from root level data
func getTemperatureFromRoot(data map[string]interface{}) (float64, bool) {
	if temp, ok := data["temperature"].(map[string]interface{}); ok {
		if current, ok := temp["current"].(float64); ok {
			return current, true
		}
	}
	return 0, false
}

// parseATAMetrics extracts metrics from ATA/SATA SMART data
func (c *ProxmoxCollector) parseATAMetrics(ch chan<- prometheus.Metric, data map[string]interface{}, labels []string) {
	// Get power on hours from general info
	if hours, ok := data["power_on_time"].(map[string]interface{}); ok {
		if h, ok := hours["hours"].(float64); ok {
			ch <- prometheus.MustNewConstMetric(c.diskPowerOnHours, prometheus.GaugeValue, h, labels...)
		}
	}

	hasTemperature := c.parseATASmartAttributes(ch, data, labels)

	// Fallback: try temperature from root level
	if !hasTemperature {
		if temp, ok := getTemperatureFromRoot(data); ok {
			ch <- prometheus.MustNewConstMetric(c.diskTemperature, prometheus.GaugeValue, temp, labels...)
		}
	}
}

// parseATASmartAttributes parses the SMART attributes table
func (c *ProxmoxCollector) parseATASmartAttributes(ch chan<- prometheus.Metric, data map[string]interface{}, labels []string) bool {
	hasTemperature := false

	ataAttrs, ok := data["ata_smart_attributes"].(map[string]interface{})
	if !ok {
		return false
	}

	table, ok := ataAttrs["table"].([]interface{})
	if !ok {
		return false
	}

	for _, attr := range table {
		attrMap, ok := attr.(map[string]interface{})
		if !ok {
			continue
		}

		id, ok := attrMap["id"].(float64)
		if !ok {
			continue
		}

		rawMap, ok := attrMap["raw"].(map[string]interface{})
		if !ok {
			continue
		}

		rawValue, ok := extractRawValue(rawMap)
		if !ok {
			continue
		}

		if int(id) == 194 { // Temperature_Celsius
			ch <- prometheus.MustNewConstMetric(c.diskTemperature, prometheus.GaugeValue, rawValue, labels...)
			hasTemperature = true
		}
	}

	return hasTemperature
}

// getStringField safely extracts a string field from a map
func getStringField(data map[string]interface{}, key string) string {
	if val, ok := data[key].(string); ok {
		return val
	}
	return ""
}
