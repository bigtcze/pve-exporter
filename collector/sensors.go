package collector

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// cachedHostname stores hostname to avoid repeated os.Hostname() calls
var (
	cachedHostname     string
	cachedHostnameOnce sync.Once
)

func getHostname() string {
	cachedHostnameOnce.Do(func() {
		cachedHostname, _ = os.Hostname()
		if cachedHostname == "" {
			cachedHostname = "localhost"
		}
	})
	return cachedHostname
}

// parseSensorKey determines the metric type from a sensor key
// Returns the metric type ("temp", "fan", "in", "power") or empty string if not relevant
func parseSensorKey(key string) (metricType string, isPriority bool) {
	switch {
	case strings.HasPrefix(key, "temp") && strings.HasSuffix(key, "_input"):
		return "temp", true
	case strings.HasPrefix(key, "fan") && strings.HasSuffix(key, "_input"):
		return "fan", true
	case strings.HasPrefix(key, "in") && strings.HasSuffix(key, "_input"):
		return "in", true
	case strings.HasPrefix(key, "power") && strings.HasSuffix(key, "_input"):
		return "power", true // power_input has priority
	case strings.HasPrefix(key, "power") && strings.HasSuffix(key, "_average"):
		return "power", false // power_average is fallback
	default:
		return "", false
	}
}

// emitSensorMetric emits a single sensor metric to the channel
func (c *ProxmoxCollector) emitSensorMetric(ch chan<- prometheus.Metric, metricType string, value float64, labels []string) {
	switch metricType {
	case "temp":
		ch <- prometheus.MustNewConstMetric(c.sensorTemperature, prometheus.GaugeValue, value, labels...)
	case "fan":
		ch <- prometheus.MustNewConstMetric(c.sensorFanRPM, prometheus.GaugeValue, value, labels...)
	case "in":
		ch <- prometheus.MustNewConstMetric(c.sensorVoltage, prometheus.GaugeValue, value, labels...)
	case "power":
		ch <- prometheus.MustNewConstMetric(c.sensorPower, prometheus.GaugeValue, value, labels...)
	}
}

// processSensor processes a single sensor's data and returns readings
func processSensor(sensorMap map[string]interface{}) map[string]float64 {
	readings := make(map[string]float64)
	hasPriority := make(map[string]bool)

	for key, value := range sensorMap {
		val, ok := value.(float64)
		if !ok {
			continue
		}

		metricType, isPriority := parseSensorKey(key)
		if metricType == "" {
			continue
		}

		// Only update if this is higher priority or no existing reading
		if isPriority || !hasPriority[metricType] {
			readings[metricType] = val
			hasPriority[metricType] = isPriority
		}
	}
	return readings
}

// collectSensorsMetrics collects hardware sensor metrics using lm-sensors
func (c *ProxmoxCollector) collectSensorsMetrics(ch chan<- prometheus.Metric) {
	cmd := exec.Command("sensors", "-j")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	hostname := getHostname()

	var sensorsData map[string]interface{}
	if err := json.Unmarshal(output, &sensorsData); err != nil {
		c.logger.Error("failed to parse sensors JSON", "error", err)
		return
	}

	for chipName, chipData := range sensorsData {
		chipMap, ok := chipData.(map[string]interface{})
		if !ok {
			continue
		}

		adapter, _ := chipMap["Adapter"].(string)

		for sensorName, sensorData := range chipMap {
			if sensorName == "Adapter" {
				continue
			}

			sensorMap, ok := sensorData.(map[string]interface{})
			if !ok {
				continue
			}

			readings := processSensor(sensorMap)
			labels := []string{hostname, chipName, adapter, sensorName}

			for metricType, value := range readings {
				c.emitSensorMetric(ch, metricType, value, labels)
			}
		}
	}
}
