package collector

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/bigtcze/pve-exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

// ProxmoxCollector collects metrics from Proxmox VE API
type ProxmoxCollector struct {
	config *config.ProxmoxConfig
	client *http.Client
	ticket string
	csrf   string
	mutex  sync.RWMutex

	// Node metrics
	nodeUp          *prometheus.Desc
	nodeUptime      *prometheus.Desc
	nodeCPULoad     *prometheus.Desc
	nodeMemoryTotal *prometheus.Desc
	nodeMemoryUsed  *prometheus.Desc
	nodeMemoryFree  *prometheus.Desc
	nodeSwapTotal   *prometheus.Desc
	nodeSwapUsed    *prometheus.Desc
	nodeSwapFree    *prometheus.Desc

	// VM/Container metrics
	vmStatus    *prometheus.Desc
	vmUptime    *prometheus.Desc
	vmCPU       *prometheus.Desc
	vmCPUs      *prometheus.Desc
	vmMemory    *prometheus.Desc
	vmMaxMemory *prometheus.Desc
	vmDisk      *prometheus.Desc
	vmMaxDisk   *prometheus.Desc
	vmNetIn     *prometheus.Desc
	vmNetOut    *prometheus.Desc
	vmDiskRead  *prometheus.Desc
	vmDiskWrite *prometheus.Desc

	// Storage metrics
	storageTotal *prometheus.Desc
	storageUsed  *prometheus.Desc
	storageAvail *prometheus.Desc
}

// NewProxmoxCollector creates a new Proxmox collector
func NewProxmoxCollector(cfg *config.ProxmoxConfig) *ProxmoxCollector {
	client := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.InsecureSkipVerify,
			},
		},
	}

	return &ProxmoxCollector{
		config: cfg,
		client: client,

		// Node metrics
		nodeUp: prometheus.NewDesc(
			"pve_node_up",
			"Node is up and reachable",
			[]string{"node"}, nil,
		),
		nodeUptime: prometheus.NewDesc(
			"pve_node_uptime_seconds",
			"Node uptime in seconds",
			[]string{"node"}, nil,
		),
		nodeCPULoad: prometheus.NewDesc(
			"pve_node_cpu_load",
			"Node CPU load",
			[]string{"node"}, nil,
		),
		nodeMemoryTotal: prometheus.NewDesc(
			"pve_node_memory_total_bytes",
			"Total memory in bytes",
			[]string{"node"}, nil,
		),
		nodeMemoryUsed: prometheus.NewDesc(
			"pve_node_memory_used_bytes",
			"Used memory in bytes",
			[]string{"node"}, nil,
		),
		nodeMemoryFree: prometheus.NewDesc(
			"pve_node_memory_free_bytes",
			"Free memory in bytes",
			[]string{"node"}, nil,
		),
		nodeSwapTotal: prometheus.NewDesc(
			"pve_node_swap_total_bytes",
			"Total swap in bytes",
			[]string{"node"}, nil,
		),
		nodeSwapUsed: prometheus.NewDesc(
			"pve_node_swap_used_bytes",
			"Used swap in bytes",
			[]string{"node"}, nil,
		),
		nodeSwapFree: prometheus.NewDesc(
			"pve_node_swap_free_bytes",
			"Free swap in bytes",
			[]string{"node"}, nil,
		),

		// VM/Container metrics
		vmStatus: prometheus.NewDesc(
			"pve_vm_status",
			"VM/Container status (1=running, 0=stopped)",
			[]string{"node", "type", "vmid", "name"}, nil,
		),
		vmUptime: prometheus.NewDesc(
			"pve_vm_uptime_seconds",
			"VM/Container uptime in seconds",
			[]string{"node", "type", "vmid", "name"}, nil,
		),
		vmCPU: prometheus.NewDesc(
			"pve_vm_cpu_usage",
			"VM/Container CPU usage",
			[]string{"node", "type", "vmid", "name"}, nil,
		),
		vmCPUs: prometheus.NewDesc(
			"pve_vm_cpus",
			"Number of CPUs allocated to VM/Container",
			[]string{"node", "type", "vmid", "name"}, nil,
		),
		vmMemory: prometheus.NewDesc(
			"pve_vm_memory_used_bytes",
			"VM/Container memory usage in bytes",
			[]string{"node", "type", "vmid", "name"}, nil,
		),
		vmMaxMemory: prometheus.NewDesc(
			"pve_vm_memory_max_bytes",
			"VM/Container maximum memory in bytes",
			[]string{"node", "type", "vmid", "name"}, nil,
		),
		vmDisk: prometheus.NewDesc(
			"pve_vm_disk_used_bytes",
			"VM/Container disk usage in bytes",
			[]string{"node", "type", "vmid", "name"}, nil,
		),
		vmMaxDisk: prometheus.NewDesc(
			"pve_vm_disk_max_bytes",
			"VM/Container maximum disk in bytes",
			[]string{"node", "type", "vmid", "name"}, nil,
		),
		vmNetIn: prometheus.NewDesc(
			"pve_vm_network_in_bytes_total",
			"VM/Container network input in bytes",
			[]string{"node", "type", "vmid", "name"}, nil,
		),
		vmNetOut: prometheus.NewDesc(
			"pve_vm_network_out_bytes_total",
			"VM/Container network output in bytes",
			[]string{"node", "type", "vmid", "name"}, nil,
		),
		vmDiskRead: prometheus.NewDesc(
			"pve_vm_disk_read_bytes_total",
			"VM/Container disk read in bytes",
			[]string{"node", "type", "vmid", "name"}, nil,
		),
		vmDiskWrite: prometheus.NewDesc(
			"pve_vm_disk_write_bytes_total",
			"VM/Container disk write in bytes",
			[]string{"node", "type", "vmid", "name"}, nil,
		),

		// Storage metrics
		storageTotal: prometheus.NewDesc(
			"pve_storage_total_bytes",
			"Total storage size in bytes",
			[]string{"node", "storage", "type"}, nil,
		),
		storageUsed: prometheus.NewDesc(
			"pve_storage_used_bytes",
			"Used storage in bytes",
			[]string{"node", "storage", "type"}, nil,
		),
		storageAvail: prometheus.NewDesc(
			"pve_storage_available_bytes",
			"Available storage in bytes",
			[]string{"node", "storage", "type"}, nil,
		),
	}
}

// Describe implements prometheus.Collector
func (c *ProxmoxCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.nodeUp
	ch <- c.nodeUptime
	ch <- c.nodeCPULoad
	ch <- c.nodeMemoryTotal
	ch <- c.nodeMemoryUsed
	ch <- c.nodeMemoryFree
	ch <- c.nodeSwapTotal
	ch <- c.nodeSwapUsed
	ch <- c.nodeSwapFree
	ch <- c.vmStatus
	ch <- c.vmUptime
	ch <- c.vmCPU
	ch <- c.vmCPUs
	ch <- c.vmMemory
	ch <- c.vmMaxMemory
	ch <- c.vmDisk
	ch <- c.vmMaxDisk
	ch <- c.vmNetIn
	ch <- c.vmNetOut
	ch <- c.vmDiskRead
	ch <- c.vmDiskWrite
	ch <- c.storageTotal
	ch <- c.storageUsed
	ch <- c.storageAvail
}

// Collect implements prometheus.Collector
func (c *ProxmoxCollector) Collect(ch chan<- prometheus.Metric) {
	// Authenticate if needed
	if err := c.authenticate(); err != nil {
		return
	}

	// Collect node metrics
	c.collectNodeMetrics(ch)

	// Collect VM/Container metrics
	c.collectVMMetrics(ch)

	// Collect storage metrics
	c.collectStorageMetrics(ch)
}

// authenticate authenticates with Proxmox API
func (c *ProxmoxCollector) authenticate() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Use token authentication if available
	if c.config.TokenID != "" && c.config.TokenSecret != "" {
		return nil // Token auth doesn't need ticket
	}

	// Use password authentication
	apiURL := fmt.Sprintf("https://%s:%d/api2/json/access/ticket", c.config.Host, c.config.Port)

	data := url.Values{}
	data.Set("username", c.config.User)
	data.Set("password", c.config.Password)

	resp, err := c.client.PostForm(apiURL, data)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed with status: %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Ticket string `json:"ticket"`
			CSRF   string `json:"CSRFPreventionToken"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	c.ticket = result.Data.Ticket
	c.csrf = result.Data.CSRF

	return nil
}

// apiRequest makes an authenticated API request
func (c *ProxmoxCollector) apiRequest(path string) ([]byte, error) {
	apiURL := fmt.Sprintf("https://%s:%d/api2/json%s", c.config.Host, c.config.Port, path)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	// Add authentication
	c.mutex.RLock()
	if c.config.TokenID != "" && c.config.TokenSecret != "" {
		req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", c.config.TokenID, c.config.TokenSecret))
	} else {
		req.Header.Set("Cookie", fmt.Sprintf("PVEAuthCookie=%s", c.ticket))
		req.Header.Set("CSRFPreventionToken", c.csrf)
	}
	c.mutex.RUnlock()

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// collectNodeMetrics collects node-level metrics
func (c *ProxmoxCollector) collectNodeMetrics(ch chan<- prometheus.Metric) {
	data, err := c.apiRequest("/nodes")
	if err != nil {
		return
	}

	var result struct {
		Data []struct {
			Node   string  `json:"node"`
			Status string  `json:"status"`
			Uptime float64 `json:"uptime"`
			CPU    float64 `json:"cpu"`
			Mem    struct {
				Total float64 `json:"total"`
				Used  float64 `json:"used"`
				Free  float64 `json:"free"`
			} `json:"mem"`
			Swap struct {
				Total float64 `json:"total"`
				Used  float64 `json:"used"`
				Free  float64 `json:"free"`
			} `json:"swap"`
		} `json:"data"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return
	}

	for _, node := range result.Data {
		up := 0.0
		if node.Status == "online" {
			up = 1.0
		}

		ch <- prometheus.MustNewConstMetric(c.nodeUp, prometheus.GaugeValue, up, node.Node)
		ch <- prometheus.MustNewConstMetric(c.nodeUptime, prometheus.GaugeValue, node.Uptime, node.Node)
		ch <- prometheus.MustNewConstMetric(c.nodeCPULoad, prometheus.GaugeValue, node.CPU, node.Node)
		ch <- prometheus.MustNewConstMetric(c.nodeMemoryTotal, prometheus.GaugeValue, node.Mem.Total, node.Node)
		ch <- prometheus.MustNewConstMetric(c.nodeMemoryUsed, prometheus.GaugeValue, node.Mem.Used, node.Node)
		ch <- prometheus.MustNewConstMetric(c.nodeMemoryFree, prometheus.GaugeValue, node.Mem.Free, node.Node)
		ch <- prometheus.MustNewConstMetric(c.nodeSwapTotal, prometheus.GaugeValue, node.Swap.Total, node.Node)
		ch <- prometheus.MustNewConstMetric(c.nodeSwapUsed, prometheus.GaugeValue, node.Swap.Used, node.Node)
		ch <- prometheus.MustNewConstMetric(c.nodeSwapFree, prometheus.GaugeValue, node.Swap.Free, node.Node)
	}
}

// collectVMMetrics collects VM and container metrics
func (c *ProxmoxCollector) collectVMMetrics(ch chan<- prometheus.Metric) {
	// Get list of nodes first
	nodesData, err := c.apiRequest("/nodes")
	if err != nil {
		return
	}

	var nodesResult struct {
		Data []struct {
			Node string `json:"node"`
		} `json:"data"`
	}

	if err := json.Unmarshal(nodesData, &nodesResult); err != nil {
		return
	}

	// Collect VMs and containers for each node
	for _, node := range nodesResult.Data {
		// QEMU VMs
		c.collectResourceMetrics(ch, node.Node, "qemu")
		// LXC containers
		c.collectResourceMetrics(ch, node.Node, "lxc")
	}
}

// collectResourceMetrics collects metrics for VMs or containers
func (c *ProxmoxCollector) collectResourceMetrics(ch chan<- prometheus.Metric, node, resType string) {
	path := fmt.Sprintf("/nodes/%s/%s", node, resType)
	data, err := c.apiRequest(path)
	if err != nil {
		return
	}

	var result struct {
		Data []struct {
			VMID      string  `json:"vmid"`
			Name      string  `json:"name"`
			Status    string  `json:"status"`
			Uptime    float64 `json:"uptime"`
			CPU       float64 `json:"cpu"`
			CPUs      float64 `json:"cpus"`
			Mem       float64 `json:"mem"`
			MaxMem    float64 `json:"maxmem"`
			Disk      float64 `json:"disk"`
			MaxDisk   float64 `json:"maxdisk"`
			NetIn     float64 `json:"netin"`
			NetOut    float64 `json:"netout"`
			DiskRead  float64 `json:"diskread"`
			DiskWrite float64 `json:"diskwrite"`
		} `json:"data"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return
	}

	for _, vm := range result.Data {
		status := 0.0
		if vm.Status == "running" {
			status = 1.0
		}

		labels := []string{node, resType, vm.VMID, vm.Name}

		ch <- prometheus.MustNewConstMetric(c.vmStatus, prometheus.GaugeValue, status, labels...)
		ch <- prometheus.MustNewConstMetric(c.vmUptime, prometheus.GaugeValue, vm.Uptime, labels...)
		ch <- prometheus.MustNewConstMetric(c.vmCPU, prometheus.GaugeValue, vm.CPU, labels...)
		ch <- prometheus.MustNewConstMetric(c.vmCPUs, prometheus.GaugeValue, vm.CPUs, labels...)
		ch <- prometheus.MustNewConstMetric(c.vmMemory, prometheus.GaugeValue, vm.Mem, labels...)
		ch <- prometheus.MustNewConstMetric(c.vmMaxMemory, prometheus.GaugeValue, vm.MaxMem, labels...)
		ch <- prometheus.MustNewConstMetric(c.vmDisk, prometheus.GaugeValue, vm.Disk, labels...)
		ch <- prometheus.MustNewConstMetric(c.vmMaxDisk, prometheus.GaugeValue, vm.MaxDisk, labels...)
		ch <- prometheus.MustNewConstMetric(c.vmNetIn, prometheus.CounterValue, vm.NetIn, labels...)
		ch <- prometheus.MustNewConstMetric(c.vmNetOut, prometheus.CounterValue, vm.NetOut, labels...)
		ch <- prometheus.MustNewConstMetric(c.vmDiskRead, prometheus.CounterValue, vm.DiskRead, labels...)
		ch <- prometheus.MustNewConstMetric(c.vmDiskWrite, prometheus.CounterValue, vm.DiskWrite, labels...)
	}
}

// collectStorageMetrics collects storage metrics
func (c *ProxmoxCollector) collectStorageMetrics(ch chan<- prometheus.Metric) {
	// Get list of nodes
	nodesData, err := c.apiRequest("/nodes")
	if err != nil {
		return
	}

	var nodesResult struct {
		Data []struct {
			Node string `json:"node"`
		} `json:"data"`
	}

	if err := json.Unmarshal(nodesData, &nodesResult); err != nil {
		return
	}

	for _, node := range nodesResult.Data {
		path := fmt.Sprintf("/nodes/%s/storage", node.Node)
		data, err := c.apiRequest(path)
		if err != nil {
			continue
		}

		var result struct {
			Data []struct {
				Storage string  `json:"storage"`
				Type    string  `json:"type"`
				Total   float64 `json:"total"`
				Used    float64 `json:"used"`
				Avail   float64 `json:"avail"`
			} `json:"data"`
		}

		if err := json.Unmarshal(data, &result); err != nil {
			continue
		}

		for _, storage := range result.Data {
			labels := []string{node.Node, storage.Storage, storage.Type}
			ch <- prometheus.MustNewConstMetric(c.storageTotal, prometheus.GaugeValue, storage.Total, labels...)
			ch <- prometheus.MustNewConstMetric(c.storageUsed, prometheus.GaugeValue, storage.Used, labels...)
			ch <- prometheus.MustNewConstMetric(c.storageAvail, prometheus.GaugeValue, storage.Avail, labels...)
		}
	}
}
