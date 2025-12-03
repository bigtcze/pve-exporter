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
	nodeCPUs        *prometheus.Desc // New
	nodeMemoryTotal *prometheus.Desc
	nodeMemoryUsed  *prometheus.Desc
	nodeMemoryFree  *prometheus.Desc
	nodeSwapTotal   *prometheus.Desc
	nodeSwapUsed    *prometheus.Desc
	nodeSwapFree    *prometheus.Desc
	nodeVMCount     *prometheus.Desc // New
	nodeLXCCount    *prometheus.Desc // New

	// VM metrics
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

	// LXC metrics
	lxcStatus    *prometheus.Desc
	lxcUptime    *prometheus.Desc
	lxcCPU       *prometheus.Desc
	lxcCPUs      *prometheus.Desc
	lxcMemory    *prometheus.Desc
	lxcMaxMemory *prometheus.Desc
	lxcDisk      *prometheus.Desc
	lxcMaxDisk   *prometheus.Desc
	lxcNetIn     *prometheus.Desc
	lxcNetOut    *prometheus.Desc
	lxcDiskRead  *prometheus.Desc
	lxcDiskWrite *prometheus.Desc

	// Storage metrics
	storageTotal *prometheus.Desc
	storageUsed  *prometheus.Desc
	storageAvail *prometheus.Desc

	// Backup metrics
	guestLastBackup *prometheus.Desc // New
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
		nodeCPUs: prometheus.NewDesc(
			"pve_node_cpus_total",
			"Total number of CPUs",
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
		nodeVMCount: prometheus.NewDesc(
			"pve_node_vm_count",
			"Number of QEMU VMs",
			[]string{"node"}, nil,
		),
		nodeLXCCount: prometheus.NewDesc(
			"pve_node_lxc_count",
			"Number of LXC containers",
			[]string{"node"}, nil,
		),

		// VM metrics
		vmStatus: prometheus.NewDesc(
			"pve_vm_status",
			"VM status (1=running, 0=stopped)",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmUptime: prometheus.NewDesc(
			"pve_vm_uptime_seconds",
			"VM uptime in seconds",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmCPU: prometheus.NewDesc(
			"pve_vm_cpu_usage",
			"VM CPU usage",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmCPUs: prometheus.NewDesc(
			"pve_vm_cpus",
			"Number of CPUs allocated to VM",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmMemory: prometheus.NewDesc(
			"pve_vm_memory_used_bytes",
			"VM memory usage in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmMaxMemory: prometheus.NewDesc(
			"pve_vm_memory_max_bytes",
			"VM maximum memory in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmDisk: prometheus.NewDesc(
			"pve_vm_disk_used_bytes",
			"VM disk usage in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmMaxDisk: prometheus.NewDesc(
			"pve_vm_disk_max_bytes",
			"VM maximum disk in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmNetIn: prometheus.NewDesc(
			"pve_vm_network_in_bytes_total",
			"VM network input in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmNetOut: prometheus.NewDesc(
			"pve_vm_network_out_bytes_total",
			"VM network output in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmDiskRead: prometheus.NewDesc(
			"pve_vm_disk_read_bytes_total",
			"VM disk read in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmDiskWrite: prometheus.NewDesc(
			"pve_vm_disk_write_bytes_total",
			"VM disk write in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),

		// LXC metrics
		lxcStatus: prometheus.NewDesc(
			"pve_lxc_status",
			"LXC status (1=running, 0=stopped)",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcUptime: prometheus.NewDesc(
			"pve_lxc_uptime_seconds",
			"LXC uptime in seconds",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcCPU: prometheus.NewDesc(
			"pve_lxc_cpu_usage",
			"LXC CPU usage",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcCPUs: prometheus.NewDesc(
			"pve_lxc_cpus",
			"Number of CPUs allocated to LXC",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcMemory: prometheus.NewDesc(
			"pve_lxc_memory_used_bytes",
			"LXC memory usage in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcMaxMemory: prometheus.NewDesc(
			"pve_lxc_memory_max_bytes",
			"LXC maximum memory in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcDisk: prometheus.NewDesc(
			"pve_lxc_disk_used_bytes",
			"LXC disk usage in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcMaxDisk: prometheus.NewDesc(
			"pve_lxc_disk_max_bytes",
			"LXC maximum disk in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcNetIn: prometheus.NewDesc(
			"pve_lxc_network_in_bytes_total",
			"LXC network input in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcNetOut: prometheus.NewDesc(
			"pve_lxc_network_out_bytes_total",
			"LXC network output in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcDiskRead: prometheus.NewDesc(
			"pve_lxc_disk_read_bytes_total",
			"LXC disk read in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcDiskWrite: prometheus.NewDesc(
			"pve_lxc_disk_write_bytes_total",
			"LXC disk write in bytes",
			[]string{"node", "vmid", "name"}, nil,
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

		// Backup metrics
		guestLastBackup: prometheus.NewDesc(
			"pve_guest_last_backup_timestamp_seconds",
			"Timestamp of the last backup",
			[]string{"node", "vmid"}, nil,
		),
	}
}

// Describe implements prometheus.Collector
func (c *ProxmoxCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.nodeUp
	ch <- c.nodeUptime
	ch <- c.nodeCPULoad
	ch <- c.nodeCPUs
	ch <- c.nodeMemoryTotal
	ch <- c.nodeMemoryUsed
	ch <- c.nodeMemoryFree
	ch <- c.nodeSwapTotal
	ch <- c.nodeSwapUsed
	ch <- c.nodeSwapFree
	ch <- c.nodeVMCount
	ch <- c.nodeLXCCount
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
	ch <- c.lxcStatus
	ch <- c.lxcUptime
	ch <- c.lxcCPU
	ch <- c.lxcCPUs
	ch <- c.lxcMemory
	ch <- c.lxcMaxMemory
	ch <- c.lxcDisk
	ch <- c.lxcMaxDisk
	ch <- c.lxcNetIn
	ch <- c.lxcNetOut
	ch <- c.lxcDiskRead
	ch <- c.lxcDiskWrite
	ch <- c.storageTotal
	ch <- c.storageUsed
	ch <- c.storageAvail
	ch <- c.guestLastBackup
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

	// Collect backup metrics
	c.collectBackupMetrics(ch)
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
			Node    string  `json:"node"`
			Status  string  `json:"status"`
			Uptime  float64 `json:"uptime"`
			CPU     float64 `json:"cpu"`
			CPUs    float64 `json:"cpus"` // New field
			MaxCPU  float64 `json:"maxcpu"`
			Mem     float64 `json:"mem"`
			MaxMem  float64 `json:"maxmem"`
			Disk    float64 `json:"disk"`
			MaxDisk float64 `json:"maxdisk"`
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
		ch <- prometheus.MustNewConstMetric(c.nodeCPUs, prometheus.GaugeValue, node.CPUs, node.Node)
		ch <- prometheus.MustNewConstMetric(c.nodeMemoryTotal, prometheus.GaugeValue, node.MaxMem, node.Node)
		ch <- prometheus.MustNewConstMetric(c.nodeMemoryUsed, prometheus.GaugeValue, node.Mem, node.Node)
		ch <- prometheus.MustNewConstMetric(c.nodeMemoryFree, prometheus.GaugeValue, node.MaxMem-node.Mem, node.Node)
		// Swap metrics are not available in /nodes endpoint
		ch <- prometheus.MustNewConstMetric(c.nodeSwapTotal, prometheus.GaugeValue, 0, node.Node)
		ch <- prometheus.MustNewConstMetric(c.nodeSwapUsed, prometheus.GaugeValue, 0, node.Node)
		ch <- prometheus.MustNewConstMetric(c.nodeSwapFree, prometheus.GaugeValue, 0, node.Node)
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
		vmCount := c.collectResourceMetrics(ch, node.Node, "qemu")
		ch <- prometheus.MustNewConstMetric(c.nodeVMCount, prometheus.GaugeValue, float64(vmCount), node.Node)

		// LXC containers
		lxcCount := c.collectResourceMetrics(ch, node.Node, "lxc")
		ch <- prometheus.MustNewConstMetric(c.nodeLXCCount, prometheus.GaugeValue, float64(lxcCount), node.Node)
	}
}

// collectResourceMetrics collects metrics for VMs or containers and returns the count
func (c *ProxmoxCollector) collectResourceMetrics(ch chan<- prometheus.Metric, node, resType string) int {
	path := fmt.Sprintf("/nodes/%s/%s", node, resType)
	data, err := c.apiRequest(path)
	if err != nil {
		return 0
	}

	var result struct {
		Data []struct {
			VMID      int64   `json:"vmid"`
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
		return 0
	}

	for _, vm := range result.Data {
		status := 0.0
		if vm.Status == "running" {
			status = 1.0
		}

		labels := []string{node, fmt.Sprintf("%d", vm.VMID), vm.Name}

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
			ch <- prometheus.MustNewConstMetric(c.lxcDiskRead, prometheus.CounterValue, vm.DiskRead, labels...)
			ch <- prometheus.MustNewConstMetric(c.lxcDiskWrite, prometheus.CounterValue, vm.DiskWrite, labels...)
		} else {
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

	return len(result.Data)
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

// collectBackupMetrics collects backup timestamp metrics
func (c *ProxmoxCollector) collectBackupMetrics(ch chan<- prometheus.Metric) {
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
		// Get list of storages for the node
		storagePath := fmt.Sprintf("/nodes/%s/storage", node.Node)
		storageData, err := c.apiRequest(storagePath)
		if err != nil {
			continue
		}

		var storageResult struct {
			Data []struct {
				Storage string `json:"storage"`
				Content string `json:"content"` // e.g. "backup,iso"
			} `json:"data"`
		}

		if err := json.Unmarshal(storageData, &storageResult); err != nil {
			continue
		}

		for _, storage := range storageResult.Data {
			// Check if storage supports backups
			// Note: We could check 'content' field but querying content=backup is safer/easier

			contentPath := fmt.Sprintf("/nodes/%s/storage/%s/content?content=backup", node.Node, storage.Storage)
			contentData, err := c.apiRequest(contentPath)
			if err != nil {
				continue
			}

			var contentResult struct {
				Data []struct {
					VolID string      `json:"volid"`
					VMID  interface{} `json:"vmid"` // Can be string or int
					CTime int64       `json:"ctime"`
				} `json:"data"`
			}

			if err := json.Unmarshal(contentData, &contentResult); err != nil {
				continue
			}

			// Track latest backup per VM
			lastBackups := make(map[string]int64)

			for _, item := range contentResult.Data {
				// Parse VMID
				var vmid string
				switch v := item.VMID.(type) {
				case float64:
					vmid = fmt.Sprintf("%.0f", v)
				case string:
					vmid = v
				default:
					// Try to extract from volid if vmid field is missing/invalid
					// Format: storage:backup/vzdump-qemu-100-2023...
					// This is complex, skipping for now if vmid is missing
					continue
				}

				if item.CTime > lastBackups[vmid] {
					lastBackups[vmid] = item.CTime
				}
			}

			for vmid, timestamp := range lastBackups {
				ch <- prometheus.MustNewConstMetric(
					c.guestLastBackup,
					prometheus.GaugeValue,
					float64(timestamp),
					node.Node,
					vmid,
				)
			}
		}
	}
}
