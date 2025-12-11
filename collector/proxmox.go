package collector

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bigtcze/pve-exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

// Pre-compiled regex patterns for backup log parsing (optimization: compile once, not per scrape)
var (
	backupFinishedRe = regexp.MustCompile(`Finished Backup of VM (\d+)`)
	backupTimeRe     = regexp.MustCompile(`Backup finished at (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})`)
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
	nodeCPUs        *prometheus.Desc
	nodeMemoryTotal *prometheus.Desc
	nodeMemoryUsed  *prometheus.Desc
	nodeMemoryFree  *prometheus.Desc
	nodeSwapTotal   *prometheus.Desc
	nodeSwapUsed    *prometheus.Desc
	nodeSwapFree    *prometheus.Desc
	nodeVMCount     *prometheus.Desc
	nodeLXCCount    *prometheus.Desc
	// New node metrics
	nodeLoad1       *prometheus.Desc
	nodeLoad5       *prometheus.Desc
	nodeLoad15      *prometheus.Desc
	nodeIOWait      *prometheus.Desc
	nodeIdle        *prometheus.Desc
	nodeCPUMhz      *prometheus.Desc
	nodeRootfsTotal *prometheus.Desc
	nodeRootfsUsed  *prometheus.Desc
	nodeRootfsFree  *prometheus.Desc
	nodeCPUCores    *prometheus.Desc
	nodeCPUSockets  *prometheus.Desc
	nodeKSMShared   *prometheus.Desc

	// VM metrics
	vmStatus    *prometheus.Desc
	vmUptime    *prometheus.Desc
	vmCPU       *prometheus.Desc
	vmCPUs      *prometheus.Desc
	vmMemory    *prometheus.Desc
	vmMaxMemory *prometheus.Desc
	vmFreeMem   *prometheus.Desc
	vmBalloon   *prometheus.Desc
	vmMaxDisk   *prometheus.Desc
	vmNetIn     *prometheus.Desc
	vmNetOut    *prometheus.Desc
	vmDiskRead  *prometheus.Desc
	vmDiskWrite *prometheus.Desc
	vmHAManaged *prometheus.Desc
	vmPID       *prometheus.Desc
	vmMemHost   *prometheus.Desc
	// VM pressure metrics (Linux PSI)
	vmPressureCPUFull    *prometheus.Desc
	vmPressureCPUSome    *prometheus.Desc
	vmPressureIOFull     *prometheus.Desc
	vmPressureIOSome     *prometheus.Desc
	vmPressureMemoryFull *prometheus.Desc
	vmPressureMemorySome *prometheus.Desc
	// VM balloon info
	vmBalloonActual        *prometheus.Desc
	vmBalloonMaxMem        *prometheus.Desc
	vmBalloonTotalMem      *prometheus.Desc
	vmBalloonMajorFaults   *prometheus.Desc
	vmBalloonMinorFaults   *prometheus.Desc
	vmBalloonMemSwappedIn  *prometheus.Desc
	vmBalloonMemSwappedOut *prometheus.Desc
	// VM block device metrics
	vmBlockReadBytes   *prometheus.Desc
	vmBlockWriteBytes  *prometheus.Desc
	vmBlockReadOps     *prometheus.Desc
	vmBlockWriteOps    *prometheus.Desc
	vmBlockFailedRead  *prometheus.Desc
	vmBlockFailedWrite *prometheus.Desc
	vmBlockFlushOps    *prometheus.Desc
	// VM NIC metrics
	vmNICNetIn  *prometheus.Desc
	vmNICNetOut *prometheus.Desc

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
	lxcSwap      *prometheus.Desc
	lxcMaxSwap   *prometheus.Desc
	lxcHAManaged *prometheus.Desc
	lxcPID       *prometheus.Desc
	// LXC pressure metrics (Linux PSI)
	lxcPressureCPUFull    *prometheus.Desc
	lxcPressureCPUSome    *prometheus.Desc
	lxcPressureIOFull     *prometheus.Desc
	lxcPressureIOSome     *prometheus.Desc
	lxcPressureMemoryFull *prometheus.Desc
	lxcPressureMemorySome *prometheus.Desc

	// Storage metrics
	storageTotal        *prometheus.Desc
	storageUsed         *prometheus.Desc
	storageAvail        *prometheus.Desc
	storageActive       *prometheus.Desc
	storageEnabled      *prometheus.Desc
	storageShared       *prometheus.Desc
	storageUsedFraction *prometheus.Desc

	// ZFS metrics
	zfsPoolHealth      *prometheus.Desc
	zfsPoolSize        *prometheus.Desc
	zfsPoolAlloc       *prometheus.Desc
	zfsPoolFree        *prometheus.Desc
	zfsPoolFrag        *prometheus.Desc
	zfsARCSize         *prometheus.Desc
	zfsARCMinSize      *prometheus.Desc
	zfsARCMaxSize      *prometheus.Desc
	zfsARCHits         *prometheus.Desc
	zfsARCMisses       *prometheus.Desc
	zfsARCHitRatio     *prometheus.Desc
	zfsARCTargetSize   *prometheus.Desc
	zfsARCL2Hits       *prometheus.Desc
	zfsARCL2Misses     *prometheus.Desc
	zfsARCL2Size       *prometheus.Desc
	zfsARCL2HeaderSize *prometheus.Desc

	// Hardware sensor metrics
	sensorTemperature *prometheus.Desc
	sensorFanRPM      *prometheus.Desc
	sensorVoltage     *prometheus.Desc
	sensorPower       *prometheus.Desc

	// Disk SMART metrics (read from /var/lib/pve-exporter/smart.json)
	diskTemperature    *prometheus.Desc
	diskPowerOnHours   *prometheus.Desc
	diskHealth         *prometheus.Desc
	diskDataWritten    *prometheus.Desc
	diskAvailableSpare *prometheus.Desc
	diskPercentageUsed *prometheus.Desc

	// Disk I/O metrics (read from /proc/diskstats, no root needed)
	diskReadBytes       *prometheus.Desc
	diskWriteBytes      *prometheus.Desc
	diskReadsCompleted  *prometheus.Desc
	diskWritesCompleted *prometheus.Desc
	diskIOTime          *prometheus.Desc

	// Backup metrics
	vmLastBackup  *prometheus.Desc
	lxcLastBackup *prometheus.Desc
}

// GuestInfo represents VM or LXC container info for sharing between collectors
type GuestInfo struct {
	Node string
	Name string
	Type string // "qemu" or "lxc"
}

// NewProxmoxCollector creates a new Proxmox collector
func NewProxmoxCollector(cfg *config.ProxmoxConfig) *ProxmoxCollector {
	client := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.InsecureSkipVerify,
			},
			// Connection pooling for better performance
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
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
		// New node metrics
		nodeLoad1: prometheus.NewDesc(
			"pve_node_load1",
			"Node load average 1 minute",
			[]string{"node"}, nil,
		),
		nodeLoad5: prometheus.NewDesc(
			"pve_node_load5",
			"Node load average 5 minutes",
			[]string{"node"}, nil,
		),
		nodeLoad15: prometheus.NewDesc(
			"pve_node_load15",
			"Node load average 15 minutes",
			[]string{"node"}, nil,
		),
		nodeIOWait: prometheus.NewDesc(
			"pve_node_iowait",
			"Node I/O wait ratio",
			[]string{"node"}, nil,
		),
		nodeIdle: prometheus.NewDesc(
			"pve_node_idle",
			"Node idle CPU ratio",
			[]string{"node"}, nil,
		),
		nodeCPUMhz: prometheus.NewDesc(
			"pve_node_cpu_mhz",
			"CPU frequency in MHz",
			[]string{"node"}, nil,
		),
		nodeRootfsTotal: prometheus.NewDesc(
			"pve_node_rootfs_total_bytes",
			"Node root filesystem total size in bytes",
			[]string{"node"}, nil,
		),
		nodeRootfsUsed: prometheus.NewDesc(
			"pve_node_rootfs_used_bytes",
			"Node root filesystem used in bytes",
			[]string{"node"}, nil,
		),
		nodeRootfsFree: prometheus.NewDesc(
			"pve_node_rootfs_free_bytes",
			"Node root filesystem free in bytes",
			[]string{"node"}, nil,
		),
		nodeCPUCores: prometheus.NewDesc(
			"pve_node_cpu_cores",
			"Number of CPU cores per socket",
			[]string{"node"}, nil,
		),
		nodeCPUSockets: prometheus.NewDesc(
			"pve_node_cpu_sockets",
			"Number of CPU sockets",
			[]string{"node"}, nil,
		),
		nodeKSMShared: prometheus.NewDesc(
			"pve_node_ksm_shared_bytes",
			"KSM shared memory in bytes",
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
		vmFreeMem: prometheus.NewDesc(
			"pve_vm_memory_free_bytes",
			"VM free memory in bytes (from guest agent/balloon)",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmBalloon: prometheus.NewDesc(
			"pve_vm_balloon_bytes",
			"VM balloon target in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmHAManaged: prometheus.NewDesc(
			"pve_vm_ha_managed",
			"VM is managed by HA (1=yes, 0=no)",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmPID: prometheus.NewDesc(
			"pve_vm_pid",
			"VM process ID",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmMemHost: prometheus.NewDesc(
			"pve_vm_memory_host_bytes",
			"VM host memory allocation in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		// VM pressure metrics (Linux PSI)
		vmPressureCPUFull: prometheus.NewDesc(
			"pve_vm_pressure_cpu_full",
			"VM CPU pressure full ratio",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmPressureCPUSome: prometheus.NewDesc(
			"pve_vm_pressure_cpu_some",
			"VM CPU pressure some ratio",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmPressureIOFull: prometheus.NewDesc(
			"pve_vm_pressure_io_full",
			"VM I/O pressure full ratio",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmPressureIOSome: prometheus.NewDesc(
			"pve_vm_pressure_io_some",
			"VM I/O pressure some ratio",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmPressureMemoryFull: prometheus.NewDesc(
			"pve_vm_pressure_memory_full",
			"VM memory pressure full ratio",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmPressureMemorySome: prometheus.NewDesc(
			"pve_vm_pressure_memory_some",
			"VM memory pressure some ratio",
			[]string{"node", "vmid", "name"}, nil,
		),
		// VM balloon info
		vmBalloonActual: prometheus.NewDesc(
			"pve_vm_balloon_actual_bytes",
			"VM balloon actual memory in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmBalloonMaxMem: prometheus.NewDesc(
			"pve_vm_balloon_max_bytes",
			"VM balloon maximum memory in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmBalloonTotalMem: prometheus.NewDesc(
			"pve_vm_balloon_total_bytes",
			"VM balloon total guest memory in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmBalloonMajorFaults: prometheus.NewDesc(
			"pve_vm_balloon_major_page_faults_total",
			"VM major page faults",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmBalloonMinorFaults: prometheus.NewDesc(
			"pve_vm_balloon_minor_page_faults_total",
			"VM minor page faults",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmBalloonMemSwappedIn: prometheus.NewDesc(
			"pve_vm_balloon_mem_swapped_in_bytes",
			"VM memory swapped in",
			[]string{"node", "vmid", "name"}, nil,
		),
		vmBalloonMemSwappedOut: prometheus.NewDesc(
			"pve_vm_balloon_mem_swapped_out_bytes",
			"VM memory swapped out",
			[]string{"node", "vmid", "name"}, nil,
		),
		// VM block device metrics
		vmBlockReadBytes: prometheus.NewDesc(
			"pve_vm_block_read_bytes_total",
			"VM block device read in bytes",
			[]string{"node", "vmid", "name", "device"}, nil,
		),
		vmBlockWriteBytes: prometheus.NewDesc(
			"pve_vm_block_write_bytes_total",
			"VM block device write in bytes",
			[]string{"node", "vmid", "name", "device"}, nil,
		),
		vmBlockReadOps: prometheus.NewDesc(
			"pve_vm_block_read_ops_total",
			"VM block device read operations",
			[]string{"node", "vmid", "name", "device"}, nil,
		),
		vmBlockWriteOps: prometheus.NewDesc(
			"pve_vm_block_write_ops_total",
			"VM block device write operations",
			[]string{"node", "vmid", "name", "device"}, nil,
		),
		vmBlockFailedRead: prometheus.NewDesc(
			"pve_vm_block_failed_read_ops_total",
			"VM block device failed read operations",
			[]string{"node", "vmid", "name", "device"}, nil,
		),
		vmBlockFailedWrite: prometheus.NewDesc(
			"pve_vm_block_failed_write_ops_total",
			"VM block device failed write operations",
			[]string{"node", "vmid", "name", "device"}, nil,
		),
		vmBlockFlushOps: prometheus.NewDesc(
			"pve_vm_block_flush_ops_total",
			"VM block device flush operations",
			[]string{"node", "vmid", "name", "device"}, nil,
		),
		// VM NIC metrics
		vmNICNetIn: prometheus.NewDesc(
			"pve_vm_nic_in_bytes_total",
			"VM NIC input in bytes",
			[]string{"node", "vmid", "name", "interface"}, nil,
		),
		vmNICNetOut: prometheus.NewDesc(
			"pve_vm_nic_out_bytes_total",
			"VM NIC output in bytes",
			[]string{"node", "vmid", "name", "interface"}, nil,
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
		lxcSwap: prometheus.NewDesc(
			"pve_lxc_swap_used_bytes",
			"LXC swap usage in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcMaxSwap: prometheus.NewDesc(
			"pve_lxc_swap_max_bytes",
			"LXC maximum swap in bytes",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcHAManaged: prometheus.NewDesc(
			"pve_lxc_ha_managed",
			"LXC is managed by HA (1=yes, 0=no)",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcPID: prometheus.NewDesc(
			"pve_lxc_pid",
			"LXC process ID",
			[]string{"node", "vmid", "name"}, nil,
		),
		// LXC pressure metrics (Linux PSI)
		lxcPressureCPUFull: prometheus.NewDesc(
			"pve_lxc_pressure_cpu_full",
			"LXC CPU pressure full ratio",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcPressureCPUSome: prometheus.NewDesc(
			"pve_lxc_pressure_cpu_some",
			"LXC CPU pressure some ratio",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcPressureIOFull: prometheus.NewDesc(
			"pve_lxc_pressure_io_full",
			"LXC I/O pressure full ratio",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcPressureIOSome: prometheus.NewDesc(
			"pve_lxc_pressure_io_some",
			"LXC I/O pressure some ratio",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcPressureMemoryFull: prometheus.NewDesc(
			"pve_lxc_pressure_memory_full",
			"LXC memory pressure full ratio",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcPressureMemorySome: prometheus.NewDesc(
			"pve_lxc_pressure_memory_some",
			"LXC memory pressure some ratio",
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
		storageActive: prometheus.NewDesc(
			"pve_storage_active",
			"Storage is active (1=active, 0=inactive)",
			[]string{"node", "storage", "type"}, nil,
		),
		storageEnabled: prometheus.NewDesc(
			"pve_storage_enabled",
			"Storage is enabled (1=enabled, 0=disabled)",
			[]string{"node", "storage", "type"}, nil,
		),
		storageShared: prometheus.NewDesc(
			"pve_storage_shared",
			"Storage is shared (1=shared, 0=local)",
			[]string{"node", "storage", "type"}, nil,
		),
		storageUsedFraction: prometheus.NewDesc(
			"pve_storage_used_fraction",
			"Storage used fraction (0.0-1.0)",
			[]string{"node", "storage", "type"}, nil,
		),

		// ZFS metrics
		zfsPoolHealth: prometheus.NewDesc(
			"pve_zfs_pool_health_status",
			"ZFS pool health status (1=ONLINE, 0=Other)",
			[]string{"node", "pool"}, nil,
		),
		zfsPoolSize: prometheus.NewDesc(
			"pve_zfs_pool_size_bytes",
			"ZFS pool total size in bytes",
			[]string{"node", "pool"}, nil,
		),
		zfsPoolAlloc: prometheus.NewDesc(
			"pve_zfs_pool_alloc_bytes",
			"ZFS pool allocated size in bytes",
			[]string{"node", "pool"}, nil,
		),
		zfsPoolFree: prometheus.NewDesc(
			"pve_zfs_pool_free_bytes",
			"ZFS pool free size in bytes",
			[]string{"node", "pool"}, nil,
		),
		zfsPoolFrag: prometheus.NewDesc(
			"pve_zfs_pool_frag_percent",
			"ZFS pool fragmentation percentage",
			[]string{"node", "pool"}, nil,
		),
		zfsARCSize: prometheus.NewDesc(
			"pve_zfs_arc_size_bytes",
			"ZFS ARC size in bytes",
			[]string{"node"}, nil,
		),
		zfsARCMinSize: prometheus.NewDesc(
			"pve_zfs_arc_min_size_bytes",
			"ZFS ARC minimum size in bytes",
			[]string{"node"}, nil,
		),
		zfsARCMaxSize: prometheus.NewDesc(
			"pve_zfs_arc_max_size_bytes",
			"ZFS ARC maximum size in bytes",
			[]string{"node"}, nil,
		),
		zfsARCHits: prometheus.NewDesc(
			"pve_zfs_arc_hits_total",
			"ZFS ARC hits total",
			[]string{"node"}, nil,
		),
		zfsARCMisses: prometheus.NewDesc(
			"pve_zfs_arc_misses_total",
			"ZFS ARC misses total",
			[]string{"node"}, nil,
		),
		zfsARCHitRatio: prometheus.NewDesc(
			"pve_zfs_arc_hit_ratio_percent",
			"ZFS ARC hit ratio in percent (0-100)",
			[]string{"node"}, nil,
		),
		zfsARCTargetSize: prometheus.NewDesc(
			"pve_zfs_arc_target_size_bytes",
			"ZFS ARC target size (c) in bytes",
			[]string{"node"}, nil,
		),
		zfsARCL2Hits: prometheus.NewDesc(
			"pve_zfs_arc_l2_hits_total",
			"ZFS L2ARC hits total",
			[]string{"node"}, nil,
		),
		zfsARCL2Misses: prometheus.NewDesc(
			"pve_zfs_arc_l2_misses_total",
			"ZFS L2ARC misses total",
			[]string{"node"}, nil,
		),
		zfsARCL2Size: prometheus.NewDesc(
			"pve_zfs_arc_l2_size_bytes",
			"ZFS L2ARC size in bytes",
			[]string{"node"}, nil,
		),
		zfsARCL2HeaderSize: prometheus.NewDesc(
			"pve_zfs_arc_l2_header_size_bytes",
			"ZFS L2ARC header size in bytes",
			[]string{"node"}, nil,
		),

		// Hardware sensor metrics
		sensorTemperature: prometheus.NewDesc(
			"pve_sensor_temperature_celsius",
			"Hardware sensor temperature in Celsius",
			[]string{"node", "chip", "adapter", "sensor"}, nil,
		),
		sensorFanRPM: prometheus.NewDesc(
			"pve_sensor_fan_rpm",
			"Hardware sensor fan speed in RPM",
			[]string{"node", "chip", "adapter", "sensor"}, nil,
		),
		sensorVoltage: prometheus.NewDesc(
			"pve_sensor_voltage_volts",
			"Hardware sensor voltage in Volts",
			[]string{"node", "chip", "adapter", "sensor"}, nil,
		),
		sensorPower: prometheus.NewDesc(
			"pve_sensor_power_watts",
			"Hardware sensor power consumption in Watts",
			[]string{"node", "chip", "adapter", "sensor"}, nil,
		),

		// Disk SMART metrics (read from /var/lib/pve-exporter/smart.json)
		diskTemperature: prometheus.NewDesc(
			"pve_disk_temperature_celsius",
			"Disk temperature in Celsius",
			[]string{"node", "device", "model", "serial", "type"}, nil,
		),
		diskPowerOnHours: prometheus.NewDesc(
			"pve_disk_power_on_hours",
			"Disk power on hours",
			[]string{"node", "device", "model", "serial", "type"}, nil,
		),
		diskHealth: prometheus.NewDesc(
			"pve_disk_health_status",
			"Disk health status (1=healthy, 0=failing)",
			[]string{"node", "device", "model", "serial", "type"}, nil,
		),
		diskDataWritten: prometheus.NewDesc(
			"pve_disk_data_written_bytes",
			"Total data written to disk in bytes (NVMe TBW)",
			[]string{"node", "device", "model", "serial", "type"}, nil,
		),
		diskAvailableSpare: prometheus.NewDesc(
			"pve_disk_available_spare_percent",
			"NVMe available spare percentage",
			[]string{"node", "device", "model", "serial", "type"}, nil,
		),
		diskPercentageUsed: prometheus.NewDesc(
			"pve_disk_percentage_used",
			"NVMe percentage of life used",
			[]string{"node", "device", "model", "serial", "type"}, nil,
		),

		// Disk I/O metrics (from /proc/diskstats)
		diskReadBytes: prometheus.NewDesc(
			"pve_disk_read_bytes_total",
			"Total bytes read from disk",
			[]string{"node", "device"}, nil,
		),
		diskWriteBytes: prometheus.NewDesc(
			"pve_disk_write_bytes_total",
			"Total bytes written to disk",
			[]string{"node", "device"}, nil,
		),
		diskReadsCompleted: prometheus.NewDesc(
			"pve_disk_reads_completed_total",
			"Total read operations completed",
			[]string{"node", "device"}, nil,
		),
		diskWritesCompleted: prometheus.NewDesc(
			"pve_disk_writes_completed_total",
			"Total write operations completed",
			[]string{"node", "device"}, nil,
		),
		diskIOTime: prometheus.NewDesc(
			"pve_disk_io_time_seconds_total",
			"Total time spent doing I/O operations",
			[]string{"node", "device"}, nil,
		),

		// Backup metrics
		vmLastBackup: prometheus.NewDesc(
			"pve_vm_last_backup_timestamp",
			"Unix timestamp of last successful backup",
			[]string{"node", "vmid", "name"}, nil,
		),
		lxcLastBackup: prometheus.NewDesc(
			"pve_lxc_last_backup_timestamp",
			"Unix timestamp of last successful backup",
			[]string{"node", "vmid", "name"}, nil,
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
	ch <- c.nodeLoad1
	ch <- c.nodeLoad5
	ch <- c.nodeLoad15
	ch <- c.nodeIOWait
	ch <- c.nodeIdle
	ch <- c.nodeCPUMhz
	ch <- c.nodeRootfsTotal
	ch <- c.nodeRootfsUsed
	ch <- c.nodeRootfsFree
	ch <- c.nodeCPUCores
	ch <- c.nodeCPUSockets
	ch <- c.nodeKSMShared
	ch <- c.vmStatus
	ch <- c.vmUptime
	ch <- c.vmCPU
	ch <- c.vmCPUs
	ch <- c.vmMemory
	ch <- c.vmMaxMemory
	ch <- c.vmFreeMem
	ch <- c.vmBalloon
	ch <- c.vmMaxDisk
	ch <- c.vmNetIn
	ch <- c.vmNetOut
	ch <- c.vmDiskRead
	ch <- c.vmDiskWrite
	ch <- c.vmHAManaged
	ch <- c.vmPID
	ch <- c.vmMemHost
	ch <- c.vmPressureCPUFull
	ch <- c.vmPressureCPUSome
	ch <- c.vmPressureIOFull
	ch <- c.vmPressureIOSome
	ch <- c.vmPressureMemoryFull
	ch <- c.vmPressureMemorySome
	ch <- c.vmBalloonActual
	ch <- c.vmBalloonMaxMem
	ch <- c.vmBalloonTotalMem
	ch <- c.vmBalloonMajorFaults
	ch <- c.vmBalloonMinorFaults
	ch <- c.vmBalloonMemSwappedIn
	ch <- c.vmBalloonMemSwappedOut
	ch <- c.vmBlockReadBytes
	ch <- c.vmBlockWriteBytes
	ch <- c.vmBlockReadOps
	ch <- c.vmBlockWriteOps
	ch <- c.vmBlockFailedRead
	ch <- c.vmBlockFailedWrite
	ch <- c.vmBlockFlushOps
	ch <- c.vmNICNetIn
	ch <- c.vmNICNetOut
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
	ch <- c.lxcSwap
	ch <- c.lxcMaxSwap
	ch <- c.lxcHAManaged
	ch <- c.lxcPID
	ch <- c.lxcPressureCPUFull
	ch <- c.lxcPressureCPUSome
	ch <- c.lxcPressureIOFull
	ch <- c.lxcPressureIOSome
	ch <- c.lxcPressureMemoryFull
	ch <- c.lxcPressureMemorySome
	ch <- c.storageTotal
	ch <- c.storageUsed
	ch <- c.storageAvail
	ch <- c.storageActive
	ch <- c.storageEnabled
	ch <- c.storageShared
	ch <- c.storageUsedFraction

	ch <- c.zfsPoolHealth
	ch <- c.zfsPoolSize
	ch <- c.zfsPoolAlloc
	ch <- c.zfsPoolFree
	ch <- c.zfsPoolFrag
	ch <- c.zfsARCSize
	ch <- c.zfsARCMinSize
	ch <- c.zfsARCMaxSize
	ch <- c.zfsARCHits
	ch <- c.zfsARCMisses
	ch <- c.zfsARCHitRatio
	ch <- c.zfsARCTargetSize
	ch <- c.zfsARCL2Hits
	ch <- c.zfsARCL2Misses
	ch <- c.zfsARCL2Size
	ch <- c.zfsARCL2HeaderSize

	// Hardware sensors
	ch <- c.sensorTemperature
	ch <- c.sensorFanRPM
	ch <- c.sensorVoltage
	ch <- c.sensorPower

	// Disk SMART
	ch <- c.diskTemperature
	ch <- c.diskPowerOnHours
	ch <- c.diskHealth
	ch <- c.diskDataWritten
	ch <- c.diskAvailableSpare
	ch <- c.diskPercentageUsed

	// Disk I/O
	ch <- c.diskReadBytes
	ch <- c.diskWriteBytes
	ch <- c.diskReadsCompleted
	ch <- c.diskWritesCompleted
	ch <- c.diskIOTime

	// Backup
	ch <- c.vmLastBackup
	ch <- c.lxcLastBackup
}

// Collect implements prometheus.Collector
func (c *ProxmoxCollector) Collect(ch chan<- prometheus.Metric) {
	// Authenticate if needed
	if err := c.authenticate(); err != nil {
		log.Printf("Error during authentication: %v", err)
		return
	}

	// Fetch nodes list ONCE and reuse across all collection functions
	nodesData, err := c.apiRequest("/nodes")
	if err != nil {
		log.Printf("Error fetching nodes: %v", err)
		return
	}

	var nodesResult struct {
		Data []struct {
			Node string `json:"node"`
		} `json:"data"`
	}

	if err := json.Unmarshal(nodesData, &nodesResult); err != nil {
		log.Printf("Error unmarshaling nodes: %v", err)
		return
	}

	// Extract node names
	nodes := make([]string, len(nodesResult.Data))
	for i, n := range nodesResult.Data {
		nodes[i] = n.Node
	}

	// OPTIMIZATION #6: Fetch all guests ONCE using /cluster/resources (single API call)
	// This replaces N×2 per-node calls (/qemu + /lxc per node)
	guests := make(map[string]GuestInfo)
	resourcesData, err := c.apiRequest("/cluster/resources?type=vm")
	if err == nil {
		var resourcesResult struct {
			Data []struct {
				VMID   int64  `json:"vmid"`
				Node   string `json:"node"`
				Name   string `json:"name"`
				Type   string `json:"type"` // "qemu" or "lxc"
				Status string `json:"status"`
			} `json:"data"`
		}
		if json.Unmarshal(resourcesData, &resourcesResult) == nil {
			for _, res := range resourcesResult.Data {
				vmid := strconv.FormatInt(res.VMID, 10)
				guests[vmid] = GuestInfo{Node: res.Node, Name: res.Name, Type: res.Type}
			}
		}
	}

	// Run all collection functions in parallel for better performance
	var wg sync.WaitGroup

	wg.Add(7)

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
		// OPTIMIZATION #2: Pass pre-fetched guest data to avoid duplicate API calls
		c.collectBackupMetricsWithGuests(ch, nodes, guests)
	}()

	wg.Wait()
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

// collectNodeMetricsWithNodes collects node-level metrics from pre-fetched data
func (c *ProxmoxCollector) collectNodeMetricsWithNodes(ch chan<- prometheus.Metric, data []byte) {
	var result struct {
		Data []struct {
			Node    string  `json:"node"`
			Status  string  `json:"status"`
			Uptime  float64 `json:"uptime"`
			CPU     float64 `json:"cpu"`
			MaxCPU  float64 `json:"maxcpu"`
			Mem     float64 `json:"mem"`
			MaxMem  float64 `json:"maxmem"`
			Disk    float64 `json:"disk"`
			MaxDisk float64 `json:"maxdisk"`
		} `json:"data"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		log.Printf("Error unmarshaling nodes data: %v", err)
		return
	}

	// Collect basic metrics first, then fetch detailed metrics in parallel
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

		// Fetch detailed node status for additional metrics in parallel
		wg.Add(1)
		go func(nodeName string) {
			defer wg.Done()
			c.collectNodeDetailedMetrics(ch, nodeName)
		}(node.Node)
	}
	wg.Wait()
}

// collectNodeDetailedMetrics fetches detailed node status from /nodes/{node}/status
func (c *ProxmoxCollector) collectNodeDetailedMetrics(ch chan<- prometheus.Metric, nodeName string) {
	path := fmt.Sprintf("/nodes/%s/status", nodeName)
	data, err := c.apiRequest(path)
	if err != nil {
		log.Printf("Error fetching node status for %s: %v", nodeName, err)
		return
	}

	var result struct {
		Data struct {
			LoadAvg []string `json:"loadavg"`
			Wait    float64  `json:"wait"`
			Idle    float64  `json:"idle"`
			KSM     struct {
				Shared float64 `json:"shared"`
			} `json:"ksm"`
			CPUInfo struct {
				Cores   float64 `json:"cores"`
				Sockets float64 `json:"sockets"`
				Mhz     string  `json:"mhz"`
			} `json:"cpuinfo"`
			Rootfs struct {
				Total float64 `json:"total"`
				Used  float64 `json:"used"`
				Free  float64 `json:"free"`
			} `json:"rootfs"`
			Swap struct {
				Total float64 `json:"total"`
				Used  float64 `json:"used"`
				Free  float64 `json:"free"`
			} `json:"swap"`
		} `json:"data"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		log.Printf("Error unmarshaling node status for %s: %v", nodeName, err)
		return
	}

	// Load averages
	if len(result.Data.LoadAvg) >= 3 {
		if load1, err := strconv.ParseFloat(result.Data.LoadAvg[0], 64); err == nil {
			ch <- prometheus.MustNewConstMetric(c.nodeLoad1, prometheus.GaugeValue, load1, nodeName)
		}
		if load5, err := strconv.ParseFloat(result.Data.LoadAvg[1], 64); err == nil {
			ch <- prometheus.MustNewConstMetric(c.nodeLoad5, prometheus.GaugeValue, load5, nodeName)
		}
		if load15, err := strconv.ParseFloat(result.Data.LoadAvg[2], 64); err == nil {
			ch <- prometheus.MustNewConstMetric(c.nodeLoad15, prometheus.GaugeValue, load15, nodeName)
		}
	}

	// I/O wait and idle
	ch <- prometheus.MustNewConstMetric(c.nodeIOWait, prometheus.GaugeValue, result.Data.Wait, nodeName)
	ch <- prometheus.MustNewConstMetric(c.nodeIdle, prometheus.GaugeValue, result.Data.Idle, nodeName)

	// CPU frequency
	if mhz, err := strconv.ParseFloat(result.Data.CPUInfo.Mhz, 64); err == nil {
		ch <- prometheus.MustNewConstMetric(c.nodeCPUMhz, prometheus.GaugeValue, mhz, nodeName)
	}

	// Root filesystem
	ch <- prometheus.MustNewConstMetric(c.nodeRootfsTotal, prometheus.GaugeValue, result.Data.Rootfs.Total, nodeName)
	ch <- prometheus.MustNewConstMetric(c.nodeRootfsUsed, prometheus.GaugeValue, result.Data.Rootfs.Used, nodeName)
	ch <- prometheus.MustNewConstMetric(c.nodeRootfsFree, prometheus.GaugeValue, result.Data.Rootfs.Free, nodeName)

	// CPU topology
	ch <- prometheus.MustNewConstMetric(c.nodeCPUCores, prometheus.GaugeValue, result.Data.CPUInfo.Cores, nodeName)
	ch <- prometheus.MustNewConstMetric(c.nodeCPUSockets, prometheus.GaugeValue, result.Data.CPUInfo.Sockets, nodeName)

	// KSM shared memory
	ch <- prometheus.MustNewConstMetric(c.nodeKSMShared, prometheus.GaugeValue, result.Data.KSM.Shared, nodeName)

	// Swap (from detailed status)
	ch <- prometheus.MustNewConstMetric(c.nodeSwapTotal, prometheus.GaugeValue, result.Data.Swap.Total, nodeName)
	ch <- prometheus.MustNewConstMetric(c.nodeSwapUsed, prometheus.GaugeValue, result.Data.Swap.Used, nodeName)
	ch <- prometheus.MustNewConstMetric(c.nodeSwapFree, prometheus.GaugeValue, result.Data.Swap.Free, nodeName)
}

// collectVMMetricsWithNodes collects VM and container metrics using pre-fetched nodes list
func (c *ProxmoxCollector) collectVMMetricsWithNodes(ch chan<- prometheus.Metric, nodes []string) {
	// Process all nodes in parallel for better performance
	var wg sync.WaitGroup
	for _, node := range nodes {
		wg.Add(1)
		go func(nodeName string) {
			defer wg.Done()
			// QEMU VMs
			vmCount := c.collectResourceMetrics(ch, nodeName, "qemu")
			ch <- prometheus.MustNewConstMetric(c.nodeVMCount, prometheus.GaugeValue, float64(vmCount), nodeName)

			// LXC containers
			lxcCount := c.collectResourceMetrics(ch, nodeName, "lxc")
			ch <- prometheus.MustNewConstMetric(c.nodeLXCCount, prometheus.GaugeValue, float64(lxcCount), nodeName)
		}(node)
	}
	wg.Wait()
}

// collectResourceMetrics collects metrics for VMs or containers and returns the count
func (c *ProxmoxCollector) collectResourceMetrics(ch chan<- prometheus.Metric, node, resType string) int {
	path := fmt.Sprintf("/nodes/%s/%s", node, resType)
	data, err := c.apiRequest(path)
	if err != nil {
		log.Printf("Error fetching %s for node %s: %v", resType, node, err)
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
		log.Printf("Error unmarshaling %s for node %s: %v", resType, node, err)
		return 0
	}

	// Process VMs in parallel for better performance
	var wg sync.WaitGroup

	for _, vm := range result.Data {
		wg.Add(1)
		go func(vm struct {
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
		}) {
			defer wg.Done()

			status := 0.0
			if vm.Status == "running" {
				status = 1.0
			}

			labels := []string{node, fmt.Sprintf("%d", vm.VMID), vm.Name}

			// Get detailed status ONCE for all metrics (disk I/O, balloon, pressure, etc.)
			diskRead := vm.DiskRead
			diskWrite := vm.DiskWrite
			var detailData []byte
			if vm.Status == "running" {
				detailPath := fmt.Sprintf("/nodes/%s/%s/%d/status/current", node, resType, vm.VMID)
				var err error
				detailData, err = c.apiRequest(detailPath)
				if err == nil {
					var detailResult struct {
						Data struct {
							DiskRead  float64 `json:"diskread"`
							DiskWrite float64 `json:"diskwrite"`
						} `json:"data"`
					}
					if err := json.Unmarshal(detailData, &detailResult); err == nil {
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
				// Get LXC swap - reuse detailData if available
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
				// Get VM detailed metrics - reuse detailData instead of making another API call
				c.collectVMDetailedMetricsFromData(ch, detailData, labels)
			}
		}(vm)
	}

	wg.Wait()
	return len(result.Data)
}

// collectLXCSwapMetricsFromData parses LXC swap metrics from already fetched data
func (c *ProxmoxCollector) collectLXCSwapMetricsFromData(ch chan<- prometheus.Metric, data []byte, labels []string) {
	if data == nil {
		return
	}

	var result struct {
		Data struct {
			Swap    float64 `json:"swap"`
			MaxSwap float64 `json:"maxswap"`
			PID     float64 `json:"pid"`
			HA      struct {
				Managed int `json:"managed"`
			} `json:"ha"`
			PressureCPUFull    string `json:"pressurecpufull"`
			PressureCPUSome    string `json:"pressurecpusome"`
			PressureIOFull     string `json:"pressureiofull"`
			PressureIOSome     string `json:"pressureiosome"`
			PressureMemoryFull string `json:"pressurememoryfull"`
			PressureMemorySome string `json:"pressurememorysome"`
		} `json:"data"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return
	}

	ch <- prometheus.MustNewConstMetric(c.lxcSwap, prometheus.GaugeValue, result.Data.Swap, labels...)
	ch <- prometheus.MustNewConstMetric(c.lxcMaxSwap, prometheus.GaugeValue, result.Data.MaxSwap, labels...)
	ch <- prometheus.MustNewConstMetric(c.lxcHAManaged, prometheus.GaugeValue, float64(result.Data.HA.Managed), labels...)
	ch <- prometheus.MustNewConstMetric(c.lxcPID, prometheus.GaugeValue, result.Data.PID, labels...)
	// Pressure metrics (LXC returns strings)
	if cpuFull, err := strconv.ParseFloat(result.Data.PressureCPUFull, 64); err == nil {
		ch <- prometheus.MustNewConstMetric(c.lxcPressureCPUFull, prometheus.GaugeValue, cpuFull, labels...)
	}
	if cpuSome, err := strconv.ParseFloat(result.Data.PressureCPUSome, 64); err == nil {
		ch <- prometheus.MustNewConstMetric(c.lxcPressureCPUSome, prometheus.GaugeValue, cpuSome, labels...)
	}
	if ioFull, err := strconv.ParseFloat(result.Data.PressureIOFull, 64); err == nil {
		ch <- prometheus.MustNewConstMetric(c.lxcPressureIOFull, prometheus.GaugeValue, ioFull, labels...)
	}
	if ioSome, err := strconv.ParseFloat(result.Data.PressureIOSome, 64); err == nil {
		ch <- prometheus.MustNewConstMetric(c.lxcPressureIOSome, prometheus.GaugeValue, ioSome, labels...)
	}
	if memFull, err := strconv.ParseFloat(result.Data.PressureMemoryFull, 64); err == nil {
		ch <- prometheus.MustNewConstMetric(c.lxcPressureMemoryFull, prometheus.GaugeValue, memFull, labels...)
	}
	if memSome, err := strconv.ParseFloat(result.Data.PressureMemorySome, 64); err == nil {
		ch <- prometheus.MustNewConstMetric(c.lxcPressureMemorySome, prometheus.GaugeValue, memSome, labels...)
	}
}

// collectVMDetailedMetricsFromData parses VM detailed metrics from already fetched data
func (c *ProxmoxCollector) collectVMDetailedMetricsFromData(ch chan<- prometheus.Metric, data []byte, labels []string) {
	if data == nil {
		return
	}

	var result struct {
		Data struct {
			Balloon float64 `json:"balloon"`
			FreeMem float64 `json:"freemem"`
			PID     float64 `json:"pid"`
			MemHost float64 `json:"memhost"`
			HA      struct {
				Managed int `json:"managed"`
			} `json:"ha"`
			BalloonInfo struct {
				Actual          float64 `json:"actual"`
				MaxMem          float64 `json:"max_mem"`
				TotalMem        float64 `json:"total_mem"`
				MajorPageFaults float64 `json:"major_page_faults"`
				MinorPageFaults float64 `json:"minor_page_faults"`
				MemSwappedIn    float64 `json:"mem_swapped_in"`
				MemSwappedOut   float64 `json:"mem_swapped_out"`
			} `json:"ballooninfo"`
			PressureCPUFull    float64 `json:"pressurecpufull"`
			PressureCPUSome    float64 `json:"pressurecpusome"`
			PressureIOFull     float64 `json:"pressureiofull"`
			PressureIOSome     float64 `json:"pressureiosome"`
			PressureMemoryFull float64 `json:"pressurememoryfull"`
			PressureMemorySome float64 `json:"pressurememorysome"`
			BlockStat          map[string]struct {
				RdBytes     float64 `json:"rd_bytes"`
				WrBytes     float64 `json:"wr_bytes"`
				RdOps       float64 `json:"rd_operations"`
				WrOps       float64 `json:"wr_operations"`
				FailedRdOps float64 `json:"failed_rd_operations"`
				FailedWrOps float64 `json:"failed_wr_operations"`
				FlushOps    float64 `json:"flush_operations"`
			} `json:"blockstat"`
			NICS map[string]struct {
				NetIn  float64 `json:"netin"`
				NetOut float64 `json:"netout"`
			} `json:"nics"`
		} `json:"data"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return
	}

	ch <- prometheus.MustNewConstMetric(c.vmBalloon, prometheus.GaugeValue, result.Data.Balloon, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmFreeMem, prometheus.GaugeValue, result.Data.FreeMem, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmHAManaged, prometheus.GaugeValue, float64(result.Data.HA.Managed), labels...)
	ch <- prometheus.MustNewConstMetric(c.vmPID, prometheus.GaugeValue, result.Data.PID, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmMemHost, prometheus.GaugeValue, result.Data.MemHost, labels...)
	// Pressure metrics
	ch <- prometheus.MustNewConstMetric(c.vmPressureCPUFull, prometheus.GaugeValue, result.Data.PressureCPUFull, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmPressureCPUSome, prometheus.GaugeValue, result.Data.PressureCPUSome, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmPressureIOFull, prometheus.GaugeValue, result.Data.PressureIOFull, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmPressureIOSome, prometheus.GaugeValue, result.Data.PressureIOSome, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmPressureMemoryFull, prometheus.GaugeValue, result.Data.PressureMemoryFull, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmPressureMemorySome, prometheus.GaugeValue, result.Data.PressureMemorySome, labels...)
	// Balloon info
	ch <- prometheus.MustNewConstMetric(c.vmBalloonActual, prometheus.GaugeValue, result.Data.BalloonInfo.Actual, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmBalloonMaxMem, prometheus.GaugeValue, result.Data.BalloonInfo.MaxMem, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmBalloonTotalMem, prometheus.GaugeValue, result.Data.BalloonInfo.TotalMem, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmBalloonMajorFaults, prometheus.CounterValue, result.Data.BalloonInfo.MajorPageFaults, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmBalloonMinorFaults, prometheus.CounterValue, result.Data.BalloonInfo.MinorPageFaults, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmBalloonMemSwappedIn, prometheus.GaugeValue, result.Data.BalloonInfo.MemSwappedIn, labels...)
	ch <- prometheus.MustNewConstMetric(c.vmBalloonMemSwappedOut, prometheus.GaugeValue, result.Data.BalloonInfo.MemSwappedOut, labels...)

	// Block device metrics
	for device, stats := range result.Data.BlockStat {
		deviceLabels := append(labels, device)
		ch <- prometheus.MustNewConstMetric(c.vmBlockReadBytes, prometheus.CounterValue, stats.RdBytes, deviceLabels...)
		ch <- prometheus.MustNewConstMetric(c.vmBlockWriteBytes, prometheus.CounterValue, stats.WrBytes, deviceLabels...)
		ch <- prometheus.MustNewConstMetric(c.vmBlockReadOps, prometheus.CounterValue, stats.RdOps, deviceLabels...)
		ch <- prometheus.MustNewConstMetric(c.vmBlockWriteOps, prometheus.CounterValue, stats.WrOps, deviceLabels...)
		ch <- prometheus.MustNewConstMetric(c.vmBlockFailedRead, prometheus.CounterValue, stats.FailedRdOps, deviceLabels...)
		ch <- prometheus.MustNewConstMetric(c.vmBlockFailedWrite, prometheus.CounterValue, stats.FailedWrOps, deviceLabels...)
		ch <- prometheus.MustNewConstMetric(c.vmBlockFlushOps, prometheus.CounterValue, stats.FlushOps, deviceLabels...)
	}

	// NIC metrics
	for iface, stats := range result.Data.NICS {
		nicLabels := append(labels, iface)
		ch <- prometheus.MustNewConstMetric(c.vmNICNetIn, prometheus.CounterValue, stats.NetIn, nicLabels...)
		ch <- prometheus.MustNewConstMetric(c.vmNICNetOut, prometheus.CounterValue, stats.NetOut, nicLabels...)
	}
}

// collectStorageMetrics collects storage metrics for all nodes in parallel
func (c *ProxmoxCollector) collectStorageMetrics(ch chan<- prometheus.Metric, nodes []string) {
	var wg sync.WaitGroup
	for _, node := range nodes {
		wg.Add(1)
		go func(nodeName string) {
			defer wg.Done()

			path := fmt.Sprintf("/nodes/%s/storage", nodeName)
			storageData, err := c.apiRequest(path)
			if err != nil {
				log.Printf("Error fetching storage for node %s: %v", nodeName, err)
				return
			}

			var result struct {
				Data []struct {
					Storage      string  `json:"storage"`
					Type         string  `json:"type"`
					Total        float64 `json:"total"`
					Used         float64 `json:"used"`
					Avail        float64 `json:"avail"`
					Active       int     `json:"active"`
					Enabled      int     `json:"enabled"`
					Shared       int     `json:"shared"`
					UsedFraction float64 `json:"used_fraction"`
				} `json:"data"`
			}

			if err := json.Unmarshal(storageData, &result); err != nil {
				log.Printf("Error unmarshaling storage for node %s: %v", nodeName, err)
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

// collectBackupMetricsWithGuests collects last backup timestamps for VMs and LXC containers
// OPTIMIZATION #2: Uses pre-fetched guest data from /cluster/resources to avoid duplicate API calls
// Also optimized with: parallel log fetches, early exit, dynamic log limits
func (c *ProxmoxCollector) collectBackupMetricsWithGuests(ch chan<- prometheus.Metric, nodes []string, guests map[string]GuestInfo) {
	// If no guests were passed (API failed), fall back to fetching ourselves
	if len(guests) == 0 {
		var guestsMutex sync.Mutex
		var wg sync.WaitGroup
		for _, node := range nodes {
			wg.Add(1)
			go func(nodeName string) {
				defer wg.Done()
				vmData, err := c.apiRequest(fmt.Sprintf("/nodes/%s/qemu", nodeName))
				if err == nil {
					var vmResult struct {
						Data []struct {
							VMID int64  `json:"vmid"`
							Name string `json:"name"`
						} `json:"data"`
					}
					if json.Unmarshal(vmData, &vmResult) == nil {
						guestsMutex.Lock()
						for _, vm := range vmResult.Data {
							vmid := strconv.FormatInt(vm.VMID, 10)
							guests[vmid] = GuestInfo{Node: nodeName, Name: vm.Name, Type: "qemu"}
						}
						guestsMutex.Unlock()
					}
				}
				lxcData, err := c.apiRequest(fmt.Sprintf("/nodes/%s/lxc", nodeName))
				if err == nil {
					var lxcResult struct {
						Data []struct {
							VMID int64  `json:"vmid"`
							Name string `json:"name"`
						} `json:"data"`
					}
					if json.Unmarshal(lxcData, &lxcResult) == nil {
						guestsMutex.Lock()
						for _, lxc := range lxcResult.Data {
							vmid := strconv.FormatInt(lxc.VMID, 10)
							guests[vmid] = GuestInfo{Node: nodeName, Name: lxc.Name, Type: "lxc"}
						}
						guestsMutex.Unlock()
					}
				}
			}(node)
		}
		wg.Wait()
	}

	// Now collect backup tasks and find latest successful backup per VMID
	backups := make(map[string]int64) // key: vmid, value: endtime timestamp
	var backupsMutex sync.Mutex

	// Count total guests for early exit optimization
	totalGuests := len(guests)

	var wg sync.WaitGroup
	for _, node := range nodes {
		wg.Add(1)
		go func(nodeName string) {
			defer wg.Done()
			// Fetch vzdump tasks (limit 50 - recent backups are most relevant)
			tasksData, err := c.apiRequest(fmt.Sprintf("/nodes/%s/tasks?typefilter=vzdump&limit=50", nodeName))
			if err != nil {
				return
			}

			var tasksResult struct {
				Data []struct {
					ID        string `json:"id"`      // VMID as string (empty for batch jobs)
					UPID      string `json:"upid"`    // Unique task ID
					EndTime   int64  `json:"endtime"` // Unix timestamp
					Status    string `json:"status"`  // "OK" for successful
					StartTime int64  `json:"starttime"`
				} `json:"data"`
			}

			if err := json.Unmarshal(tasksData, &tasksResult); err != nil {
				return
			}

			// Collect batch jobs to process in parallel later
			type batchJob struct {
				UPID    string
				EndTime int64
			}
			var batchJobs []batchJob
			const maxBatchLogFetches = 5

			// First pass: collect single VM backups (fast) and identify batch jobs
			backupsMutex.Lock()
			for _, task := range tasksResult.Data {
				if task.Status != "OK" {
					continue
				}
				if task.ID != "" {
					// Single VM backup - use task data directly (fast path)
					if existing, ok := backups[task.ID]; !ok || task.EndTime > existing {
						backups[task.ID] = task.EndTime
					}
				} else if task.UPID != "" && len(batchJobs) < maxBatchLogFetches {
					batchJobs = append(batchJobs, batchJob{UPID: task.UPID, EndTime: task.EndTime})
				}
			}
			backupsMutex.Unlock()

			// OPTIMIZATION: Parallel batch log fetches (mutex released during API calls)
			if len(batchJobs) > 0 {
				var batchWg sync.WaitGroup
				localBackups := make(map[string]int64)
				var localMutex sync.Mutex

				for _, job := range batchJobs {
					batchWg.Add(1)
					go func(upid string) {
						defer batchWg.Done()

						// Dynamic log limit based on guest count (20 lines per guest, min 200)
						logLimit := totalGuests * 20
						if logLimit < 200 {
							logLimit = 200
						}

						logData, err := c.apiRequest(fmt.Sprintf("/nodes/%s/tasks/%s/log?limit=%d", nodeName, url.PathEscape(upid), logLimit))
						if err != nil {
							return
						}

						var logResult struct {
							Data []struct {
								N int    `json:"n"`
								T string `json:"t"`
							} `json:"data"`
						}

						if json.Unmarshal(logData, &logResult) != nil {
							return
						}

						// Parse log lines to find finished backups and their times
						var currentVMID string
						foundCount := 0
						for _, line := range logResult.Data {
							if match := backupFinishedRe.FindStringSubmatch(line.T); match != nil {
								currentVMID = match[1]
							} else if currentVMID != "" && strings.Contains(line.T, "Backup finished at") {
								if match := backupTimeRe.FindStringSubmatch(line.T); match != nil {
									if t, err := time.Parse("2006-01-02 15:04:05", match[1]); err == nil {
										timestamp := t.Unix()
										localMutex.Lock()
										if existing, ok := localBackups[currentVMID]; !ok || timestamp > existing {
											localBackups[currentVMID] = timestamp
											foundCount++
										}
										localMutex.Unlock()
									}
								}
								currentVMID = ""

								// OPTIMIZATION: Early exit if we found enough backups
								if foundCount >= totalGuests {
									break
								}
							}
						}
					}(job.UPID)
				}
				batchWg.Wait()

				// Merge local results into global backups map
				backupsMutex.Lock()
				for vmid, ts := range localBackups {
					if existing, ok := backups[vmid]; !ok || ts > existing {
						backups[vmid] = ts
					}
				}
				backupsMutex.Unlock()
			}
		}(node)
	}
	wg.Wait()

	// Emit metrics for each guest with a backup
	for vmid, endtime := range backups {
		guest, ok := guests[vmid]
		if !ok {
			continue // Skip if we don't have guest info (maybe deleted)
		}
		labels := []string{guest.Node, vmid, guest.Name}
		if guest.Type == "qemu" {
			ch <- prometheus.MustNewConstMetric(c.vmLastBackup, prometheus.GaugeValue, float64(endtime), labels...)
		} else {
			ch <- prometheus.MustNewConstMetric(c.lxcLastBackup, prometheus.GaugeValue, float64(endtime), labels...)
		}
	}
}
