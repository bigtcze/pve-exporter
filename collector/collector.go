package collector

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/bigtcze/pve-exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/time/rate"
)

const (
	maxIdleConns        = 100
	maxIdleConnsPerHost = 10
	idleConnTimeout     = 90 * time.Second
)

var (
	version = "dev"
	commit  = "none"
)

func SetBuildInfo(v, c string) {
	version = v
	commit = c
}

// ProxmoxCollector collects metrics from Proxmox VE API
type ProxmoxCollector struct {
	config *config.ProxmoxConfig
	client *http.Client
	ticket     string
	csrf       string
	mutex      sync.RWMutex
	limiter    *rate.Limiter
	ticketTime time.Time
	logger     *slog.Logger
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

	// Cluster/HA metrics
	clusterQuorate     *prometheus.Desc
	clusterNodesTotal  *prometheus.Desc
	clusterNodesOnline *prometheus.Desc
	haResourcesTotal   *prometheus.Desc
	haResourcesActive  *prometheus.Desc

	// Replication metrics
	replicationLastSync *prometheus.Desc
	replicationDuration *prometheus.Desc
	replicationStatus   *prometheus.Desc

	// Certificate metrics
	certificateExpiry *prometheus.Desc

	// Exporter self-monitoring metrics
	exporterUp             *prometheus.Desc
	exporterBuildInfo      *prometheus.Desc
	exporterScrapeDuration *prometheus.Desc
}

// GuestInfo represents VM or LXC container info for sharing between collectors
type GuestInfo struct {
	Node string
	Name string
	Type string // "qemu" or "lxc"
}

// NewProxmoxCollector creates a new Proxmox collector
func NewProxmoxCollector(cfg *config.ProxmoxConfig, logger *slog.Logger) *ProxmoxCollector {
	if logger == nil {
		logger = slog.Default()
	}

	client := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.InsecureSkipVerify,
			},
			MaxIdleConns:        maxIdleConns,
			MaxIdleConnsPerHost: maxIdleConnsPerHost,
			IdleConnTimeout:     idleConnTimeout,
		},
	}

	return &ProxmoxCollector{
		config:  cfg,
		client:  client,
		logger:  logger,
		limiter: rate.NewLimiter(rate.Every(100*time.Millisecond), 10), // 10 req/s with burst of 10

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

		// Cluster/HA metrics
		clusterQuorate: prometheus.NewDesc(
			"pve_cluster_quorate",
			"Cluster has quorum (1=yes, 0=no)",
			nil, nil,
		),
		clusterNodesTotal: prometheus.NewDesc(
			"pve_cluster_nodes_total",
			"Total number of nodes in cluster",
			nil, nil,
		),
		clusterNodesOnline: prometheus.NewDesc(
			"pve_cluster_nodes_online",
			"Number of online nodes in cluster",
			nil, nil,
		),
		haResourcesTotal: prometheus.NewDesc(
			"pve_ha_resources_total",
			"Total number of HA managed resources",
			nil, nil,
		),
		haResourcesActive: prometheus.NewDesc(
			"pve_ha_resources_active",
			"Number of active HA resources",
			nil, nil,
		),

		// Replication metrics
		replicationLastSync: prometheus.NewDesc(
			"pve_replication_last_sync_timestamp",
			"Unix timestamp of last successful replication",
			[]string{"guest", "job"}, nil,
		),
		replicationDuration: prometheus.NewDesc(
			"pve_replication_duration_seconds",
			"Duration of last replication in seconds",
			[]string{"guest", "job"}, nil,
		),
		replicationStatus: prometheus.NewDesc(
			"pve_replication_status",
			"Replication status (1=OK, 0=error)",
			[]string{"guest", "job"}, nil,
		),

		// Certificate metrics
		certificateExpiry: prometheus.NewDesc(
			"pve_certificate_expiry_seconds",
			"Seconds until SSL certificate expires",
			[]string{"node"}, nil,
		),

		exporterUp: prometheus.NewDesc(
			"pve_exporter_up",
			"Whether the PVE API is reachable (1=yes, 0=no)",
			nil, nil,
		),
		exporterBuildInfo: prometheus.NewDesc(
			"pve_exporter_build_info",
			"Build information about the exporter",
			[]string{"version", "commit", "goversion"}, nil,
		),
		exporterScrapeDuration: prometheus.NewDesc(
			"pve_exporter_scrape_duration_seconds",
			"Duration of the last scrape in seconds",
			nil, nil,
		),
	}
}
