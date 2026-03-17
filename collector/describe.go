package collector

import "github.com/prometheus/client_golang/prometheus"

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

	// Cluster/HA
	ch <- c.clusterQuorate
	ch <- c.clusterNodesTotal
	ch <- c.clusterNodesOnline
	ch <- c.haResourcesTotal
	ch <- c.haResourcesActive

	// Replication
	ch <- c.replicationLastSync
	ch <- c.replicationDuration
	ch <- c.replicationStatus

	// Certificate
	ch <- c.certificateExpiry

	ch <- c.exporterUp
	ch <- c.exporterBuildInfo
	ch <- c.exporterScrapeDuration
}
