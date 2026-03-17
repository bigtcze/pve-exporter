package collector

// Node API responses

type nodesListResponse struct {
	Data []nodeListEntry `json:"data"`
}

type nodeListEntry struct {
	Node    string  `json:"node"`
	Status  string  `json:"status"`
	Uptime  float64 `json:"uptime"`
	CPU     float64 `json:"cpu"`
	MaxCPU  float64 `json:"maxcpu"`
	Mem     float64 `json:"mem"`
	MaxMem  float64 `json:"maxmem"`
	Disk    float64 `json:"disk"`
	MaxDisk float64 `json:"maxdisk"`
}

type nodeStatusResponse struct {
	Data nodeStatusData `json:"data"`
}

type nodeStatusData struct {
	LoadAvg []string       `json:"loadavg"`
	Wait    float64        `json:"wait"`
	Idle    float64        `json:"idle"`
	KSM     nodeKSM        `json:"ksm"`
	CPUInfo nodeCPUInfo    `json:"cpuinfo"`
	Rootfs  nodeFilesystem `json:"rootfs"`
	Swap    nodeFilesystem `json:"swap"`
}

type nodeKSM struct {
	Shared float64 `json:"shared"`
}

type nodeCPUInfo struct {
	Cores   float64 `json:"cores"`
	Sockets float64 `json:"sockets"`
	Mhz     string  `json:"mhz"`
}

type nodeFilesystem struct {
	Total float64 `json:"total"`
	Used  float64 `json:"used"`
	Free  float64 `json:"free"`
}

// VM/LXC API responses

type resourceListResponse struct {
	Data []resourceEntry `json:"data"`
}

type resourceEntry struct {
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
}

type vmDetailResponse struct {
	Data vmDetailData `json:"data"`
}

type vmDetailData struct {
	DiskRead           float64                `json:"diskread"`
	DiskWrite          float64                `json:"diskwrite"`
	Balloon            float64                `json:"balloon"`
	FreeMem            float64                `json:"freemem"`
	PID                float64                `json:"pid"`
	MemHost            float64                `json:"memhost"`
	HA                 haStatus               `json:"ha"`
	BalloonInfo        balloonInfo            `json:"ballooninfo"`
	PressureCPUFull    float64                `json:"pressurecpufull"`
	PressureCPUSome    float64                `json:"pressurecpusome"`
	PressureIOFull     float64                `json:"pressureiofull"`
	PressureIOSome     float64                `json:"pressureiosome"`
	PressureMemoryFull float64                `json:"pressurememoryfull"`
	PressureMemorySome float64                `json:"pressurememorysome"`
	BlockStat          map[string]blockStats  `json:"blockstat"`
	NICS               map[string]nicStats    `json:"nics"`
}

type haStatus struct {
	Managed int `json:"managed"`
}

type balloonInfo struct {
	Actual          float64 `json:"actual"`
	MaxMem          float64 `json:"max_mem"`
	TotalMem        float64 `json:"total_mem"`
	MajorPageFaults float64 `json:"major_page_faults"`
	MinorPageFaults float64 `json:"minor_page_faults"`
	MemSwappedIn    float64 `json:"mem_swapped_in"`
	MemSwappedOut   float64 `json:"mem_swapped_out"`
}

type blockStats struct {
	RdBytes     float64 `json:"rd_bytes"`
	WrBytes     float64 `json:"wr_bytes"`
	RdOps       float64 `json:"rd_operations"`
	WrOps       float64 `json:"wr_operations"`
	FailedRdOps float64 `json:"failed_rd_operations"`
	FailedWrOps float64 `json:"failed_wr_operations"`
	FlushOps    float64 `json:"flush_operations"`
}

type nicStats struct {
	NetIn  float64 `json:"netin"`
	NetOut float64 `json:"netout"`
}

type lxcDetailResponse struct {
	Data lxcDetailData `json:"data"`
}

type lxcDetailData struct {
	Swap               float64  `json:"swap"`
	MaxSwap            float64  `json:"maxswap"`
	PID                float64  `json:"pid"`
	HA                 haStatus `json:"ha"`
	PressureCPUFull    string   `json:"pressurecpufull"`
	PressureCPUSome    string   `json:"pressurecpusome"`
	PressureIOFull     string   `json:"pressureiofull"`
	PressureIOSome     string   `json:"pressureiosome"`
	PressureMemoryFull string   `json:"pressurememoryfull"`
	PressureMemorySome string   `json:"pressurememorysome"`
}

// Storage API responses

type storageResponse struct {
	Data []storageEntry `json:"data"`
}

type storageEntry struct {
	Storage      string  `json:"storage"`
	Type         string  `json:"type"`
	Total        float64 `json:"total"`
	Used         float64 `json:"used"`
	Avail        float64 `json:"avail"`
	Active       int     `json:"active"`
	Enabled      int     `json:"enabled"`
	Shared       int     `json:"shared"`
	UsedFraction float64 `json:"used_fraction"`
}

// ZFS API responses

type zfsPoolResponse struct {
	Data []zfsPoolEntry `json:"data"`
}

type zfsPoolEntry struct {
	Name   string  `json:"name"`
	Health string  `json:"health"`
	Size   float64 `json:"size"`
	Alloc  float64 `json:"alloc"`
	Free   float64 `json:"free"`
	Frag   float64 `json:"frag"`
}

// Cluster API responses

type clusterStatusResponse struct {
	Data []clusterStatusEntry `json:"data"`
}

type clusterStatusEntry struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Quorate int    `json:"quorate"`
	Online  int    `json:"online"`
	Nodes   int    `json:"nodes"`
}

type haResourcesResponse struct {
	Data []haResourceEntry `json:"data"`
}

type haResourceEntry struct {
	Sid   string `json:"sid"`
	State string `json:"state"`
}

type replicationResponse struct {
	Data []replicationEntry `json:"data"`
}

type replicationEntry struct {
	ID        string  `json:"id"`
	Guest     int64   `json:"guest"`
	JobNum    int     `json:"jobnum"`
	LastSync  int64   `json:"last_sync"`
	Duration  float64 `json:"duration"`
	FailCount int     `json:"fail_count"`
	Error     string  `json:"error"`
}

type certificatesResponse struct {
	Data []certificateEntry `json:"data"`
}

type certificateEntry struct {
	Filename string `json:"filename"`
	NotAfter int64  `json:"notafter"`
}

// Cluster resources (used in collect.go)

type clusterResourcesResponse struct {
	Data []clusterResourceEntry `json:"data"`
}

type clusterResourceEntry struct {
	VMID   int64  `json:"vmid"`
	Node   string `json:"node"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

// Backup API responses

type guestListResponse struct {
	Data []guestListEntry `json:"data"`
}

type guestListEntry struct {
	VMID int64  `json:"vmid"`
	Name string `json:"name"`
}

type tasksResponse struct {
	Data []taskEntry `json:"data"`
}

type taskEntry struct {
	ID        string `json:"id"`
	UPID      string `json:"upid"`
	EndTime   int64  `json:"endtime"`
	Status    string `json:"status"`
	StartTime int64  `json:"starttime"`
}

type taskLogResponse struct {
	Data []taskLogLine `json:"data"`
}

type taskLogLine struct {
	N int    `json:"n"`
	T string `json:"t"`
}

// Nodes-only response (used in collect.go for node name extraction)

type nodesOnlyResponse struct {
	Data []struct {
		Node string `json:"node"`
	} `json:"data"`
}

type authTicketResponse struct {
	Data struct {
		Ticket string `json:"ticket"`
		CSRF   string `json:"CSRFPreventionToken"`
	} `json:"data"`
}
