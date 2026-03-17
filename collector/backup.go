package collector

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	taskFetchLimit = 50
	maxLogLines    = 1_000_000
)

var (
	backupFinishedRe = regexp.MustCompile(`Finished Backup of VM (\d+)`)
	backupTimeRe     = regexp.MustCompile(`Backup finished at (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})`)
)

type batchJob struct {
	UPID    string
	EndTime int64
}

func (c *ProxmoxCollector) collectBackupMetricsWithGuests(ch chan<- prometheus.Metric, nodes []string, guests map[string]GuestInfo) {
	if len(guests) == 0 {
		c.fetchGuestsFallback(nodes, guests)
	}

	backups := make(map[string]int64)
	var backupsMutex sync.Mutex
	totalGuests := len(guests)

	var wg sync.WaitGroup
	for _, node := range nodes {
		wg.Add(1)
		go func(nodeName string) {
			defer wg.Done()
			c.collectNodeBackups(nodeName, totalGuests, backups, &backupsMutex)
		}(node)
	}
	wg.Wait()

	c.emitBackupMetrics(ch, backups, guests)
}

func (c *ProxmoxCollector) fetchGuestsFallback(nodes []string, guests map[string]GuestInfo) {
	var guestsMutex sync.Mutex
	var wg sync.WaitGroup
	for _, node := range nodes {
		wg.Add(1)
		go func(nodeName string) {
			defer wg.Done()
			c.fetchNodeGuests(nodeName, guests, &guestsMutex)
		}(node)
	}
	wg.Wait()
}

func (c *ProxmoxCollector) fetchNodeGuests(nodeName string, guests map[string]GuestInfo, mu *sync.Mutex) {
	vmResult, err := fetchJSON[guestListResponse](c, apiPathf("/nodes/%s/qemu", nodeName))
	if err == nil {
		mu.Lock()
		for _, vm := range vmResult.Data {
			vmid := strconv.FormatInt(vm.VMID, 10)
			guests[vmid] = GuestInfo{Node: nodeName, Name: vm.Name, Type: "qemu"}
		}
		mu.Unlock()
	}

	lxcResult, err := fetchJSON[guestListResponse](c, apiPathf("/nodes/%s/lxc", nodeName))
	if err == nil {
		mu.Lock()
		for _, lxc := range lxcResult.Data {
			vmid := strconv.FormatInt(lxc.VMID, 10)
			guests[vmid] = GuestInfo{Node: nodeName, Name: lxc.Name, Type: "lxc"}
		}
		mu.Unlock()
	}
}

func (c *ProxmoxCollector) collectNodeBackups(nodeName string, totalGuests int, backups map[string]int64, backupsMutex *sync.Mutex) {
	tasksResult, err := fetchJSON[tasksResponse](c, fmt.Sprintf("/nodes/%s/tasks?typefilter=vzdump&limit=%d", nodeName, taskFetchLimit))
	if err != nil {
		return
	}

	var batchJobs []batchJob
	const maxBatchLogFetches = 5

	backupsMutex.Lock()
	for _, task := range tasksResult.Data {
		if task.Status != "OK" {
			continue
		}
		if task.ID != "" {
			if existing, ok := backups[task.ID]; !ok || task.EndTime > existing {
				backups[task.ID] = task.EndTime
			}
		} else if task.UPID != "" && len(batchJobs) < maxBatchLogFetches {
			batchJobs = append(batchJobs, batchJob{UPID: task.UPID, EndTime: task.EndTime})
		}
	}
	backupsMutex.Unlock()

	if len(batchJobs) > 0 {
		c.processBatchBackupJobs(nodeName, batchJobs, totalGuests, backups, backupsMutex)
	}
}

func (c *ProxmoxCollector) processBatchBackupJobs(nodeName string, batchJobs []batchJob, totalGuests int, backups map[string]int64, backupsMutex *sync.Mutex) {
	var batchWg sync.WaitGroup
	localBackups := make(map[string]int64)
	var localMutex sync.Mutex

	for _, job := range batchJobs {
		batchWg.Add(1)
		go func(upid string) {
			defer batchWg.Done()
			c.parseBackupLog(nodeName, upid, totalGuests, localBackups, &localMutex)
		}(job.UPID)
	}
	batchWg.Wait()

	backupsMutex.Lock()
	for vmid, ts := range localBackups {
		if existing, ok := backups[vmid]; !ok || ts > existing {
			backups[vmid] = ts
		}
	}
	backupsMutex.Unlock()
}

func (c *ProxmoxCollector) parseBackupLog(nodeName, upid string, totalGuests int, localBackups map[string]int64, localMutex *sync.Mutex) {
	logData, err := c.apiRequest(fmt.Sprintf("/nodes/%s/tasks/%s/log?limit=%d", nodeName, url.PathEscape(upid), maxLogLines))
	if err != nil {
		return
	}

	var logResult taskLogResponse
	if json.Unmarshal(logData, &logResult) != nil {
		return
	}

	var currentVMID string
	foundCount := 0
	for _, line := range logResult.Data {
		if match := backupFinishedRe.FindStringSubmatch(line.T); match != nil {
			currentVMID = match[1]
			continue
		}
		if currentVMID == "" || !strings.Contains(line.T, "Backup finished at") {
			continue
		}
		match := backupTimeRe.FindStringSubmatch(line.T)
		if match == nil {
			continue
		}
		t, err := time.Parse("2006-01-02 15:04:05", match[1])
		if err != nil {
			continue
		}
		timestamp := t.Unix()
		localMutex.Lock()
		if existing, ok := localBackups[currentVMID]; !ok || timestamp > existing {
			localBackups[currentVMID] = timestamp
			foundCount++
		}
		localMutex.Unlock()
		currentVMID = ""

		if foundCount >= totalGuests {
			break
		}
	}
}

func (c *ProxmoxCollector) emitBackupMetrics(ch chan<- prometheus.Metric, backups map[string]int64, guests map[string]GuestInfo) {
	for vmid, endtime := range backups {
		guest, ok := guests[vmid]
		if !ok {
			continue
		}
		labels := []string{guest.Node, vmid, guest.Name}
		if guest.Type == "qemu" {
			ch <- prometheus.MustNewConstMetric(c.vmLastBackup, prometheus.GaugeValue, float64(endtime), labels...)
		} else {
			ch <- prometheus.MustNewConstMetric(c.lxcLastBackup, prometheus.GaugeValue, float64(endtime), labels...)
		}
	}
}
