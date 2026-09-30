# Proxmox VE Exporter
[![GitHub release](https://img.shields.io/github/release/bigtcze/pve-exporter.svg)](https://github.com/bigtcze/pve-exporter/releases)
[![License](https://img.shields.io/github/license/bigtcze/pve-exporter.svg)](LICENSE)

Prometheus exporter for Proxmox VE API metrics and local host hardware metrics, written in Go.

## Contents

- [Systemd Installation](#systemd-installation)
- [Updating](#updating)
- [Configuration](#configuration)
- [Local Hardware Setup](#local-hardware-setup)
- [Metrics](#metrics)
- [Grafana Dashboard](#grafana-dashboard)
- [Development](#development)
- [License](#license)

## Systemd Installation

The commands below use Bash, `curl`, `sha256sum`, and `sudo` on a Linux host with systemd.
The exporter serves plain HTTP on `:9221` with no endpoint authentication and connects to the Proxmox API over HTTPS on port `8006` by default.

### 1. Create a Proxmox User and API Token

In the Proxmox web interface:

1. Under Datacenter > Permissions > Users, create `monitoring@pve`.
2. Under Datacenter > Permissions, add a user permission for `monitoring@pve` with role `PVEAuditor`. Use path `/` and enable propagation for cluster-wide audit access, or choose narrower ACL paths for the resources you want to expose.
3. Under Datacenter > Permissions > API Tokens, create a token named `exporter` for that user. Disable Privilege Separation to inherit the user's permissions. If you keep it enabled, also assign ACLs to the token; its effective permissions are limited by both user and token ACLs.
4. Record the full token ID, `monitoring@pve!exporter`, and its secret, which is shown only when the token is created.

`PVEAuditor` grants audit privileges within the assigned ACL scope, not guaranteed access to every endpoint used by the exporter. Check service logs for permission failures and the resulting missing or partial metrics.

### 2. Install the Binary and Service Account

Choose the release asset for the exporter host:

| Linux Architecture | Asset |
|--------------------|-------|
| amd64 (x86-64) | `pve-exporter-linux-amd64` |
| arm64 (AArch64) | `pve-exporter-linux-arm64` |
| ARMv7 (32-bit) | `pve-exporter-linux-armv7` |

Set `asset` below to the matching name. The download resolves the latest release once, then fetches the binary and `checksums.txt` from that same release. A download or SHA256 failure stops installation.

```bash
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin pve-exporter

(
  set -euo pipefail
  asset=pve-exporter-linux-amd64
  repo=https://github.com/bigtcze/pve-exporter
  release_url=$(curl -fsSL -o /dev/null -w '%{url_effective}' "$repo/releases/latest")
  release=${release_url##*/}
  base="$repo/releases/download/$release"
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT

  curl -fsSL "$base/$asset" -o "$tmp/$asset"
  curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt"
  (cd "$tmp" && grep "  ${asset}$" checksums.txt | sha256sum --check --strict -)
  sudo install -o root -g root -m 0755 "$tmp/$asset" /usr/local/bin/pve-exporter
)
```

### 3. Create the Configuration

Replace the host and token secret before running this command. The file is created with owner `root`, group `pve-exporter`, and mode `0640` before credentials are written.

```bash
sudo install -d -o root -g pve-exporter -m 0750 /etc/pve-exporter
sudo install -o root -g pve-exporter -m 0640 /dev/null /etc/pve-exporter/config.yml
sudo tee /etc/pve-exporter/config.yml > /dev/null <<'EOF'
proxmox:
  host: "proxmox.example.com"
  port: 8006
  token_id: "monitoring@pve!exporter"
  token_secret: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  insecure_skip_verify: true
  timeout: 30s

server:
  listen_address: ":9221"
  metrics_path: "/metrics"
EOF
```

`insecure_skip_verify: true` is the intentional default for Proxmox installations using self-signed certificates. API traffic still uses HTTPS, but the certificate is not verified.

### 4. Create the Systemd Service

```bash
sudo tee /etc/systemd/system/pve-exporter.service > /dev/null <<'EOF'
[Unit]
Description=Proxmox VE Exporter for Prometheus
Documentation=https://github.com/bigtcze/pve-exporter
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pve-exporter
Group=pve-exporter
ExecStart=/usr/local/bin/pve-exporter -config /etc/pve-exporter/config.yml
Restart=on-failure
RestartSec=5

ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadOnlyPaths=/
ReadWritePaths=

[Install]
WantedBy=multi-user.target
EOF
```

### 5. Start, Verify, and Scrape

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pve-exporter
sudo systemctl status pve-exporter --no-pager
sudo journalctl -u pve-exporter -n 50 --no-pager
curl -fsS http://localhost:9221/metrics
```

Look for `pve_exporter_up 1`, build information, and the expected resource metrics. See [Exporter Metrics](#exporter-metrics) for the limits of the health indicators.

Add a scrape job to Prometheus, replacing the target with the exporter host:

```yaml
scrape_configs:
  - job_name: 'proxmox'
    static_configs:
      - targets: ['pve-exporter:9221']
    scrape_interval: 30s
    scrape_timeout: 10s
```

An example with target labels and relabeling is in [`examples/prometheus.yml`](examples/prometheus.yml). The scrape timeout covers the whole collection; `proxmox.timeout` applies to individual API requests. Check scrape duration when choosing the scrape timeout.

## Updating

### Self-Update

For the installation above on Linux amd64 or arm64:

```bash
sudo /usr/local/bin/pve-exporter -selfupdate
```

Self-update checks the latest GitHub release and requires a matching SHA256 entry in that release's `checksums.txt`. Missing checksums, failed downloads, or checksum mismatches abort the update.

It replaces only the executable you invoke, resolving symlinks to their target. It needs permission to create and rename files in that executable's directory; root is used above because `/usr/local/bin` is root-owned, not because self-update universally requires root.

After replacement, it makes a best-effort `systemctl restart pve-exporter` attempt. A restart failure prints a warning but does not undo the replacement. Other unit names or process supervisors need a manual restart. The temporary `.bak` file is removed after a successful replacement; no rollback backup is retained.

**ARMv7 requires manual updates.** Self-update looks for `pve-exporter-linux-arm`, but the release workflow publishes `pve-exporter-linux-armv7`.

### Manual Update

Use this fallback for ARMv7 or when self-update is unavailable. Set `asset` to the matching name from the installation table. This resolves one release for both downloads, verifies SHA256, then installs to a temporary sibling and renames it into place without overwriting the running executable's inode.

```bash
(
  set -euo pipefail
  asset=pve-exporter-linux-amd64
  repo=https://github.com/bigtcze/pve-exporter
  release_url=$(curl -fsSL -o /dev/null -w '%{url_effective}' "$repo/releases/latest")
  release=${release_url##*/}
  base="$repo/releases/download/$release"
  tmp=$(mktemp -d)
  staged=""
  trap 'rm -rf "$tmp"; if [ -n "$staged" ]; then sudo rm -f "$staged"; fi' EXIT

  curl -fsSL "$base/$asset" -o "$tmp/$asset"
  curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt"
  (cd "$tmp" && grep "  ${asset}$" checksums.txt | sha256sum --check --strict -)
  staged=$(sudo mktemp /usr/local/bin/.pve-exporter.XXXXXX)
  sudo install -o root -g root -m 0755 "$tmp/$asset" "$staged"
  sudo mv -fT "$staged" /usr/local/bin/pve-exporter
  staged=""
  sudo systemctl restart pve-exporter
)
```

To select a specific release instead of latest, replace the `release_url` and `release` assignments with `release=TAG`, using its published tag. Keep the binary and checksums on the same release.

### Verify the Running Version

After either update method, check the service and its live metrics:

```bash
sudo systemctl status pve-exporter --no-pager
sudo journalctl -u pve-exporter -n 50 --no-pager
curl -fsS http://localhost:9221/metrics | grep '^pve_exporter_build_info{'
```

Confirm the `version` label matches the intended release. `-version` reports the binary on disk, not necessarily the version still running in the service. If the automatic restart failed, run `sudo systemctl restart pve-exporter` and check again. Manual replacement also retains no rollback backup; an older release can be installed using the same matching-asset/checksum procedure.

## Configuration

Pass `-config /etc/pve-exporter/config.yml` to load YAML, or omit `-config` to use environment variables and defaults. Environment variables initialize the defaults; fields supplied in YAML override them. See [`config.example.yml`](config.example.yml) for a password-authentication example.

| YAML Option | Environment Variable | Default | Meaning |
|-------------|----------------------|---------|---------|
| `proxmox.host` | `PVE_HOST` | `localhost` | API hostname or IP address, without scheme or port |
| `proxmox.port` | None | `8006` | HTTPS API port; no `PVE_PORT` variable is supported |
| `proxmox.user` | `PVE_USER` | `root@pam` | Full `user@realm` name for password authentication |
| `proxmox.password` | `PVE_PASSWORD` | Empty | Password for that user |
| `proxmox.token_id` | `PVE_TOKEN_ID` | Empty | Full `user@realm!tokenname` token ID |
| `proxmox.token_secret` | `PVE_TOKEN_SECRET` | Empty | API token secret |
| `proxmox.realm` | `PVE_REALM` | `pam` | Stored setting; not used to change authentication |
| `proxmox.insecure_skip_verify` | `PVE_INSECURE_SKIP_VERIFY` | `true` | Skip verification of the API's TLS certificate |
| `proxmox.timeout` | None | `30s` | API request timeout; durations below `1s` reset to `30s` |
| `server.listen_address` | `LISTEN_ADDRESS` | `:9221` | Plain HTTP listen address |
| `server.metrics_path` | `METRICS_PATH` | `/metrics` | Metrics endpoint path, beginning with `/` |

Configure either a password or both token fields. A complete token pair takes precedence over a password. For password authentication, `proxmox.user` must include the realm, such as `monitoring@pve`; setting `proxmox.realm` does not append it. The `!` in a token ID is part of Proxmox token syntax.

For `PVE_INSECURE_SKIP_VERIFY`, `true`, `1`, and `yes` enable the option; any other nonempty value disables it. Restart the service after configuration changes; there is no runtime configuration reload.

## Local Hardware Setup

These optional collectors run on the exporter host, not through the Proxmox API. Local disk I/O and ZFS ARC statistics need no helper when their `/proc` files are readable.

### Sensors

Install `lm-sensors` and verify that the service user can run `/usr/bin/sensors -j`. On a Debian/Proxmox host:

```bash
sudo apt-get install lm-sensors
sudo -u pve-exporter /usr/bin/sensors -j
```

The exporter reads the available temperature, fan, voltage, and power readings on each scrape. If `sensors -j` fails, sensor metrics are omitted.

### SMART

The [`scripts/pve-smart-collector.sh`](scripts/pve-smart-collector.sh) script needs `smartmontools`, Python 3, and `lsblk`/`flock` from `util-linux`. It runs as root outside the unprivileged exporter and writes `/var/lib/pve-exporter/smart.json`.

Run the following from a checkout of this repository on the exporter host:

```bash
sudo apt-get install smartmontools python3 util-linux
sudo install -o root -g root -m 0755 scripts/pve-smart-collector.sh /usr/local/bin/pve-smart-collector.sh
sudo install -d -o root -g root -m 0755 /var/lib/pve-exporter
sudo tee /etc/cron.d/pve-smart-collector > /dev/null <<'EOF'
*/5 * * * * root /usr/local/bin/pve-smart-collector.sh
EOF
sudo chmod 0644 /etc/cron.d/pve-smart-collector
sudo /usr/local/bin/pve-smart-collector.sh
sudo -u pve-exporter test -r /var/lib/pve-exporter/smart.json
curl -fsS http://localhost:9221/metrics | grep '^pve_disk_'
```

Ensure cron is running. The script writes the data file with mode `0644`, so the exporter can read it. A missing file omits SMART metrics; a file whose modification time is more than 10 minutes old logs a warning and is skipped. Read and JSON errors are logged and also omit SMART metrics.

## Metrics

Metrics are exposed at `/metrics` by default. API collectors cover the nodes and resources visible to the configured credentials. ZFS ARC, `/proc/diskstats`, sensors, and SMART describe only the local exporter host. Their `node` labels use the local hostname (SMART uses the script's hostname, preferably an FQDN), which may differ from Proxmox API node names.

Availability depends on ACLs, API fields, guest state, and local data. Partial collector failures do not necessarily fail the HTTP scrape: resource-list failures can produce zero VM/LXC counts, HA lookup failures produce zero HA counts, missing numeric fields can become zero, and other failures omit metrics. Check logs alongside the metrics rather than treating every zero as an observed state.

If authentication or initial node discovery fails, all resource and local hardware collectors are skipped. Only exporter build, status, and scrape-duration metrics are exposed.

Cumulative I/O values are totals, not throughput; for example, `rate(pve_disk_read_bytes_total[5m])` gives bytes per second. A `_total` suffix alone does not establish the Prometheus type: CPU, node, and HA counts are gauges, while I/O totals are counters. PSI values are passed through from the API without scaling or conversion.

### Exporter Metrics

| Metric | Description |
|--------|-------------|
| `pve_exporter_up` | Gauge: 1 after authentication and initial node discovery succeed, 0 if either fails; later collector failures do not change it |
| `pve_exporter_build_info` | Gauge fixed at 1, with `version`, `commit`, and `goversion` labels for the running process |
| `pve_exporter_scrape_duration_seconds` | Gauge: elapsed collection time in seconds for the current scrape, including early authentication/discovery failures |

`/health` returns HTTP 200 while the process can serve HTTP requests. It does not check API access or collector results.

### Node Metrics

Label: `node` from the Proxmox API. Detailed metrics require a successful node status request; VM/LXC counts include stopped guests.

| Metric | Description |
|--------|-------------|
| `pve_node_up` | Node status (1=online) |
| `pve_node_uptime_seconds` | Node uptime in seconds |
| `pve_node_cpu_load` | CPU usage fraction (0-1), not a load average |
| `pve_node_cpus_total` | Number of logical CPUs (gauge) |
| `pve_node_memory_total_bytes` | Total memory in bytes |
| `pve_node_memory_used_bytes` | Used memory in bytes |
| `pve_node_memory_free_bytes` | Free memory in bytes |
| `pve_node_swap_total_bytes` | Total swap in bytes |
| `pve_node_swap_used_bytes` | Used swap in bytes |
| `pve_node_swap_free_bytes` | Free swap in bytes |
| `pve_node_vm_count` | Number of QEMU VMs |
| `pve_node_lxc_count` | Number of LXC containers |
| `pve_node_load1` | 1-minute load average, not a percentage |
| `pve_node_load5` | 5-minute load average, not a percentage |
| `pve_node_load15` | 15-minute load average, not a percentage |
| `pve_node_iowait` | I/O wait ratio |
| `pve_node_idle` | Idle CPU ratio |
| `pve_node_cpu_mhz` | CPU frequency in MHz |
| `pve_node_rootfs_total_bytes` | Root filesystem total size in bytes |
| `pve_node_rootfs_used_bytes` | Root filesystem used bytes |
| `pve_node_rootfs_free_bytes` | Root filesystem free bytes |
| `pve_node_cpu_cores` | CPU core count reported by the API |
| `pve_node_cpu_sockets` | Number of CPU sockets |
| `pve_node_ksm_shared_bytes` | KSM shared memory in bytes |

### VM Metrics (QEMU)

Labels: `node`, `vmid`, `name`. Block metrics add `device`; NIC metrics add `interface`.
Balloon, free/host memory, HA, PID, PSI, block, and NIC metrics require a running VM and a successful status response. Block/NIC series exist only for returned devices/interfaces; missing numeric fields in the status response can be zero.

| Metric | Description |
|--------|-------------|
| `pve_vm_status` | VM status (1=running, 0=stopped) |
| `pve_vm_uptime_seconds` | VM uptime in seconds |
| `pve_vm_cpu_usage` | VM CPU usage (0.0-1.0) |
| `pve_vm_cpus` | Number of CPUs allocated |
| `pve_vm_memory_used_bytes` | Used memory in bytes |
| `pve_vm_memory_max_bytes` | Maximum configured memory in bytes |
| `pve_vm_memory_free_bytes` | Free memory reported by the API in bytes (`freemem`) |
| `pve_vm_memory_host_bytes` | Host memory allocation in bytes |
| `pve_vm_balloon_bytes` | Balloon target in bytes |
| `pve_vm_balloon_actual_bytes` | Actual balloon memory in bytes |
| `pve_vm_balloon_max_bytes` | Maximum balloon memory in bytes |
| `pve_vm_balloon_total_bytes` | Total guest memory from balloon statistics in bytes |
| `pve_vm_balloon_major_page_faults_total` | Cumulative major page faults |
| `pve_vm_balloon_minor_page_faults_total` | Cumulative minor page faults |
| `pve_vm_balloon_mem_swapped_in_bytes` | Cumulative swapped-in memory in bytes (gauge) |
| `pve_vm_balloon_mem_swapped_out_bytes` | Cumulative swapped-out memory in bytes (gauge) |
| `pve_vm_disk_max_bytes` | Maximum disk size reported by the API in bytes |
| `pve_vm_network_in_bytes_total` | Cumulative received network bytes |
| `pve_vm_network_out_bytes_total` | Cumulative transmitted network bytes |
| `pve_vm_disk_read_bytes_total` | Cumulative disk read bytes |
| `pve_vm_disk_write_bytes_total` | Cumulative disk written bytes |
| `pve_vm_ha_managed` | Managed by HA (1=yes) |
| `pve_vm_pid` | Process ID |
| `pve_vm_pressure_cpu_full` | API CPU pressure full value (unscaled) |
| `pve_vm_pressure_cpu_some` | API CPU pressure some value (unscaled) |
| `pve_vm_pressure_io_full` | API I/O pressure full value (unscaled) |
| `pve_vm_pressure_io_some` | API I/O pressure some value (unscaled) |
| `pve_vm_pressure_memory_full` | API memory pressure full value (unscaled) |
| `pve_vm_pressure_memory_some` | API memory pressure some value (unscaled) |
| `pve_vm_block_read_bytes_total` | Cumulative block device read bytes |
| `pve_vm_block_write_bytes_total` | Cumulative block device written bytes |
| `pve_vm_block_read_ops_total` | Cumulative block device read operations |
| `pve_vm_block_write_ops_total` | Cumulative block device write operations |
| `pve_vm_block_failed_read_ops_total` | Cumulative failed block device read operations |
| `pve_vm_block_failed_write_ops_total` | Cumulative failed block device write operations |
| `pve_vm_block_flush_ops_total` | Cumulative block device flush operations |
| `pve_vm_nic_in_bytes_total` | Cumulative received NIC bytes |
| `pve_vm_nic_out_bytes_total` | Cumulative transmitted NIC bytes |
| `pve_vm_last_backup_timestamp` | Latest discovered successful backup, Unix seconds; see [Backup Timestamps](#backup-timestamps) |

### LXC Metrics (Containers)

Labels: `node`, `vmid`, `name`. Swap, HA, PID, and PSI metrics require a running container and a successful status response. PSI series are emitted only when their API values parse as numbers; other missing numeric fields can be zero.

| Metric | Description |
|--------|-------------|
| `pve_lxc_status` | LXC status (1=running, 0=stopped) |
| `pve_lxc_uptime_seconds` | LXC uptime in seconds |
| `pve_lxc_cpu_usage` | LXC CPU usage (0.0-1.0) |
| `pve_lxc_cpus` | Number of CPUs allocated |
| `pve_lxc_memory_used_bytes` | Used memory in bytes |
| `pve_lxc_memory_max_bytes` | Maximum configured memory in bytes |
| `pve_lxc_disk_used_bytes` | Used disk space in bytes |
| `pve_lxc_disk_max_bytes` | Total disk space in bytes |
| `pve_lxc_swap_used_bytes` | Used swap in bytes |
| `pve_lxc_swap_max_bytes` | Maximum swap in bytes |
| `pve_lxc_network_in_bytes_total` | Cumulative received network bytes |
| `pve_lxc_network_out_bytes_total` | Cumulative transmitted network bytes |
| `pve_lxc_disk_read_bytes_total` | Cumulative disk read bytes |
| `pve_lxc_disk_write_bytes_total` | Cumulative disk written bytes |
| `pve_lxc_ha_managed` | Managed by HA (1=yes) |
| `pve_lxc_pid` | Process ID |
| `pve_lxc_pressure_cpu_full` | API CPU pressure full value (unscaled) |
| `pve_lxc_pressure_cpu_some` | API CPU pressure some value (unscaled) |
| `pve_lxc_pressure_io_full` | API I/O pressure full value (unscaled) |
| `pve_lxc_pressure_io_some` | API I/O pressure some value (unscaled) |
| `pve_lxc_pressure_memory_full` | API memory pressure full value (unscaled) |
| `pve_lxc_pressure_memory_some` | API memory pressure some value (unscaled) |
| `pve_lxc_last_backup_timestamp` | Latest discovered successful backup, Unix seconds; see [Backup Timestamps](#backup-timestamps) |

#### Backup Timestamps

Backup collection examines up to 50 recent `vzdump` tasks per node and at most five successful batch-task logs per node. It emits the latest successful backup timestamp it discovers for each known guest. If none is found, the series is omitted, not set to zero. This is a bounded task-history lookup, not a complete backup or Proxmox Backup Server inventory.

Single-guest tasks use the API's `endtime`. Batch-log completion times are parsed as UTC; if a log uses another local timezone, the exported timestamp can be offset.

### Storage Metrics

Labels: `node`, `storage`, `type`. Values come from each node's storage API response; an inaccessible storage endpoint omits that node's storage metrics.

| Metric | Description |
|--------|-------------|
| `pve_storage_total_bytes` | Total storage size in bytes |
| `pve_storage_used_bytes` | Used storage in bytes |
| `pve_storage_available_bytes` | Available storage in bytes |
| `pve_storage_active` | Storage is active (1=yes) |
| `pve_storage_enabled` | Storage is enabled (1=yes) |
| `pve_storage_shared` | Storage is shared (1=yes) |
| `pve_storage_used_fraction` | Used fraction (0.0-1.0) |

### ZFS Metrics

Pool metrics come from the API with labels `node`, `pool`. ARC metrics come from the local `/proc/spl/kstat/zfs/arcstats` file with label `node` and are omitted when that file is unavailable. ARC hit ratio uses cumulative hits and misses, not a recent time window.

| Metric | Description |
|--------|-------------|
| `pve_zfs_pool_health_status` | Pool health (1=ONLINE, 0=other) |
| `pve_zfs_pool_size_bytes` | Pool total size in bytes |
| `pve_zfs_pool_alloc_bytes` | Pool allocated bytes |
| `pve_zfs_pool_free_bytes` | Pool free bytes |
| `pve_zfs_pool_frag_percent` | Pool fragmentation in percent |
| `pve_zfs_arc_size_bytes` | ARC size in bytes |
| `pve_zfs_arc_min_size_bytes` | ARC minimum size in bytes |
| `pve_zfs_arc_max_size_bytes` | ARC maximum size in bytes |
| `pve_zfs_arc_hits_total` | Cumulative ARC hits |
| `pve_zfs_arc_misses_total` | Cumulative ARC misses |
| `pve_zfs_arc_hit_ratio_percent` | ARC hit ratio in percent (0-100), emitted when hits + misses > 0 |
| `pve_zfs_arc_target_size_bytes` | ARC target size (`c`) in bytes |
| `pve_zfs_arc_l2_hits_total` | Cumulative L2ARC hits |
| `pve_zfs_arc_l2_misses_total` | Cumulative L2ARC misses |
| `pve_zfs_arc_l2_size_bytes` | L2ARC size in bytes |
| `pve_zfs_arc_l2_header_size_bytes` | L2ARC header size in bytes |

### Cluster/HA Metrics

No exporter-defined labels. If the status response has no cluster entry, quorum is reported as 1 and the node entries supply the total count. HA lookup failures produce zero HA counts.

| Metric | Description |
|--------|-------------|
| `pve_cluster_quorate` | Cluster has quorum (1=yes, 0=no) |
| `pve_cluster_nodes_total` | Number of nodes in cluster (gauge) |
| `pve_cluster_nodes_online` | Number of online nodes |
| `pve_ha_resources_total` | Number of HA-managed resources (gauge) |
| `pve_ha_resources_active` | Number of HA resources with reported state `started`, not a health check |

### Replication Metrics

Labels: `guest`, `job`. An inaccessible replication endpoint omits these metrics.

| Metric | Description |
|--------|-------------|
| `pve_replication_last_sync_timestamp` | Last successful sync in Unix seconds, emitted only when the API timestamp is positive |
| `pve_replication_duration_seconds` | Duration of the last replication in seconds |
| `pve_replication_status` | 0 if failure count is positive or an error is present, otherwise 1 |

### Certificate Metrics

Label: `node`. One certificate is selected per node: the first API entry named `pveproxy-ssl.pem` or `pve-ssl.pem`, otherwise the first returned certificate. This is not a series for every certificate; an empty or inaccessible response omits it.

| Metric | Description |
|--------|-------------|
| `pve_certificate_expiry_seconds` | Seconds until the selected certificate expires; negative when expired |

### Hardware Sensor Metrics

Labels: `node`, `chip`, `adapter`, `sensor`. Metrics require local readings from [`sensors -j`](#sensors).

| Metric | Description |
|--------|-------------|
| `pve_sensor_temperature_celsius` | Temperature reading in Celsius |
| `pve_sensor_fan_rpm` | Fan speed in RPM |
| `pve_sensor_voltage_volts` | Voltage reading in volts |
| `pve_sensor_power_watts` | Power reading in watts |

### Disk Metrics

#### Disk I/O

Labels: `node`, `device`. These local metrics require readable `/proc/diskstats`, not root privileges. The collector filters partition-like names and the `loop`, `ram`, `zd`, and `dm-` device prefixes.

| Metric | Description |
|--------|-----------|
| `pve_disk_read_bytes_total` | Total bytes read from disk |
| `pve_disk_write_bytes_total` | Total bytes written to disk |
| `pve_disk_reads_completed_total` | Total read operations |
| `pve_disk_writes_completed_total` | Total write operations |
| `pve_disk_io_time_seconds_total` | Cumulative time spent doing I/O in seconds |

#### Disk SMART

Labels: `node`, `device`, `model`, `serial`, `type`. These metrics require the local data file described in [SMART Setup](#smart). Temperature, power-on hours, written bytes, and available spare are emitted only when positive; NVMe percentage used can be zero.

| Metric | Description |
|--------|-----------|
| `pve_disk_temperature_celsius` | Disk temperature in Celsius |
| `pve_disk_power_on_hours` | Power-on time in hours |
| `pve_disk_health_status` | 1=healthy, 0=failing; the script defaults to 1 if SMART provides no pass/fail field |
| `pve_disk_data_written_bytes` | Cumulative NVMe written bytes, converted from data units written (512000 bytes per unit) |
| `pve_disk_available_spare_percent` | NVMe available spare in percent |
| `pve_disk_percentage_used` | NVMe estimated percentage of endurance used |

## Grafana Dashboard

Import dashboard [24550 from Grafana.com](https://grafana.com/grafana/dashboards/24550), or import [`grafana/pve-exporter.json`](grafana/pve-exporter.json).

## Development

Requires Go 1.27 or newer and `make`. From the repository root:

```bash
make build
make test
```

## License

MIT License - see [LICENSE](LICENSE) for details.
