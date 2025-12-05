# Proxmox VE Exporter
[![Go Report Card](https://goreportcard.com/badge/github.com/bigtcze/pve-exporter)](https://goreportcard.com/report/github.com/bigtcze/pve-exporter)
[![GitHub release](https://img.shields.io/github/release/bigtcze/pve-exporter.svg)](https://github.com/bigtcze/pve-exporter/releases)
[![License](https://img.shields.io/github/license/bigtcze/pve-exporter.svg)](LICENSE)

A professional Prometheus exporter for Proxmox VE, written in Go. It collects comprehensive metrics from your Proxmox nodes, virtual machines (QEMU), LXC containers, and storage, exposing them for monitoring and alerting.

## 🚀 Features

- **Comprehensive Metrics**:
  - **Node**: CPU, Memory, Uptime, Status, VM/LXC counts.
  - **VM (QEMU)**: CPU, Memory, Disk, Network I/O, Uptime, Status.
  - **LXC Containers**: CPU, Memory, Disk, Network I/O, Uptime, Status.
  - **Storage**: Usage, Availability, Total size.
- **Secure**: Supports API Token authentication (recommended) and standard password auth.
- **Lightweight**: Single static binary, runs as systemd service.
- **Easy Configuration**: Configure via environment variables or YAML file.

## ⚡ Quick Start

### Download Binary

```bash
# Download latest release
wget https://github.com/bigtcze/pve-exporter/releases/latest/download/pve-exporter-linux-amd64
chmod +x pve-exporter-linux-amd64

# Run manually
./pve-exporter-linux-amd64 -config config.yml
```

### CLI Commands

| Command | Description |
|---------|-------------|
| `-version` | Print version and exit |
| `-selfupdate` | Update to latest version from GitHub and restart service |

**Self-update:**
```bash
# Update to latest version (run as root)
sudo pve-exporter -selfupdate
```

> **Note:** `-selfupdate` requires root privileges because it:
> - Replaces the binary in `/usr/local/bin/`
> - Runs `systemctl restart pve-exporter` to apply the update



## 🔧 Systemd Service Installation

For production use, install the exporter as a systemd service running under a dedicated user.

### 1. Create dedicated user

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin pve-exporter
```

### 2. Install binary

```bash
sudo wget -O /usr/local/bin/pve-exporter \
  https://github.com/bigtcze/pve-exporter/releases/latest/download/pve-exporter-linux-amd64
sudo chmod +x /usr/local/bin/pve-exporter
```

### 3. Create configuration

```bash
sudo mkdir -p /etc/pve-exporter
sudo cat > /etc/pve-exporter/config.yml << 'EOF'
proxmox:
  host: "proxmox.example.com"
  port: 8006
  
  # Option A: Password authentication
  user: "monitoring@pve"
  password: "your-password"
  
  # Option B: API Token authentication (recommended, comment out user/password above)
  # token_id: "monitoring@pve!exporter"
  # token_secret: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  
  insecure_skip_verify: true

server:
  listen_address: ":9221"
  metrics_path: "/metrics"
EOF

# Secure the config file (contains credentials)
sudo chown root:pve-exporter /etc/pve-exporter/config.yml
sudo chmod 640 /etc/pve-exporter/config.yml
```

> **Note:** The `token_id` format is `user@realm!tokenname` - the exclamation mark is Proxmox syntax, not an error.

### 4. Create systemd service

```bash
sudo cat > /etc/systemd/system/pve-exporter.service << 'EOF'
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

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadOnlyPaths=/
ReadWritePaths=

[Install]
WantedBy=multi-user.target
EOF
```

### 5. Start and enable service

```bash
sudo systemctl daemon-reload
sudo systemctl enable pve-exporter
sudo systemctl start pve-exporter

# Check status
sudo systemctl status pve-exporter

# View logs
sudo journalctl -u pve-exporter -f
```

## ⚙️ Configuration

### Configuration File Options

| Option | Description | Default |
|--------|-------------|---------|
| `proxmox.host` | Proxmox host address | `localhost` |
| `proxmox.port` | Proxmox API port | `8006` |
| `proxmox.user` | Proxmox user (for password auth) | `root@pam` |
| `proxmox.password` | Proxmox password | - |
| `proxmox.token_id` | API token ID (alternative to password) | - |
| `proxmox.token_secret` | API token secret | - |
| `proxmox.insecure_skip_verify` | Skip TLS verification | `true` |
| `server.listen_address` | HTTP server listen address | `:9221` |
| `server.metrics_path` | Metrics endpoint path | `/metrics` |

### Environment Variables

As an alternative to a config file, you can use environment variables:

| Variable | Config equivalent |
|----------|------------------|
| `PVE_HOST` | `proxmox.host` |
| `PVE_USER` | `proxmox.user` |
| `PVE_PASSWORD` | `proxmox.password` |
| `PVE_TOKEN_ID` | `proxmox.token_id` |
| `PVE_TOKEN_SECRET` | `proxmox.token_secret` |
| `PVE_INSECURE_SKIP_VERIFY` | `proxmox.insecure_skip_verify` |
| `LISTEN_ADDRESS` | `server.listen_address` |
| `METRICS_PATH` | `server.metrics_path` |

## 📈 Grafana Dashboard

Import the official dashboard from Grafana.com: 24512
Or import manually from [`grafana/pve-exporter.json`](grafana/pve-exporter.json)

**Features:**
- Cluster overview with node/VM/LXC counts
- Per-node CPU, Memory, Load, and Filesystem metrics
- VM and LXC tables with status, CPU, memory, uptime
- Network and Disk I/O graphs
- Storage usage visualization
- ZFS pool health, fragmentation, and ARC statistics

## 📊 Metrics

The exporter exposes the following metrics at `/metrics`.

### Node Metrics

| Metric | Description |
|--------|-------------|
| `pve_node_up` | Node status (1=online) |
| `pve_node_uptime_seconds` | Node uptime in seconds |
| `pve_node_cpu_load` | Node CPU load |
| `pve_node_cpus_total` | Total number of CPUs |
| `pve_node_memory_total_bytes` | Total memory in bytes |
| `pve_node_memory_used_bytes` | Used memory in bytes |
| `pve_node_memory_free_bytes` | Free memory in bytes |
| `pve_node_swap_total_bytes` | Total swap in bytes |
| `pve_node_swap_used_bytes` | Used swap in bytes |
| `pve_node_swap_free_bytes` | Free swap in bytes |
| `pve_node_vm_count` | Number of QEMU VMs |
| `pve_node_lxc_count` | Number of LXC containers |
| `pve_node_load1` | Load average 1 minute |
| `pve_node_load5` | Load average 5 minutes |
| `pve_node_load15` | Load average 15 minutes |
| `pve_node_iowait` | I/O wait ratio |
| `pve_node_idle` | Idle CPU ratio |
| `pve_node_cpu_mhz` | CPU frequency in MHz |
| `pve_node_rootfs_total_bytes` | Root filesystem total size |
| `pve_node_rootfs_used_bytes` | Root filesystem used |
| `pve_node_rootfs_free_bytes` | Root filesystem free |
| `pve_node_cpu_cores` | CPU cores per socket |
| `pve_node_cpu_sockets` | Number of CPU sockets |
| `pve_node_ksm_shared_bytes` | KSM shared memory |

### VM Metrics (QEMU)

| Metric | Description |
|--------|-------------|
| `pve_vm_status` | VM status (1=running, 0=stopped) |
| `pve_vm_uptime_seconds` | VM uptime in seconds |
| `pve_vm_cpu_usage` | VM CPU usage (0.0-1.0) |
| `pve_vm_cpus` | Number of CPUs allocated |
| `pve_vm_memory_used_bytes` | Used memory in bytes |
| `pve_vm_memory_max_bytes` | Total memory in bytes |
| `pve_vm_memory_free_bytes` | Free memory (guest agent) |
| `pve_vm_memory_host_bytes` | Host memory allocation |
| `pve_vm_balloon_bytes` | Balloon target in bytes |
| `pve_vm_balloon_actual_bytes` | Balloon actual memory |
| `pve_vm_balloon_max_bytes` | Balloon max memory |
| `pve_vm_balloon_total_bytes` | Balloon total guest memory |
| `pve_vm_balloon_major_page_faults_total` | Major page faults |
| `pve_vm_balloon_minor_page_faults_total` | Minor page faults |
| `pve_vm_balloon_mem_swapped_in_bytes` | Memory swapped in |
| `pve_vm_balloon_mem_swapped_out_bytes` | Memory swapped out |
| `pve_vm_disk_max_bytes` | Total disk space in bytes |
| `pve_vm_network_in_bytes_total` | Network input bytes |
| `pve_vm_network_out_bytes_total` | Network output bytes |
| `pve_vm_disk_read_bytes_total` | Disk read bytes |
| `pve_vm_disk_write_bytes_total` | Disk write bytes |
| `pve_vm_ha_managed` | Managed by HA (1=yes) |
| `pve_vm_pid` | Process ID |
| `pve_vm_pressure_cpu_full` | CPU pressure full |
| `pve_vm_pressure_cpu_some` | CPU pressure some |
| `pve_vm_pressure_io_full` | I/O pressure full |
| `pve_vm_pressure_io_some` | I/O pressure some |
| `pve_vm_pressure_memory_full` | Memory pressure full |
| `pve_vm_pressure_memory_some` | Memory pressure some |
| `pve_vm_block_read_bytes_total` | Block device read bytes (label: device) |
| `pve_vm_block_write_bytes_total` | Block device write bytes (label: device) |
| `pve_vm_block_read_ops_total` | Block device read ops (label: device) |
| `pve_vm_block_write_ops_total` | Block device write ops (label: device) |
| `pve_vm_block_failed_read_ops_total` | Block device failed read ops (label: device) |
| `pve_vm_block_failed_write_ops_total` | Block device failed write ops (label: device) |
| `pve_vm_block_flush_ops_total` | Block device flush ops (label: device) |
| `pve_vm_nic_in_bytes_total` | NIC input bytes (label: interface) |
| `pve_vm_nic_out_bytes_total` | NIC output bytes (label: interface) |

### LXC Metrics (Containers)

| Metric | Description |
|--------|-------------|
| `pve_lxc_status` | LXC status (1=running, 0=stopped) |
| `pve_lxc_uptime_seconds` | LXC uptime in seconds |
| `pve_lxc_cpu_usage` | LXC CPU usage (0.0-1.0) |
| `pve_lxc_cpus` | Number of CPUs allocated |
| `pve_lxc_memory_used_bytes` | Used memory in bytes |
| `pve_lxc_memory_max_bytes` | Total memory in bytes |
| `pve_lxc_disk_used_bytes` | Used disk space in bytes |
| `pve_lxc_disk_max_bytes` | Total disk space in bytes |
| `pve_lxc_swap_used_bytes` | Used swap in bytes |
| `pve_lxc_swap_max_bytes` | Maximum swap in bytes |
| `pve_lxc_network_in_bytes_total` | Network input bytes |
| `pve_lxc_network_out_bytes_total` | Network output bytes |
| `pve_lxc_disk_read_bytes_total` | Disk read bytes |
| `pve_lxc_disk_write_bytes_total` | Disk write bytes |
| `pve_lxc_ha_managed` | Managed by HA (1=yes) |
| `pve_lxc_pid` | Process ID |
| `pve_lxc_pressure_cpu_full` | CPU pressure full |
| `pve_lxc_pressure_cpu_some` | CPU pressure some |
| `pve_lxc_pressure_io_full` | I/O pressure full |
| `pve_lxc_pressure_io_some` | I/O pressure some |
| `pve_lxc_pressure_memory_full` | Memory pressure full |
| `pve_lxc_pressure_memory_some` | Memory pressure some |

### Storage Metrics

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

| Metric | Description |
|--------|-------------|
| `pve_zfs_pool_health_status` | Pool health (1=ONLINE) |
| `pve_zfs_pool_size_bytes` | Pool total size |
| `pve_zfs_pool_alloc_bytes` | Pool allocated size |
| `pve_zfs_pool_free_bytes` | Pool free size |
| `pve_zfs_pool_frag_percent` | Pool fragmentation % |
| `pve_zfs_arc_size_bytes` | ARC size in bytes |
| `pve_zfs_arc_min_size_bytes` | ARC min size |
| `pve_zfs_arc_max_size_bytes` | ARC max size |
| `pve_zfs_arc_hits_total` | ARC hits |
| `pve_zfs_arc_misses_total` | ARC misses |
| `pve_zfs_arc_hit_ratio_percent` | ARC hit ratio in percent (0-100) |
| `pve_zfs_arc_target_size_bytes` | ARC target size (c) |
| `pve_zfs_arc_l2_hits_total` | L2ARC hits |
| `pve_zfs_arc_l2_misses_total` | L2ARC misses |
| `pve_zfs_arc_l2_size_bytes` | L2ARC size |
| `pve_zfs_arc_l2_header_size_bytes` | L2ARC header size |

## 🔒 Authentication & Permissions

For security best practices, create a dedicated monitoring user with **read-only** permissions.

1. **Create User**: `monitoring@pve`
2. **Assign Role**: `PVEAuditor` (provides read-only access to Nodes, VMs, Storage)
3. **Create API Token**: `monitoring@pve!exporter` (uncheck "Privilege Separation")

## 🛠️ Development

```bash
# Clone
git clone https://github.com/bigtcze/pve-exporter.git
cd pve-exporter

# Build
go build -o pve-exporter .

# Test
go test ./...
```

## 🤝 Contributing

Contributions are welcome! Please submit a Pull Request.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

