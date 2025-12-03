# Proxmox VE Exporter

[![Go Report Card](https://goreportcard.com/badge/github.com/bigtcze/pve-exporter)](https://goreportcard.com/report/github.com/bigtcze/pve-exporter)
[![GitHub release](https://img.shields.io/github/release/bigtcze/pve-exporter.svg)](https://github.com/bigtcze/pve-exporter/releases)
[![License](https://img.shields.io/github/license/bigtcze/pve-exporter.svg)](LICENSE)

A professional Prometheus exporter for Proxmox VE, written in Go. It collects comprehensive metrics from your Proxmox nodes, virtual machines (QEMU), LXC containers, and storage, exposing them for monitoring and alerting.

## 🚀 Features

- **Comprehensive Metrics**:
  - **Node**: CPU, Memory, Uptime, Status.
  - **VM (QEMU)**: CPU, Memory, Disk, Network I/O, Uptime, Status.
  - **LXC Containers**: CPU, Memory, Disk, Network I/O, Uptime, Status.
  - **Storage**: Usage, Availability, Total size.
- **Secure**: Supports API Token authentication (recommended) and standard password auth.
- **Lightweight**: Built as a single binary or minimal Docker container.
- **Easy Configuration**: Configure via environment variables or YAML file.

## ⚡ Quick Start

### Docker

```bash
docker run -d \
  -p 9221:9221 \
  -e PVE_USER="root@pam" \
  -e PVE_PASSWORD="your-password" \
  -e PVE_HOST="proxmox.example.com" \
  --name pve-exporter \
  ghcr.io/bigtcze/pve-exporter:latest
```

### Binary

```bash
# Download latest release
wget https://github.com/bigtcze/pve-exporter/releases/latest/download/pve-exporter_linux_amd64
chmod +x pve-exporter_linux_amd64

# Run
./pve-exporter_linux_amd64 -config config.yml
```

## ⚙️ Configuration

You can configure the exporter using a `config.yml` file or environment variables.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PVE_HOST` | Proxmox host address | `localhost` |
| `PVE_USER` | Proxmox user | `root@pam` |
| `PVE_PASSWORD` | Proxmox password | - |
| `PVE_TOKEN_ID` | API token ID (alternative to password) | - |
| `PVE_TOKEN_SECRET` | API token secret | - |
| `PVE_INSECURE_SKIP_VERIFY` | Skip TLS verification | `true` |
| `LISTEN_ADDRESS` | HTTP server listen address | `:9221` |
| `METRICS_PATH` | Metrics endpoint path | `/metrics` |

### Configuration File (`config.yml`)

```yaml
proxmox:
  host: "proxmox.example.com"
  port: 8006
  user: "root@pam"
  # Recommended: Use API Token instead of password
  token_id: "monitoring@pve!exporter"
  token_secret: "your-token-secret"
  insecure_skip_verify: true

server:
  listen_address: ":9221"
  metrics_path: "/metrics"
```

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
| `pve_node_vm_count` | Number of QEMU VMs |
| `pve_node_lxc_count` | Number of LXC containers |

### VM Metrics (QEMU)

| Metric | Description |
|--------|-------------|
| `pve_vm_status` | VM status (1=running, 0=stopped) |
| `pve_vm_uptime_seconds` | VM uptime in seconds |
| `pve_vm_cpu_usage` | VM CPU usage (0.0-1.0) |
| `pve_vm_cpus` | Number of CPUs allocated |
| `pve_vm_memory_used_bytes` | Used memory in bytes |
| `pve_vm_memory_max_bytes` | Total memory in bytes |
| `pve_vm_disk_used_bytes` | Used disk space in bytes |
| `pve_vm_disk_max_bytes` | Total disk space in bytes |
| `pve_vm_network_in_bytes_total` | Network input bytes |
| `pve_vm_network_out_bytes_total` | Network output bytes |
| `pve_vm_disk_read_bytes_total` | Disk read bytes |
| `pve_vm_disk_write_bytes_total` | Disk write bytes |
| `pve_guest_last_backup_timestamp_seconds` | Timestamp of the last backup |

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
| `pve_lxc_network_in_bytes_total` | Network input bytes |
| `pve_lxc_network_out_bytes_total` | Network output bytes |
| `pve_lxc_disk_read_bytes_total` | Disk read bytes |
| `pve_lxc_disk_write_bytes_total` | Disk write bytes |
| `pve_guest_last_backup_timestamp_seconds` | Timestamp of the last backup |

### Storage Metrics

| Metric | Description |
|--------|-------------|
| `pve_storage_total_bytes` | Total storage size in bytes |
| `pve_storage_used_bytes` | Used storage in bytes |
| `pve_storage_available_bytes` | Available storage in bytes |

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
