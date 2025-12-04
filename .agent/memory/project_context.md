# Project Context: Proxmox Exporter for Prometheus

## Overview

The Proxmox Exporter is a specialized Prometheus exporter written in Go that collects metrics from Proxmox Virtual Environment (PVE) and exposes them in Prometheus format. It replicates the same metrics that Proxmox sends to InfluxDB, with additional comprehensive ZFS statistics.

## Architecture

### Components

1. **Main Application** (`main.go`)
   - HTTP server setup with graceful shutdown
   - Prometheus registry initialization
   - Collector registration
   - Health and metrics endpoints

2. **Configuration** (`config/config.go`)
   - Multi-source configuration (file, env vars, flags)
   - YAML-based config file support
   - Environment variable overrides
   - Validation logic

3. **Proxmox Collector** (`collector/proxmox.go`)
   - Proxmox API client with authentication (password and token)
   - Node metrics collection
   - VM/Container metrics collection
   - Storage metrics collection
   - Implements `prometheus.Collector` interface

4. **ZFS Collector** (`collector/zfs.go`)
   - Reads ZFS kstat files from `/proc/spl/kstat/zfs/`
   - ARC statistics (hit/miss ratios, sizes, throttling)
   - Pool metrics (health, capacity, fragmentation)
   - Implements `prometheus.Collector` interface

## Design Decisions

### Authentication
- Supports both password and API token authentication
- Token authentication is recommended for production
- TLS verification can be disabled for self-signed certificates

### Metrics Collection
- Pull-based model (Prometheus scrapes the exporter)
- Metrics collected on-demand during scrape
- No local caching to ensure fresh data

### ZFS Integration
- Reads directly from kernel statistics files
- Gracefully handles missing ZFS (returns no metrics)
- Can be disabled via configuration

### Systemd Deployment
- Single static binary installed to `/usr/local/bin/`
- Runs under dedicated non-root user (`pve-exporter`)
- Config file at `/etc/pve-exporter/config.yml` with restricted permissions
- Systemd service with security hardening (NoNewPrivileges, ProtectSystem, etc.)
- Multi-architecture builds (amd64, arm64, armv7)

## Metric Naming Convention

All metrics follow Prometheus naming best practices:

- **Proxmox metrics**: Prefixed with `pve_`
- **ZFS metrics**: Prefixed with `zfs_`
- **Counters**: Suffixed with `_total`
- **Bytes**: Suffixed with `_bytes`
- **Percentages**: Suffixed with `_percent`
- **Seconds**: Suffixed with `_seconds`

## Labels

Metrics include relevant labels for filtering:
- `node`: Proxmox node name
- `type`: Resource type (qemu, lxc)
- `vmid`: VM/Container ID
- `name`: VM/Container name
- `storage`: Storage name
- `pool`: ZFS pool name

## Future Enhancements

Potential areas for expansion:
- Cluster-wide metrics aggregation
- Additional ZFS dataset-level metrics
- L2ARC statistics
- VDEV-level metrics
- Backup job metrics
- Certificate metrics
