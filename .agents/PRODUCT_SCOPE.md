# Existing product scope

The shipped README and source code define the current feature inventory, not a new feature wish list.

- Proxmox API collectors: cluster/HA, nodes, QEMU/LXC guests, storage, ZFS pools, replication, backup timestamps and certificates as available through the configured ACLs.
- Local host collectors: ZFS ARC, disk I/O, lm-sensors and optional SMART JSON produced by a separately scheduled privileged helper.
- Server: configurable plain-HTTP Prometheus `/metrics`, `/health` and informational root endpoint.
- Configuration: YAML overrides environment defaults; Proxmox token and password authentication; TLS settings and request timeouts.
- Operations: standalone Go binary, systemd installation, Grafana dashboard, Prometheus example, self-update and release binaries/checksums for documented architectures.

Preserve metric families, names, labels, types, CLI/config keys, update expectations and documented failure semantics. An unapproved compatibility break is not routine maintenance. Do not add dependencies on a database, GUI, container platform or privileged HTTP server. Note known limitations honestly—for example, the README currently documents an ARMv7 self-update asset-name mismatch.
