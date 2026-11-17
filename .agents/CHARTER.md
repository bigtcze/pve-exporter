# Charter

**Purpose:** Export dependable Prometheus metrics from Proxmox VE APIs and optional local Linux hardware using a small, self-hosted Go service.

The project is already released and in production use. Preserve functioning cluster/node/guest/storage/HA/replication/backup observability, local host collection and the documented operating experience. Do not reinterpret maintenance as an invitation to rewrite the exporter or add unrelated services.

Permanent goals: compatible Prometheus metrics, bounded collection overhead, honest missing-data semantics, secure handling of credentials, unprivileged normal operation and verifiable Linux binaries. Improvements to functionality or architecture require explicit authorization; new ideas alone do not establish a backlog.
