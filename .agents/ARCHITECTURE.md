# Architecture

## Components
- `main.go` owns CLI flags, HTTP server, registration and shutdown.
- `config/` handles YAML/environment defaults and validation.
- `collector/` owns Proxmox API authentication/requests, metric descriptors, resource collectors, local hardware readers and scrape coordination.
- `selfupdate.go` handles release discovery, artifact verification and executable replacement.
- `scripts/pve-smart-collector.sh` is an optional, separately privileged JSON producer—not a root subprocess of the exporter.
- `grafana/` and `examples/` are user-facing observability assets.

## Data flow and boundaries
Prometheus requests trigger a scrape; the exporter authenticates to Proxmox and collects multiple metric families, some concurrently. Optional local sources are limited to the exporter's actual host, not all nodes visible through the Proxmox API. Node labels from local sources may differ from API node names.

Keep authentication, API request handling and metric construction testable separately. Bound fan-out, response sizes, timeouts, retries and task-history scans. A successful HTTP scrape does not imply that every subcollector succeeded; preserve explicit partial-failure/omission semantics. Avoid needless extra architectural layers and shared mutable state.
