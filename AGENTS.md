# pve-exporter — engineering guidance

pve-exporter is an existing Go Prometheus exporter for Proxmox VE and local Linux hardware. Preserve its published metrics, configuration, installation and update compatibility. This repository defines technical/product requirements—not employee assignments, work selection or release schedules.

## Project contracts

- Product and architecture: `.agents/CHARTER.md`, `.agents/PRODUCT_SCOPE.md`, `.agents/ARCHITECTURE.md`.
- Prometheus compatibility: `.agents/METRICS_CONTRACT.md`.
- Security and safety: `.agents/SECURITY.md`, `.agents/GUARDRAILS.md`.
- Code/test quality: `.agents/CODE_QUALITY.md`, `.agents/TEST_STRATEGY.md`.
- Delivery, documentation and release qualification: `.agents/DEFINITION_OF_DONE.md`, `.agents/DOCUMENTATION.md`, `.agents/RELEASE_QUALITY.md`.
- `.agents/ROADMAP.md` is not a work backlog.

## Working in this repository

`go.mod` defines the Go version and module requirements. `mise.toml` reads Go from `go.mod` and pins golangci-lint. Run `mise install` and `mise run verify` (or individual test/lint/build tasks). Preserve the existing PR tests, Go race detector, release CI and Renovate.

Verify collector changes using deterministic simulated Proxmox API responses and local test fixtures, without a real PVE host, credentials or privileged hardware. Review all changes through PRs; don't suppress meaningful tests, weaken protected checks or claim unobserved success. The README documents actual user-facing metrics and installation.

Assignments, task permissions, and release cadence are managed outside the repository.
