# Security contract

## Secrets and authentication
Keep API token/password credentials out of logs, test output and release artifacts. Preserve existing authentication precedence and Proxmox ACL behavior; restricted visibility must not be reported as complete cluster coverage. Validate and encode all dynamic API path segments and untrusted response data.

## Network
The exporter serves unauthenticated plain HTTP metrics by default: document the need for trusted network placement, bind/firewall or reverse-proxy isolation. The Proxmox API uses HTTPS. `insecure_skip_verify` currently defaults to true for self-signed deployments; this is a documented compatibility/security tradeoff, not permission to suppress TLS warnings or silently change behavior. Verified TLS is preferable when configured.

## Filesystem and update safety
Keep ordinary exporter execution unprivileged. Optional SMART collection is separate and privileged only where necessary; validate data files, ownership and staleness. Protect filesystem paths, symlink resolution and temporary-file cleanup in self-update. Download the expected asset and checksums from the same GitHub release and verify SHA-256 before replacing an executable. Do not claim rollback is available where it is not.

Test authentication failures, expired tickets, TLS options, path escaping, response-size and timeout limits, malformed JSON, checksum failures and relevant file-permission cases. No tests against real production credentials or devices.
