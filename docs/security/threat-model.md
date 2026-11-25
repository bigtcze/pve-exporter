# Threat Model and Assurance Notes

This document describes the security assumptions, trust boundaries, and mitigations of pve-exporter as implemented on branch `feat/openssf-readiness-11` (pre-merge). It is an assurance aid for operators and reviewers. Each mitigation is traced to code and to tests. It does not claim that the project is certified or independently audited.

Compatibility: this document describes existing behaviour. Phase 1 of issue #11 changed the self-update and release build code (size limits, reproducible static builds); no published metric, configuration key, CLI flag or asset name changed.

## Assets

- **Proxmox API credentials**: the API token secret or the `root@pam`-style password, held in the operator's configuration file or environment.
- **Session tickets and CSRF tokens**: short-lived values obtained from the Proxmox API when password authentication is used.
- **Metrics data**: cluster, node, guest, storage and hardware observability.
- **Executable integrity**: the installed binary and its update path.
- **Release artifacts**: binaries and `checksums.txt` published on GitHub Releases.
- **Local SMART data**: `/var/lib/pve-exporter/smart.json`, written by a separate helper.

## Actors

- **Operator**: installs and configures the exporter, controls the config file and the host.
- **Prometheus and other scrapers**: network clients of the metrics endpoint.
- **Proxmox API**: a trusted-but-network-reachable HTTPS service.
- **GitHub**: hosts the source, CI, releases and the self-update source.
- **Local attacker**: a user or process on the exporter host, or a network attacker between the exporter and the Proxmox API.

## Trust Boundaries

1. Network client → exporter HTTP server (`/metrics`, `/health`, `/`). **Unauthenticated, plain HTTP.**
2. Exporter → Proxmox API. HTTPS, authenticated; certificate verification is **off by default** (`insecure_skip_verify: true`) and on only when the operator sets `insecure_skip_verify: false`.
3. Exporter → local filesystem and kernel interfaces (`/proc`, `/var/lib/pve-exporter/smart.json`, `/usr/bin/sensors`).
4. Exporter → GitHub (release API and asset downloads) during `-selfupdate`.
5. Root-owned helper → SMART JSON file (separate privileged producer).

## Mitigations and Residual Risks by Area

### 1. API token and password handling

- Token authentication sends `Authorization: PVEAPIToken=<id>=<secret>` on each request (`collector/api.go`, `setRequestCredentials`). Password authentication posts to `/access/ticket` and then sends `Cookie: PVEAuthCookie=…` plus `CSRFPreventionToken` (`collector/api.go`, `login`, `setRequestCredentials`).
- Token authentication is preferred when both are configured: `credentialsForRequest` returns token credentials whenever `TokenID` and `TokenSecret` are set. Tests: `TestTokenUnauthorizedNeverRequestsTicket` (`collector/api_test.go`) asserts that a token-authenticated 401 never triggers a ticket request.
- Ticket refresh after `401` is serialised: concurrent unauthorized requests share one refresh (`TestConcurrentUnauthorizedRequestsSharePasswordRefresh`, `TestConcurrentUnauthorizedRequestsShareFailedPasswordRefresh`, `TestAPIRequestRefreshesFreshPasswordTicketAfterUnauthorized`, `TestRequestStartingDuringFailedRefreshJoinsGeneration` in `collector/api_test.go`, plus `TestAuthenticatePreservesFreshPasswordTicket`).
- Secrets are not logged by design. A repository search finds no logging call that formats `TokenSecret` or `Password`. Errors from authentication use status and wrapped transport errors. This is a code-review finding, not an automated test; see residual risks.
- Config validation requires a `!` in the token ID when one is set (the documented form is `user@realm!tokenname`), and requires either a password or a token (`config/config.go`, validation around `token_id`). Tests: `config/config_test.go`.
- **Residual risk:** secrets live in plaintext in the YAML file or the systemd environment. The exporter warns when the config file is world-readable (`config/config.go`: "config file is world-readable, consider chmod 640"); it does not enforce permissions.

### 2. Proxmox ACL scope (least privilege)

- The README recommends a dedicated user with the `PVEAuditor` role, and a token with privilege separation disabled to inherit user permissions (or explicit token ACLs when enabled).
- The exporter does not enforce ACLs. Permission failures and partial visibility show up as zero values or missing series, depending on the endpoint. `TestCompatibilityHAErrorZeros` asserts that HA resource counts are emitted as zero when cluster status is empty (`collector/compatibility_regression_test.go`). Failed or malformed API responses are logged and complete the scrape with `pve_exporter_up` at 0 (`TestMalformedNodesCompletesFailedScrapeOnce` and `TestInternalFailuresAreLogged` in `collector/phase2_test.go`).
- **Residual risk:** an over-broad ACL grants the exporter more read access than needed. Operators choose the scope.

### 3. TLS to the Proxmox API

- `proxmox.insecure_skip_verify` defaults to **`true`** (`config/config.go`, `PVE_INSECURE_SKIP_VERIFY`), so self-signed Proxmox certificates work out of the box. The HTTP client sets `InsecureSkipVerify` from this value (`collector/collector.go`, `NewProxmoxCollector`).
- The exporter logs a startup warning when verification is disabled (`main.go`: "TLS certificate verification is disabled, this is insecure for production use").
- Recommended: set `insecure_skip_verify: false` and trust the Proxmox CA on the exporter host.
- Tests: the httptest TLS servers in `collector/api_test.go` and `collector/mock_test.go` set `InsecureSkipVerify` explicitly so they can use self-signed certificates. The tests I checked do not assert the default value, and none connects to a server with a verified certificate chain.
- **Residual risk:** the default permits a man-in-the-middle on the exporter→Proxmox path. It is a documented compatibility trade-off (gosec G402 is suppressed with this justification in `collector/collector.go`).

### 4. Unauthenticated plain-HTTP metrics endpoint

- The HTTP server serves `/metrics`, `/health` and the root page without authentication and without TLS (`main.go`, `newServeMux`). It listens on `:9221` by default (`LISTEN_ADDRESS`).
- Mitigations are operational: bind to a trusted interface, firewall the port to the Prometheus host, or front it with a reverse proxy that adds TLS and authentication. The README documents this.
- Server timeouts are set (`ReadTimeout` 30 s, `WriteTimeout` 60 s, `IdleTimeout` 120 s in `main.go`). The root and health handlers return fixed content. Tests: `TestServeMuxEndpoints` (`serve_mux_test.go`) and `TestMetricsHandler…` in `main_test.go`.
- **Residual risk:** metrics, including host names, node names, guest names and disk serials, are visible to anyone who can reach the port.

### 5. Path escaping for Proxmox API requests

- Dynamic path segments (node names, guest IDs, storage names, pool names) are escaped with `url.PathEscape` through `apiPathf` (`collector/api_path.go`).
- `buildAPIURL` rejects hosts that contain schemes, paths, user info, ports in the host field, or malformed IPv6 literals (`collector/api.go`). Tests: `TestAPIPathEscapesDynamicSegments`, `TestBuildAPIURL`, `TestBuildAPIURLRejectsInvalidHosts` (`collector/api_test.go`).
- **Residual risk:** none known for path injection in dynamic segments; the Proxmox API itself is trusted to validate its own data.

### 6. Bounded responses, retries, rate limits and timeouts

- API response bodies are read through `readBoundedBody` with a **10 MiB** limit (`collector/api.go`, `maxResponseSize`). Oversize bodies return an error. Tests: `TestAPIResponseSizeLimit`, `TestOversizedUnauthorizedBodyStillRefreshes`, `TestOversizedServerErrorBodyStillRetries`, `TestAuthenticationResponseSizeLimit` (`collector/api_test.go`).
- Requests are attempted at most 3 times (`maxRetries`). Transport errors and `5xx` responses wait with exponential backoff from 100 ms. A `401` triggers re-authentication and an immediate retry, without backoff.
- A token-bucket limiter (10 requests/s, burst 10) gates API requests (`rate.NewLimiter` in `collector/collector.go`).
- Each request has the configured timeout (default 30 s) applied through a context (`collector/api.go`).
- Tests cover oversize responses and the retry paths listed above; the limiter and timeouts are exercised indirectly. **Residual risk:** the limiter and per-request timeout have no dedicated test.

### 7. Optional privileged SMART helper

- `scripts/pve-smart-collector.sh` runs as root from `/etc/cron.d` and writes `/var/lib/pve-exporter/smart.json`. The exporter does **not** run as root and does not execute the helper (see `.agents/ARCHITECTURE.md`).
- The exporter reads the file with `os.ReadFile` after `os.Stat`. It skips files whose modification time is more than **10 minutes** old (`smartDataMaxAge`, `collector/disk.go`), logs and omits metrics on read or JSON errors, and emits no series for a missing file. Tests: `TestSmartMissingFileIsSilent`, `TestSmartStaleFileIsSkipped`, `TestSmartMalformedJSONEmitsNothing`, `TestSmartFixtureMetricsAndOmission` (`collector/local_sources_test.go`).
- The helper writes with mode `0644`, so any local user can read the file. Metrics are local observability data, not secrets, but disk serial numbers are present.
- **Residual risk:** the SMART JSON size is **not bounded**: `collectSmartMetrics` calls `os.ReadFile` with no limit. A huge file written by a process with write access to `/var/lib/pve-exporter` could consume memory. Write access to that directory is root-only in the documented installation. Bounding this is a recommended follow-up, not done in this change.
- **Residual risk:** the helper's own parsing of `smartctl` output is not covered by the exporter's tests.

### 8. Sensors command

- The exporter runs `/usr/bin/sensors -j` by absolute path with fixed arguments and no shell (`collector/sensors.go`, `sensorsCommand`). The command is not user-configurable. Tests: `TestCollectSensorsMetricsFromFixture`, `TestCollectSensorsMalformedJSONEmitsNothing`, `TestCollectSensorsCommandFailureEmitsNothing` (`collector/local_sources_test.go`).
- **Residual risk:** `sensors` output is trusted from the local host; a malicious `sensors` binary at `/usr/bin` would already be a root compromise.

### 9. Self-update: filesystem, symlinks and temporary files

- The executable path is resolved with `filepath.EvalSymlinks` (`getExecutablePath`), so the symlink target is replaced, not the link.
- The download goes to a temporary file created in the **same directory** as the executable (`os.CreateTemp`), so the final step is a same-filesystem `os.Rename`. The new file is `chmod 0755` (gosec G302 is suppressed with this justification).
- On checksum or validation failure, the temporary file is removed. The original executable is renamed to `.bak`, the new file is renamed into place, and the backup is removed on success. If the install step fails, the backup is restored (`replaceExecutable`).
- Tests (`selfupdate_test.go`): `TestDownloadBinary` (temp file location, cleanup on non-200 and oversize), `TestReplaceExecutable` (success, restore on install failure, backup failure), `TestSelfUpdateFailurePaths` and `TestSelfUpdateNegativePaths` (the original executable is byte-identical and no temporary files remain after failures), and `TestGetExecutablePathResolves`.
- **Residual risk:** there is no rollback copy after success; the `.bak` is deleted. Restoring an older release is a manual step documented in the README.

### 10. Self-update integrity

- The binary and `checksums.txt` are fetched from the same release, over HTTPS, from `api.github.com` and `github.com`. The updater verifies SHA-256 against `checksums.txt` before replacing the executable; a missing checksum entry or missing checksums file aborts the update (`SelfUpdate`, `verifyChecksum`, `downloadChecksums`).
- Downloads are bounded: release JSON 1 MiB, `checksums.txt` 1 MiB, binary 256 MiB, with explicit errors when exceeded (`readLimited`, `maxReleaseJSONBytes`, `maxChecksumsBytes`, `maxBinaryBytes`). Tests: `TestCheckLatestVersion` (oversize), `TestDownloadChecksums` (oversize), `TestDownloadBinary` (oversize).
- Before replacement, the new binary is run with `--version`, then `--help`. If both fail, a `file` output check is used as a fallback (`verifyBinary`). This is a basic sanity check, not an authenticity check.
- **Residual risk:** the checksum and the binary come from the **same release channel**. A compromised GitHub release (or account) can publish a matching pair. The updater does not verify a signature. Mitigations available to operators: verify GitHub build provenance with `gh attestation verify` on releases built after this change, or compare with a reproduced build (see the README section [Verifying Release Artifacts](../../README.md#verifying-release-artifacts)). The updater itself does not perform attestation verification.
- **Residual risk:** the ARMv7 asset-name mismatch (`pve-exporter-linux-arm` vs `pve-exporter-linux-armv7`) means ARMv7 self-update fails safely by not finding an asset; it is a documented limitation.

### 11. Release artifacts and build pipeline

- Release binaries are built with `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false` and fixed build metadata by `scripts/build-release.sh`. `scripts/check-reproducible.sh` compares two independent builds. Releases built after this change are attested with `actions/attest-build-provenance`.
- Workflow permissions are read-only by default; the release job requests write access only for release creation and attestation. Third-party actions are pinned to full commit SHAs. Dependency vulnerabilities are checked with `govulncheck` (CI `security` job); static analysis with `gosec`; secret leakage with `gitleaks`.
- **Residual risk:** tags are annotated but **not GPG-signed**, and releases published before this change were not reproducible or attested.

### 12. Secrets in source control

- `gitleaks git --redact .` runs in the `security` CI job and in `mise run security`. `.gitignore` excludes `config.yml`, `config.local.yml`, `metrics_*.txt` and `metrics.txt` and local tooling directories.
- **Residual risk:** gitleaks checks committed content only. Operators must keep real config files out of the repository.

## Known Gaps Summary

| Gap | Status |
|-----|--------|
| SMART JSON size not bounded | Open, recommended follow-up |
| No signature verification inside the updater | Accepted; mitigated by attestations and reproducible builds for new releases |
| Config files are not permission-enforced | Accepted; warning only |
| Metrics endpoint is unauthenticated plain HTTP | Documented; operator must isolate |
| `insecure_skip_verify` defaults to `true` | Documented compatibility default |
| Limiter and per-request timeout lack dedicated tests | Open, test gap |
| Tags are not GPG-signed | Open |

## Compatibility

This document changes no published behaviour. Security-relevant behaviour changes made under issue #11 are the bounded self-update downloads and the static release build; both are described in the README and in the release notes for the release that includes them.
