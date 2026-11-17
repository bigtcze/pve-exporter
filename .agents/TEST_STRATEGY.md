# Test strategy

## Required baseline
- `mise run test`: Go unit/regression suite with `-race`; PR CI also records coverage.
- `mise run lint`: pinned golangci-lint.
- `mise run build`: compile the exporter.
- An applicable test failure is a release blocker; don't skip it or replace behavior tests with superficial mocks of the functions under test.

## Deterministic Proxmox API tests
Use Go `httptest`/TLS servers and realistic JSON fixtures, not a live hypervisor. Cover token and password auth, expired and concurrently refreshed tickets, unauthorized and insufficient-ACL responses, bad/empty/malformed data, escaped paths, timeouts, server errors, oversized responses and bounded retries. Preserve the existing `collector/*_test.go` regression coverage.

## Metric contracts
Assert actual Prometheus metric-family names, types, label keys, exact values, stable units and deliberate series omission on partial failures. Test stopped guests, inaccessible nodes/storage, unavailable local data, empty cluster responses and concurrent scrapes as appropriate. Avoid false-positive tests that only assert a function returned without panic.

## Hardware and update logic
Use fixture-backed or temporary simulated local files, SMART JSON and sensor command output. Verify malformed/stale/permission cases. For self-update test asset selection, checksums, failure cleanup and architecture limitations without actually replacing a real executable or restarting systemd.

## Evidence
Explain what tests really exercised, not what they were assumed to prove. Diagnose and fix flakes and races; don't weaken assertions. Any untested hardware/live PVE case should be called out rather than silently marked verified.
