---
description: How to release a new version of pve-exporter
---

# Release Procedure

To ensure release notes are correctly populated in GitHub Releases, follow this procedure:

1.  **Prepare Changes**: Ensure all code changes are committed.

2.  **Deploy & Verify on Test Server**
    - Build linux binary: `$env:GOOS='linux'; $env:GOARCH='amd64'; go build -o pve-exporter-linux-amd64 .`
    - Copy to test server: `pscp -batch pve-exporter-linux-amd64 root@<TEST_SERVER_IP>:/usr/local/bin/pve-exporter`
      *(See `~/.gemini/pve-exporter-secrets.md` for actual IP)*
    - Restart service: `ssh root@<TEST_SERVER_IP> "systemctl restart pve-exporter"`
    - Verify metrics: `curl http://<TEST_SERVER_IP>:9221/metrics | grep <new_metric>`

3.  **Tag Release**: Create an **annotated tag** with the changelog in the message body.
    *   The **Subject** (first line) will be the Release Title.
    *   The **Body** (subsequent lines) must be a **Technical Summary** of changes to the binary/codebase.
    *   **Do NOT** include: CI/CD changes (chore), Documentation updates (docs), or refactoring without functional impact.
    *   **Focus on**: New metrics, bug fixes, performance improvements, and breaking changes.

    ```bash
    git tag -a v1.X.X -m "v1.X.X: Release Title" -m "## Technical Changes" -m "- Added per-device metrics for VM disks and NICs" -m "- Implemented missing Proxmox API metrics (pressure, balloon, HA)"
    ```

4.  **Push Tag**: Push the tag to GitHub to trigger the release workflow.
    ```bash
    git push origin v1.X.X
    ```

**Important**: The GitHub Action extracts the release notes directly from the git tag annotation. Ensure the tag message is clean, user-facing, and formatted as a Markdown list.
