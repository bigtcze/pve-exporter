# Security Policy

## Supported Versions

Only the latest release line receives security fixes. At the time of writing that is the **1.14.x** line (latest release `v1.14.4`). Older releases are not patched; upgrade to the latest release, using the steps in the README's [Updating](README.md#updating) section.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately through GitHub's private vulnerability reporting:

**https://github.com/bigtcze/pve-exporter/security/advisories/new**

Do not open a public issue, pull request or discussion for a suspected vulnerability. No security email address is published for this project; the advisory form above is the supported channel.

Include, where you can:

- the exporter version (`pve-exporter -version`) and how it was installed (release binary, self-update, or built from source);
- the affected component (exporter HTTP endpoints, Proxmox API client, local SMART or sensor collectors, self-update, release artifacts, or CI);
- a description of the impact and the steps or a minimal configuration needed to reproduce it;
- any proof-of-concept code, redacted logs or metrics output. **Do not send real Proxmox API tokens, passwords, or production metrics dumps.** Redact hostnames and credentials.

## What to Expect

- **Acknowledgement:** we aim to acknowledge a report within **14 days**.
- **Triage and fix:** the maintainer will confirm whether the issue is in scope, assess severity, and work on a fix. Status updates are posted in the private advisory.
- **Coordinated disclosure:** the default embargo is **90 days** from the report, shortened or extended by agreement when a fix or upstream dependency requires it. Fixes ship in a new release, and a GitHub Security Advisory is published. Where applicable, a CVE is requested through GitHub.
- **Credit:** reporters are credited in the advisory unless they ask not to be named.

## Scope

In scope:

- the exporter binary: HTTP endpoints (`/metrics`, `/health`, the root page), configuration loading, and the Proxmox API client, including authentication, TLS handling, path escaping and response limits;
- the optional local collectors: `/proc` readers, the `sensors -j` invocation, and reading the SMART JSON file;
- the `-selfupdate` path: release discovery, download, checksum verification, executable replacement;
- release artifacts and the build and release workflows in this repository.

Out of scope:

- Proxmox VE itself, its API, and its authentication or permission model; report those to the Proxmox project.
- The optional SMART helper script's privileges and cron setup as operated by the administrator, beyond the file format it writes.
- Vulnerabilities in dependencies that are not reachable from this project; please report upstream, and tell us if this project's use makes them reachable.
- Missing hardening of the plain-HTTP metrics endpoint when it is exposed without a trusted network, firewall or reverse proxy. This is documented behaviour; see the [threat model](docs/security/threat-model.md).

## Verifying Releases

Release binaries are published with `checksums.txt`. Releases built after the attestation change include GitHub build provenance; see the README section [Verifying Release Artifacts](README.md#verifying-release-artifacts) for the `gh attestation verify` command.

## Further Reading

- [Threat model and assurance notes](docs/security/threat-model.md)
- [OpenSSF readiness assessment](docs/security/openssf-readiness.md)
