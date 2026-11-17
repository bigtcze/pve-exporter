# Documentation standards

The existing README is the canonical user/operator guide and metric reference: Proxmox permissions and credentials, TLS/security caveats, YAML/environment configuration, metrics names and labels, optional hardware prerequisites, systemd installation, Prometheus/Grafana, update steps and known limitations.

Keep instructions consistent with shipped code and generated release assets. Update examples when behavior changes. Clearly distinguish local-host hardware data from API-reported cluster data; omitted metrics and partial API failures must not be described as valid observed zeros.

Write human-readable release notes: meaningful operator-facing changes, compatibility and security impact, configuration changes, installation/update instructions and confirmed limitations. Don't substitute a raw commit log or fabricated screenshots/proof. Verify commands, paths, links, versions and asset names against actual published outputs.
