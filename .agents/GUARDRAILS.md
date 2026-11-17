# Engineering guardrails

- Maintain the existing Proxmox/Prometheus exporter; no routine rewrite, unwanted new architecture, runtime database, GUI or privilege escalation.
- Do not silently change public metrics, types, units, labels, CLI/configuration, supported binaries or documented service behavior.
- Preserve feature behavior and security constraints while upgrading Go, modules, Actions or lint tools. Understand upstream breaking changes instead of blindly merging or endlessly retrying CI.
- Do not commit secrets; do not require live Proxmox hosts, production disks, root-only resources or external paid services in CI.
- Work via reviewable PRs. Do not directly bypass required checks, suppress lint/race failures, weaken assertions or fabricate validation/release evidence.
- Fundamental product, security or metrics contracts change only after explicit authorization and meaningful independent review.
- Avoid scope creep from speculative roadmaps, automatic backlog generation and maintenance-only refactors without concrete value.
