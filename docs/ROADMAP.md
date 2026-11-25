# Roadmap

pve-exporter is in **maintenance mode**. This page describes what the maintainer intends to keep doing. It makes no feature promises and no release dates.

## Priorities

1. **Compatibility.** Keep published Prometheus metric names, types, labels and HELP text, configuration keys, environment variables, CLI flags and release asset names stable. Breaking changes need an explicit, documented compatibility plan.
2. **Security fixes.** Handle reports made under [SECURITY.md](../SECURITY.md) and ship fixes in the latest release line.
3. **Dependency and toolchain maintenance.** Keep Go, module dependencies, GitHub Actions and the pinned tools current through Renovate, with CI gates on every change.
4. **Documentation accuracy.** Keep the README, examples and dashboards consistent with the shipped behaviour.

## Known Limitations

- **ARMv7 self-update.** `-selfupdate` looks for the asset `pve-exporter-linux-arm`, but the release publishes `pve-exporter-linux-armv7`. ARMv7 hosts must update manually, as documented in the README. This is a documented limitation, not yet fixed.

## Open Readiness Items

The security and project-readiness work tracked in [issue #11](https://github.com/bigtcze/pve-exporter/issues/11) is assessed in [docs/security/openssf-readiness.md](security/openssf-readiness.md). It includes owner actions that are not yet complete, such as enabling required pull requests and status checks on the default branch.

## Not Planned Right Now

No new features are scheduled. Proposals can be raised as [GitHub Issues](https://github.com/bigtcze/pve-exporter/issues); the maintainer decides whether they fit the maintenance scope.
