# Contributing

Thank you for helping improve pve-exporter. This project is maintained by one person (see [GOVERNANCE.md](GOVERNANCE.md)), so clear reports and focused changes make the biggest difference.

## Reporting Bugs and Requesting Features

Use [GitHub Issues](https://github.com/bigtcze/pve-exporter/issues). Before filing:

- search existing issues;
- include the exporter version (`pve-exporter -version`), the installation method and the Proxmox VE version;
- describe the observed and expected behaviour, and the metric names or configuration keys involved.

**Never post credentials, API tokens, passwords, hostnames you consider private, or dumps of real metrics.** Redact them first. A minimal, synthetic example is always preferred.

Security problems must not be reported in issues. Follow [SECURITY.md](SECURITY.md).

Discussions are not enabled for this repository; use Issues for questions as well.

## Pull Request Workflow

1. Open an issue first for anything beyond a small fix, so the change can be discussed.
2. Fork or branch from `main`, and keep each pull request focused on one change.
3. Run the local checks described below. CI runs the same gates on every pull request to `main`.
4. Describe what changed, why, and how it was verified. Link the related issue.
5. Expect review feedback. The maintainer reviews and merges pull requests, and CI is expected to pass first. Branch rules do not yet enforce this; see [GOVERNANCE.md](GOVERNANCE.md#review-and-merge).

## Acceptable Contributions

Before writing code, read [AGENTS.md](AGENTS.md) and the contracts in [`.agents/`](.agents/). In particular:

- **Metrics compatibility:** do not rename, retype, relabel or remove published `pve_*` metrics, and do not change HELP text, units or documented omission semantics without an explicit compatibility plan. See `.agents/METRICS_CONTRACT.md`.
- **Configuration and CLI compatibility:** existing configuration keys, environment variables and flags must keep working.
- **Scope:** the project is in maintenance mode (see [docs/ROADMAP.md](docs/ROADMAP.md)). New features need prior agreement in an issue.
- **No live infrastructure:** tests must not require a live Proxmox host, real credentials, production disks or privileged hardware.

## Coding Standards

- Format with `gofmt`. Lint with the pinned `golangci-lint` (no `.golangci` file is present; the default linter set is used).
- Follow [Effective Go](https://go.dev/doc/effective_go) and the [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments) guide.
- Use the Go version in `go.mod`, with [mise](https://mise.jdx.dev/) as the tool runner.
- Keep package boundaries as described in [AGENTS.md](AGENTS.md); avoid unused abstraction.
- Do not weaken checks. A `#nosec` annotation goes on the line above the flagged statement, with a specific justification after `--`. Do not disable gosec rules globally.

## Testing Policy

- New behaviour needs tests. Bug fixes need a regression test that fails before the fix.
- Tests must be deterministic: use `httptest` servers, fixtures and temporary files, not live services.
- Statement coverage must stay at or above **80%**. `mise run coverage` enforces this gate.
- Do not skip, delete or weaken existing assertions to make a change pass. Explain any removed test in the pull request.
- Race-detector runs are required (`mise run test` and `mise run coverage` use `-race`).

## Local Commands

From the repository root:

```bash
mise install            # Go, golangci-lint, gosec, govulncheck and gitleaks at pinned versions
mise run verify         # full gate: coverage, lint, security, build, reproducible-build check
```

Individual tasks:

| Task | Purpose |
|------|---------|
| `mise run test` | `go test -race ./...` |
| `mise run coverage` | race tests with coverage profile and the 80% gate |
| `mise run lint` | pinned `golangci-lint run` |
| `mise run security` | `gosec ./...`, `govulncheck ./...`, `gitleaks git --redact .` |
| `mise run build` | `go build -v .` |
| `mise run repro` | builds the release assets twice and compares checksums |

The `make` targets in the `Makefile` still work with an installed Go toolchain.

## Developer Certificate of Origin

A Developer Certificate of Origin (DCO) sign-off is **not currently required**. Whether to require one is an open decision for the maintainer. Do not rely on a sign-off being accepted or ignored; check this file for updates before submitting.

## Licensing of Contributions

The project is licensed under the [MIT License](LICENSE). By submitting a contribution, you agree that it is provided under the same license.

## Code of Conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
