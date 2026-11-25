# Governance

## Project Maintainer

pve-exporter has a single maintainer, [`@bigtcze`](https://github.com/bigtcze), who owns the repository and is its only administrator. Commits on `main` come from the maintainer and from the Renovate bot (`renovate[bot]`).

## Roles

- **Maintainer:** owns the repository and its settings; reviews and merges changes; decides scope; cuts and publishes releases; handles security reports under [SECURITY.md](SECURITY.md) and conduct reports under [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- **Contributors:** anyone who files an issue, opens a pull request or reports a vulnerability privately, following [CONTRIBUTING.md](CONTRIBUTING.md).
- **Renovate:** automated dependency update pull requests, merged only through the same review and CI process as other changes.

## Decision Making

Decisions are made by the maintainer. Discussion happens in GitHub Issues and pull requests. Changes to published metrics, configuration keys, CLI flags, release asset names or installation and update behaviour are compatibility decisions and must be documented in the change and in the release notes.

The project's contracts are in [AGENTS.md](AGENTS.md) and [`.agents/`](.agents/).

## Review and Merge

Changes are expected to arrive through pull requests, with CI passing (`test`, `security` and `reproducible-build` jobs in [`ci.yml`](.github/workflows/ci.yml)).

**Current limitation:** the repository's default-branch ruleset blocks branch deletion and force-pushes, but it does **not** yet require pull requests or required status checks. Direct pushes to `main` are therefore not technically blocked. Adding those rules is a tracked owner action; see [docs/security/openssf-readiness.md](docs/security/openssf-readiness.md#owner-only-actions).

## Releases

Releases are created only by the maintainer, by pushing a `v*` tag. The [release workflow](.github/workflows/release.yml) builds the assets and creates the GitHub release for that tag. Release notes come from the annotated tag message. Release artifacts are the binaries and `checksums.txt` listed in the README.

## Continuity

There is currently **no second maintainer** and **no documented access-recovery arrangement** for the repository or its release process. This is a known bus-factor risk and an owner action. It will be updated here when arrangements exist; none are implied by this document.

## Changes to This Document

The maintainer may update this document through a pull request.
