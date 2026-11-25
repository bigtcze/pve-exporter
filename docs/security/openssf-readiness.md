# OpenSSF Readiness Assessment

> Issue [#11](https://github.com/bigtcze/pve-exporter/issues/11). **Assessed on branch `feat/openssf-readiness-11`, pre-merge.** Statuses describe the repository state on that branch and the GitHub settings verified on 2026-11-25. They do not describe the default branch, and they are not an OpenSSF certification, badge award or independent audit.

## Criteria sources and versions

| Source | Version or date | Used for |
|--------|-----------------|----------|
| OpenSSF Best Practices criteria, [`criteria/criteria.yml` at 880f1cb](https://github.com/coreinfrastructure/best-practices-badge/blob/880f1cb943a815f4418980391360d47e707321fa/criteria/criteria.yml) (blob `7804ec1`) | upstream commit `880f1cb`, checked 2026-11-25 | Passing (67 IDs) and Silver (55 IDs) lists, with the level shown for each list |
| OpenSSF Baseline (OSPS), Level 1 requirements, [ossf/security-baseline tag `v2026.08.28`](https://github.com/ossf/security-baseline/releases/tag/v2026.08.28) | tag `v2026.08.28` (commit `a26a796`) | 25 Level-1 entries; `OSPS-BR-01.02` is retired upstream and is listed as N/A |
| OpenSSF Best Practices official criterion text, [`config/locales/en.yml` at 5ea0f48](https://github.com/coreinfrastructure/best-practices-badge/blob/5ea0f484ea2e4d56a8149c490b4d109d18e85f28/config/locales/en.yml) (blob `c0ed63d`) | upstream commit `5ea0f48`, checked 2026-11-25 | Official wording for the criterion rows cited with "(official en.yml text)" in the tables, including `delivery_unsigned`, `achieve_passing`, `crypto_certificate_verification`, `crypto_verification_private` and `automated_integration_testing`. |
| Scorecard | Not run locally; the `scorecard.yml` workflow runs weekly and on pushes to `main` | Automated Scorecard checks (results appear after merge) |

Level notes: the level for each ID is taken from the Passing or Silver list it belongs to (the criteria file reuses some IDs in both lists, with different levels). An ID that appears in both tables is therefore assessed twice, once per list. The criterion text itself is not restated; the ID is the key.

Scope of the criteria: the Best Practices badge is not awarded until the project is registered at [bestpractices.dev](https://www.bestpractices.dev/). The project is **not registered**, so no Best Practices level is claimed.

## Status legend

- **Met**: the repository or setting supports the criterion, and the evidence is cited.
- **Partial**: the criterion is partly met, or the evidence is weaker than the criterion asks for. The gap is stated.
- **Unmet**: the criterion is not met today.
- **Owner**: the criterion depends on a maintainer attestation, a GitHub setting, or a decision the repository cannot verify.
- **N/A**: the criterion does not apply to this project, with the rationale given.

## Summary

- Passing (67 IDs): Met 51, Partial 8, Unmet 1, Owner 2, N/A 5.
- Silver (55 IDs): Met 36, Partial 5, Unmet 6, Owner 1, N/A 7.
- OSPS Baseline Level 1 (25 IDs): Met 17, Partial 3, Unmet 1, Owner 2, N/A 2.

Passing and Silver tables include every ID from the lists, so a criterion missing from a table is a bug in this document.

Key open items: the default-branch ruleset does not require pull requests or status checks (OSPS-AC-03.01); secret scanning and push protection are disabled (OSPS-BR-07.01); TLS certificate verification is off by default (Silver `crypto_certificate_verification` and `crypto_verification_private` are Unmet); the Best Practices badge is blocked by registration and open Passing items (Silver `achieve_passing`); no second maintainer or access-recovery arrangement exists (Silver `access_continuity`, `bus_factor`); the Scorecard result is not yet published; and no attested release exists yet.

## Must not be claimed yet

- **Not** an OpenSSF Best Practices badge or passing/silver/gold level: the project is not registered.
- **Not** OpenSSF Baseline compliance, or a claim that every Level-1 requirement is met.
- **Not** a Scorecard score: `https://api.scorecard.dev/projects/github.com/bigtcze/pve-exporter` returned 404 on 2026-11-25, and results appear only after `scorecard.yml` runs on `main` after merge.
- **Not** verified MFA for the maintainer account: the API does not expose it.
- **Not** signed or attested releases for existing versions. v1.14.4 has no attestation and its tags are not GPG-signed.
- **Not** protected default-branch merges: direct pushes to `main` are not blocked by branch rules.
- **Not** TLS certificate verification by default. The exporter's default `insecure_skip_verify: true` means the Proxmox API connection and its credentials are not verified; the Silver TLS rows are Unmet for that reason.
- **Not** publisher authentication for release downloads. Checksums and binaries come from the same HTTPS channel; attestations cover only releases built after this PR.
- **Not** a Best Practices passing badge today. `achieve_passing` is Unmet: registration has not happened and Passing items are open.
- **Not** published SBOM: none is attached to releases (see Inherited debt).
- **Not** a secure-design or secure-knowledge attestation from the maintainer.

## Owner-only actions

1. **Register at bestpractices.dev** for the project and complete the self-assessment, using this document as the source. Add the Best Practices badge only after registration.
2. **Attest MFA** for the `bigtcze` account (OSPS-AC-01.01). The GitHub API does not expose 2FA status; it returns null.
3. **Add a pull-request requirement and required status checks** `test`, `security` and `reproducible-build` to default-branch ruleset `27497346` (OSPS-AC-03.01). Keep the existing deletion and non-fast-forward rules.
4. **Enable secret scanning and push protection** under repository security settings (OSPS-BR-07.01; Silver/Passing no_leaked_credentials).
5. **Enable Dependabot alerts** (not Dependabot version or security-update PRs). Renovate remains the update bot.
6. **Optionally enable `sha_pinning_required`** in Actions settings. All workflow `uses:` entries are pinned to full commit SHAs now.
7. **Name a second maintainer or document access-recovery arrangements** (Silver `access_continuity`, `bus_factor`).
8. **Make the secure-design and common-error attestations** (Passing `know_secure_design`, `know_common_errors`).
9. **Decide on DCO sign-off** (Silver `dco`).
10. **Verify the first attested release**: `gh attestation verify <asset> --repo bigtcze/pve-exporter`, after the first tag built from this workflow.
11. **Decide on history cleanup** for the committed binary in `7200809` (OSPS-QA-05.01). Rewriting history affects all clones and is outside this PR.
12. **Decide the CGO default and debug-symbol policy** for release builds (`build_preserve_debug`).
13. **Confirm there are no collaborators beyond the owner** (OSPS-AC-02.01).
14. **Decide on the TLS verification default** for the Proxmox API client (`insecure_skip_verify`, currently `true`). Silver `crypto_certificate_verification` and `crypto_verification_private` are Unmet until this changes. A change of default is a compatibility decision and is out of scope for #11; the product contract forbids changing it silently.

## Unresolved mandatory requirements

Requirements at MUST level whose status is not **Met** (Unmet, Partial or Owner). Each row needs owner action or a follow-up change.

| List | ID | Status |
|---|---|---|
| Passing | `release_notes_vulns` | Partial |
| Passing | `report_responses` | Partial |
| Passing | `vulnerability_report_response` | Partial |
| Passing | `tests_are_added` | Partial |
| Passing | `know_secure_design` | Owner |
| Passing | `know_common_errors` | Owner |
| Passing | `vulnerabilities_fixed_60_days` | Partial |
| Silver | `achieve_passing` | Unmet |
| Silver | `access_continuity` | Unmet |
| Silver | `documentation_achievements` | Partial |
| Silver | `regression_tests_added50` | Partial |
| Silver | `warnings_strict` | Partial |
| Silver | `crypto_certificate_verification` | Unmet |
| Silver | `crypto_verification_private` | Unmet |
| Silver | `signed_releases` | Partial |
| OSPS L1 | `OSPS-AC-01.01` | Owner |
| OSPS L1 | `OSPS-AC-02.01` | Owner |
| OSPS L1 | `OSPS-AC-03.01` | Unmet |
| OSPS L1 | `OSPS-BR-07.01` | Partial |
| OSPS L1 | `OSPS-QA-05.01` | Partial |
| OSPS L1 | `OSPS-QA-05.02` | Partial |

Count: 21 MUST-level items are not Met.

## Dependency licenses

Modules linked into the release binary, from `go list -deps` (the project module itself excluded). Each license text was read from the module cache (`go env GOMODCACHE`). All SPDX identifiers below are MIT-compatible.

| Module | Version | SPDX | License file checked |
|--------|---------|------|----------------------|
| `github.com/beorn7/perks` | v1.0.1 | MIT | LICENSE |
| `github.com/cespare/xxhash/v2` | v2.3.0 | MIT | LICENSE.txt |
| `github.com/munnerz/goautoneg` | v0.0.0-20191010083416-a7dc8b61c822 | BSD-3-Clause | LICENSE (includes the non-endorsement clause) |
| `github.com/pandatix/go-abnf` | v0.5.5 | MIT | LICENSE |
| `github.com/prometheus/client_golang` | v1.25.0 | Apache-2.0 | LICENSE |
| `github.com/prometheus/client_model` | v0.6.3 | Apache-2.0 | LICENSE |
| `github.com/prometheus/common` | v0.74.0 | Apache-2.0 | LICENSE |
| `github.com/prometheus/procfs` | v0.23.0 | Apache-2.0 | LICENSE |
| `go.yaml.in/yaml/v4` | v4.0.0 | Apache-2.0 AND MIT | LICENSE (Apache-2.0); NOTICE (parts ported from libyaml are MIT-licensed, per the NOTICE file) |
| `golang.org/x/sys` | v0.49.0 | BSD-3-Clause | LICENSE |
| `golang.org/x/time` | v0.16.0 | BSD-3-Clause | LICENSE |
| `google.golang.org/protobuf` | v1.36.12 | BSD-3-Clause | LICENSE |

Go standard library: BSD-3-Clause, bundled with the Go toolchain. Module files were not byte-compared against SPDX templates; identifiers were assigned from the license text headers and clauses.

Not checked here: whether the Go toolchain's own license notices are reproduced in release artifacts. The release assets carry no third-party notice file (this is a gap; see Inherited debt).

## Inherited debt versus this PR

What this PR changes, and what was already present before it.

- **Self-update had no tests before this PR.** Commit `4518909` (2026-06-01, "harden self-update, fix security issues") changed `selfupdate.go` and added no test files. `selfupdate_test.go` now covers that path (this PR), with temp-dir and httptest fixtures and a faked restart hook.
- **Collectors for local hardware had little coverage.** SMART and sensors tests are new in `collector/local_sources_test.go`.
- **gosec findings** (5) were triaged in this PR with narrow `#nosec` justifications. None were disabled globally. No finding is left open.
- **Release builds were not reproducible or attested.** This PR adds `scripts/build-release.sh`, `scripts/check-reproducible.sh`, and attestation on tags. Releases built before it (including v1.14.4) are not reproducible or attested, and their amd64 binary is dynamically linked.
- **A 15.5 MB binary is in git history** (`7200809`, removed in `92e96d1`). It is not in the current tree. This PR does not rewrite history.
- **gofmt is enforced in CI** (ci.yml test job, `Check gofmt` step), so formatting drift is not merged.
- **Tags are not GPG-signed.** Unchanged by this PR.
- **Secret scanning, push protection and branch PR rules** are not enabled. These are owner settings, not repository code.
- **Scorecard and attestation workflows** are added in this PR and have not run yet.
- **No third-party license notice file is shipped with release assets.** The MIT project license is in the source tree, but the BSD and Apache dependency notices are not bundled with binaries. Not required by the criteria checked here; tracked as a follow-up.
- **No SBOM is published.** Not required by Passing, Silver or OSPS Level 1. Decision in this PR: no SBOM release asset, because the asset list is a public contract. Go embeds module versions in each binary (`go version -m pve-exporter-linux-amd64`), and `go.mod`/`go.sum` is the machine-readable list. Publishing an SBOM is a recommended follow-up.

## Evidence index

Repository files and commands behind the statuses:

- Workflows: `.github/workflows/ci.yml` (jobs `test`, `security`, `reproducible-build`), `.github/workflows/release.yml`, `.github/workflows/scorecard.yml`.
- Local gates: `mise.toml` (`test`, `coverage`, `lint`, `security`, `build`, `repro`, `verify`), `scripts/check-coverage.sh`, `scripts/build-release.sh`, `scripts/check-reproducible.sh`.
- Security documents: `SECURITY.md`, `docs/security/threat-model.md`.
- Governance: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `GOVERNANCE.md`, `docs/ROADMAP.md`.
- Dependencies: `go.mod`, `go.sum`, `renovate.json`.
- Checks behind these statuses, all run by `ci.yml` at the PR head ([CI run 45656646885](https://github.com/bigtcze/pve-exporter/actions/runs/45656646885)): gofmt check, race tests with the 80% statement-coverage gate (88.4% in CI), `golangci-lint run` (0 issues), gosec (0 open), `govulncheck ./...` (no vulnerabilities), `gitleaks git --redact .` (no leaks) and `scripts/check-reproducible.sh` (identical checksums). Earlier evidence links cite run 45650125770 at commit 5b5a0c9.
- GitHub API, verified 2026-11-25: private vulnerability reporting enabled; default-branch ruleset `27497346` (deletion and non-fast-forward rules); security settings as listed in Owner-only actions; Scorecard API 404.

## Best Practices

### Passing criteria (67)

| ID | Level | Status | Evidence / N/A rationale | Owner action |
|---|---|---|---|---|
| `description_good` | MUST | Met | README.md opening section and Contents describe purpose and scope. | — |
| `interact` | MUST | Met | GitHub Issues enabled; CONTRIBUTING.md 'Reporting Bugs and Requesting Features'. | — |
| `contribution` | MUST | Met | CONTRIBUTING.md 'Pull Request Workflow'. | — |
| `contribution_requirements` | SHOULD | Met | CONTRIBUTING.md 'Acceptable Contributions', 'Coding Standards', 'Testing Policy'. | — |
| `floss_license` | MUST | Met | LICENSE (MIT, Copyright (c) 2025 bigtcze); README 'License' section. | — |
| `floss_license_osi` | SUGGESTED | Met | MIT is OSI-approved. | — |
| `license_location` | MUST | Met | LICENSE at repository root. | — |
| `documentation_basics` | MUST | Met | README.md: installation, updating, configuration, metrics, development. | — |
| `documentation_interface` | MUST | Met | README.md Configuration (YAML keys, environment variables, flags) and Metrics sections. | — |
| `sites_https` | MUST | Met | Project channels are github.com over https. README localhost http:// examples refer to the local metrics endpoint, not a project channel. | — |
| `discussion` | MUST | Met | GitHub Issues is the public discussion channel (CONTRIBUTING.md). Discussions are disabled; Issues satisfies the criterion. | — |
| `english` | SHOULD | Met | Documentation and issue handling are in English. | — |
| `maintained` | MUST | Met | Commits on main in 2026-11 (git log); Renovate active (renovate.json; dependency PRs #8, #9, #12, #13 merged 2026-11-25; dashboard issue #10). | — |
| `repo_public` | MUST | Met | bigtcze/pve-exporter is public (gh API, verified 2026-11-25). | — |
| `repo_track` | MUST | Met | Git history with authors and dates (git log). | — |
| `repo_interim` | MUST | Met | Interim changes are commits on main; the default branch is publicly readable. | — |
| `repo_distributed` | SUGGESTED | Met | Git is a distributed VCS; the public GitHub repository is cloneable. | — |
| `version_unique` | MUST | Met | Release tags v1.x.y are unique; `pve-exporter -version` prints version, commit and date. | — |
| `version_semver` | SUGGESTED | Met | Tags follow vMAJOR.MINOR.PATCH (for example v1.14.4). | — |
| `version_tags` | SUGGESTED | Met | Annotated release tags exist (`git tag -l 'v*'`). | — |
| `release_notes` | MUST | Met | release.yml takes release notes from the annotated tag message; v1.14.4 tag subject: 'Dependency refresh & Go security update'. | — |
| `release_notes_vulns` | MUST | Partial | Notes describe changes. Security-specific content in past release notes was not checked in this assessment. | Owner: state security fixes in release notes for future security releases. |
| `report_process` | MUST | Met | CONTRIBUTING.md 'Reporting Bugs and Requesting Features'. | — |
| `report_tracker` | SHOULD | Met | GitHub Issues is the defect tracker. | — |
| `report_responses` | MUST | Partial | Issue #1 (external feature request) is closed with two comments. No published response-time commitment exists. | Owner: decide and document a response practice. |
| `enhancement_responses` | SHOULD | Partial | Issue #1 received responses. ROADMAP.md says proposals are decided by the maintainer; no response-time commitment. | Owner: document response expectations for enhancements. |
| `report_archive` | MUST | Met | GitHub Issues are publicly searchable and archived. | — |
| `vulnerability_report_process` | MUST | Met | SECURITY.md 'Reporting a Vulnerability' gives the private advisory URL. | — |
| `vulnerability_report_private` | MUST | Met | Private vulnerability reporting enabled (`gh api repos/bigtcze/pve-exporter/private-vulnerability-reporting` -> enabled:true, 2026-11-25). | — |
| `vulnerability_report_response` | MUST | Partial | SECURITY.md commits to acknowledgement within 14 days. No response record exists yet. | Owner: keep the 14-day commitment and record response times. |
| `build` | MUST | Met | `go build -v .` (mise run build); scripts/build-release.sh builds the release assets. | — |
| `build_common_tools` | SUGGESTED | Met | Standard Go toolchain with mise, as documented in CONTRIBUTING.md. | — |
| `build_floss_tools` | SHOULD | Met | Go, mise, golangci-lint, gosec, govulncheck and gitleaks are FLOSS (mise.toml). | — |
| `test` | MUST | Met | `go test -race ./...` (mise run test); CI test job in .github/workflows/ci.yml. | — |
| `test_invocation` | SHOULD | Met | CONTRIBUTING.md 'Local Commands' documents mise run test and the coverage task. | — |
| `test_most` | SUGGESTED | Met | Statement coverage 88.4% in CI ([CI run 45650125770](https://github.com/bigtcze/pve-exporter/actions/runs/45650125770), test job, coverage gate 80%). | — |
| `test_continuous_integration` | SUGGESTED | Met | ci.yml test job runs on pull requests and pushes to main. | — |
| `test_policy` | MUST | Met | CONTRIBUTING.md 'Testing Policy': new behaviour needs tests; bug fixes need regression tests. | — |
| `tests_are_added` | MUST | Partial | Fix commit 5d7b9a1 (2026-09-30) added three test files; hardening commit 4518909 (2026-06-01) added none. This PR adds selfupdate_test.go and local_sources_test.go. | Owner: keep requiring tests with fixes. |
| `tests_documented_added` | SUGGESTED | Met | CONTRIBUTING.md 'Testing Policy' documents when tests are added. | — |
| `warnings` | MUST | Met | golangci-lint (default linters, includes govet) reports 0 issues; run in CI ci.yml lint step. | — |
| `warnings_fixed` | MUST | Met | golangci-lint runs with no findings in CI ([CI run 45650125770](https://github.com/bigtcze/pve-exporter/actions/runs/45650125770), test job). | — |
| `warnings_strict` | SUGGESTED | Partial | Default golangci-lint linter set only; no stricter set and no .golangci config. | Owner (optional): choose a stricter linter set. |
| `know_secure_design` | MUST | Owner | Evidence for the maintainer's knowledge: docs/security/threat-model.md. The knowledge itself requires maintainer attestation. | Owner: attest secure-design knowledge. |
| `know_common_errors` | MUST | Owner | Supporting evidence: gosec and golangci-lint in CI; threat-model.md. Knowledge requires maintainer attestation. | Owner: attest common-error knowledge. |
| `crypto_published` | MUST | Met | Only Go standard library crypto: crypto/tls (TLS) and crypto/sha256 (checksums). Both are published algorithms. | — |
| `crypto_call` | SHOULD | N/A | No custom cryptography; the project calls standard library functions only. Not designing or implementing crypto. | — |
| `crypto_floss` | MUST | Met | Go standard library is BSD-3-Clause (FLOSS). | — |
| `crypto_keylength` | MUST | Met | The project generates no keys. TLS key parameters are negotiated by Go crypto/tls with the Proxmox server. | — |
| `crypto_working` | MUST | Met | crypto/tls (TLS to Proxmox and GitHub) and SHA-256 (update checksums); no deprecated primitives in project code. | — |
| `crypto_weaknesses` | SHOULD | Met | Project configures no cipher suites or algorithms; Go stdlib defaults apply. | — |
| `crypto_pfs` | SHOULD | N/A | Cipher-suite selection is not configured by the project; forward secrecy depends on the server and Go defaults. N/A because the project selects no suites. | — |
| `crypto_password_storage` | MUST | N/A | The project stores no user passwords. Operator-supplied Proxmox credentials come from the config file or environment (config/config.go). | — |
| `crypto_random` | MUST | N/A | The project generates no random values or keys (no crypto/rand or math/rand in non-test code). | — |
| `delivery_mitm` | MUST | Met | Release downloads and self-update use HTTPS to api.github.com and github.com (selfupdate.go). Project URLs use https. | — |
| `delivery_unsigned` | MUST | Met | Checksums are fetched only over HTTPS from GitHub: the README install and manual-update steps use `https://github.com/bigtcze/pve-exporter/releases/download/...`, and self-update uses `https://api.github.com` and the `browser_download_url` of the release (selfupdate.go). No `http://` URL exists in non-test Go code. Checksums and binary share one channel, so this is transport integrity, not publisher authentication. Releases built after this PR also get GitHub build provenance (release.yml, actions/attest-build-provenance) for publisher authentication; v1.14.4 has no attestation. | Owner: verify the first attested release with `gh attestation verify`. |
| `vulnerabilities_fixed_60_days` | MUST | Partial | govulncheck runs in CI and reports no known vulnerabilities ([CI run 45650125770](https://github.com/bigtcze/pve-exporter/actions/runs/45650125770), security job). Time-to-fix for past advisories was not assessed. | Owner: track future advisories against the 60-day target. |
| `vulnerabilities_critical_fixed` | SHOULD | Partial | No critical vulnerabilities found by govulncheck now; critical-fix history was not assessed. | — |
| `no_leaked_credentials` | MUST | Met | gitleaks git --redact . runs in the CI security job and reports no leaks ([CI run 45650125770](https://github.com/bigtcze/pve-exporter/actions/runs/45650125770)). config.yml is gitignored. | Owner: enable GitHub secret scanning and push protection (not verified as enabled). |
| `static_analysis` | MUST | Met | gosec ./..., golangci-lint and govulncheck run in CI (ci.yml test and security jobs; [CI run 45650125770](https://github.com/bigtcze/pve-exporter/actions/runs/45650125770)). | — |
| `static_analysis_common_vulnerabilities` | SUGGESTED | Met | gosec covers common Go vulnerability classes; 5 findings triaged with #nosec justifications, 0 open. | — |
| `static_analysis_fixed` | MUST | Met | gosec reports 0 open findings; each finding was fixed or justified (see Inherited debt section). | — |
| `static_analysis_often` | SUGGESTED | Met | Static analysis runs on every pull request and push to main, and weekly (ci.yml schedule). | — |
| `dynamic_analysis` | SUGGESTED | Met | Race detector (`go test -race`) runs in CI test job and mise run test. | — |
| `dynamic_analysis_unsafe` | SUGGESTED | N/A | No C/C++ code in the repository, cgo is disabled in release builds (CGO_ENABLED=0), and project packages do not import unsafe (some dependencies do). | — |
| `dynamic_analysis_enable_assertions` | SUGGESTED | Unmet | No assertion-based runtime checks are used; Go has no assert facility. SUGGESTED level. | Owner (optional): decide whether to add assertion-style checks. |
| `dynamic_analysis_fixed` | MUST | Met | The race detector runs in CI test job; the run passed ([CI run 45650125770](https://github.com/bigtcze/pve-exporter/actions/runs/45650125770)). | — |

### Silver criteria (55)

| ID | Level | Status | Evidence / N/A rationale | Owner action |
|---|---|---|---|---|
| `achieve_passing` | MUST | Unmet | The Best Practices badge requires registration at bestpractices.dev, which has not happened, and all Passing MUST criteria to be met. Passing has open items (see Passing table), so the project does not reach a passing badge level today. | Owner: register at bestpractices.dev, complete the self-assessment from this document, and close the open Passing MUST items. |
| `contribution_requirements` | MUST | Met | CONTRIBUTING.md 'Acceptable Contributions' and 'Testing Policy'. | — |
| `dco` | SHOULD | Owner | DCO sign-off is documented as not currently required (CONTRIBUTING.md 'Developer Certificate of Origin'). This is an open maintainer decision. | Owner: decide whether to require DCO sign-off. |
| `governance` | MUST | Met | GOVERNANCE.md: roles, decision making, review and merge, releases, continuity. | — |
| `code_of_conduct` | MUST | Met | CODE_OF_CONDUCT.md (Contributor Covenant 2.1); enforcement via SECURITY.md private channel. | — |
| `roles_responsibilities` | MUST | Met | GOVERNANCE.md 'Roles' (single maintainer, contributors, Renovate). | — |
| `access_continuity` | MUST | Unmet | No second maintainer and no documented access-recovery arrangement (GOVERNANCE.md 'Continuity'). | Owner: name a second maintainer or document recovery arrangements. |
| `bus_factor` | SHOULD | Unmet | Single maintainer (GOVERNANCE.md); bus factor is 1. | Owner: add a second maintainer or a documented successor. |
| `documentation_roadmap` | MUST | Met | docs/ROADMAP.md: maintenance mode, priorities, known limitations. | — |
| `documentation_architecture` | MUST | Met | AGENTS.md and .agents/ARCHITECTURE.md (tracked in git) describe components and data flow. | — |
| `documentation_security` | MUST | Met | SECURITY.md, docs/security/threat-model.md, README 'Security' section (added in this PR). | — |
| `documentation_quick_start` | MUST | Met | README 'Systemd Installation' is the quick-start path. | — |
| `documentation_current` | MUST | Met | README is updated in this PR; the build and install commands in it are the ones used by scripts/build-release.sh and the release workflow. | — |
| `documentation_achievements` | MUST | Partial | Scorecard badge added to README; it renders only after scorecard.yml runs on main after merge. Best Practices badge not added (not registered). | Owner: add the Best Practices badge only after registration. |
| `accessibility_best_practices` | SHOULD | N/A | The only user-facing UI is a minimal informational HTML page with text links; no accessibility assessment applies to this scope. | — |
| `internationalization` | SHOULD | N/A | English-only; no translatable user interface. | — |
| `sites_password_security` | MUST | N/A | The project operates no website with login or password handling; GitHub hosts it. | — |
| `maintenance_or_update` | MUST | Met | Renovate keeps dependencies and Actions current (renovate.json); releases are cut from main by tag. | — |
| `report_tracker` | MUST | Met | GitHub Issues is the defect tracker. | — |
| `vulnerability_report_credit` | MUST | Met | SECURITY.md commits to credit reporters unless they decline. No past reports are verified. | — |
| `vulnerability_response_process` | MUST | Met | SECURITY.md 'What to Expect' describes acknowledgement, triage, fix and coordinated disclosure. | — |
| `coding_standards` | MUST | Met | CONTRIBUTING.md 'Coding Standards' (gofmt, Effective Go, Go Code Review Comments). | — |
| `coding_standards_enforced` | MUST | Met | ci.yml test job runs `gofmt -l .` and fails on any unformatted file (step 'Check gofmt'); golangci-lint runs in the same job. Tools are pinned in mise.toml. | — |
| `build_standard_variables` | MUST | N/A | Go build via `go build` and mise; no autotools-style build variables apply. Release build variables (CGO_ENABLED, GOOS, GOARCH, GOARM) are documented in scripts/build-release.sh. | — |
| `build_preserve_debug` | SHOULD | Partial | Release binaries are built with -s -w (symbols stripped) by design. Local `go build` keeps debug info. | Owner: decide whether release builds should keep debug info. |
| `build_non_recursive` | MUST | Met | Makefile and mise tasks invoke go and scripts directly; none recurse into themselves. | — |
| `build_repeatable` | MUST | Met | scripts/check-reproducible.sh builds from two clones and compares checksums; the ci.yml reproducible-build job runs it ([CI run 45650125770](https://github.com/bigtcze/pve-exporter/actions/runs/45650125770)). | — |
| `installation_common` | MUST | Met | README 'Systemd Installation' with release binaries and a systemd unit. | — |
| `installation_standard_variables` | MUST | N/A | Single binary installed to a documented path (/usr/local/bin/pve-exporter); no configurable install prefix is provided. | — |
| `installation_development_quick` | MUST | Met | CONTRIBUTING.md 'Local Commands': mise install and mise run verify. | — |
| `external_dependencies` | MUST | Met | go.mod and go.sum list all dependencies; `go list -deps` shows 12 linked third-party modules (see Dependency licenses). | — |
| `dependency_monitoring` | MUST | Met | Renovate monitors Go modules and GitHub Actions (renovate.json); ci.yml runs govulncheck weekly. | — |
| `updateable_reused_components` | MUST | Met | Renovate updates dependencies (commits 2587a6f, 2537425, 84e3cab on main); modules pinned in go.mod. | — |
| `interfaces_current` | SHOULD | Met | go.mod targets Go 1.27.4 and Renovate tracks the Go version (renovate.json packageRules). | — |
| `automated_integration_testing` | MUST | Met | Criterion (official en.yml text): an automated test suite MUST be applied on each check-in to a shared repository and MUST report success or failure. CI runs the suite on every pull request and push to main and reports results ([CI run 45650125770](https://github.com/bigtcze/pve-exporter/actions/runs/45650125770), test job). | — |
| `regression_tests_added50` | MUST | Partial | Proxy measure from commit subjects, not a full bug inventory: of three fix-type commits since 2026-05-25 (9c51a86, 5d7b9a1, 4518909), one added tests (5d7b9a1). 4518909 (self-update hardening) added none; this PR adds self-update regression tests. | Owner: keep requiring regression tests for bug fixes. |
| `test_statement_coverage80` | MUST | Met | Total statement coverage 88.4% in CI ([CI run 45650125770](https://github.com/bigtcze/pve-exporter/actions/runs/45650125770)); gate at 80%. | — |
| `test_policy_mandated` | MUST | Met | CONTRIBUTING.md 'Testing Policy'; ci.yml enforces the coverage gate. | — |
| `tests_documented_added` | MUST | Met | CONTRIBUTING.md documents that new behaviour needs tests and bug fixes need regression tests. | — |
| `warnings_strict` | MUST | Partial | Default golangci-lint set; no stricter warnings set enabled. | Owner (optional): choose a stricter linter set. |
| `implement_secure_design` | MUST | Met | docs/security/threat-model.md traces each mitigation to code and tests. | — |
| `crypto_weaknesses` | MUST | Met | No weak algorithms configured or used by the project; TLS parameters use Go defaults. | — |
| `crypto_algorithm_agility` | SHOULD | N/A | The project selects no algorithms; crypto/tls and crypto/sha256 defaults apply. | — |
| `crypto_credential_agility` | MUST | Met | Credentials change via config file or environment (PVE_TOKEN_ID, PVE_TOKEN_SECRET, PVE_PASSWORD); a restart is required (README). | — |
| `crypto_used_network` | SHOULD | Met | Network use is crypto/tls to the Proxmox API and HTTPS to GitHub for self-update. | — |
| `crypto_tls12` | SHOULD | Met | The project does not set MinVersion (grep); Go's client default minimum is TLS 1.2. | — |
| `crypto_certificate_verification` | MUST | Unmet | Criterion (official en.yml text): TLS certificate verification must be performed by default when using TLS, including on subresources. Default is `insecure_skip_verify: true` (config/config.go, PVE_INSECURE_SKIP_VERIFY), so the Proxmox API client does not verify certificates by default. Met only when an operator sets `insecure_skip_verify: false`. Compatibility trade-off, documented in README and threat-model.md. | Owner: decide on a compatibility-managed default change; out of scope for #11, and the product contract forbids a silent change. |
| `crypto_verification_private` | MUST | Unmet | Criterion (official en.yml text): before sending HTTP headers with private information (such as secure cookies), TLS certificate verification must be performed. With the default `insecure_skip_verify: true`, the exporter sends `Authorization: PVEAPIToken=...` and password-login cookies/CSRF tokens (collector/api.go) without verification. Met only when an operator sets `insecure_skip_verify: false`. | Owner: same decision as crypto_certificate_verification (compatibility-managed default change, out of scope for #11). |
| `signed_releases` | MUST | Partial | Releases from this PR carry GitHub build provenance (Sigstore-backed attestations) and checksums. No attested release exists yet; tags are not GPG-signed. | Owner: verify the first attested release with `gh attestation verify --repo bigtcze/pve-exporter`. |
| `version_tags_signed` | SUGGESTED | Unmet | Release tags are annotated but not GPG-signed (verified via git cat-file: tag objects). | Owner (optional): enable tag signing. |
| `input_validation` | MUST | Met | Config validation (config/config.go: token ID format, auth required); normalizeAPIHost and buildAPIURL reject invalid hosts and paths; apiPathf escapes segments (collector/api_path.go). | — |
| `hardening` | SHOULD | Met | Release builds use CGO_ENABLED=0, -trimpath, -buildvcs=false; HTTP server timeouts (main.go); bounded responses and downloads; systemd example in README uses ProtectSystem=strict and a dedicated user. | — |
| `assurance_case` | MUST | Met | docs/security/threat-model.md is the assurance case, with trust boundaries, mitigations and residual risks. | — |
| `static_analysis_common_vulnerabilities` | MUST | Met | gosec in CI covers common Go vulnerability classes; findings are triaged with #nosec justifications. | — |
| `dynamic_analysis_unsafe` | MUST | N/A | No C/C++ code in the repository, cgo is disabled in release builds (CGO_ENABLED=0), and project packages do not import unsafe (some dependencies do). | — |

## OpenSSF Baseline Level 1 (25 IDs)

| ID | Level | Status | Evidence / N/A rationale | Owner action |
|---|---|---|---|---|
| `OSPS-AC-01.01` | MUST | Owner | Not verifiable through the API. MFA for the maintainer account is attested by the owner. | Owner: attest MFA for the bigtcze account. |
| `OSPS-AC-02.01` | MUST | Owner | Sole admin is the owner (gh API). Collaborator roles are assigned manually by the admin in GitHub; the current collaborator list and default role were not checked via API in this assessment. | Owner: confirm there are no collaborators beyond the owner, and assign any new one a minimal role manually. |
| `OSPS-AC-03.01` | MUST | Unmet | Default-branch ruleset 27497346 (active, no bypass actors) has only `deletion` and `non_fast_forward` rules. Direct pushes to main are not blocked. | Owner: add 'require pull request' and required status checks test, security, reproducible-build to ruleset 27497346. |
| `OSPS-AC-03.02` | MUST | Met | Ruleset 27497346 blocks branch deletion and non-fast-forward (force) pushes (gh API, 2026-11-25). | — |
| `OSPS-BR-01.01` | MUST | Met | release.yml and ci.yml use no untrusted event metadata in run: blocks; ${{ github.ref }} is passed through env. Verified by grep (no pull_request_target). | — |
| `OSPS-BR-01.02` | MUST | N/A | Retired in ossf/security-baseline PR 443. No action required. | — |
| `OSPS-BR-01.03` | MUST | Met | ci.yml uses the pull_request trigger (not pull_request_target), with `permissions: contents: read` and persist-credentials false, so untrusted PR code has no privileged credentials. | — |
| `OSPS-BR-03.01` | MUST | Met | Project channels are github.com (https). README localhost http:// examples are local endpoints, not project channels. | — |
| `OSPS-BR-03.02` | MUST | Met | Release assets and checksums are fetched over HTTPS (TLS-authenticated). Attestations cover releases built after this PR. | — |
| `OSPS-BR-07.01` | MUST | Partial | gitleaks runs in CI and locally; GitHub secret scanning and push protection are disabled, so pushes are not blocked. | Owner: enable secret scanning and push protection. |
| `OSPS-DO-01.01` | MUST | Met | README.md is the user guide for installation, configuration, metrics and updates. | — |
| `OSPS-DO-02.01` | MUST | Met | CONTRIBUTING.md 'Reporting Bugs and Requesting Features' guides defect reporting. | — |
| `OSPS-GV-02.01` | MUST | Met | GitHub Issues is the public discussion mechanism (CONTRIBUTING.md). Discussions are disabled. | — |
| `OSPS-GV-03.01` | MUST | Met | CONTRIBUTING.md explains the contribution process. | — |
| `OSPS-LE-02.01` | MUST | Met | MIT License (OSI-approved). | — |
| `OSPS-LE-02.02` | MUST | Met | MIT License (OSI-approved). The v1.14.4 source tag contains LICENSE (git ls-tree v1.14.4). | — |
| `OSPS-LE-03.01` | MUST | Met | LICENSE file at repository root. | — |
| `OSPS-LE-03.02` | MUST | Met | LICENSE is in the released source tree (git ls-tree v1.14.4). | — |
| `OSPS-QA-01.01` | MUST | Met | Repository is public (gh API). | — |
| `OSPS-QA-01.02` | MUST | Met | Public git history with authors and dates. | — |
| `OSPS-QA-02.01` | MUST | Met | go.mod and go.sum list direct and indirect dependencies. | — |
| `OSPS-QA-04.01` | MUST | N/A | Single repository; no multi-repository project list is required. | — |
| `OSPS-QA-05.01` | MUST | Partial | Current tree has no executable artifacts (no 100755 files, no ELF MIME types in git ls-files). History still contains a 15.5 MB `pve-exporter` binary, added in 7200809 (2025-12-04) and removed in 92e96d1. | Owner (decision): whether to rewrite history. Rewriting history affects every clone and is not part of this PR. |
| `OSPS-QA-05.02` | MUST | Partial | Current tree has no binary artifacts (MIME check of tracked files). The same historical binary as OSPS-QA-05.01 is in history. | Owner (decision): see OSPS-QA-05.01. |
| `OSPS-VM-02.01` | MUST | Met | SECURITY.md provides the private advisory channel as the security contact. | — |
