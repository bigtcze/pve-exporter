# Definition of done

A change is complete only when applicable conditions hold:

1. It fulfills the authorized scope without unintended changes to supported features, metrics or configuration.
2. The patch is cohesive, maintainable and has no unresolved known race, credentials exposure or error-path bug.
3. Relevant regression and negative-path tests demonstrate the actual changed behavior, including metrics compatibility and concurrency where applicable.
4. The required pinned lint, Go race tests and build pass on the actual PR; full required GitHub CI is green.
5. Changes to CLI, config, metrics, install/update behavior or operator expectations are reflected accurately in README and examples.
6. An independent reviewer has considered meaningful compatibility, security, failure and architecture risks, and findings are resolved.
7. The approved PR is merged through normal checks. A standalone commit, PR draft or unsupported success claim is not completion.
8. Release work additionally satisfies `RELEASE_QUALITY.md`: actual published artifacts, checksums, validated release notes and upgrade/install evidence.

Routine dependency updates still require compatibility review and passing gates. These rules define quality and acceptance, not a release schedule or an authorization mechanism for new work.
