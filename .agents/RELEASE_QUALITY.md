# Release and distribution quality

This contract defines **how** a release is qualified; it does not prescribe **when** a release is scheduled.

- Preserve semantic versioning, existing release-tag workflow and meaningful annotated-tag release notes. Review release source and verify tests/race checks/lint and independent quality findings before tagging.
- Build and actually verify the currently documented Linux binaries: amd64, arm64 and ARMv7, plus matching `checksums.txt`. Asset names, architectures and checksums are public installation/update contracts.
- Verify the published GitHub release exists, its files are downloadable, checksums match the uploaded bytes, documentation is current, and the result corresponds to the approved source commit.
- Assess Go toolchain and dependency changes for binary compatibility and supported host environments.
- Test/manual-review installer and self-update behavior relevant to the changes, including expected failures. The known ARMv7 self-update name mismatch remains a documented limitation until fixed and independently verified.
- Do not ship an empty release or invent verification evidence. Include honest operator-facing notes and any required upgrade, restart, migration or rollback caveats.
