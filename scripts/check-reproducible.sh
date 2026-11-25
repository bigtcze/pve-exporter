#!/usr/bin/env bash
# Usage: scripts/check-reproducible.sh
#
# Builds the release assets twice from two different source paths (copies of
# HEAD created with git archive) and separate GOCACHE directories, then fails
# unless checksums.txt is byte-identical. Prints the resulting checksums.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

work="$(mktemp -d "${TMPDIR:-/tmp}/pve-exporter-repro.XXXXXX")"
trap 'rm -rf "$work"' EXIT

version="v0.0.0-repro"

head_sha="$(git rev-parse HEAD)"

for run in a b; do
  # A local clone at a fixed commit gives each run its own path and a .git
  # directory (build-release.sh reads commit and date from git). Uncommitted
  # working-tree changes are intentionally not part of the check.
  src="$work/src-$run"
  git clone --quiet --no-local --no-checkout "$repo_root" "$src"
  git -C "$src" checkout --quiet --detach "$head_sha"
  (
    cd "$src"
    export GOCACHE="$work/gocache-$run"
    # The build script comes from the working tree; the clone supplies the
    # sources (build-release.sh resolves the repo from the current directory).
    "$repo_root/scripts/build-release.sh" "$version" "$work/out-$run"
  )
done

if cmp -s "$work/out-a/checksums.txt" "$work/out-b/checksums.txt"; then
  echo "Reproducible: checksums are byte-identical across two builds."
else
  echo "NOT reproducible: checksums differ." >&2
  diff "$work/out-a/checksums.txt" "$work/out-b/checksums.txt" >&2 || true
  exit 1
fi

for f in pve-exporter-linux-amd64 pve-exporter-linux-arm64 pve-exporter-linux-armv7; do
  if ! cmp -s "$work/out-a/$f" "$work/out-b/$f"; then
    echo "binary $f differs between builds" >&2
    exit 1
  fi
done

echo "checksums.txt:"
cat "$work/out-a/checksums.txt"
