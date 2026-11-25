#!/usr/bin/env bash
# Usage: scripts/build-release.sh VERSION OUTDIR
#
# Builds the documented release assets into OUTDIR:
#   pve-exporter-linux-amd64, pve-exporter-linux-arm64, pve-exporter-linux-armv7
#   checksums.txt (sha256sum format, only the three binaries above)
#
# The build is intended to be reproducible: it uses CGO_ENABLED=0, -trimpath,
# -buildvcs=false and a build date taken from the commit time (UTC), not the
# wall clock. Run from a git checkout.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 VERSION OUTDIR" >&2
  exit 2
fi

version="$1"
outdir="$2"

mkdir -p "$outdir"
outdir="$(cd "$outdir" && pwd)"

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

commit="$(git rev-parse --short HEAD)"
# Commit time in UTC, so the same commit always yields the same date.
build_date="$(TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ HEAD)"

ldflags="-s -w -X main.version=${version} -X main.commit=${commit} -X main.date=${build_date}"

build() {
  local goarch="$1" goarm="$2" out="$3"
  echo "building $out (GOOS=linux GOARCH=$goarch${goarm:+ GOARM=$goarm})"
  env CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" ${goarm:+GOARM="$goarm"} \
    go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$outdir/$out" .
}

build amd64 "" pve-exporter-linux-amd64
build arm64 "" pve-exporter-linux-arm64
build arm 7 pve-exporter-linux-armv7

(
  cd "$outdir"
  sha256sum pve-exporter-linux-amd64 pve-exporter-linux-arm64 pve-exporter-linux-armv7 > checksums.txt
)

echo "Release assets written to $outdir:"
cat "$outdir/checksums.txt"
