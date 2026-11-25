#!/usr/bin/env bash
# Usage: scripts/check-coverage.sh [coverage.out] [threshold]
#
# Prints the per-function coverage summary and the total statement coverage
# from a Go coverage profile, writes the summary to coverage-func.txt, and
# fails when the total is below the threshold (percent, default 80).
set -euo pipefail

profile="${1:-coverage.out}"
threshold="${2:-80}"
summary="coverage-func.txt"

if [[ ! -f "$profile" ]]; then
  echo "check-coverage: profile not found: $profile" >&2
  exit 2
fi

if ! [[ "$threshold" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "check-coverage: threshold must be a number, got: $threshold" >&2
  exit 2
fi

go tool cover -func="$profile" > "$summary"
cat "$summary"

total_line="$(grep -E '^total:' "$summary" || true)"
if [[ -z "$total_line" ]]; then
  echo "check-coverage: no total line in coverage summary" >&2
  exit 2
fi

total="$(awk '/^total:/ { sub(/%$/, "", $NF); print $NF }' "$summary")"

echo "Total statement coverage: ${total}% (threshold ${threshold}%)"

if awk -v t="$total" -v min="$threshold" 'BEGIN { exit !(t + 0 >= min + 0) }'; then
  echo "Coverage gate passed."
else
  echo "Coverage gate FAILED: ${total}% is below ${threshold}%." >&2
  exit 1
fi
