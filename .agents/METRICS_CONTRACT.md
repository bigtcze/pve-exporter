# Prometheus compatibility contract

Metric names, HELP/TYPE metadata, label keys, units and semantics are public interfaces used by dashboards, alert rules and recording rules. Use the README's metric inventory and implementation as the baseline; never invent a competing, unverified catalog.

- Preserve existing `pve_*` metric families and label sets unless a specifically authorized compatibility change includes migration guidance.
- Keep units (bytes, seconds, ratios, percentages), monotonic counters and gauges correct; a `_total` suffix alone does not prove a Prometheus Counter type.
- Preserve documented labels such as `node`, `vmid`, `device`, `interface`, `storage` where used; don't introduce unbounded values, per-scrape IDs or raw error text as labels.
- Do not turn failed API requests, missing/stale local data or insufficient ACLs into fabricated observed zeros. Distinguish observed zero, expected omitted series and outright failure as documented.
- Preserve local-host versus cluster-wide metric provenance and bounded scrape work.

Any affected collector change needs deterministic tests asserting family names, types, label combinations, values and omission behavior. Include malformed/partial API responses, offline guests, permission errors and concurrency where relevant. Verify descriptor consistency and no unintended duplicate time series.
