# Reproducibility contract

Every run emits a unique directory with:

- `manifest.json`: run identity, UTC timestamps, Git state, configuration hashes, input fingerprint,
  external snapshot placeholders, Python/platform/package metadata, seed, and CLI arguments;
- `metrics.json` and `metrics.csv`;
- `events.csv` with the lifecycle and assigned resources;
- `logs.jsonl` structured run events;
- `validation_summary.json`;
- a warning-labelled `README.md`.

Compared treatments must share the same scenario hash, seed, and input fingerprint. External-data
runs must also pin source checksums, VulZoo commit, EPSS date/model version, and KEV catalogue date.
Current and historical data are never silently mixed. Generated run directories remain outside Git.

Canonical catalogue joins are identity-bound: approved DiverseVul profiles and EPSS manifests
must carry the SHA-256 of sorted, newline-delimited CVE IDs, not only a row count. GHSA acquisition
manifests must carry per-file SHA-256 values plus a canonical collection fingerprint approved by a
separate audit. A completed EPSS parent-panel marker is required before its observations are eligible
for public binding.

The public-binding fingerprint includes CVE, CVSS, EPSS, KEV, DiverseVul and recalculated
risk-weight material. Expanding this contract deliberately invalidates earlier public-binding and
downstream operational fingerprints; they must be regenerated from the frozen inputs and never
copied forward.

Recommended research process: clean commit → frozen configs → repeated runs → immutable manifests →
validated aggregation → figures/tables generated from recorded outputs.
