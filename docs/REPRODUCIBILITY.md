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

Recommended research process: clean commit → frozen configs → repeated runs → immutable manifests →
validated aggregation → figures/tables generated from recorded outputs.

