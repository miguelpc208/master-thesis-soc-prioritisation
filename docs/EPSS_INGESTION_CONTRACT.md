# FIRST EPSS historical-panel ingestion contract

This contract governs the approved FIRST Exploit Prediction Scoring System daily panel. It joins
official probability and percentile observations to existing canonical VulZoo CVEs without
inventing missing vulnerabilities, mixing model generations, or claiming exact historical ground
truth for unrelated sources.

## Approved source and observed acquisition

- Official source documentation: `https://www.first.org/epss/data`.
- Official historical archive: `https://github.com/empiricalsec/epss_scores`.
- Archive Git commit: `3b3ae5b793011090800848c75ceea4cecaa9d309`.
- Acquisition date: 2026-08-24; the exact UTC retrieval timestamp is retained in the local
  acquisition manifest and each source snapshot.
- First active score date: 2025-03-21.
- Last active score date: 2025-04-04.
- Contiguous daily files: 15.
- Model version throughout: `v2025.03.14`.
- Panel SHA-256 fingerprint:
  `221e5281bf5929a0daa2cbf2b16a9792636ccc3770416d49c362d90484a20cb3`.
- Audited source rows: 4,083,075.
- Rows whose CVE already exists in the approved VulZoo catalogue: 4,075,133.
- Valid score rows outside the approved canonical catalogue: 7,942.

The baseline and stress scenarios start at 2025-03-22 09:00 UTC and run for 336 hours. Because a
date-only observation becomes available conservatively at 23:59:59 UTC, the 2025-03-21 score is
required for the first morning. The 2025-04-04 score is the last score available before the
2025-04-05 09:00 horizon. All selected dates use one EPSS model generation. The scenario start
lies one day after the newest retained NVD publication and three days after the retained KEV
catalogue date, reducing the prior approximately 286-day cross-source misalignment.

## Retained superseded panel

The original 2025-12-31 through 2026-01-14 panel remains available as an immutable local archive:

- Source rows: 4,643,360; VulZoo-joinable observations: 4,152,416.
- Valid out-of-snapshot source rows: 490,944.
- Fingerprint: `1cec6b4591f0df289531778bc3e14fffa50dee396a0ff05aacfaa3472436b2b9`.
- Daily source snapshots: 15; files and ingestion history remain unchanged.

Changing the active panel is append-only: no earlier score observations, source snapshots, runs,
files or acquisition manifests are deleted. The two disjoint panels contain 8,227,549 retained
observations across 30 score dates. January 2026 observations cannot become eligible at a March
2025 decision because the shared temporal contract filters by source-effective score date.

## Source meaning

An EPSS probability estimates the likelihood that a published vulnerability will be exploited in
the wild during the 30 days following score publication. It is neither observed exploitation nor
proof that an organisational asset is exposed. Percentile is the relative position within that
day's scored population; populations can change between days.

EPSS supplements the pinned NVD CVSS and CISA KEV evidence. It does not replace the CPE
applicability evaluator, business context, remediation feasibility, analyst review, or a
validated SOC simulation.

## Acquisition and local boundary

- Historical files are downloaded from the official archive, pinned to its full Git commit.
- The FIRST API must not be used for bulk ingestion.
- Each approved panel's 15 `.csv.gz` files and acquisition manifest remain below
  `THESIS_DATA_ROOT/snapshots/epss`.
- The SQLite database remains elsewhere below `THESIS_DATA_ROOT`, outside Git and OneDrive.
- Git contains source configuration, contracts, migrations, import code and synthetic tests only.
- The importer never downloads or modifies dataset files and never emits raw score rows in reports.

## Integrity and model boundaries

Before creating any EPSS ingestion runs, the importer verifies:

1. Enabled source configuration, pinned archive commit and approved panel fingerprint.
2. The actual timezone-aware retrieval timestamp against the configured retrieval date.
3. Exactly one contiguous daily file per approved score date.
4. Each archive-pinned URL, approved relative path, compressed length and compressed SHA-256.
5. The official leading comment, unchanged publish timestamp and `v2025.03.14` model version.
6. Exact CSV fields `cve`, `epss` and `percentile`.
7. The acquired canonical VulZoo population and per-day input, accepted and excluded counts.

CVEs must match `CVE-YYYY-NNNN...`; duplicate daily CVEs are rejected. Probability and percentile
must be finite numeric values between zero and one. Missing or out-of-range values are never
replaced by zero. A different model version requires a new explicit approval and analytical
boundary.

## Normalised database semantics

Each dated `.csv.gz` becomes one `source_snapshot` with:

- `source_name = first_epss`;
- `source_version = v2025.03.14`;
- `snapshot_date = score_date`;
- the actual manifest retrieval timestamp;
- `sha256:<compressed-file-sha256>`;
- the archive-commit-pinned upstream URL and approved relative local path.

Each daily execution creates a separate `ingestion_run`. Every matched row becomes one
`epss_observation` with canonical `cve_id`, probability, percentile, score date, model version,
retrieval timestamp, source-snapshot identity and ingestion-run identity. Re-ingestion is
idempotent for observations and snapshots while retaining a fresh execution audit per day.

Daily writes are atomic. A malformed or inconsistent daily file rolls back that day's rows and
records a failed execution without discarding previously successful dates. Migration 007 enforces
probability/percentile ranges, date validity, required provenance, daily source-snapshot coherence
and run-to-snapshot ownership directly in SQLite.

The active panel's 7,942 rows outside the pinned VulZoo catalogue are valid source observations
but outside this join scope. They are counted as `outside_vulzoo_snapshot`, not imported, not
converted into canonical CVEs, and not represented as malformed-record rejections. The archived
January panel retains its separately observed 490,944 out-of-snapshot source rows.

## Temporal and claim boundaries

- `score_date` is a source date, not the actual local download time.
- Reconstruction eligibility starts at `score_dateT23:59:59Z`.
- Strict-snapshot eligibility starts at the later of that UTC day-end and the actual 2026-08-24
  retrieval timestamp.
- Therefore March-April 2025 decisions may use the active panel only in the explicitly declared
  `source_effective_reconstruction` mode, not in `strict_snapshot` mode.
- EPSS has a complete daily panel only for each separately approved 15-day window.
- NVD and KEV remain single retained snapshots; the combined reconstruction is not exact
  historical ground truth.
- Existing synthetic E1/E2 smoke experiments are not automatically connected to the real SQLite
  observations by this ingestion step.

See [TEMPORAL_EVIDENCE_CONTRACT.md](TEMPORAL_EVIDENCE_CONTRACT.md) for the shared as-of rules.

## Execution

```powershell
python -m thesis_pipeline.cli init-db `
    --path "$env:THESIS_DATA_ROOT\databases\vulzoo-ingestion.sqlite"

python -m thesis_pipeline.cli ingest-epss-panel `
    --config configs/data_sources.yaml `
    --database "$env:THESIS_DATA_ROOT\databases\vulzoo-ingestion.sqlite" `
    --acquisition-manifest "$env:THESIS_DATA_ROOT\snapshots\epss\manifests\APPROVED.json" `
    --progress-every 100000
```

Reports belong under ignored `outputs/`. No EPSS probabilities, compressed source files, database
backups or absolute machine-specific paths may be committed to Git.
