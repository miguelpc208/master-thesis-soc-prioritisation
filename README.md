# Master thesis SOC prioritisation pipeline

This repository is the reproducible engineering foundation for a simulation-based study of
vulnerability prioritisation, alert-fatigue reduction, and incident-mitigation assistance in an
organisational SOC. It models existing human triage and remediation work; each treatment measures
marginal improvement rather than comparing against an unrealistic no-process organisation.

The current vertical slice generates a seeded fictional organisation and vulnerability findings,
runs E1 (CVSS-only) and E2 (CVSS + EPSS + KEV), schedules finite analyst and remediation capacity,
and emits traceable manifests, event records, validation summaries, and metrics. These outputs are
engineering smoke tests, not dissertation evidence.

## Safe quick start on Windows

```powershell
conda env create -f environment.yml
conda activate thesis-soc
python -m pip install -e .
python -m thesis_pipeline.cli doctor
python -m pytest
ruff check .
.\scripts\run_smoke_test.ps1
```

If Conda reports that `thesis-soc` already exists, use
`conda env update -n thesis-soc -f environment.yml --prune` instead of recreating it.

## Commands

```powershell
python -m thesis_pipeline.cli generate-synthetic --config configs/scenarios/smoke.yaml
python -m thesis_pipeline.cli run-experiment --experiment configs/experiments/e1_cvss.yaml --scenario configs/scenarios/smoke.yaml
python -m thesis_pipeline.cli run-experiment --experiment configs/experiments/e2_threat_intel.yaml --scenario configs/scenarios/smoke.yaml
python -m thesis_pipeline.cli inventory-vulzoo --config configs/data_sources.yaml
python -m thesis_pipeline.cli profile-vulzoo --config configs/data_sources.yaml --sample-limit 2 --max-json-mib 50
python -m thesis_pipeline.cli scan-vulzoo-coverage --config configs/data_sources.yaml --max-json-mib 5
python -m thesis_pipeline.cli init-db --path "$env:THESIS_DATA_ROOT\databases\vulzoo-ingestion.sqlite"
python -m thesis_pipeline.cli ingest-vulzoo --config configs/data_sources.yaml --database "$env:THESIS_DATA_ROOT\databases\vulzoo-ingestion.sqlite" --coverage-report outputs/vulzoo-coverage-v2.json
python -m thesis_pipeline.cli ingest-diversevul --config configs/data_sources.yaml --database "$env:THESIS_DATA_ROOT\databases\vulzoo-ingestion.sqlite" --acquisition-manifest "$env:THESIS_DATA_ROOT\DiverseVul\manifests\APPROVED-MANIFEST.json" --profile-report outputs/APPROVED-DIVERSEVUL-PROFILE.json
python -m thesis_pipeline.cli ingest-epss-panel --config configs/data_sources.yaml --database "$env:THESIS_DATA_ROOT\databases\vulzoo-ingestion.sqlite" --acquisition-manifest "$env:THESIS_DATA_ROOT\snapshots\epss\manifests\APPROVED-MANIFEST.json"
python -m thesis_pipeline.cli ingest-github-advisories --config configs/data_sources.yaml --database "$env:THESIS_DATA_ROOT\databases\vulzoo-ingestion.sqlite" --acquisition-manifest "$env:THESIS_DATA_ROOT\snapshots\vulzoo-github-advisory\manifests\APPROVED-MANIFEST.json" --audit-report outputs/APPROVED-PATCH-ADVISORY-AUDIT.json --decision-at "2025-03-22T09:00:00Z"
python -m thesis_pipeline.cli audit-technical-as-of --database "$env:THESIS_DATA_ROOT\databases\vulzoo-ingestion.sqlite" --decision-at "2026-08-24T23:59:59Z" --mode strict_snapshot
python -m thesis_pipeline.cli cmdbuild-preview --phase all --database "$env:THESIS_DATA_ROOT\databases\vulzoo-ingestion.sqlite"
python -m thesis_pipeline.cli cmdbuild-ingest-business --expected-fingerprint <approved-business-sha256>
python -m thesis_pipeline.cli cmdbuild-ingest-operational --database "$env:THESIS_DATA_ROOT\databases\vulzoo-ingestion.sqlite" --expected-fingerprint <approved-operational-sha256>
python -m thesis_pipeline.cli cmdbuild-export-evidence --database "$env:THESIS_DATA_ROOT\databases\vulzoo-ingestion.sqlite" --output "$env:THESIS_DATA_ROOT\evidence\cmdbuild-evidence.json"
```

`inventory-vulzoo` never downloads data. It inventories an already approved local clone beneath
`THESIS_DATA_ROOT`.

`ingest-vulzoo` requires the previously approved complete coverage report and re-verifies its
content fingerprint while reading local data. It writes only to an initialized SQLite database
beneath `THESIS_DATA_ROOT`; FIRST EPSS is ingested separately, while exploit payloads remain
excluded.

`ingest-diversevul` re-verifies the approved acquisition manifest, dataset and metadata checksums,
read-only profile, and existing VulZoo catalogue before joining function-level research labels to
canonical CVEs. Raw function source remains exclusively in the approved local JSONL dataset; it is
never copied into SQLite, Git, logs, or generated reports.

`ingest-epss-panel` re-verifies a dated, archive-commit-pinned FIRST EPSS acquisition manifest and
all compressed daily checksums before joining probability/percentile observations to existing
VulZoo CVEs. Each day retains separate source and execution provenance; valid CVEs outside the
pinned VulZoo snapshot are counted and excluded without creating synthetic canonical records.
The active March-April 2025 panel aligns with the retained NVD and KEV snapshots; the superseded
January 2026 panel remains archived without influencing the earlier scenario cut-offs.

`ingest-github-advisories` re-verifies the separately approved pinned advisory collection, its
acquisition manifest and the read-only relationship audit. It retains only non-withdrawn,
time-eligible advisories with authoritative canonical-CVE aliases, bounded package/version
metadata, and same-CVE commit hashes corroborated by direct commit URLs. Commit references without
an authoritative advisory source-availability anchor remain undated and historically ineligible;
advisory descriptions, patch bodies and exploit payloads are never copied.

`audit-technical-as-of` opens SQLite read-only and reports which normalized observations are
eligible at an explicit UTC decision cut-off. `strict_snapshot` uses retained-snapshot availability;
`source_effective_reconstruction` is an explicitly incomplete historical reconstruction. See
`docs/TEMPORAL_EVIDENCE_CONTRACT.md` before using either mode.

The versioned CMDBuild commands rebuild the same plans used by preview and ingestion. Preview is
read-only; both ingestion commands retain the existing exact-fingerprint and rollback gates; the
evidence command refuses to write inside Git or overwrite an existing file. See
`docs/PR4_REMEDIATION_CONTRACT.md` before reusing pre-remediation fingerprints.

## Experiment ladder

| ID | Treatment | Status |
| --- | --- | --- |
| E1 | CVSS-only, documented tie-break | Implemented smoke baseline |
| E2 | KEV, then EPSS, then CVSS | Implemented smoke baseline |
| E3 | Technical and business context | Configuration scaffold; research implementation pending |
| E4 | E3 plus capacity and operational constraints | Configuration scaffold; minimal capacity model exists |
| E5 | Local AI assistance with human review | Interface scaffold; disabled |
| E6 | Authorised replayed honeypot evidence | Interface scaffold; disabled |

## Repository map

- `src/thesis_pipeline`: reusable pipeline, strategies, simulation, and evaluation.
- `configs`: versioned source, scenario, and experiment assumptions.
- `tests`: unit and end-to-end checks using only synthetic inputs.
- `docs`: research design, data contract, limitations, roadmap, and Ricardo's action list.
- `research`: literature-review workspaces and empty evidence templates.
- `notebooks`: thin, valid entry points that call reusable modules.
- `outputs`: ignored runtime outputs; only its README is versioned.

## Data boundary

VulZoo, DiverseVul source functions, EPSS/KEV downloads, SQLite databases, Parquet data, generated
runs, model responses, and honeypot payloads stay outside Git. Approve an absolute non-OneDrive
`THESIS_DATA_ROOT` with at least 30 GB free before Phase 3. Store the path only in `.env`; `.env`
is ignored.

## Reproducibility contract

Compared experiments must use the same scenario configuration and seed. Every run records input
hashes, an input fingerprint, Git state, package metadata, timestamps, CLI arguments, and source
snapshot placeholders. Evidence dated after a decision is rejected. All internal timestamps use
UTC.

## Limitations

Synthetic time metrics estimate relative scenario effects and are not measured enterprise MTTM or
MTTR. Current smoke enrichment is synthetic and cannot support causal, predictive, or business
claims. DiverseVul labels describe a dated function-level research corpus and do not establish
exploitation, asset exposure, business impact, or current vulnerability intelligence. The acquired
snapshot's observed counts differ from the paper's headline counts and must be reported as
observed. The active EPSS panel is complete only for its approved March-April 2025 scenario window;
retained NVD and KEV sources remain single snapshots, so historical reconstruction is not exact
ground truth. Legacy-only CVEs without recoverable publication timestamps cannot be treated as
historically eligible by inferring missing dates.
Retained GHSA records are one approved snapshot, not a complete historical advisory panel;
fixed-version events and corroborated commits do not prove asset applicability or deployed fixes.
E3/E4 assumptions require calibration and sensitivity analysis. E5/E6 remain optional.

## Source anchors

- VulZoo repository: https://github.com/NUS-Curiosity/VulZoo
- VulZoo paper: https://doi.org/10.1145/3691620.3695345
- DiverseVul repository: https://github.com/wagner-group/diversevul
- DiverseVul paper: https://doi.org/10.1145/3607199.3607242
- FIRST EPSS: https://www.first.org/epss/data
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

The final dissertation title and software licence remain pending supervisor/university confirmation.
