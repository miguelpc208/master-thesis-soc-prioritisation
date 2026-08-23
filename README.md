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
```

`inventory-vulzoo` never downloads data. It inventories an already approved local clone beneath
`THESIS_DATA_ROOT`.

`ingest-vulzoo` requires the previously approved complete coverage report and re-verifies its
content fingerprint while reading local data. It writes only to an initialized SQLite database
beneath `THESIS_DATA_ROOT`; EPSS and exploit payloads remain excluded.

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

VulZoo, EPSS/KEV downloads, SQLite databases, Parquet data, generated runs, model responses, and
honeypot payloads stay outside Git. Approve an absolute non-OneDrive `THESIS_DATA_ROOT` with at least
30 GB free before Phase 3. Store the path only in `.env`; `.env` is ignored.

## Reproducibility contract

Compared experiments must use the same scenario configuration and seed. Every run records input
hashes, an input fingerprint, Git state, package metadata, timestamps, CLI arguments, and source
snapshot placeholders. Evidence dated after a decision is rejected. All internal timestamps use
UTC.

## Limitations

Synthetic time metrics estimate relative scenario effects and are not measured enterprise MTTM or
MTTR. Current smoke enrichment is synthetic and cannot support causal, predictive, or business
claims. E3/E4 assumptions require calibration and sensitivity analysis. E5/E6 remain optional.

## Source anchors

- VulZoo repository: https://github.com/NUS-Curiosity/VulZoo
- VulZoo paper: https://doi.org/10.1145/3691620.3695345
- FIRST EPSS: https://www.first.org/epss/data
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

The final dissertation title and software licence remain pending supervisor/university confirmation.
