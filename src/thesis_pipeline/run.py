from __future__ import annotations

import csv
import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path
from typing import Any

from thesis_pipeline import __version__
from thesis_pipeline.config import load_experiment, load_scenario
from thesis_pipeline.evaluation.metrics import calculate_metrics
from thesis_pipeline.logging_config import append_json_log
from thesis_pipeline.prioritisation.strategies import build_strategy
from thesis_pipeline.simulation.workflow import SimulationResult, simulate_workflow
from thesis_pipeline.synthetic_org.generator import generate_dataset


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_metadata(root: Path) -> dict[str, Any]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        branch = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        )
        return {"commit": commit, "branch": branch, "dirty": dirty}
    except (FileNotFoundError, subprocess.CalledProcessError):
        return {"commit": None, "branch": None, "dirty": None}


def _package_versions() -> dict[str, str | None]:
    versions: dict[str, str | None] = {}
    for package in ("PyYAML", "pydantic", "simpy", "pytest", "ruff"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = None
    return versions


def _write_metrics(path: Path, metrics: dict[str, float | int | str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["metric", "value"])
        writer.writerows(metrics.items())


def _write_events(path: Path, result: SimulationResult) -> None:
    fields = [
        "finding_id",
        "cve_id",
        "asset_id",
        "team_id",
        "priority_rank",
        "finding_created",
        "alert_created",
        "correlated",
        "assigned",
        "triage_started",
        "triage_completed",
        "decision",
        "remediation_started",
        "remediation_completed",
        "sla_deadline",
        "analyst_id",
        "remediator_id",
        "actionable",
        "risk_weight",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for record in result.records:
            writer.writerow(
                {
                    "finding_id": record.finding.finding_id,
                    "cve_id": record.finding.cve_id,
                    "asset_id": record.finding.asset_id,
                    "team_id": record.finding.team_id,
                    "priority_rank": record.priority_rank,
                    "finding_created": record.finding_created.isoformat(),
                    "alert_created": record.alert_created.isoformat(),
                    "correlated": record.correlated.isoformat(),
                    "assigned": record.assigned.isoformat(),
                    "triage_started": record.triage_started.isoformat(),
                    "triage_completed": record.triage_completed.isoformat(),
                    "decision": record.decision.isoformat(),
                    "remediation_started": record.remediation_started.isoformat(),
                    "remediation_completed": record.remediation_completed.isoformat(),
                    "sla_deadline": record.sla_deadline.isoformat(),
                    "analyst_id": record.analyst_id,
                    "remediator_id": record.remediator_id,
                    "actionable": record.finding.actionable,
                    "risk_weight": record.finding.risk_weight,
                }
            )


def run_experiment(
    experiment_path: str | Path,
    scenario_path: str | Path,
    output_root: str | Path | None = None,
    cli_arguments: list[str] | None = None,
) -> Path:
    root = project_root()
    experiment_file = Path(experiment_path).resolve()
    scenario_file = Path(scenario_path).resolve()
    experiment = load_experiment(experiment_file)
    scenario = load_scenario(scenario_file)
    if not experiment.enabled:
        raise RuntimeError(
            f"Experiment {experiment.experiment_id} is scaffolded but disabled pending "
            "research design"
        )
    strategy = build_strategy(experiment.policy)
    dataset = generate_dataset(scenario)
    result = simulate_workflow(dataset.findings, scenario, strategy)
    metrics = calculate_metrics(result, scenario)

    created_at = datetime.now(UTC)
    run_id = (
        f"{experiment.experiment_id}-{scenario.scenario_id}-"
        f"{created_at.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    )
    parent = Path(output_root).resolve() if output_root else root / "outputs"
    run_directory = parent / run_id
    run_directory.mkdir(parents=True, exist_ok=False)
    log_path = run_directory / "logs.jsonl"
    append_json_log(log_path, "run_started", run_id=run_id)

    lifecycle_monotonic = all(
        all(later >= earlier for earlier, later in pairwise(item.lifecycle()))
        for item in result.records
    )
    timestamps_utc = all(
        stamp.utcoffset() is not None and stamp.utcoffset().total_seconds() == 0
        for item in result.records
        for stamp in item.lifecycle()
    )
    validation = {
        "status": "passed" if lifecycle_monotonic and timestamps_utc else "failed",
        "configuration_valid": True,
        "lifecycle_monotonic": lifecycle_monotonic,
        "timestamps_utc": timestamps_utc,
        "look_ahead_guard_applied": experiment.policy == "threat_intel",
        "same_input_contract": "scenario hash + seed + synthetic input fingerprint",
        "smoke_only": scenario.scenario_id == "smoke",
    }
    manifest = {
        "run_id": run_id,
        "created_at_utc": created_at.isoformat(),
        "completed_at_utc": datetime.now(UTC).isoformat(),
        "research_status": "engineering_smoke_not_dissertation_result",
        "pipeline_version": __version__,
        "experiment": {
            "id": experiment.experiment_id,
            "policy": experiment.policy,
            "config_path": str(experiment_file.relative_to(root)),
            "config_sha256": _sha256(experiment_file),
        },
        "scenario": {
            "id": scenario.scenario_id,
            "config_path": str(scenario_file.relative_to(root)),
            "config_sha256": _sha256(scenario_file),
            "seed": scenario.seed,
        },
        "inputs": {
            "type": "synthetic",
            "fingerprint_sha256": dataset.fingerprint,
            "vulzoo_commit": None,
            "epss_snapshot_date": None,
            "epss_model_version": None,
            "kev_catalogue_date": None,
            "note": "No external vulnerability data were used by this smoke run.",
        },
        "git": _git_metadata(root),
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "packages": _package_versions(),
        },
        "cli_arguments": cli_arguments or [],
        "validation_status": validation["status"],
    }

    (run_directory / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    (run_directory / "metrics.json").write_text(
        json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8"
    )
    _write_metrics(run_directory / "metrics.csv", metrics)
    _write_events(run_directory / "events.csv", result)
    (run_directory / "validation_summary.json").write_text(
        json.dumps(validation, indent=2, sort_keys=True), encoding="utf-8"
    )
    (run_directory / "README.md").write_text(
        "\n".join(
            [
                f"# Run {run_id}",
                "",
                "**Status: engineering smoke test; not a dissertation research result.**",
                "",
                f"Experiment: `{experiment.experiment_id}` (`{experiment.policy}`)",
                f"Scenario: `{scenario.scenario_id}`; seed `{scenario.seed}`",
                f"Synthetic input fingerprint: `{dataset.fingerprint}`",
                "",
                "Synthetic cycle-time metrics estimate relative scenario behaviour only. They are",
                "not measured enterprise MTTM/MTTR and cannot support causal or predictive claims.",
                "See `manifest.json` and `validation_summary.json` before interpreting metrics.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    append_json_log(
        log_path,
        "run_completed",
        run_id=run_id,
        validation_status=validation["status"],
        input_fingerprint=dataset.fingerprint,
    )
    return run_directory
