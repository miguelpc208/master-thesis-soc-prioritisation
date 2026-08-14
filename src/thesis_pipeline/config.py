from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from thesis_pipeline.models import ExperimentConfig, ScenarioConfig


class ConfigurationError(ValueError):
    """Raised when a configuration cannot be used safely."""


def _read_yaml(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigurationError(f"Configuration file does not exist: {config_path}")
    try:
        document = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"Invalid YAML in {config_path}: {exc}") from exc
    if not isinstance(document, dict):
        raise ConfigurationError(f"Expected a YAML mapping in {config_path}")
    return document


def _required(mapping: dict[str, Any], key: str, context: str) -> Any:
    if key not in mapping:
        raise ConfigurationError(f"Missing required field '{context}.{key}'")
    return mapping[key]


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigurationError(f"{name} must be a positive integer")
    return value


def _positive_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ConfigurationError(f"{name} must be a positive number")
    return float(value)


def load_scenario(path: str | Path) -> ScenarioConfig:
    root = _required(_read_yaml(path), "scenario", "document")
    if not isinstance(root, dict):
        raise ConfigurationError("scenario must be a mapping")
    organisation = _required(root, "organisation", "scenario")
    workload = _required(root, "workload", "scenario")
    capacity = _required(root, "capacity", "scenario")
    workflow = _required(root, "workflow", "scenario")
    sla = _required(root, "sla_hours", "scenario")
    for name, value in {
        "organisation": organisation,
        "workload": workload,
        "capacity": capacity,
        "workflow": workflow,
        "sla_hours": sla,
    }.items():
        if not isinstance(value, dict):
            raise ConfigurationError(f"scenario.{name} must be a mapping")

    try:
        start_time = datetime.fromisoformat(str(_required(root, "start_time_utc", "scenario")))
    except ValueError as exc:
        raise ConfigurationError("scenario.start_time_utc must be ISO-8601") from exc
    if start_time.tzinfo is None or start_time.utcoffset() is None:
        raise ConfigurationError("scenario.start_time_utc must include a UTC offset")
    if start_time.utcoffset().total_seconds() != 0:
        raise ConfigurationError("scenario.start_time_utc must be expressed in UTC")

    duplicate_rate = workload.get("duplicate_rate")
    if not isinstance(duplicate_rate, (int, float)) or isinstance(duplicate_rate, bool):
        raise ConfigurationError("scenario.workload.duplicate_rate must be numeric")
    if not 0 <= float(duplicate_rate) < 1:
        raise ConfigurationError("scenario.workload.duplicate_rate must be in [0, 1)")

    for severity in ("critical", "high", "medium", "low"):
        _positive_number(_required(sla, severity, "scenario.sla_hours"), f"sla_hours.{severity}")

    triage_min = _positive_int(capacity.get("triage_minutes_min"), "triage_minutes_min")
    triage_max = _positive_int(capacity.get("triage_minutes_max"), "triage_minutes_max")
    remediation_min = _positive_int(
        capacity.get("remediation_minutes_min"), "remediation_minutes_min"
    )
    remediation_max = _positive_int(
        capacity.get("remediation_minutes_max"), "remediation_minutes_max"
    )
    if triage_min > triage_max or remediation_min > remediation_max:
        raise ConfigurationError("Minimum service times cannot exceed maximum service times")

    return ScenarioConfig(
        scenario_id=str(_required(root, "id", "scenario")),
        label=str(_required(root, "label", "scenario")),
        seed=_positive_int(_required(root, "seed", "scenario"), "scenario.seed"),
        start_time_utc=start_time,
        horizon_hours=_positive_number(root.get("horizon_hours"), "scenario.horizon_hours"),
        departments=_positive_int(organisation.get("departments"), "departments"),
        services=_positive_int(organisation.get("services"), "services"),
        assets=_positive_int(organisation.get("assets"), "assets"),
        teams=_positive_int(organisation.get("teams"), "teams"),
        findings=_positive_int(workload.get("findings"), "findings"),
        duplicate_rate=float(duplicate_rate),
        arrival_interval_minutes=_positive_number(
            workload.get("arrival_interval_minutes"), "arrival_interval_minutes"
        ),
        analysts=_positive_int(capacity.get("analysts"), "analysts"),
        remediators=_positive_int(capacity.get("remediators"), "remediators"),
        triage_minutes_min=triage_min,
        triage_minutes_max=triage_max,
        remediation_minutes_min=remediation_min,
        remediation_minutes_max=remediation_max,
        alert_delay_minutes=_positive_int(workflow.get("alert_delay_minutes"), "alert_delay"),
        correlation_minutes=_positive_int(
            workflow.get("correlation_minutes"), "correlation_minutes"
        ),
        assignment_minutes=_positive_int(workflow.get("assignment_minutes"), "assignment"),
        patch_window_delay_minutes=_positive_int(
            workflow.get("patch_window_delay_minutes"), "patch_window_delay"
        ),
        sla_hours={key: float(value) for key, value in sla.items()},
    )


def load_experiment(path: str | Path) -> ExperimentConfig:
    root = _required(_read_yaml(path), "experiment", "document")
    if not isinstance(root, dict):
        raise ConfigurationError("experiment must be a mapping")
    experiment_id = str(_required(root, "id", "experiment"))
    policy = str(_required(root, "policy", "experiment"))
    supported = {"cvss", "threat_intel", "business_context", "constrained_schedule"}
    if policy not in supported:
        raise ConfigurationError(
            f"Unsupported policy '{policy}'. Expected one of {sorted(supported)}"
        )
    enabled = root.get("enabled")
    if not isinstance(enabled, bool):
        raise ConfigurationError("experiment.enabled must be true or false")
    if policy == "business_context":
        weights = root.get("weights")
        if not isinstance(weights, dict) or not weights:
            raise ConfigurationError("Business-context experiments require weights")
        total = sum(float(value) for value in weights.values())
        if abs(total - 1.0) > 1e-9:
            raise ConfigurationError(f"Business-context weights must sum to 1.0; got {total}")
    return ExperimentConfig(
        experiment_id=experiment_id,
        label=str(_required(root, "label", "experiment")),
        policy=policy,
        enabled=enabled,
        raw=root,
    )
