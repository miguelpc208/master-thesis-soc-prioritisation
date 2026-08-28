from __future__ import annotations

import csv
from pathlib import Path

from thesis_pipeline.config import load_scenario
from thesis_pipeline.evaluation.metrics import calculate_metrics
from thesis_pipeline.prioritisation.strategies import CvssStrategy
from thesis_pipeline.run import _write_events
from thesis_pipeline.simulation.workflow import simulate_workflow
from thesis_pipeline.synthetic_org.generator import generate_dataset

ROOT = Path(__file__).resolve().parents[2]


def _simulation():
    scenario = load_scenario(ROOT / "configs/scenarios/smoke.yaml")
    dataset = generate_dataset(scenario)
    result = simulate_workflow(
        dataset.findings,
        scenario,
        CvssStrategy(),
    )
    return scenario, dataset, result


def test_correlation_uses_earliest_finding_and_any_actionability() -> None:
    _scenario, dataset, result = _simulation()
    groups = {}
    for finding in dataset.findings:
        groups.setdefault(finding.correlation_key, []).append(finding)
    records_by_key = {
        record.finding.correlation_key: record for record in result.records
    }

    assert len(result.records) == 201
    assert sum(record.finding.actionable for record in result.records) == 55
    for correlation_key, findings in groups.items():
        ordered = sorted(
            findings,
            key=lambda item: (item.finding_created, item.finding_id),
        )
        earliest = ordered[0]
        correlated = records_by_key[correlation_key].finding
        assert correlated.finding_id == earliest.finding_id
        assert correlated.triage_minutes == earliest.triage_minutes
        assert correlated.remediation_minutes == earliest.remediation_minutes
        assert correlated.actionable is any(item.actionable for item in ordered)


def test_only_actionable_cases_consume_remediator_capacity() -> None:
    _scenario, _dataset, result = _simulation()
    actionable = [record for record in result.records if record.finding.actionable]
    non_actionable = [record for record in result.records if not record.finding.actionable]

    assert len(actionable) == 55
    assert len(non_actionable) == 146
    assert all(record.remediation_started is not None for record in actionable)
    assert all(record.remediation_completed is not None for record in actionable)
    assert all(record.remediator_id is not None for record in actionable)
    assert all(record.remediation_started is None for record in non_actionable)
    assert all(record.remediation_completed is None for record in non_actionable)
    assert all(record.remediator_id is None for record in non_actionable)
    assert all(record.closed_at == record.decision for record in non_actionable)
    assert all(len(record.lifecycle()) == 7 for record in non_actionable)
    assert all(len(record.lifecycle()) == 9 for record in actionable)


def test_metrics_separate_case_closure_from_actionable_remediation() -> None:
    scenario, _dataset, result = _simulation()
    metrics = calculate_metrics(result, scenario)

    assert metrics["actionable_case_count"] == 55
    assert metrics["sla_evaluated_count"] <= 55
    assert (
        metrics["remediation_completed_within_horizon"]
        + metrics["remediation_backlog_at_horizon"]
        == 55
    )
    assert metrics["completed_within_horizon"] + metrics["backlog_at_horizon"] == 201
    assert (
        metrics["actionable_completed_within_horizon"]
        == metrics["remediation_completed_within_horizon"]
    )


def test_event_export_leaves_non_actionable_remediation_empty(tmp_path: Path) -> None:
    _scenario, _dataset, result = _simulation()
    output_path = tmp_path / "events.csv"
    _write_events(output_path, result)

    with output_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == 201
    non_actionable = next(row for row in rows if row["actionable"] == "False")
    actionable = next(row for row in rows if row["actionable"] == "True")
    assert non_actionable["remediation_started"] == ""
    assert non_actionable["remediation_completed"] == ""
    assert non_actionable["remediator_id"] == ""
    assert non_actionable["closed_at"] == non_actionable["decision"]
    assert actionable["remediation_started"]
    assert actionable["remediation_completed"]
    assert actionable["remediator_id"]
