from __future__ import annotations

import math
import statistics
from datetime import datetime, timedelta

from thesis_pipeline.models import ScenarioConfig, WorkflowRecord
from thesis_pipeline.simulation.workflow import SimulationResult


def _hours(start: datetime, end: datetime) -> float:
    return (end - start).total_seconds() / 3600


def _mean(values: list[float]) -> float:
    return statistics.fmean(values) if values else 0.0


def _median(values: list[float]) -> float:
    return statistics.median(values) if values else 0.0


def _ranking_metrics(records: tuple[WorkflowRecord, ...]) -> dict[str, float | int]:
    ordered = sorted(records, key=lambda record: record.priority_rank)
    if not ordered:
        return {"ranking_k": 0, "precision_at_k": 0.0, "recall_at_k": 0.0, "ndcg_at_k": 0.0}
    k = max(1, min(25, math.ceil(len(ordered) * 0.10)))
    top = ordered[:k]
    relevant_total = sum(record.finding.actionable for record in ordered)
    relevant_top = sum(record.finding.actionable for record in top)
    dcg = sum(
        (1.0 if record.finding.actionable else 0.0) / math.log2(index + 2)
        for index, record in enumerate(top)
    )
    ideal_relevant = min(k, relevant_total)
    ideal_dcg = sum(1.0 / math.log2(index + 2) for index in range(ideal_relevant))
    return {
        "ranking_k": k,
        "precision_at_k": relevant_top / k,
        "recall_at_k": relevant_top / relevant_total if relevant_total else 0.0,
        "ndcg_at_k": dcg / ideal_dcg if ideal_dcg else 0.0,
    }


def calculate_metrics(
    result: SimulationResult, config: ScenarioConfig
) -> dict[str, float | int | str]:
    records = result.records
    horizon_end = config.start_time_utc + timedelta(hours=config.horizon_hours)
    closed = [record for record in records if record.closed_at <= horizon_end]
    backlog = [record for record in records if record.closed_at > horizon_end]
    actionable_records = [record for record in records if record.finding.actionable]
    completed_remediations = [
        record
        for record in actionable_records
        if record.remediation_completed is not None
        and record.remediation_completed <= horizon_end
    ]
    remediation_backlog = [
        record
        for record in actionable_records
        if record.remediation_completed is None
        or record.remediation_completed > horizon_end
    ]
    triage_waits = [_hours(record.assigned, record.triage_started) for record in records]
    triage_times = [_hours(record.alert_created, record.triage_completed) for record in records]
    decision_times = [_hours(record.alert_created, record.decision) for record in records]
    remediation_times = [
        _hours(record.alert_created, record.remediation_completed)
        for record in completed_remediations
        if record.remediation_completed is not None
    ]

    evaluated_for_sla = [
        record
        for record in actionable_records
        if (
            record.remediation_completed is not None
            and record.remediation_completed <= horizon_end
        )
        or record.sla_deadline <= horizon_end
    ]
    breached = [
        record
        for record in evaluated_for_sla
        if record.remediation_completed is None
        or record.remediation_completed > record.sla_deadline
    ]
    evaluated_risk = sum(record.finding.risk_weight for record in evaluated_for_sla)
    breached_risk = sum(record.finding.risk_weight for record in breached)
    actionable_total = len(actionable_records)
    actionable_completed = len(completed_remediations)

    analyst_busy_hours = sum(record.finding.triage_minutes / 60 for record in records)
    remediator_busy_hours = sum(
        max(0.0, _hours(record.remediation_started, min(record.remediation_completed, horizon_end)))
        for record in actionable_records
        if record.remediation_started is not None
        and record.remediation_completed is not None
        and record.remediation_started < horizon_end
    )
    capacity_hours_analyst = config.analysts * config.horizon_hours
    capacity_hours_remediator = config.remediators * config.horizon_hours
    exposure_hours = sum(
        record.finding.risk_weight
        * max(0.0, _hours(record.alert_created, min(record.closed_at, horizon_end)))
        for record in records
    )

    metrics: dict[str, float | int | str] = {
        "metric_scope": "synthetic_engineering_smoke_not_research_result",
        "raw_finding_count": result.raw_finding_count,
        "correlated_case_count": result.correlated_case_count,
        "deduplication_reduction_rate": 1 - result.correlated_case_count / result.raw_finding_count,
        "completed_within_horizon": len(closed),
        "backlog_at_horizon": len(backlog),
        "throughput_cases_per_hour": len(closed) / config.horizon_hours,
        "remediation_completed_within_horizon": len(completed_remediations),
        "remediation_backlog_at_horizon": len(remediation_backlog),
        "remediation_throughput_cases_per_hour": (
            len(completed_remediations) / config.horizon_hours
        ),
        "non_actionable_closed_within_horizon": sum(
            not record.finding.actionable and record.closed_at <= horizon_end
            for record in records
        ),
        "mean_time_to_triage_hours": _mean(triage_times),
        "median_time_to_triage_hours": _median(triage_times),
        "mean_time_to_decision_hours": _mean(decision_times),
        "mean_time_to_remediation_hours_completed_only": _mean(remediation_times),
        "mean_triage_queue_wait_hours": _mean(triage_waits),
        "max_triage_queue_wait_hours": max(triage_waits, default=0.0),
        "sla_evaluated_count": len(evaluated_for_sla),
        "sla_breach_count": len(breached),
        "sla_breach_rate": len(breached) / len(evaluated_for_sla) if evaluated_for_sla else 0.0,
        "risk_weighted_sla_breach_rate": breached_risk / evaluated_risk if evaluated_risk else 0.0,
        "actionable_case_count": actionable_total,
        "actionable_completed_within_horizon": actionable_completed,
        "actionable_capture_within_horizon_rate": (
            actionable_completed / actionable_total if actionable_total else 0.0
        ),
        "analyst_utilisation_proxy": min(1.0, analyst_busy_hours / capacity_hours_analyst),
        "remediator_utilisation_proxy": min(1.0, remediator_busy_hours / capacity_hours_remediator),
        "risk_weighted_exposure_hours": exposure_hours,
    }
    metrics.update(_ranking_metrics(records))
    return metrics
