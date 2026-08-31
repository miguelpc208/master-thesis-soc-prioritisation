from __future__ import annotations

import heapq
from dataclasses import dataclass, replace
from datetime import timedelta
from itertools import pairwise

from thesis_pipeline.models import Finding, ScenarioConfig, WorkflowRecord
from thesis_pipeline.prioritisation.strategies import PrioritisationStrategy


@dataclass(frozen=True)
class SimulationResult:
    raw_finding_count: int
    correlated_case_count: int
    records: tuple[WorkflowRecord, ...]


def _severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _correlate(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    """Keep the earliest finding while promoting actionability with an ANY rule."""

    representatives: dict[str, Finding] = {}
    actionable_by_key: dict[str, bool] = {}
    for finding in sorted(findings, key=lambda item: (item.finding_created, item.finding_id)):
        representatives.setdefault(finding.correlation_key, finding)
        actionable_by_key[finding.correlation_key] = (
            actionable_by_key.get(finding.correlation_key, False) or finding.actionable
        )
    return tuple(
        replace(representative, actionable=actionable_by_key[correlation_key])
        for correlation_key, representative in representatives.items()
    )


def simulate_workflow(
    findings: tuple[Finding, ...],
    config: ScenarioConfig,
    strategy: PrioritisationStrategy,
) -> SimulationResult:
    """Run a deterministic batch-priority queue with finite human capacity.

    This deliberately small event scheduler proves the lifecycle and queueing contract. Full
    scenario research can replace it with SimPy while preserving the same records and metrics.
    """
    cases = _correlate(findings)
    decision_cutoff = config.start_time_utc
    decisions = strategy.rank(cases, decision_cutoff)
    by_id = {finding.finding_id: finding for finding in cases}

    analyst_heap = [(config.start_time_utc, index) for index in range(config.analysts)]
    remediator_heap = [(config.start_time_utc, index) for index in range(config.remediators)]
    heapq.heapify(analyst_heap)
    heapq.heapify(remediator_heap)
    records: list[WorkflowRecord] = []

    for priority in decisions:
        finding = by_id[priority.finding_id]
        alert_created = finding.finding_created + timedelta(minutes=config.alert_delay_minutes)
        correlated = alert_created + timedelta(minutes=config.correlation_minutes)
        assigned = max(
            correlated + timedelta(minutes=config.assignment_minutes),
            config.start_time_utc,
        )

        analyst_available, analyst_index = heapq.heappop(analyst_heap)
        triage_started = max(assigned, analyst_available)
        triage_completed = triage_started + timedelta(minutes=finding.triage_minutes)
        heapq.heappush(analyst_heap, (triage_completed, analyst_index))
        decision_time = triage_completed + timedelta(minutes=1)

        remediation_started = None
        remediation_completed = None
        remediator_index = None
        if finding.actionable:
            remediator_available, remediator_index = heapq.heappop(remediator_heap)
            remediation_started = max(decision_time, remediator_available) + timedelta(
                minutes=config.patch_window_delay_minutes
            )
            remediation_completed = remediation_started + timedelta(
                minutes=finding.remediation_minutes
            )
            heapq.heappush(
                remediator_heap,
                (remediation_completed, remediator_index),
            )

        severity = _severity(finding.cvss)
        sla_deadline = alert_created + timedelta(hours=config.sla_hours[severity])
        record = WorkflowRecord(
            finding=finding,
            priority_rank=priority.rank,
            finding_created=finding.finding_created,
            alert_created=alert_created,
            correlated=correlated,
            assigned=assigned,
            triage_started=triage_started,
            triage_completed=triage_completed,
            decision=decision_time,
            remediation_started=remediation_started,
            remediation_completed=remediation_completed,
            sla_deadline=sla_deadline,
            analyst_id=f"ANALYST-{analyst_index + 1:02d}",
            remediator_id=(
                f"REMEDIATOR-{remediator_index + 1:02d}"
                if remediator_index is not None
                else None
            ),
        )
        if any(later < earlier for earlier, later in pairwise(record.lifecycle())):
            raise RuntimeError(f"Non-monotonic lifecycle for {finding.finding_id}")
        records.append(record)

    return SimulationResult(
        raw_finding_count=len(findings),
        correlated_case_count=len(cases),
        records=tuple(records),
    )
