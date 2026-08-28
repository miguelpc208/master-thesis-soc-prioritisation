from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class ScenarioConfig:
    scenario_id: str
    label: str
    seed: int
    start_time_utc: datetime
    horizon_hours: float
    departments: int
    services: int
    assets: int
    teams: int
    findings: int
    duplicate_rate: float
    arrival_interval_minutes: float
    analysts: int
    remediators: int
    triage_minutes_min: int
    triage_minutes_max: int
    remediation_minutes_min: int
    remediation_minutes_max: int
    alert_delay_minutes: int
    correlation_minutes: int
    assignment_minutes: int
    patch_window_delay_minutes: int
    sla_hours: dict[str, float]


@dataclass(frozen=True)
class ExperimentConfig:
    experiment_id: str
    label: str
    policy: str
    enabled: bool
    raw: dict[str, Any]


@dataclass(frozen=True)
class Service:
    service_id: str
    department_id: str
    criticality: int
    regulatory_scope: bool


@dataclass(frozen=True)
class Asset:
    asset_id: str
    service_id: str
    team_id: str
    environment: str
    criticality: int
    internet_exposed: bool
    data_sensitivity: int
    compensating_control: bool


@dataclass(frozen=True)
class Finding:
    finding_id: str
    correlation_key: str
    cve_id: str
    asset_id: str
    service_id: str
    team_id: str
    finding_created: datetime
    cvss: float
    epss_probability: float
    epss_observed_at: datetime
    kev: bool
    kev_observed_at: datetime
    asset_criticality: int
    service_criticality: int
    internet_exposed: bool
    environment: str
    data_sensitivity: int
    regulatory_scope: bool
    compensating_control: bool
    triage_minutes: int
    remediation_minutes: int
    actionable: bool
    risk_weight: float

    def serialisable(self) -> dict[str, Any]:
        data = asdict(self)
        for key, value in tuple(data.items()):
            if isinstance(value, datetime):
                data[key] = value.isoformat()
        return data


@dataclass(frozen=True)
class PriorityDecision:
    finding_id: str
    rank: int
    policy: str
    score_components: dict[str, float | bool]
    explanation: str


@dataclass(frozen=True)
class WorkflowRecord:
    finding: Finding
    priority_rank: int
    finding_created: datetime
    alert_created: datetime
    correlated: datetime
    assigned: datetime
    triage_started: datetime
    triage_completed: datetime
    decision: datetime
    remediation_started: datetime | None
    remediation_completed: datetime | None
    sla_deadline: datetime
    analyst_id: str
    remediator_id: str | None

    @property
    def closed_at(self) -> datetime:
        """Close non-actionable cases at decision and actionable cases at remediation."""

        return self.remediation_completed or self.decision

    def lifecycle(self) -> tuple[datetime, ...]:
        base = (
            self.finding_created,
            self.alert_created,
            self.correlated,
            self.assigned,
            self.triage_started,
            self.triage_completed,
            self.decision,
        )
        if (self.remediation_started is None) != (
            self.remediation_completed is None
        ):
            raise RuntimeError(
                "Remediation timestamps must either both be present or both be absent"
            )
        if self.remediation_started is None:
            return base
        return base + (
            self.remediation_started,
            self.remediation_completed,
        )
