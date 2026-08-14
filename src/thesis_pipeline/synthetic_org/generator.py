from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass
from datetime import timedelta

from thesis_pipeline.models import Asset, Finding, ScenarioConfig, Service


@dataclass(frozen=True)
class SyntheticDataset:
    services: tuple[Service, ...]
    assets: tuple[Asset, ...]
    findings: tuple[Finding, ...]
    fingerprint: str


def _weighted_choice(rng: random.Random, values: tuple, weights: tuple[int, ...]):
    return rng.choices(values, weights=weights, k=1)[0]


def _fingerprint(findings: tuple[Finding, ...]) -> str:
    payload = [finding.serialisable() for finding in findings]
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def generate_dataset(config: ScenarioConfig) -> SyntheticDataset:
    """Generate transparent fictional inputs; no real organisation is represented."""
    rng = random.Random(config.seed)
    services = tuple(
        Service(
            service_id=f"SVC-{index + 1:03d}",
            department_id=f"DEPT-{index % config.departments + 1:02d}",
            criticality=_weighted_choice(rng, (1, 2, 3, 4, 5), (5, 15, 35, 30, 15)),
            regulatory_scope=rng.random() < 0.35,
        )
        for index in range(config.services)
    )
    environments = ("production", "pre-production", "development")
    assets = tuple(
        Asset(
            asset_id=f"AST-{index + 1:05d}",
            service_id=services[index % len(services)].service_id,
            team_id=f"TEAM-{index % config.teams + 1:02d}",
            environment=_weighted_choice(rng, environments, (60, 20, 20)),
            criticality=_weighted_choice(rng, (1, 2, 3, 4, 5), (5, 15, 35, 30, 15)),
            internet_exposed=rng.random() < 0.18,
            data_sensitivity=_weighted_choice(rng, (1, 2, 3, 4, 5), (5, 20, 35, 25, 15)),
            compensating_control=rng.random() < 0.25,
        )
        for index in range(config.assets)
    )
    service_by_id = {service.service_id: service for service in services}
    findings: list[Finding] = []
    batch_minutes = config.findings * config.arrival_interval_minutes
    batch_start = config.start_time_utc - timedelta(minutes=batch_minutes + 10)

    for index in range(config.findings):
        asset = rng.choice(assets)
        service = service_by_id[asset.service_id]
        duplicate_of = (
            rng.choice(findings) if findings and rng.random() < config.duplicate_rate else None
        )
        if duplicate_of:
            asset = next(item for item in assets if item.asset_id == duplicate_of.asset_id)
            service = service_by_id[asset.service_id]
            cve_id = duplicate_of.cve_id
            correlation_key = duplicate_of.correlation_key
            cvss = duplicate_of.cvss
            epss = duplicate_of.epss_probability
            kev = duplicate_of.kev
        else:
            cve_id = f"CVE-SYNTH-{index + 1:06d}"
            correlation_key = f"{cve_id}|{asset.asset_id}"
            cvss = round(rng.triangular(2.0, 10.0, 7.0), 1)
            epss = round(rng.random() ** 2.6, 6)
            kev = rng.random() < (0.02 + 0.12 * epss + (0.04 if cvss >= 9 else 0))
        created = batch_start + timedelta(minutes=index * config.arrival_interval_minutes)
        epss_date = config.start_time_utc - timedelta(days=rng.randint(1, 7))
        kev_date = config.start_time_utc - timedelta(days=rng.randint(1, 60))
        future_signal_probability = min(
            0.95,
            0.04
            + epss * 0.60
            + (0.18 if asset.internet_exposed else 0)
            + (0.12 if cvss >= 9 else 0),
        )
        actionable = rng.random() < future_signal_probability
        control_multiplier = 0.75 if asset.compensating_control else 1.0
        risk_weight = round(
            cvss
            * (1 + asset.criticality / 5)
            * (1 + service.criticality / 5)
            * (1.25 if asset.internet_exposed else 1)
            * control_multiplier,
            4,
        )
        findings.append(
            Finding(
                finding_id=f"FND-{index + 1:06d}",
                correlation_key=correlation_key,
                cve_id=cve_id,
                asset_id=asset.asset_id,
                service_id=asset.service_id,
                team_id=asset.team_id,
                finding_created=created,
                cvss=cvss,
                epss_probability=epss,
                epss_observed_at=epss_date,
                kev=kev,
                kev_observed_at=kev_date,
                asset_criticality=asset.criticality,
                service_criticality=service.criticality,
                internet_exposed=asset.internet_exposed,
                environment=asset.environment,
                data_sensitivity=asset.data_sensitivity,
                regulatory_scope=service.regulatory_scope,
                compensating_control=asset.compensating_control,
                triage_minutes=rng.randint(config.triage_minutes_min, config.triage_minutes_max),
                remediation_minutes=rng.randint(
                    config.remediation_minutes_min, config.remediation_minutes_max
                ),
                actionable=actionable,
                risk_weight=risk_weight,
            )
        )

    frozen_findings = tuple(findings)
    return SyntheticDataset(
        services=services,
        assets=assets,
        findings=frozen_findings,
        fingerprint=_fingerprint(frozen_findings),
    )
