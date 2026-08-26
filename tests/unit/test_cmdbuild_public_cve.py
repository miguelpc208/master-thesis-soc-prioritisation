import sqlite3
from collections import Counter
from pathlib import Path

import pytest

from thesis_pipeline.cmdbuild.public_cve import (
    PublicCVEBindingError,
    bind_public_cves,
)
from thesis_pipeline.config import load_scenario
from thesis_pipeline.synthetic_org.generator import generate_dataset

ROOT = Path(__file__).resolve().parents[2]


def _create_database(path: Path, records_per_severity: int = 100) -> None:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE cve (
            cve_id TEXT PRIMARY KEY,
            published_at_utc TEXT,
            source_name TEXT NOT NULL
        );
        CREATE TABLE cvss_observation (
            cvss_observation_id TEXT PRIMARY KEY,
            cve_id TEXT NOT NULL,
            version TEXT,
            base_score REAL,
            observed_at_utc TEXT,
            source_name TEXT NOT NULL,
            metric_type TEXT
        );
        CREATE TABLE epss_observation (
            epss_observation_id TEXT PRIMARY KEY,
            cve_id TEXT NOT NULL,
            score REAL,
            percentile REAL,
            score_date TEXT NOT NULL,
            model_version TEXT,
            source_name TEXT NOT NULL
        );
        CREATE TABLE kev_observation (
            cve_id TEXT NOT NULL,
            date_added TEXT NOT NULL,
            catalogue_date TEXT NOT NULL,
            known_ransomware_use TEXT
        );
        CREATE TABLE diversevul_function_cve (
            cve_id TEXT NOT NULL
        );
        """
    )
    scores = {
        "critical": 9.5,
        "high": 8.0,
        "medium": 5.5,
        "low": 3.0,
    }
    record_number = 0
    for _severity, score in scores.items():
        for index in range(records_per_severity):
            record_number += 1
            cve_id = f"CVE-2024-{10000 + record_number}"
            connection.execute(
                "INSERT INTO cve VALUES (?, ?, ?)",
                (cve_id, "2025-01-01T00:00:00Z", "nvd"),
            )
            connection.execute(
                "INSERT INTO cvss_observation VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    f"cvss-{record_number}",
                    cve_id,
                    "3.1",
                    score,
                    "2025-03-20T12:00:00Z",
                    "nvd",
                    "Primary",
                ),
            )
            connection.execute(
                "INSERT INTO epss_observation VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    f"epss-prior-{record_number}",
                    cve_id,
                    record_number / 1000,
                    0.5,
                    "2025-03-21",
                    "v2025.03.14",
                    "first_epss",
                ),
            )
            connection.execute(
                "INSERT INTO epss_observation VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    f"epss-same-day-{record_number}",
                    cve_id,
                    0.999,
                    0.999,
                    "2025-03-22",
                    "v2025.03.14",
                    "first_epss",
                ),
            )
            if index % 20 == 0:
                connection.execute(
                    "INSERT INTO kev_observation VALUES (?, ?, ?, ?)",
                    (cve_id, "2025-03-01", "2025-03-19", "Unknown"),
                )
            if index % 3 == 0:
                connection.execute(
                    "INSERT INTO diversevul_function_cve VALUES (?)",
                    (cve_id,),
                )
    connection.execute(
        "INSERT INTO cve VALUES (?, ?, ?)",
        ("CVE-2025-99999", "2025-03-23T00:00:00Z", "nvd"),
    )
    connection.execute(
        "INSERT INTO cvss_observation VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "cvss-future-cve",
            "CVE-2025-99999",
            "3.1",
            9.9,
            "2025-03-20T12:00:00Z",
            "nvd",
            "Primary",
        ),
    )
    connection.execute(
        "INSERT INTO epss_observation VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "epss-future-cve",
            "CVE-2025-99999",
            0.5,
            0.5,
            "2025-03-21",
            "v2025.03.14",
            "first_epss",
        ),
    )
    connection.commit()
    connection.close()


def test_public_binding_is_deterministic_and_preserves_occurrence_grain(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "vulzoo-ingestion.sqlite"
    _create_database(database_path)
    scenario = load_scenario(ROOT / "configs/scenarios/smoke.yaml")
    dataset = generate_dataset(scenario)

    first = bind_public_cves(dataset, scenario, database_path)
    second = bind_public_cves(dataset, scenario, database_path)

    assert first.binding_fingerprint == second.binding_fingerprint
    assert first.findings == second.findings
    assert len(first.findings) == scenario.findings
    assert len(first.bindings) == 201
    assert len({binding.public.cve_id for binding in first.bindings}) == 201
    assert first.selection_mode == "natural"
    assert first.minimum_kev == 0
    assert first.coverage_replacements == 0
    assert first.selected_kev_count == sum(
        binding.public.kev for binding in first.bindings
    )
    assert all(not finding.cve_id.startswith("CVE-SYNTH-") for finding in first.findings)
    assert all(
        binding.public.published_at_utc <= first.earliest_finding_utc
        for binding in first.bindings
    )
    assert all(
        binding.public.cvss_observed_at_utc <= first.earliest_finding_utc
        for binding in first.bindings
    )
    assert first.epss_as_of_date.isoformat() == "2025-03-21"
    assert all(finding.epss_probability != 0.999 for finding in first.findings)
    assert all(
        finding.kev_observed_at.date().isoformat() == "2025-03-19"
        for finding in first.findings
    )
    assert all(binding.public.cve_id != "CVE-2025-99999" for binding in first.bindings)

    original_grain = {(finding.cve_id, finding.asset_id) for finding in dataset.findings}
    bound_grain = {(finding.cve_id, finding.asset_id) for finding in first.findings}
    assert len(original_grain) == len(bound_grain) == 201
    assert len(first.findings) - len(bound_grain) == 39

    original_duplicates = Counter(
        (finding.cve_id, finding.asset_id) for finding in dataset.findings
    )
    bound_duplicates = Counter(
        (finding.cve_id, finding.asset_id) for finding in first.findings
    )
    assert sorted(original_duplicates.values()) == sorted(bound_duplicates.values())

    original_operational = [
        (
            finding.finding_id,
            finding.asset_id,
            finding.service_id,
            finding.team_id,
            finding.finding_created,
            finding.triage_minutes,
            finding.remediation_minutes,
            finding.actionable,
            finding.risk_weight,
        )
        for finding in dataset.findings
    ]
    bound_operational = [
        (
            finding.finding_id,
            finding.asset_id,
            finding.service_id,
            finding.team_id,
            finding.finding_created,
            finding.triage_minutes,
            finding.remediation_minutes,
            finding.actionable,
            finding.risk_weight,
        )
        for finding in first.findings
    ]
    assert original_operational == bound_operational

    connection = sqlite3.connect(database_path)
    try:
        assert connection.execute("SELECT COUNT(*) FROM cve").fetchone()[0] == 401
    finally:
        connection.close()


def test_smoke_coverage_enforces_four_kev_without_changing_severity(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "vulzoo-ingestion.sqlite"
    _create_database(database_path)
    scenario = load_scenario(ROOT / "configs/scenarios/smoke.yaml")
    dataset = generate_dataset(scenario)

    natural = bind_public_cves(dataset, scenario, database_path)
    covered = bind_public_cves(dataset, scenario, database_path, minimum_kev=4)
    repeated = bind_public_cves(dataset, scenario, database_path, minimum_kev=4)

    assert covered.selection_mode == "minimum_kev_coverage"
    assert covered.minimum_kev == 4
    assert covered.selected_kev_count >= 4
    assert covered.selected_kev_count == sum(
        binding.public.kev for binding in covered.bindings
    )
    assert covered.binding_fingerprint == repeated.binding_fingerprint
    assert covered.findings == repeated.findings
    assert len(covered.findings) == len(natural.findings) == 240
    assert len(covered.bindings) == len(natural.bindings) == 201
    assert len({binding.public.cve_id for binding in covered.bindings}) == 201

    source_severities = Counter(
        "critical"
        if finding.cvss >= 9.0
        else "high"
        if finding.cvss >= 7.0
        else "medium"
        if finding.cvss >= 4.0
        else "low"
        for finding in dataset.findings
    )
    covered_severities = Counter(
        "critical"
        if finding.cvss >= 9.0
        else "high"
        if finding.cvss >= 7.0
        else "medium"
        if finding.cvss >= 4.0
        else "low"
        for finding in covered.findings
    )
    assert covered_severities == source_severities


def test_public_binding_rejects_invalid_minimum_kev(tmp_path: Path) -> None:
    database_path = tmp_path / "vulzoo-ingestion.sqlite"
    _create_database(database_path)
    scenario = load_scenario(ROOT / "configs/scenarios/smoke.yaml")
    dataset = generate_dataset(scenario)

    with pytest.raises(PublicCVEBindingError, match="between"):
        bind_public_cves(dataset, scenario, database_path, minimum_kev=202)


def test_public_binding_rejects_insufficient_eligible_kev_pool(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "vulzoo-ingestion.sqlite"
    _create_database(database_path)
    scenario = load_scenario(ROOT / "configs/scenarios/smoke.yaml")
    dataset = generate_dataset(scenario)

    with pytest.raises(PublicCVEBindingError, match="Insufficient eligible KEV"):
        bind_public_cves(dataset, scenario, database_path, minimum_kev=21)


def test_public_binding_rejects_an_insufficient_severity_pool(tmp_path: Path) -> None:
    database_path = tmp_path / "vulzoo-ingestion.sqlite"
    _create_database(database_path, records_per_severity=1)
    scenario = load_scenario(ROOT / "configs/scenarios/smoke.yaml")
    dataset = generate_dataset(scenario)

    with pytest.raises(PublicCVEBindingError, match="Insufficient"):
        bind_public_cves(dataset, scenario, database_path)


def test_public_binding_rejects_backup_database_names(tmp_path: Path) -> None:
    database_path = tmp_path / "vulzoo-ingestion-before-009.sqlite"
    database_path.touch()
    scenario = load_scenario(ROOT / "configs/scenarios/smoke.yaml")
    dataset = generate_dataset(scenario)

    with pytest.raises(PublicCVEBindingError, match="canonical"):
        bind_public_cves(dataset, scenario, database_path)
