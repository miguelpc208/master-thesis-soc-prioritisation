"""Deterministically bind synthetic occurrences to public as-of CVE evidence."""

from __future__ import annotations

import hashlib
import heapq
import json
import re
import sqlite3
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, time
from pathlib import Path
from typing import Any

from thesis_pipeline.models import Finding, ScenarioConfig
from thesis_pipeline.risk import calculate_risk_weight

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
SEVERITIES = ("critical", "high", "medium", "low")


class PublicCVEBindingError(RuntimeError):
    """Raised when a temporally safe public-CVE binding cannot be produced."""


@dataclass(frozen=True, slots=True)
class PublicCVERecord:
    """Technical evidence available before the earliest synthetic finding."""

    cve_id: str
    published_at_utc: datetime
    source_name: str
    cvss: float
    cvss_version: str | None
    cvss_observed_at_utc: datetime
    cvss_source_name: str
    epss_probability: float
    epss_percentile: float | None
    epss_score_date: date
    epss_model_version: str | None
    epss_source_name: str
    kev: bool
    kev_date_added: date | None
    kev_catalogue_date: date
    known_ransomware_use: str | None
    diversevul: bool


@dataclass(frozen=True, slots=True)
class PublicCVEBinding:
    """One synthetic occurrence mapped to one public CVE."""

    synthetic_cve_id: str
    asset_id: str
    public: PublicCVERecord


@dataclass(frozen=True, slots=True)
class PublicCVEBindingResult:
    """Bound findings and an auditable deterministic selection manifest."""

    findings: tuple[Finding, ...]
    bindings: tuple[PublicCVEBinding, ...]
    source_dataset_fingerprint: str
    binding_fingerprint: str
    database_name: str
    earliest_finding_utc: datetime
    epss_as_of_date: date
    eligible_pool_counts: tuple[tuple[str, int], ...]
    eligible_kev_pool_counts: tuple[tuple[str, int], ...]
    selection_mode: str
    minimum_kev: int
    selected_kev_count: int
    coverage_replacements: int


def _parse_datetime(value: Any, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise PublicCVEBindingError(f"Invalid timestamp in public evidence: {field_name}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PublicCVEBindingError(
            f"Invalid timestamp in public evidence: {field_name}"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PublicCVEBindingError(
            f"Public evidence timestamp is not timezone-aware: {field_name}"
        )
    return parsed.astimezone(UTC)


def _parse_date(value: Any, field_name: str) -> date:
    if not isinstance(value, str) or not value.strip():
        raise PublicCVEBindingError(f"Invalid date in public evidence: {field_name}")
    try:
        return date.fromisoformat(value[:10])
    except ValueError as exc:
        raise PublicCVEBindingError(f"Invalid date in public evidence: {field_name}") from exc


def _optional_date(value: Any, field_name: str) -> date | None:
    if value is None:
        return None
    return _parse_date(value, field_name)


def _severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _stable_rank(seed: int, cve_id: str) -> int:
    digest = hashlib.sha256(f"{seed}|{cve_id}".encode()).digest()
    return int.from_bytes(digest, byteorder="big", signed=False)


def _offer_ranked_record(
    heap: list[tuple[int, str, PublicCVERecord]],
    record: PublicCVERecord,
    seed: int,
    limit: int,
) -> None:
    if limit == 0:
        return
    rank = _stable_rank(seed, record.cve_id)
    entry = (-rank, record.cve_id, record)
    if len(heap) < limit:
        heapq.heappush(heap, entry)
    elif rank < -heap[0][0]:
        heapq.heapreplace(heap, entry)


def _connect_read_only(database_path: Path) -> sqlite3.Connection:
    if database_path.name != "vulzoo-ingestion.sqlite":
        raise PublicCVEBindingError(
            "Public-CVE binding requires the canonical vulzoo-ingestion.sqlite database"
        )
    if not database_path.is_file():
        raise PublicCVEBindingError("Canonical vulnerability database does not exist")
    connection = sqlite3.connect(database_path.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    return connection


def _validate_schema(connection: sqlite3.Connection) -> None:
    required = {
        "cve": {"cve_id", "published_at_utc", "source_name"},
        "cvss_observation": {
            "cvss_observation_id",
            "cve_id",
            "version",
            "base_score",
            "observed_at_utc",
            "source_name",
            "metric_type",
        },
        "epss_observation": {
            "epss_observation_id",
            "cve_id",
            "score",
            "percentile",
            "score_date",
            "model_version",
            "source_name",
            "source_snapshot_id",
        },
        "epss_panel_ingestion": {
            "epss_panel_ingestion_id",
            "panel_fingerprint_sha256",
            "first_score_date",
            "last_score_date",
            "expected_days",
            "completed_days",
            "status",
        },
        "epss_panel_ingestion_day": {
            "epss_panel_ingestion_id",
            "score_date",
            "source_snapshot_id",
            "ingestion_run_id",
            "status",
        },
        "kev_observation": {
            "cve_id",
            "date_added",
            "catalogue_date",
            "known_ransomware_use",
        },
        "diversevul_function_cve": {"cve_id"},
    }
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    missing_tables = sorted(set(required) - tables)
    if missing_tables:
        raise PublicCVEBindingError(
            "Canonical vulnerability database is missing tables: " + ", ".join(missing_tables)
        )
    for table_name, required_columns in required.items():
        columns = {
            row[1]
            for row in connection.execute(f'PRAGMA table_info("{table_name}")')
        }
        missing_columns = sorted(required_columns - columns)
        if missing_columns:
            raise PublicCVEBindingError(
                f"Table '{table_name}' is missing columns: " + ", ".join(missing_columns)
            )


def _candidate_query() -> str:
    return """
        WITH
        ranked_cvss AS (
            SELECT
                cve_id,
                base_score,
                version,
                observed_at_utc,
                source_name,
                ROW_NUMBER() OVER (
                    PARTITION BY cve_id
                    ORDER BY
                        datetime(observed_at_utc) DESC,
                        CASE version
                            WHEN '4.0' THEN 0
                            WHEN '3.1' THEN 1
                            WHEN '3.0' THEN 2
                            WHEN '2.0' THEN 3
                            ELSE 4
                        END,
                        CASE lower(COALESCE(metric_type, ''))
                            WHEN 'primary' THEN 0
                            ELSE 1
                        END,
                        cvss_observation_id
                ) AS evidence_rank
            FROM cvss_observation
            WHERE base_score IS NOT NULL
              AND base_score BETWEEN 0.0 AND 10.0
              AND observed_at_utc IS NOT NULL
              AND datetime(observed_at_utc) <= datetime(:cutoff)
        ),
        epss_latest_date AS (
            SELECT MAX(day.score_date) AS score_date
            FROM epss_panel_ingestion AS panel
            INNER JOIN epss_panel_ingestion_day AS day
                ON day.epss_panel_ingestion_id = panel.epss_panel_ingestion_id
               AND day.status = 'succeeded'
            WHERE panel.status = 'succeeded'
              AND panel.completed_days = panel.expected_days
              AND date(day.score_date) < date(:cutoff)
        ),
        epss_panel AS (
            SELECT
                day.score_date,
                MIN(day.source_snapshot_id) AS source_snapshot_id,
                COUNT(DISTINCT day.source_snapshot_id) AS source_snapshot_count
            FROM epss_panel_ingestion AS panel
            INNER JOIN epss_panel_ingestion_day AS day
                ON day.epss_panel_ingestion_id = panel.epss_panel_ingestion_id
               AND day.status = 'succeeded'
            INNER JOIN epss_latest_date AS latest
                ON latest.score_date = day.score_date
            WHERE panel.status = 'succeeded'
              AND panel.completed_days = panel.expected_days
            GROUP BY day.score_date
        ),
        ranked_epss AS (
            SELECT
                observation.cve_id,
                observation.score,
                observation.percentile,
                observation.score_date,
                observation.model_version,
                observation.source_name,
                ROW_NUMBER() OVER (
                    PARTITION BY observation.cve_id
                    ORDER BY observation.epss_observation_id
                ) AS evidence_rank
            FROM epss_observation AS observation
            INNER JOIN epss_panel AS panel
                ON panel.score_date = observation.score_date
               AND panel.source_snapshot_id = observation.source_snapshot_id
            WHERE observation.score IS NOT NULL
              AND observation.score BETWEEN 0.0 AND 1.0
              AND panel.source_snapshot_count = 1
        ),
        kev_snapshot AS (
            SELECT MAX(catalogue_date) AS catalogue_date
            FROM kev_observation
            WHERE date(catalogue_date) <= date(:cutoff)
        ),
        eligible_kev AS (
            SELECT
                observation.cve_id,
                MIN(observation.date_added) AS date_added,
                MAX(observation.known_ransomware_use) AS known_ransomware_use
            FROM kev_observation AS observation
            INNER JOIN kev_snapshot AS snapshot
                ON snapshot.catalogue_date = observation.catalogue_date
            WHERE date(observation.date_added) <= date(:cutoff)
            GROUP BY observation.cve_id
        ),
        diversevul AS (
            SELECT DISTINCT cve_id
            FROM diversevul_function_cve
            WHERE cve_id IS NOT NULL
        )
        SELECT
            vulnerability.cve_id,
            vulnerability.published_at_utc,
            vulnerability.source_name,
            cvss.base_score,
            cvss.version,
            cvss.observed_at_utc,
            cvss.source_name AS cvss_source_name,
            epss.score,
            epss.percentile,
            epss.score_date,
            epss.model_version,
            epss.source_name AS epss_source_name,
            kev.date_added AS kev_date_added,
            snapshot.catalogue_date AS kev_catalogue_date,
            kev.known_ransomware_use,
            CASE WHEN kev.cve_id IS NULL THEN 0 ELSE 1 END AS is_kev,
            CASE WHEN diverse.cve_id IS NULL THEN 0 ELSE 1 END AS is_diversevul
        FROM cve AS vulnerability
        INNER JOIN ranked_cvss AS cvss
            ON cvss.cve_id = vulnerability.cve_id
           AND cvss.evidence_rank = 1
        INNER JOIN ranked_epss AS epss
            ON epss.cve_id = vulnerability.cve_id
           AND epss.evidence_rank = 1
        CROSS JOIN kev_snapshot AS snapshot
        LEFT JOIN eligible_kev AS kev
            ON kev.cve_id = vulnerability.cve_id
        LEFT JOIN diversevul AS diverse
            ON diverse.cve_id = vulnerability.cve_id
        WHERE vulnerability.published_at_utc IS NOT NULL
          AND datetime(vulnerability.published_at_utc) <= datetime(:cutoff)
        ORDER BY vulnerability.cve_id
    """


def _iter_candidates(
    connection: sqlite3.Connection,
    cutoff: datetime,
) -> Iterator[PublicCVERecord]:
    cursor = connection.execute(_candidate_query(), {"cutoff": cutoff.isoformat()})
    for row in cursor:
        cve_id = row["cve_id"]
        if not isinstance(cve_id, str) or CVE_PATTERN.fullmatch(cve_id) is None:
            continue
        record = PublicCVERecord(
            cve_id=cve_id,
            published_at_utc=_parse_datetime(row["published_at_utc"], "published_at_utc"),
            source_name=str(row["source_name"]),
            cvss=float(row["base_score"]),
            cvss_version=None if row["version"] is None else str(row["version"]),
            cvss_observed_at_utc=_parse_datetime(
                row["observed_at_utc"], "observed_at_utc"
            ),
            cvss_source_name=str(row["cvss_source_name"]),
            epss_probability=float(row["score"]),
            epss_percentile=None if row["percentile"] is None else float(row["percentile"]),
            epss_score_date=_parse_date(row["score_date"], "score_date"),
            epss_model_version=(
                None if row["model_version"] is None else str(row["model_version"])
            ),
            epss_source_name=str(row["epss_source_name"]),
            kev=bool(row["is_kev"]),
            kev_date_added=_optional_date(row["kev_date_added"], "kev_date_added"),
            kev_catalogue_date=_parse_date(row["kev_catalogue_date"], "kev_catalogue_date"),
            known_ransomware_use=(
                None
                if row["known_ransomware_use"] is None
                else str(row["known_ransomware_use"])
            ),
            diversevul=bool(row["is_diversevul"]),
        )
        if record.published_at_utc > cutoff or record.cvss_observed_at_utc > cutoff:
            raise PublicCVEBindingError("Candidate pool contains future CVE or CVSS evidence")
        if record.epss_score_date >= cutoff.date():
            raise PublicCVEBindingError("Candidate pool contains same-day or future EPSS evidence")
        if record.kev_catalogue_date > cutoff.date():
            raise PublicCVEBindingError("Candidate pool contains future KEV evidence")
        if record.kev_date_added is not None and record.kev_date_added > cutoff.date():
            raise PublicCVEBindingError("Candidate pool contains a future KEV membership")
        yield record


def _select_records(
    connection: sqlite3.Connection,
    cutoff: datetime,
    seed: int,
    required_by_severity: Counter[str],
    minimum_kev: int,
) -> tuple[
    dict[str, list[PublicCVERecord]],
    Counter[str],
    Counter[str],
    int,
]:
    heaps: dict[str, list[tuple[int, str, PublicCVERecord]]] = {
        severity: [] for severity in SEVERITIES
    }
    kev_heaps: dict[str, list[tuple[int, str, PublicCVERecord]]] = {
        severity: [] for severity in SEVERITIES
    }
    eligible_counts: Counter[str] = Counter()
    eligible_kev_counts: Counter[str] = Counter()
    for record in _iter_candidates(connection, cutoff):
        severity = _severity(record.cvss)
        eligible_counts[severity] += 1
        limit = required_by_severity[severity]
        if limit == 0:
            continue
        _offer_ranked_record(heaps[severity], record, seed, limit)
        if record.kev:
            eligible_kev_counts[severity] += 1
            _offer_ranked_record(
                kev_heaps[severity],
                record,
                seed,
                min(limit, minimum_kev),
            )
    selected: dict[str, list[PublicCVERecord]] = {}
    for severity in SEVERITIES:
        required = required_by_severity[severity]
        if len(heaps[severity]) != required:
            raise PublicCVEBindingError(
                f"Insufficient '{severity}' public CVEs: required {required}, "
                f"eligible {eligible_counts[severity]}"
            )
        selected[severity] = sorted(
            (entry[2] for entry in heaps[severity]),
            key=lambda record: (record.cvss, record.cve_id),
        )
    selected_ids = {
        record.cve_id
        for records in selected.values()
        for record in records
    }
    selected_kev_count = sum(
        record.kev for records in selected.values() for record in records
    )
    coverage_replacements = 0
    if selected_kev_count < minimum_kev:
        candidates = sorted(
            (
                entry[2]
                for severity in SEVERITIES
                for entry in kev_heaps[severity]
                if entry[2].cve_id not in selected_ids
            ),
            key=lambda record: (_stable_rank(seed, record.cve_id), record.cve_id),
        )
        for candidate in candidates:
            if selected_kev_count >= minimum_kev:
                break
            severity = _severity(candidate.cvss)
            replaceable = [record for record in selected[severity] if not record.kev]
            if not replaceable:
                continue
            evicted = max(
                replaceable,
                key=lambda record: (_stable_rank(seed, record.cve_id), record.cve_id),
            )
            selected[severity].remove(evicted)
            selected[severity].append(candidate)
            selected_ids.remove(evicted.cve_id)
            selected_ids.add(candidate.cve_id)
            selected_kev_count += 1
            coverage_replacements += 1
    if selected_kev_count < minimum_kev:
        raise PublicCVEBindingError(
            f"Insufficient eligible KEV coverage: required {minimum_kev}, "
            f"selected {selected_kev_count}, eligible {sum(eligible_kev_counts.values())}"
        )
    for severity in SEVERITIES:
        selected[severity].sort(key=lambda record: (record.cvss, record.cve_id))
    return selected, eligible_counts, eligible_kev_counts, coverage_replacements


def _binding_fingerprint(
    source_fingerprint: str,
    bindings: tuple[PublicCVEBinding, ...],
    bound_findings: tuple[Finding, ...],
    cutoff: datetime,
    epss_as_of_date: date,
    minimum_kev: int,
    coverage_replacements: int,
) -> str:
    payload = {
        "source_dataset_fingerprint": source_fingerprint,
        "earliest_finding_utc": cutoff.isoformat(),
        "epss_policy": "latest_score_date_strictly_before_finding_date",
        "epss_as_of_date": epss_as_of_date.isoformat(),
        "selection_mode": "minimum_kev_coverage" if minimum_kev else "natural",
        "minimum_kev": minimum_kev,
        "coverage_replacements": coverage_replacements,
        "risk_weight_policy": "cvss_x_asset_x_service_x_exposure_x_control_v1",
        "bindings": [
            {
                "synthetic_cve_id": binding.synthetic_cve_id,
                "asset_id": binding.asset_id,
                "public_cve_id": binding.public.cve_id,
                "cve_published_at_utc": binding.public.published_at_utc.isoformat(),
                "cve_source_name": binding.public.source_name,
                "cvss": binding.public.cvss,
                "cvss_version": binding.public.cvss_version,
                "cvss_observed_at_utc": binding.public.cvss_observed_at_utc.isoformat(),
                "cvss_source_name": binding.public.cvss_source_name,
                "epss": binding.public.epss_probability,
                "epss_percentile": binding.public.epss_percentile,
                "epss_score_date": binding.public.epss_score_date.isoformat(),
                "epss_model_version": binding.public.epss_model_version,
                "epss_source_name": binding.public.epss_source_name,
                "kev": binding.public.kev,
                "kev_date_added": (
                    None
                    if binding.public.kev_date_added is None
                    else binding.public.kev_date_added.isoformat()
                ),
                "kev_catalogue_date": binding.public.kev_catalogue_date.isoformat(),
                "known_ransomware_use": binding.public.known_ransomware_use,
                "diversevul": binding.public.diversevul,
                "bound_risk_weights": [
                    finding.risk_weight
                    for finding in bound_findings
                    if finding.cve_id == binding.public.cve_id
                    and finding.asset_id == binding.asset_id
                ],
            }
            for binding in bindings
        ],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def bind_public_cves(
    dataset: Any,
    scenario: ScenarioConfig,
    database_path: str | Path,
    *,
    minimum_kev: int = 0,
) -> PublicCVEBindingResult:
    """Replace synthetic signals, optionally enforcing explicit KEV coverage."""

    findings = tuple(dataset.findings)
    if not findings:
        raise PublicCVEBindingError("Synthetic dataset contains no findings")
    if not isinstance(dataset.fingerprint, str) or not dataset.fingerprint:
        raise PublicCVEBindingError("Synthetic dataset fingerprint is missing")
    if not all(finding.cve_id.startswith("CVE-SYNTH-") for finding in findings):
        raise PublicCVEBindingError("Input findings must use synthetic CVE fixture identifiers")
    cutoff = min(finding.finding_created for finding in findings)
    if cutoff.tzinfo is None or cutoff.utcoffset() is None:
        raise PublicCVEBindingError("Finding timestamps must be timezone-aware")
    cutoff = cutoff.astimezone(UTC)
    representative_by_occurrence: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        key = (finding.cve_id, finding.asset_id)
        representative_by_occurrence.setdefault(key, finding)
    representatives_by_severity: dict[str, list[tuple[tuple[str, str], Finding]]] = {
        severity: [] for severity in SEVERITIES
    }
    for key, finding in representative_by_occurrence.items():
        representatives_by_severity[_severity(float(finding.cvss))].append((key, finding))
    required_by_severity: Counter[str] = Counter(
        {
            severity: len(representatives_by_severity[severity])
            for severity in SEVERITIES
        }
    )
    occurrence_count = sum(required_by_severity.values())
    if isinstance(minimum_kev, bool) or not isinstance(minimum_kev, int):
        raise PublicCVEBindingError("minimum_kev must be an integer")
    if minimum_kev < 0 or minimum_kev > occurrence_count:
        raise PublicCVEBindingError(
            f"minimum_kev must be between 0 and {occurrence_count}"
        )
    database = Path(database_path)
    connection = _connect_read_only(database)
    try:
        _validate_schema(connection)
        selected, eligible_counts, eligible_kev_counts, coverage_replacements = (
            _select_records(
                connection,
                cutoff,
                scenario.seed,
                required_by_severity,
                minimum_kev,
            )
        )
    finally:
        connection.close()
    public_by_occurrence: dict[tuple[str, str], PublicCVERecord] = {}
    for severity in SEVERITIES:
        representatives = sorted(
            representatives_by_severity[severity],
            key=lambda item: (float(item[1].cvss), item[0]),
        )
        for representative, public in zip(
            representatives, selected[severity], strict=True
        ):
            public_by_occurrence[representative[0]] = public
    bindings = tuple(
        PublicCVEBinding(
            synthetic_cve_id=synthetic_cve_id,
            asset_id=asset_id,
            public=public_by_occurrence[(synthetic_cve_id, asset_id)],
        )
        for synthetic_cve_id, asset_id in representative_by_occurrence
    )
    if len({binding.public.cve_id for binding in bindings}) != len(bindings):
        raise PublicCVEBindingError("Public CVEs were not selected without replacement")
    bound_findings = []
    for finding in findings:
        public = public_by_occurrence[(finding.cve_id, finding.asset_id)]
        epss_observed_at = datetime.combine(
            public.epss_score_date, time.min, tzinfo=UTC
        )
        kev_observed_at = datetime.combine(
            public.kev_catalogue_date, time.min, tzinfo=UTC
        )
        bound_findings.append(
            replace(
                finding,
                cve_id=public.cve_id,
                correlation_key=f"{public.cve_id}|{finding.asset_id}",
                cvss=public.cvss,
                epss_probability=public.epss_probability,
                epss_observed_at=epss_observed_at,
                kev=public.kev,
                kev_observed_at=kev_observed_at,
                risk_weight=calculate_risk_weight(
                    cvss=public.cvss,
                    asset_criticality=finding.asset_criticality,
                    service_criticality=finding.service_criticality,
                    internet_exposed=finding.internet_exposed,
                    compensating_control=finding.compensating_control,
                ),
            )
        )
    bound_tuple = tuple(bound_findings)
    if any(finding.cve_id.startswith("CVE-SYNTH-") for finding in bound_tuple):
        raise PublicCVEBindingError("Synthetic CVE identifiers remain after public binding")
    bound_grain = {(finding.cve_id, finding.asset_id) for finding in bound_tuple}
    if len(bound_grain) != len(bindings):
        raise PublicCVEBindingError("Public binding changed the vulnerability-occurrence grain")
    epss_dates = {binding.public.epss_score_date for binding in bindings}
    if len(epss_dates) != 1:
        raise PublicCVEBindingError("Public binding did not use one reproducible EPSS panel")
    epss_as_of_date = next(iter(epss_dates))
    selected_kev_count = sum(binding.public.kev for binding in bindings)
    if selected_kev_count < minimum_kev:
        raise PublicCVEBindingError("Public binding did not satisfy minimum KEV coverage")
    fingerprint = _binding_fingerprint(
        dataset.fingerprint,
        bindings,
        bound_tuple,
        cutoff,
        epss_as_of_date,
        minimum_kev,
        coverage_replacements,
    )
    return PublicCVEBindingResult(
        findings=bound_tuple,
        bindings=bindings,
        source_dataset_fingerprint=dataset.fingerprint,
        binding_fingerprint=fingerprint,
        database_name=database.name,
        earliest_finding_utc=cutoff,
        epss_as_of_date=epss_as_of_date,
        eligible_pool_counts=tuple(
            (severity, eligible_counts[severity]) for severity in SEVERITIES
        ),
        eligible_kev_pool_counts=tuple(
            (severity, eligible_kev_counts[severity]) for severity in SEVERITIES
        ),
        selection_mode="minimum_kev_coverage" if minimum_kev else "natural",
        minimum_kev=minimum_kev,
        selected_kev_count=selected_kev_count,
        coverage_replacements=coverage_replacements,
    )
