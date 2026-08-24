from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import sys
import uuid
from collections import Counter
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from thesis_pipeline.ingestion.coverage import (
    CVE_ID_PATTERN,
    CWE_ID_PATTERN,
    CWE_PLACEHOLDERS,
    MAX_JSON_COVERAGE_BYTES,
    _parse_date,
    _parse_utc_datetime,
    _read_json,
    _scan_kev_relationship,
    _sorted_files,
    _temporal_text,
)
from thesis_pipeline.ingestion.source import load_vulzoo_source_config, resolve_vulzoo_root
from thesis_pipeline.storage.schema import initialise_database

INGESTION_CONTRACT = "vulzoo-ingestion-v2"
EXPECTED_COVERAGE_CONTRACT = "vulzoo-coverage-v2"
SUPPORTED_CVSS_VERSIONS = {"2.0", "3.0", "3.1", "4.0"}
SUPPORTED_SEVERITIES = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
SUPPORTED_CONFIGURATION_OPERATORS = {"AND", "OR"}
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _now_utc() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _stable_id(kind: str, *values: Any) -> str:
    payload = json.dumps([kind, *values], separators=(",", ":"), ensure_ascii=True)
    return f"{kind}:{hashlib.sha256(payload.encode('utf-8')).hexdigest()}"


def _bounded_text(value: Any, maximum_length: int = 500) -> str | None:
    if not isinstance(value, str):
        return None
    result = value.strip()
    if not result or len(result) > maximum_length:
        return None
    return result


def _english_description(entries: Any) -> str | None:
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        language = entry.get("lang")
        if isinstance(language, str) and language.casefold() in {"en", "eng", "en-us"}:
            value = entry.get("value")
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _retrieval_timestamp(source: dict[str, Any]) -> str:
    configured = source.get("retrieval_date")
    if not isinstance(configured, str):
        raise ValueError("VulZoo retrieval_date must be a date in YYYY-MM-DD format")
    try:
        retrieval_date = date.fromisoformat(configured)
    except ValueError as exc:
        raise ValueError("VulZoo retrieval_date must be a date in YYYY-MM-DD format") from exc
    return f"{retrieval_date.isoformat()}T23:59:59Z"


def _validated_report(path: str | Path, source: dict[str, Any]) -> dict[str, Any]:
    report_path = Path(path).expanduser().resolve()
    if not report_path.is_file():
        raise ValueError("An existing approved VulZoo coverage report is required")
    try:
        document = json.loads(report_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("The approved VulZoo coverage report cannot be parsed") from exc
    if not isinstance(document, dict):
        raise ValueError("The approved VulZoo coverage report must be a JSON object")

    policy = document.get("policy")
    scope = document.get("scope")
    reported_source = document.get("source")
    fingerprint = document.get("input_fingerprint_sha256")
    if not isinstance(policy, dict) or policy.get("contract") != EXPECTED_COVERAGE_CONTRACT:
        raise ValueError("The coverage report does not satisfy the vulzoo-coverage-v2 contract")
    if not isinstance(scope, dict) or any(
        scope.get(field) is not False
        for field in ("raw_records_included", "network_accessed", "dataset_mutated")
    ):
        raise ValueError("The coverage report does not satisfy the approved data boundary")
    if not isinstance(reported_source, dict) or (
        reported_source.get("checksum") != source.get("checksum")
    ):
        raise ValueError("The coverage report does not match the configured VulZoo checksum")
    if not isinstance(fingerprint, str) or SHA256_PATTERN.fullmatch(fingerprint) is None:
        raise ValueError("The coverage report input fingerprint is not a SHA-256 value")

    max_json_bytes = policy.get("max_json_bytes")
    if isinstance(max_json_bytes, bool) or not isinstance(max_json_bytes, int):
        raise ValueError("The coverage report JSON size limit must be an integer")
    if not 1 <= max_json_bytes <= MAX_JSON_COVERAGE_BYTES:
        raise ValueError("The coverage report JSON size limit is outside the approved boundary")

    for collection in ("nvd", "legacy_cve", "cisa_kev"):
        summary = document.get(collection)
        if not isinstance(summary, dict) or not isinstance(summary.get("accepted_records"), int):
            raise ValueError(f"The coverage report is missing the {collection} acceptance count")
    return document


def _validated_database(path: str | Path, root: Path) -> Path:
    database = Path(path).expanduser().resolve()
    approved_root = Path(os.environ["THESIS_DATA_ROOT"]).expanduser().resolve()
    if not database.is_relative_to(approved_root) or database.is_relative_to(root):
        raise ValueError("The SQLite database must be beneath THESIS_DATA_ROOT and outside VulZoo")
    if not database.is_file():
        raise ValueError("Initialise the approved SQLite database before starting ingestion")
    return initialise_database(database)


@dataclass
class DatabaseRejections:
    connection: sqlite3.Connection
    ingestion_run_id: str
    reasons: Counter[str] = field(default_factory=Counter)
    sequence: int = 0

    def add(
        self,
        reason: str,
        relative_path: str,
        record_hash_sha256: str | None,
        *,
        source_record_id: str | None = None,
        field_name: str | None = None,
    ) -> None:
        self.sequence += 1
        self.reasons[reason] += 1
        rejection_id = _stable_id(
            "rejection",
            self.ingestion_run_id,
            self.sequence,
            relative_path,
            reason,
        )
        self.connection.execute(
            """
            INSERT INTO ingestion_rejection(
                ingestion_rejection_id, ingestion_run_id, source_relative_path,
                source_record_id, reason_code, field_name, record_hash_sha256, created_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rejection_id,
                self.ingestion_run_id,
                relative_path,
                source_record_id,
                reason,
                field_name,
                record_hash_sha256,
                _now_utc(),
            ),
        )


@dataclass
class IngestionContext:
    connection: sqlite3.Connection
    root: Path
    source_snapshot_id: str
    ingestion_run_id: str
    retrieved_at_utc: str
    max_json_bytes: int
    fingerprint: Any
    rejections: DatabaseRejections
    progress_every: int = 0
    source_counts: dict[str, Counter[str]] = field(
        default_factory=lambda: {
            "nvd": Counter(),
            "legacy_cve": Counter(),
            "cisa_kev": Counter(),
        }
    )
    row_counts: Counter[str] = field(default_factory=Counter)
    files_processed: int = 0

    def progress(self, source_name: str) -> None:
        self.files_processed += 1
        if self.progress_every and self.files_processed % self.progress_every == 0:
            print(
                f"Processed {self.files_processed:,} source files; "
                f"current collection: {source_name}",
                file=sys.stderr,
                flush=True,
            )


def _insert_snapshot(
    connection: sqlite3.Connection,
    source: dict[str, Any],
    retrieved_at_utc: str,
) -> str:
    checksum = source.get("checksum")
    if not isinstance(checksum, str) or not checksum.strip():
        raise ValueError("The VulZoo source requires an approved non-empty checksum")
    snapshot_id = _stable_id("snapshot", "vulzoo", checksum)
    metadata = {
        "contract": INGESTION_CONTRACT,
        "readme_index_date": source.get("snapshot_date"),
        "readme_index_note": source.get("snapshot_date_note"),
        "retrieval_date_precision": "date",
        "retrieval_availability_policy": "end_of_day_utc",
    }
    connection.execute(
        """
        INSERT OR IGNORE INTO source_snapshot(
            source_snapshot_id, source_name, source_version, snapshot_date,
            retrieved_at_utc, checksum, upstream_url, local_relative_path,
            metadata_json, created_at_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            snapshot_id,
            "vulzoo",
            checksum.split(":", 1)[-1],
            None,
            retrieved_at_utc,
            checksum,
            source.get("url"),
            source.get("local_relative_path"),
            json.dumps(metadata, separators=(",", ":"), sort_keys=True),
            _now_utc(),
        ),
    )
    return snapshot_id


def _insert_cve(
    context: IngestionContext,
    cve_id: str,
    *,
    description: str | None,
    published_at_utc: str | None,
    modified_at_utc: str | None,
    vulnerability_status: str | None,
    source_name: str,
) -> None:
    connection = context.connection
    existing = connection.execute("SELECT 1 FROM cve WHERE cve_id = ?", (cve_id,)).fetchone()
    if source_name == "nvd":
        connection.execute(
            """
            INSERT INTO cve(
                cve_id, description, published_at_utc, modified_at_utc, source_name,
                source_record_id, retrieved_at_utc, created_at_utc, vulnerability_status,
                source_snapshot_id, ingestion_run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                description = COALESCE(excluded.description, cve.description),
                published_at_utc = excluded.published_at_utc,
                modified_at_utc = excluded.modified_at_utc,
                source_name = excluded.source_name,
                source_record_id = excluded.source_record_id,
                retrieved_at_utc = excluded.retrieved_at_utc,
                vulnerability_status = excluded.vulnerability_status,
                source_snapshot_id = excluded.source_snapshot_id,
                ingestion_run_id = excluded.ingestion_run_id
            """,
            (
                cve_id,
                description,
                published_at_utc,
                modified_at_utc,
                source_name,
                cve_id,
                context.retrieved_at_utc,
                _now_utc(),
                vulnerability_status,
                context.source_snapshot_id,
                context.ingestion_run_id,
            ),
        )
    else:
        connection.execute(
            """
            INSERT INTO cve(
                cve_id, description, published_at_utc, modified_at_utc, source_name,
                source_record_id, retrieved_at_utc, created_at_utc, vulnerability_status,
                source_snapshot_id, ingestion_run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                description = COALESCE(cve.description, excluded.description)
            """,
            (
                cve_id,
                description,
                published_at_utc,
                modified_at_utc,
                source_name,
                cve_id,
                context.retrieved_at_utc,
                _now_utc(),
                vulnerability_status,
                context.source_snapshot_id,
                context.ingestion_run_id,
            ),
        )
    if existing is None:
        context.row_counts["cve"] += 1


def _insert_cvss(
    context: IngestionContext,
    cve_id: str,
    observed_at_utc: str,
    document: dict[str, Any],
    relative_path: str,
    digest: str,
) -> None:
    metrics = document.get("metrics")
    if not isinstance(metrics, dict):
        return

    for group_name in sorted(metrics):
        group = metrics[group_name]
        if not isinstance(group, list):
            context.rejections.add(
                "cvss_group_not_list", relative_path, digest, source_record_id=cve_id
            )
            continue
        for metric in group:
            data = metric.get("cvssData") if isinstance(metric, dict) else None
            if not isinstance(data, dict):
                context.rejections.add(
                    "cvss_data_missing", relative_path, digest, source_record_id=cve_id
                )
                continue
            version = data.get("version")
            if version not in SUPPORTED_CVSS_VERSIONS:
                context.rejections.add(
                    "cvss_unsupported_version",
                    relative_path,
                    digest,
                    source_record_id=cve_id,
                    field_name="metrics.*.cvssData.version",
                )
                continue
            score = data.get("baseScore")
            if score is not None and (
                isinstance(score, bool)
                or not isinstance(score, (int, float))
                or not 0 <= score <= 10
            ):
                context.rejections.add(
                    "cvss_invalid_base_score",
                    relative_path,
                    digest,
                    source_record_id=cve_id,
                    field_name="metrics.*.cvssData.baseScore",
                )
                continue
            vector = _bounded_text(data.get("vectorString"), 250)
            severity = data.get("baseSeverity", metric.get("baseSeverity"))
            if severity is not None and severity not in SUPPORTED_SEVERITIES:
                context.rejections.add(
                    "cvss_invalid_base_severity",
                    relative_path,
                    digest,
                    source_record_id=cve_id,
                    field_name="metrics.*.baseSeverity",
                )
                continue

            metric_source = _bounded_text(metric.get("source"), 250)
            metric_type = _bounded_text(metric.get("type"), 100)
            observation_id = _stable_id(
                "cvss",
                cve_id,
                version,
                vector or "",
                observed_at_utc,
                "nvd",
                metric_source or "",
                metric_type or "",
                context.source_snapshot_id,
            )
            previous_changes = context.connection.total_changes
            context.connection.execute(
                """
                INSERT OR IGNORE INTO cvss_observation(
                    cvss_observation_id, cve_id, version, base_score, vector,
                    observed_at_utc, source_name, retrieved_at_utc, created_at_utc,
                    base_severity, exploitability_score, impact_score, metric_source,
                    metric_type, source_snapshot_id, ingestion_run_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation_id,
                    cve_id,
                    version,
                    score,
                    vector,
                    observed_at_utc,
                    "nvd",
                    context.retrieved_at_utc,
                    _now_utc(),
                    severity,
                    metric.get("exploitabilityScore"),
                    metric.get("impactScore"),
                    metric_source,
                    metric_type,
                    context.source_snapshot_id,
                    context.ingestion_run_id,
                ),
            )
            if context.connection.total_changes > previous_changes:
                context.row_counts["cvss_observation"] += 1


def _insert_cwe(
    context: IngestionContext,
    cve_id: str,
    observed_at_utc: str,
    document: dict[str, Any],
) -> None:
    weaknesses = document.get("weaknesses")
    if not isinstance(weaknesses, list):
        return

    for weakness in weaknesses:
        descriptions = weakness.get("description") if isinstance(weakness, dict) else None
        if not isinstance(descriptions, list):
            continue
        for description in descriptions:
            cwe_id = description.get("value") if isinstance(description, dict) else None
            if (
                not isinstance(cwe_id, str)
                or cwe_id in CWE_PLACEHOLDERS
                or CWE_ID_PATTERN.fullmatch(cwe_id) is None
            ):
                continue
            previous_changes = context.connection.total_changes
            context.connection.execute(
                """
                INSERT OR IGNORE INTO cwe(
                    cwe_id, name, source_name, retrieved_at_utc, created_at_utc,
                    source_snapshot_id, ingestion_run_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cwe_id,
                    None,
                    "nvd",
                    context.retrieved_at_utc,
                    _now_utc(),
                    context.source_snapshot_id,
                    context.ingestion_run_id,
                ),
            )
            if context.connection.total_changes > previous_changes:
                context.row_counts["cwe"] += 1

            previous_changes = context.connection.total_changes
            context.connection.execute(
                """
                INSERT OR IGNORE INTO cve_cwe(
                    cve_cwe_id, cve_id, cwe_id, observed_at_utc, source_name,
                    retrieved_at_utc, source_snapshot_id, ingestion_run_id, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _stable_id(
                        "cve_cwe", cve_id, cwe_id, observed_at_utc, context.source_snapshot_id
                    ),
                    cve_id,
                    cwe_id,
                    observed_at_utc,
                    "nvd",
                    context.retrieved_at_utc,
                    context.source_snapshot_id,
                    context.ingestion_run_id,
                    _now_utc(),
                ),
            )
            if context.connection.total_changes > previous_changes:
                context.row_counts["cve_cwe"] += 1


def _insert_cpe_match(
    context: IngestionContext,
    cve_id: str,
    observed_at_utc: str,
    match: dict[str, Any],
    relative_path: str,
    digest: str,
) -> str | None:
    criteria = match.get("criteria")
    vulnerable = match.get("vulnerable")
    if not isinstance(criteria, str) or not criteria.startswith("cpe:"):
        context.rejections.add(
            "cpe_invalid_criteria",
            relative_path,
            digest,
            source_record_id=cve_id,
            field_name="configurations.*.cpeMatch.*.criteria",
        )
        return None
    if not isinstance(vulnerable, bool):
        context.rejections.add(
            "cpe_invalid_vulnerable_flag",
            relative_path,
            digest,
            source_record_id=cve_id,
            field_name="configurations.*.cpeMatch.*.vulnerable",
        )
        return None

    cpe_id = _stable_id("cpe", criteria)
    previous_changes = context.connection.total_changes
    context.connection.execute(
        """
        INSERT OR IGNORE INTO cpe(
            cpe_id, cpe_uri, source_name, retrieved_at_utc, created_at_utc,
            source_snapshot_id, ingestion_run_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            cpe_id,
            criteria,
            "nvd",
            context.retrieved_at_utc,
            _now_utc(),
            context.source_snapshot_id,
            context.ingestion_run_id,
        ),
    )
    if context.connection.total_changes > previous_changes:
        context.row_counts["cpe"] += 1

    criteria_id = _bounded_text(match.get("matchCriteriaId"), 250)
    version_bounds = tuple(
        _bounded_text(match.get(key), 250)
        for key in (
            "versionStartIncluding",
            "versionStartExcluding",
            "versionEndIncluding",
            "versionEndExcluding",
        )
    )
    cve_cpe_id = _stable_id(
        "cve_cpe",
        cve_id,
        cpe_id,
        vulnerable,
        criteria_id,
        *version_bounds,
        observed_at_utc,
        context.source_snapshot_id,
    )
    previous_changes = context.connection.total_changes
    context.connection.execute(
        """
        INSERT OR IGNORE INTO cve_cpe(
            cve_cpe_id, cve_id, cpe_id, vulnerable, criteria_id,
            version_start_including, version_start_excluding,
            version_end_including, version_end_excluding, observed_at_utc,
            source_name, retrieved_at_utc, source_snapshot_id,
            ingestion_run_id, created_at_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            cve_cpe_id,
            cve_id,
            cpe_id,
            int(vulnerable),
            criteria_id,
            *version_bounds,
            observed_at_utc,
            "nvd",
            context.retrieved_at_utc,
            context.source_snapshot_id,
            context.ingestion_run_id,
            _now_utc(),
        ),
    )
    if context.connection.total_changes > previous_changes:
        context.row_counts["cve_cpe"] += 1
    return cve_cpe_id


def _configuration_operator(
    context: IngestionContext,
    value: Any,
    relative_path: str,
    digest: str,
    cve_id: str,
    source_path: str,
) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and value.upper() in SUPPORTED_CONFIGURATION_OPERATORS:
        return value.upper()
    context.rejections.add(
        "cpe_configuration_invalid_operator",
        relative_path,
        digest,
        source_record_id=cve_id,
        field_name=f"{source_path}.operator",
    )
    return None


def _configuration_negate(
    context: IngestionContext,
    value: Any,
    relative_path: str,
    digest: str,
    cve_id: str,
    source_path: str,
) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    context.rejections.add(
        "cpe_configuration_invalid_negate",
        relative_path,
        digest,
        source_record_id=cve_id,
        field_name=f"{source_path}.negate",
    )
    return None


def _insert_configuration_node(
    context: IngestionContext,
    cve_id: str,
    observed_at_utc: str,
    node: dict[str, Any],
    *,
    parent_node_id: str | None,
    node_kind: str,
    source_path: str,
    depth: int,
    sibling_position: int,
    relative_path: str,
    digest: str,
) -> None:
    operator = _configuration_operator(
        context,
        node.get("operator"),
        relative_path,
        digest,
        cve_id,
        source_path,
    )
    negate = _configuration_negate(
        context,
        node.get("negate"),
        relative_path,
        digest,
        cve_id,
        source_path,
    )
    node_id = _stable_id(
        "cve_configuration_node",
        cve_id,
        source_path,
        context.source_snapshot_id,
    )
    previous_changes = context.connection.total_changes
    context.connection.execute(
        """
        INSERT OR IGNORE INTO cve_configuration_node(
            cve_configuration_node_id, cve_id, parent_node_id, node_kind,
            source_path, depth, sibling_position, logical_operator, negate,
            observed_at_utc, source_name, retrieved_at_utc, source_snapshot_id,
            ingestion_run_id, created_at_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            node_id,
            cve_id,
            parent_node_id,
            node_kind,
            source_path,
            depth,
            sibling_position,
            operator,
            negate,
            observed_at_utc,
            "nvd",
            context.retrieved_at_utc,
            context.source_snapshot_id,
            context.ingestion_run_id,
            _now_utc(),
        ),
    )
    if context.connection.total_changes > previous_changes:
        context.row_counts["cve_configuration_node"] += 1

    matches = node.get("cpeMatch")
    if isinstance(matches, list):
        for match_position, match in enumerate(matches):
            match_path = f"{source_path}.cpeMatch[{match_position}]"
            if not isinstance(match, dict):
                context.rejections.add(
                    "cpe_match_not_mapping",
                    relative_path,
                    digest,
                    source_record_id=cve_id,
                    field_name=match_path,
                )
                continue
            cve_cpe_id = _insert_cpe_match(
                context,
                cve_id,
                observed_at_utc,
                match,
                relative_path,
                digest,
            )
            if cve_cpe_id is None:
                continue
            previous_changes = context.connection.total_changes
            context.connection.execute(
                """
                INSERT OR IGNORE INTO cve_configuration_match(
                    cve_configuration_match_id, cve_id,
                    cve_configuration_node_id, cve_cpe_id, source_path,
                    match_position, source_snapshot_id, ingestion_run_id,
                    created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _stable_id(
                        "cve_configuration_match",
                        cve_id,
                        match_path,
                        context.source_snapshot_id,
                    ),
                    cve_id,
                    node_id,
                    cve_cpe_id,
                    match_path,
                    match_position,
                    context.source_snapshot_id,
                    context.ingestion_run_id,
                    _now_utc(),
                ),
            )
            if context.connection.total_changes > previous_changes:
                context.row_counts["cve_configuration_match"] += 1

    for child_key in ("nodes", "children"):
        children = node.get(child_key)
        if not isinstance(children, list):
            continue
        for child_position, child in enumerate(children):
            child_path = f"{source_path}.{child_key}[{child_position}]"
            if not isinstance(child, dict):
                context.rejections.add(
                    "cpe_configuration_node_not_mapping",
                    relative_path,
                    digest,
                    source_record_id=cve_id,
                    field_name=child_path,
                )
                continue
            _insert_configuration_node(
                context,
                cve_id,
                observed_at_utc,
                child,
                parent_node_id=node_id,
                node_kind="node",
                source_path=child_path,
                depth=depth + 1,
                sibling_position=child_position,
                relative_path=relative_path,
                digest=digest,
            )


def _insert_cpe(
    context: IngestionContext,
    cve_id: str,
    observed_at_utc: str,
    document: dict[str, Any],
    relative_path: str,
    digest: str,
) -> None:
    configurations = document.get("configurations")
    if not isinstance(configurations, list):
        return
    for configuration_position, configuration in enumerate(configurations):
        source_path = f"configurations[{configuration_position}]"
        if not isinstance(configuration, dict):
            context.rejections.add(
                "cpe_configuration_not_mapping",
                relative_path,
                digest,
                source_record_id=cve_id,
                field_name=source_path,
            )
            continue
        _insert_configuration_node(
            context,
            cve_id,
            observed_at_utc,
            configuration,
            parent_node_id=None,
            node_kind="configuration",
            source_path=source_path,
            depth=0,
            sibling_position=configuration_position,
            relative_path=relative_path,
            digest=digest,
        )


def _ingest_nvd(context: IngestionContext, collection: Path) -> None:
    identifiers: set[str] = set()
    for path in _sorted_files(collection):
        context.progress("nvd")
        result = _read_json(
            path,
            context.root,
            context.max_json_bytes,
            context.fingerprint,
            context.rejections,
        )
        if result is None:
            context.source_counts["nvd"]["rejected"] += 1
            continue
        document, digest, relative_path = result
        if not isinstance(document, dict):
            context.rejections.add("nvd_record_not_mapping", relative_path, digest)
            context.source_counts["nvd"]["rejected"] += 1
            continue

        cve_id = document.get("id")
        if not isinstance(cve_id, str) or CVE_ID_PATTERN.fullmatch(cve_id) is None:
            context.rejections.add(
                "nvd_invalid_cve_id", relative_path, digest, field_name="id"
            )
            context.source_counts["nvd"]["rejected"] += 1
            continue
        if path.stem != cve_id:
            context.rejections.add(
                "nvd_filename_id_mismatch",
                relative_path,
                digest,
                source_record_id=cve_id,
                field_name="id",
            )
            context.source_counts["nvd"]["rejected"] += 1
            continue
        if cve_id in identifiers:
            context.rejections.add(
                "nvd_duplicate_cve_id",
                relative_path,
                digest,
                source_record_id=cve_id,
                field_name="id",
            )
            context.source_counts["nvd"]["rejected"] += 1
            continue

        published = _parse_utc_datetime(document.get("published"), assume_utc_if_naive=True)
        modified = _parse_utc_datetime(document.get("lastModified"), assume_utc_if_naive=True)
        if published is None or modified is None:
            context.rejections.add(
                "nvd_invalid_required_datetime",
                relative_path,
                digest,
                source_record_id=cve_id,
                field_name="published" if published is None else "lastModified",
            )
            context.source_counts["nvd"]["rejected"] += 1
            continue

        identifiers.add(cve_id)
        published_at_utc = _temporal_text(published)
        observed_at_utc = _temporal_text(modified)
        if published_at_utc is None or observed_at_utc is None:
            raise RuntimeError("A validated NVD timestamp could not be normalised")
        _insert_cve(
            context,
            cve_id,
            description=_english_description(document.get("descriptions")),
            published_at_utc=published_at_utc,
            modified_at_utc=observed_at_utc,
            vulnerability_status=_bounded_text(document.get("vulnStatus"), 100),
            source_name="nvd",
        )
        _insert_cvss(context, cve_id, observed_at_utc, document, relative_path, digest)
        _insert_cwe(context, cve_id, observed_at_utc, document)
        _insert_cpe(context, cve_id, observed_at_utc, document, relative_path, digest)
        context.source_counts["nvd"]["accepted"] += 1


def _ingest_legacy_cve(context: IngestionContext, collection: Path) -> None:
    identifiers: set[str] = set()
    for path in _sorted_files(collection):
        context.progress("legacy_cve")
        result = _read_json(
            path,
            context.root,
            context.max_json_bytes,
            context.fingerprint,
            context.rejections,
        )
        if result is None:
            context.source_counts["legacy_cve"]["rejected"] += 1
            continue
        document, digest, relative_path = result
        metadata = document.get("CVE_data_meta") if isinstance(document, dict) else None
        if not isinstance(metadata, dict):
            context.rejections.add("legacy_cve_metadata_missing", relative_path, digest)
            context.source_counts["legacy_cve"]["rejected"] += 1
            continue
        cve_id = metadata.get("ID")
        if not isinstance(cve_id, str) or CVE_ID_PATTERN.fullmatch(cve_id) is None:
            context.rejections.add(
                "legacy_cve_invalid_id",
                relative_path,
                digest,
                field_name="CVE_data_meta.ID",
            )
            context.source_counts["legacy_cve"]["rejected"] += 1
            continue
        if path.stem != cve_id:
            context.rejections.add(
                "legacy_cve_filename_id_mismatch",
                relative_path,
                digest,
                source_record_id=cve_id,
                field_name="CVE_data_meta.ID",
            )
            context.source_counts["legacy_cve"]["rejected"] += 1
            continue
        if cve_id in identifiers:
            context.rejections.add(
                "legacy_cve_duplicate_id",
                relative_path,
                digest,
                source_record_id=cve_id,
                field_name="CVE_data_meta.ID",
            )
            context.source_counts["legacy_cve"]["rejected"] += 1
            continue

        identifiers.add(cve_id)
        descriptions = document.get("description")
        entries = descriptions.get("description_data") if isinstance(descriptions, dict) else None
        _insert_cve(
            context,
            cve_id,
            description=_english_description(entries),
            published_at_utc=None,
            modified_at_utc=None,
            vulnerability_status=None,
            source_name="legacy_cve",
        )
        context.source_counts["legacy_cve"]["accepted"] += 1


def _ingest_kev_record(
    context: IngestionContext,
    record: Any,
    *,
    identifiers: set[str],
    relative_path: str,
    digest: str,
    catalogue_date: str,
) -> None:
    if not isinstance(record, dict):
        context.rejections.add("kev_record_not_mapping", relative_path, digest)
        context.source_counts["cisa_kev"]["rejected"] += 1
        return
    cve_id = record.get("cveID")
    if not isinstance(cve_id, str) or CVE_ID_PATTERN.fullmatch(cve_id) is None:
        context.rejections.add(
            "kev_invalid_cve_id", relative_path, digest, field_name="cveID"
        )
        context.source_counts["cisa_kev"]["rejected"] += 1
        return
    if cve_id in identifiers:
        context.rejections.add(
            "kev_duplicate_cve_id",
            relative_path,
            digest,
            source_record_id=cve_id,
            field_name="cveID",
        )
        context.source_counts["cisa_kev"]["rejected"] += 1
        return
    date_added = _parse_date(record.get("dateAdded"))
    due_date = _parse_date(record.get("dueDate"))
    if date_added is None or (record.get("dueDate") is not None and due_date is None):
        invalid_added = date_added is None
        context.rejections.add(
            "kev_invalid_date_added" if invalid_added else "kev_invalid_due_date",
            relative_path,
            digest,
            source_record_id=cve_id,
            field_name="dateAdded" if invalid_added else "dueDate",
        )
        context.source_counts["cisa_kev"]["rejected"] += 1
        return

    identifiers.add(cve_id)
    _insert_cve(
        context,
        cve_id,
        description=None,
        published_at_utc=None,
        modified_at_utc=None,
        vulnerability_status=None,
        source_name="cisa_kev",
    )
    previous_changes = context.connection.total_changes
    context.connection.execute(
        """
        INSERT OR IGNORE INTO kev_observation(
            kev_observation_id, cve_id, date_added, due_date, known_ransomware_use,
            catalogue_date, source_name, retrieved_at_utc, created_at_utc,
            vendor_project, product, vulnerability_name, short_description,
            required_action, notes, source_snapshot_id, ingestion_run_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _stable_id(
                "kev", cve_id, date_added.isoformat(), catalogue_date, context.source_snapshot_id
            ),
            cve_id,
            date_added.isoformat(),
            due_date.isoformat() if due_date else None,
            _bounded_text(record.get("knownRansomwareCampaignUse"), 100),
            catalogue_date,
            "cisa_kev",
            context.retrieved_at_utc,
            _now_utc(),
            _bounded_text(record.get("vendorProject"), 500),
            _bounded_text(record.get("product"), 500),
            _bounded_text(record.get("vulnerabilityName"), 1000),
            _bounded_text(record.get("shortDescription"), 5000),
            _bounded_text(record.get("requiredAction"), 5000),
            _bounded_text(record.get("notes"), 5000),
            context.source_snapshot_id,
            context.ingestion_run_id,
        ),
    )
    if context.connection.total_changes > previous_changes:
        context.row_counts["kev_observation"] += 1
    context.source_counts["cisa_kev"]["accepted"] += 1


def _ingest_kev(context: IngestionContext, path: Path) -> set[str]:
    context.progress("cisa_kev")
    result = _read_json(
        path,
        context.root,
        context.max_json_bytes,
        context.fingerprint,
        context.rejections,
    )
    if result is None:
        context.source_counts["cisa_kev"]["rejected"] += 1
        return set()
    document, digest, relative_path = result
    if not isinstance(document, dict) or not isinstance(document.get("vulnerabilities"), list):
        context.rejections.add("kev_catalogue_invalid", relative_path, digest)
        context.source_counts["cisa_kev"]["rejected"] += 1
        return set()

    released = _parse_utc_datetime(document.get("dateReleased"))
    if released is None:
        raise RuntimeError("The approved CISA KEV catalogue has no usable release timestamp")
    identifiers: set[str] = set()
    for record in document["vulnerabilities"]:
        _ingest_kev_record(
            context,
            record,
            identifiers=identifiers,
            relative_path=relative_path,
            digest=digest,
            catalogue_date=released.date().isoformat(),
        )
    return identifiers


def _verify_counts(context: IngestionContext, report: dict[str, Any]) -> None:
    for collection in ("nvd", "legacy_cve", "cisa_kev"):
        accepted = context.source_counts[collection]["accepted"]
        rejected = context.source_counts[collection]["rejected"]
        expected_accepted = report[collection]["accepted_records"]
        expected_rejected = report[collection].get("rejected_records", 0)
        if accepted != expected_accepted or rejected != expected_rejected:
            raise RuntimeError(
                f"The {collection} ingestion counts do not match the approved coverage report: "
                f"accepted={accepted}/{expected_accepted}; "
                f"rejected={rejected}/{expected_rejected}"
            )
    actual_fingerprint = context.fingerprint.hexdigest()
    if actual_fingerprint != report["input_fingerprint_sha256"]:
        raise RuntimeError(
            "The source fingerprint changed since the approved coverage scan; "
            "the ingestion transaction was rolled back"
        )


def ingest_vulzoo(
    config_path: str | Path,
    database_path: str | Path,
    coverage_report_path: str | Path,
    *,
    progress_every: int = 0,
) -> dict[str, Any]:
    if isinstance(progress_every, bool) or not isinstance(progress_every, int):
        raise ValueError("progress_every must be an integer")
    if not 0 <= progress_every <= 1_000_000:
        raise ValueError("progress_every must be between 0 and 1,000,000")

    source = load_vulzoo_source_config(config_path)
    root = resolve_vulzoo_root(source)
    report = _validated_report(coverage_report_path, source)
    database = _validated_database(database_path, root)
    retrieved_at_utc = _retrieval_timestamp(source)
    processed = root / "processed"
    paths = {
        "nvd": processed / "nvd-database",
        "legacy_cve": processed / "cve-database",
        "cisa_kev": processed / "cisa-kev-database" / "kev.json",
        "relationships": processed / "relationships" / "rel-cve-kev.json",
    }
    for name, path in paths.items():
        expected = path.is_dir() if name in {"nvd", "legacy_cve"} else path.is_file()
        if not expected:
            raise RuntimeError(f"A required approved VulZoo input is missing: {name}")

    max_json_bytes = report["policy"]["max_json_bytes"]
    fingerprint = hashlib.sha256()
    fingerprint.update(
        json.dumps(
            {
                "contract": EXPECTED_COVERAGE_CONTRACT,
                "source_checksum": source.get("checksum"),
                "max_json_bytes": max_json_bytes,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    fingerprint.update(b"\n")

    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
        connection.execute("PRAGMA cache_size = -65536")
        connection.execute("PRAGMA busy_timeout = 10000")
        snapshot_id = _insert_snapshot(connection, source, retrieved_at_utc)
        run_id = f"run:{uuid.uuid4()}"
        started_at_utc = _now_utc()
        configuration = {
            "contract": INGESTION_CONTRACT,
            "coverage_contract": EXPECTED_COVERAGE_CONTRACT,
            "max_json_bytes": max_json_bytes,
            "excluded_sources": ["epss", "exploit_db", "exploit_references"],
            "nvd_naive_datetime_interpretation": "UTC (NVD default GMT)",
            "retrieval_date_precision": "date",
            "retrieval_availability_policy": "end_of_day_utc",
        }
        connection.execute(
            """
            INSERT INTO ingestion_run(
                ingestion_run_id, source_snapshot_id, started_at_utc, status,
                input_fingerprint_sha256, configuration_json, created_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                snapshot_id,
                started_at_utc,
                "running",
                report["input_fingerprint_sha256"],
                json.dumps(configuration, separators=(",", ":"), sort_keys=True),
                started_at_utc,
            ),
        )
        connection.commit()
        rejections = DatabaseRejections(connection, run_id)
        context = IngestionContext(
            connection,
            root,
            snapshot_id,
            run_id,
            retrieved_at_utc,
            max_json_bytes,
            fingerprint,
            rejections,
            progress_every,
        )

        try:
            connection.execute("BEGIN IMMEDIATE")
            _ingest_nvd(context, paths["nvd"])
            _ingest_legacy_cve(context, paths["legacy_cve"])
            kev_ids = _ingest_kev(context, paths["cisa_kev"])
            context.progress("relationships")
            _, relationship_ids = _scan_kev_relationship(
                paths["relationships"],
                root,
                max_json_bytes,
                fingerprint,
                rejections,
            )
            _verify_counts(context, report)
            foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
            if foreign_key_errors:
                raise RuntimeError("Normalised ingestion produced invalid foreign keys")

            accepted = sum(counter["accepted"] for counter in context.source_counts.values())
            rejected = sum(counter["rejected"] for counter in context.source_counts.values())
            completed_at_utc = _now_utc()
            connection.execute(
                """
                UPDATE ingestion_run
                SET completed_at_utc = ?, status = ?, input_record_count = ?,
                    accepted_record_count = ?, rejected_record_count = ?
                WHERE ingestion_run_id = ?
                """,
                (completed_at_utc, "succeeded", accepted + rejected, accepted, rejected, run_id),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            connection.execute(
                """
                UPDATE ingestion_run
                SET completed_at_utc = ?, status = ?
                WHERE ingestion_run_id = ?
                """,
                (_now_utc(), "failed", run_id),
            )
            connection.commit()
            raise

    return {
        "contract": INGESTION_CONTRACT,
        "source_snapshot_id": snapshot_id,
        "ingestion_run_id": run_id,
        "status": "succeeded",
        "input_fingerprint_sha256": fingerprint.hexdigest(),
        "retrieved_at_utc": retrieved_at_utc,
        "source_counts": {
            name: {
                "accepted_records": counts["accepted"],
                "rejected_records": counts["rejected"],
            }
            for name, counts in context.source_counts.items()
        },
        "new_rows": dict(sorted(context.row_counts.items())),
        "bounded_rejections": {
            "count": sum(rejections.reasons.values()),
            "reason_counts": dict(sorted(rejections.reasons.items())),
            "raw_records_included": False,
        },
        "kev_reconciliation": {
            "catalogue_only": len(kev_ids - relationship_ids),
            "relationship_only": len(relationship_ids - kev_ids),
        },
        "scope": {
            "network_accessed": False,
            "dataset_mutated": False,
            "epss_ingested": False,
            "exploit_references_ingested": False,
        },
        "research_status": "historical_engineering_snapshot",
    }
