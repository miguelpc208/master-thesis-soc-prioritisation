from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

AS_OF_MODES = ("strict_snapshot", "source_effective_reconstruction")


def _normalise_decision_time(value: str | datetime) -> str:
    if isinstance(value, str):
        candidate = value.strip()
        if candidate.endswith("Z"):
            candidate = f"{candidate[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise ValueError("decision time must be an ISO-8601 timestamp") from exc
    else:
        parsed = value

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("decision time must include an explicit UTC offset")

    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _database_path(value: str | Path) -> Path:
    path = Path(value).expanduser().resolve()
    root = Path(__file__).resolve().parents[3]

    if not path.is_file():
        raise ValueError(f"database does not exist: {path}")
    if path == root or root in path.parents:
        raise ValueError("SQLite databases must remain outside the Git repository")
    if path.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
        raise ValueError("database path must end with .db, .sqlite, or .sqlite3")

    return path


def _read_only_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _evidence_summary(
    connection: sqlite3.Connection,
    decision_at_utc: str,
) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        WITH evidence_counts AS (
            SELECT
                evidence_kind,
                COUNT(*) AS total_records,
                SUM(CASE WHEN strict_available_at_utc <= ? THEN 1 ELSE 0 END)
                    AS strict_snapshot_eligible,
                SUM(CASE WHEN reconstruction_available_at_utc <= ? THEN 1 ELSE 0 END)
                    AS reconstruction_eligible,
                SUM(CASE WHEN effective_at_utc IS NULL THEN 1 ELSE 0 END)
                    AS missing_effective_time,
                SUM(CASE WHEN effective_at_utc > ? THEN 1 ELSE 0 END)
                    AS effective_after_cutoff,
                SUM(CASE WHEN retrieved_at_utc > ? THEN 1 ELSE 0 END)
                    AS retrieved_after_cutoff,
                MIN(effective_at_utc) AS earliest_effective_at_utc,
                MAX(effective_at_utc) AS latest_effective_at_utc,
                MIN(retrieved_at_utc) AS earliest_retrieved_at_utc,
                MAX(retrieved_at_utc) AS latest_retrieved_at_utc
            FROM technical_evidence_availability
            GROUP BY evidence_kind
        )
        SELECT
            policy.evidence_kind,
            policy.operational_role,
            policy.history_status,
            COALESCE(counts.total_records, 0) AS total_records,
            COALESCE(counts.strict_snapshot_eligible, 0) AS strict_snapshot_eligible,
            COALESCE(counts.reconstruction_eligible, 0) AS reconstruction_eligible,
            COALESCE(counts.missing_effective_time, 0) AS missing_effective_time,
            COALESCE(counts.effective_after_cutoff, 0) AS effective_after_cutoff,
            COALESCE(counts.retrieved_after_cutoff, 0) AS retrieved_after_cutoff,
            counts.earliest_effective_at_utc,
            counts.latest_effective_at_utc,
            counts.earliest_retrieved_at_utc,
            counts.latest_retrieved_at_utc
        FROM evidence_time_policy AS policy
        LEFT JOIN evidence_counts AS counts
          ON counts.evidence_kind = policy.evidence_kind
        ORDER BY policy.evidence_kind
        """,
        (
            decision_at_utc,
            decision_at_utc,
            decision_at_utc,
            decision_at_utc,
        ),
    ).fetchall()

    return [dict(row) for row in rows]


def _policy_summary(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT
            evidence_kind,
            source_name,
            operational_role,
            history_status,
            effective_time_semantics,
            source_observed_time_semantics,
            strict_availability_semantics,
            reconstruction_availability_semantics
        FROM evidence_time_policy
        ORDER BY evidence_kind
        """
    ).fetchall()
    return [dict(row) for row in rows]


def _snapshot_summary(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT
            source_snapshot_id,
            source_name,
            source_version,
            snapshot_date,
            retrieved_at_utc,
            checksum
        FROM source_snapshot
        ORDER BY source_name, source_snapshot_id
        """
    ).fetchall()
    return [dict(row) for row in rows]


def audit_technical_evidence_as_of(
    database_path: str | Path,
    decision_time: str | datetime,
    *,
    mode: str = "strict_snapshot",
) -> dict[str, Any]:
    """Audit eligible technical evidence without reading raw source payloads or mutating SQLite."""
    if mode not in AS_OF_MODES:
        raise ValueError(f"mode must be one of: {', '.join(AS_OF_MODES)}")

    path = _database_path(database_path)
    decision_at_utc = _normalise_decision_time(decision_time)

    with closing(_read_only_connection(path)) as connection:
        versions = [
            int(row[0])
            for row in connection.execute(
                "SELECT version FROM schema_version ORDER BY version"
            )
        ]
        if not versions or versions[-1] < 6:
            raise RuntimeError("database migration 006 is required for temporal auditing")

        integrity = connection.execute("PRAGMA quick_check").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError(f"database integrity check failed: {integrity}")

        evidence = _evidence_summary(connection, decision_at_utc)
        policies = _policy_summary(connection)
        snapshots = _snapshot_summary(connection)

    eligibility_field = (
        "strict_snapshot_eligible"
        if mode == "strict_snapshot"
        else "reconstruction_eligible"
    )
    total_records = sum(int(item["total_records"]) for item in evidence)
    eligible_records = sum(int(item[eligibility_field]) for item in evidence)
    decision_context_eligible = sum(
        int(item[eligibility_field])
        for item in evidence
        if item["operational_role"] != "offline_label"
    )
    prioritisation_eligible = sum(
        int(item[eligibility_field])
        for item in evidence
        if item["operational_role"] == "prioritisation"
    )
    applicability_eligible = sum(
        int(item[eligibility_field])
        for item in evidence
        if item["operational_role"] == "applicability"
    )
    catalogue_eligible = sum(
        int(item[eligibility_field])
        for item in evidence
        if item["operational_role"] == "catalogue"
    )
    offline_labels_eligible = sum(
        int(item[eligibility_field])
        for item in evidence
        if item["operational_role"] == "offline_label"
    )

    fingerprint_payload = {
        "contract": "technical-evidence-as-of-v1",
        "decision_at_utc": decision_at_utc,
        "mode": mode,
        "schema_versions": versions,
        "source_snapshots": snapshots,
        "evidence": evidence,
    }
    fingerprint = hashlib.sha256(
        json.dumps(fingerprint_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    return {
        "contract": "technical-evidence-as-of-v1",
        "decision_at_utc": decision_at_utc,
        "mode": mode,
        "input_fingerprint_sha256": fingerprint,
        "database": {
            "path": str(path),
            "schema_versions": versions,
            "integrity": integrity,
        },
        "scope": {
            "raw_records_included": False,
            "network_accessed": False,
            "database_mutated": False,
            "look_ahead_guard_enforced": True,
        },
        "totals": {
            "evidence_records": total_records,
            "eligible_records": eligible_records,
            "excluded_after_cutoff": total_records - eligible_records,
            "decision_context_evidence_eligible": decision_context_eligible,
            "prioritisation_evidence_eligible": prioritisation_eligible,
            "applicability_evidence_eligible": applicability_eligible,
            "catalogue_records_eligible": catalogue_eligible,
            "offline_labels_eligible": offline_labels_eligible,
        },
        "evidence": evidence,
        "policies": policies,
        "source_snapshots": snapshots,
        "limitations": {
            "complete_historical_panel": False,
            "single_snapshot_sources_are_version_incomplete": True,
            "diversevul_source_time_known": False,
            "strict_snapshot_is_historical_ground_truth": False,
            "reconstruction_is_historical_ground_truth": False,
        },
        "research_status": (
            "strict_snapshot_engineering_audit"
            if mode == "strict_snapshot"
            else "source_effective_reconstruction_not_historical_ground_truth"
        ),
    }
