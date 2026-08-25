from __future__ import annotations

import csv
import gzip
import hashlib
import json
import math
import os
import re
import sqlite3
import sys
import uuid
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from thesis_pipeline.ingestion.normalise import _now_utc, _stable_id
from thesis_pipeline.storage.schema import initialise_database

INGESTION_CONTRACT = "first-epss-ingestion-v1"
ACQUISITION_CONTRACT = "first-epss-acquisition-v1"
ARCHIVE_REPOSITORY = "https://github.com/empiricalsec/epss_scores"
ARCHIVE_RAW_ROOT = "https://raw.githubusercontent.com/empiricalsec/epss_scores"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
MODEL_VERSION_PATTERN = re.compile(r"^v[0-9]{4}[.][0-9]{2}[.][0-9]{2}$")
CSV_COLUMNS = ["cve", "epss", "percentile"]
INSERT_BATCH_SIZE = 5_000


@dataclass(frozen=True)
class ApprovedDailyFile:
    score_date: str
    path: Path
    relative_path: str
    upstream_url: str
    sha256: str
    published_at: str
    source_records: int
    records_matching_vulzoo: int
    records_not_in_vulzoo: int


@dataclass(frozen=True)
class ApprovedEpssPanel:
    source: dict[str, Any]
    database: Path
    root: Path
    files: tuple[ApprovedDailyFile, ...]
    retrieved_at_utc: str
    fingerprint: str
    upstream_commit: str
    first_score_date: str
    last_score_date: str
    model_version: str
    canonical_cves: int


def _read_json(path: str | Path) -> dict[str, Any]:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("The EPSS acquisition manifest is missing or invalid") from exc
    if not isinstance(document, dict):
        raise ValueError("The EPSS acquisition manifest must contain a JSON object")
    return document


def _source_config(path: str | Path) -> dict[str, Any]:
    try:
        document = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        source = document["sources"]["epss"]
    except (OSError, UnicodeError, yaml.YAMLError, KeyError, TypeError) as exc:
        raise ValueError("The FIRST EPSS source configuration is missing or invalid") from exc
    if not isinstance(source, dict):
        raise ValueError("The FIRST EPSS source configuration must be a mapping")
    if source.get("enabled") is not True:
        raise RuntimeError("FIRST EPSS is not enabled in the approved source configuration")
    return source


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"The EPSS {label} must be a lowercase SHA-256 value")
    return value


def _nonnegative(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"The EPSS {label} must be a nonnegative integer")
    return value


def _date(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"The EPSS {label} must be an ISO calendar date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"The EPSS {label} must be an ISO calendar date") from exc
    if parsed.isoformat() != value:
        raise ValueError(f"The EPSS {label} must be an ISO calendar date")
    return value


def _utc_timestamp(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("The EPSS retrieval timestamp must be timezone-aware")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("The EPSS retrieval timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("The EPSS retrieval timestamp must be timezone-aware")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _approved_path(root: Path, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"The EPSS {label} must be a non-empty relative path")
    relative = Path(value)
    if relative.is_absolute():
        raise ValueError(f"The EPSS {label} must be a relative path")
    resolved = (root / relative).resolve()
    if resolved == root or not resolved.is_relative_to(root):
        raise ValueError(f"The EPSS {label} escapes its approved local root")
    return resolved


def _file_sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _panel_fingerprint(
    archive_commit: str,
    first_date: str,
    last_date: str,
    model_version: str,
    files: list[dict[str, Any]],
) -> str:
    material = {
        "archive_commit": archive_commit,
        "first_score_date": first_date,
        "last_score_date": last_date,
        "model_version": model_version,
        "files": [
            {
                "score_date": item["score_date"],
                "sha256": item["sha256"],
                "source_records": item["source_records"],
                "records_matching_vulzoo": item["records_matching_vulzoo"],
            }
            for item in files
        ],
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _validated_file(
    entry: Any,
    *,
    expected_date: date,
    data_root: Path,
    panel_root: Path,
    archive_commit: str,
    model_version: str,
) -> ApprovedDailyFile:
    if not isinstance(entry, dict):
        raise ValueError("Every EPSS acquisition file entry must be a mapping")

    score_date = _date(entry.get("score_date"), "daily score date")
    if score_date != expected_date.isoformat():
        raise ValueError("EPSS daily files must be contiguous, ordered and unique")
    if entry.get("model_version") != model_version:
        raise ValueError("The EPSS panel crosses an unapproved model-version boundary")
    if entry.get("columns") != CSV_COLUMNS:
        raise ValueError("The EPSS acquisition manifest declares unexpected CSV columns")

    relative = entry.get("relative_path")
    path = _approved_path(data_root, relative, "daily file relative_path")
    expected_name = f"epss_scores-{score_date}.csv.gz"
    if path.parent != panel_root or path.name != expected_name:
        raise ValueError("The EPSS daily file is outside its approved date-pinned panel")
    if not path.is_file():
        raise RuntimeError(f"An approved historical EPSS file is missing: {expected_name}")

    expected_url = f"{ARCHIVE_RAW_ROOT}/{archive_commit}/{expected_date.year}/{expected_name}"
    if entry.get("upstream_url") != expected_url:
        raise ValueError("An EPSS daily file URL is not pinned to the approved archive commit")

    digest = _sha256(entry.get("sha256"), "daily file digest")
    if _file_sha256(path) != digest:
        raise RuntimeError(
            f"An approved historical EPSS file changed after acquisition: {score_date}"
        )

    compressed_bytes = _nonnegative(entry.get("compressed_bytes"), "compressed byte count")
    if path.stat().st_size != compressed_bytes:
        raise RuntimeError("An approved historical EPSS file size changed after acquisition")

    published_at = entry.get("published_at")
    if not isinstance(published_at, str) or published_at[:10] != score_date:
        raise ValueError("The approved EPSS publication timestamp does not match its score date")

    records = _nonnegative(entry.get("source_records"), "daily source record count")
    matched = _nonnegative(entry.get("records_matching_vulzoo"), "daily VulZoo match count")
    outside = _nonnegative(entry.get("records_not_in_vulzoo"), "daily outside-scope count")
    if records != matched + outside or matched == 0:
        raise ValueError("The EPSS daily population accounting is inconsistent")

    return ApprovedDailyFile(
        score_date=score_date,
        path=path,
        relative_path=str(relative),
        upstream_url=expected_url,
        sha256=digest,
        published_at=published_at,
        source_records=records,
        records_matching_vulzoo=matched,
        records_not_in_vulzoo=outside,
    )


def _validated_inputs(
    config_path: str | Path,
    database_path: str | Path,
    manifest_path: str | Path,
) -> ApprovedEpssPanel:
    source = _source_config(config_path)
    configured_root = os.environ.get("THESIS_DATA_ROOT")
    if not configured_root:
        raise RuntimeError("THESIS_DATA_ROOT must be configured before EPSS ingestion")
    data_root = Path(configured_root).expanduser().resolve()
    if any("onedrive" in component.casefold() for component in data_root.parts):
        raise RuntimeError("THESIS_DATA_ROOT must remain outside OneDrive")

    root = _approved_path(data_root, source.get("local_relative_path"), "local_relative_path")
    panel_root = _approved_path(root, source.get("panel_relative_path"), "panel_relative_path")
    if not panel_root.is_dir():
        raise RuntimeError("The approved historical EPSS panel directory does not exist")

    database = Path(database_path).expanduser().resolve()
    if not database.is_relative_to(data_root) or database.is_relative_to(root):
        raise ValueError(
            "The SQLite database must remain beneath THESIS_DATA_ROOT and outside EPSS"
        )
    if not database.is_file():
        raise ValueError("Initialise the approved SQLite database before EPSS ingestion")

    manifest_file = Path(manifest_path).expanduser().resolve()
    if not manifest_file.is_relative_to(root / "manifests"):
        raise ValueError("The EPSS acquisition manifest must remain in its approved manifest root")
    manifest = _read_json(manifest_file)
    if manifest.get("contract") != ACQUISITION_CONTRACT:
        raise ValueError("The EPSS acquisition manifest contract is invalid")

    retrieval = _utc_timestamp(manifest.get("retrieved_at_utc"))
    if source.get("retrieval_date") != retrieval[:10]:
        raise ValueError("The EPSS retrieval date does not match the approved acquisition manifest")

    declared_source = manifest.get("source")
    if not isinstance(declared_source, dict):
        raise ValueError("The EPSS acquisition manifest must identify its official upstream source")
    upstream_commit = declared_source.get("archive_commit")
    if (
        not isinstance(upstream_commit, str)
        or GIT_COMMIT_PATTERN.fullmatch(upstream_commit) is None
    ):
        raise ValueError("The EPSS upstream archive commit must be a full lowercase Git SHA")
    if (
        declared_source.get("archive_repository") != ARCHIVE_REPOSITORY
        or source.get("archive_url") != ARCHIVE_REPOSITORY
        or source.get("upstream_commit") != upstream_commit
    ):
        raise ValueError("The EPSS acquisition source does not match the approved official archive")

    panel = manifest.get("panel")
    if not isinstance(panel, dict):
        raise ValueError("The EPSS acquisition manifest must define a dated historical panel")
    first_date = _date(panel.get("first_score_date"), "first score date")
    last_date = _date(panel.get("last_score_date"), "last score date")
    if source.get("panel_start_date") != first_date or source.get("panel_end_date") != last_date:
        raise ValueError("The EPSS acquisition dates do not match approved source configuration")
    model_version = panel.get("model_version")
    if (
        not isinstance(model_version, str)
        or MODEL_VERSION_PATTERN.fullmatch(model_version) is None
        or model_version != source.get("model_version")
    ):
        raise ValueError("The EPSS panel model version does not match approved configuration")
    if (
        panel.get("temporal_mode") != "source_effective_reconstruction"
        or panel.get("historical_ground_truth_claimed") is not False
    ):
        raise ValueError("The EPSS acquisition manifest overclaims historical availability")

    expected_days = (date.fromisoformat(last_date) - date.fromisoformat(first_date)).days + 1
    if expected_days <= 0 or panel.get("days") != expected_days:
        raise ValueError("The EPSS panel must describe a positive contiguous date range")
    entries = manifest.get("files")
    if not isinstance(entries, list) or len(entries) != expected_days:
        raise ValueError("The EPSS panel must contain exactly one file per approved score date")

    scope = manifest.get("scope")
    if not isinstance(scope, dict) or any(
        scope.get(field) is not False
        for field in (
            "database_mutated",
            "raw_score_records_included_in_manifest",
            "source_api_used_for_bulk_download",
        )
    ):
        raise ValueError("The EPSS acquisition manifest violates its approved scope")

    fingerprint = _sha256(manifest.get("input_fingerprint_sha256"), "panel fingerprint")
    configured_checksum = source.get("checksum")
    if configured_checksum != f"sha256:{fingerprint}":
        raise ValueError("The EPSS panel fingerprint does not match approved source configuration")

    files = tuple(
        _validated_file(
            entry,
            expected_date=date.fromisoformat(first_date) + timedelta(days=offset),
            data_root=data_root,
            panel_root=panel_root,
            archive_commit=upstream_commit,
            model_version=model_version,
        )
        for offset, entry in enumerate(entries)
    )
    if (
        _panel_fingerprint(upstream_commit, first_date, last_date, model_version, entries)
        != fingerprint
    ):
        raise ValueError("The EPSS acquisition manifest fingerprint is inconsistent")

    totals = manifest.get("totals")
    if not isinstance(totals, dict):
        raise ValueError("The EPSS acquisition manifest must contain audited population totals")
    if any(
        totals.get(field) != sum(getattr(item, attribute) for item in files)
        for field, attribute in (
            ("source_records", "source_records"),
            ("records_matching_vulzoo", "records_matching_vulzoo"),
            ("records_not_in_vulzoo", "records_not_in_vulzoo"),
        )
    ):
        raise ValueError("The EPSS acquisition manifest population totals are inconsistent")
    canonical = _nonnegative(totals.get("canonical_vulzoo_cves"), "canonical VulZoo CVE count")
    if canonical == 0:
        raise ValueError(
            "The EPSS acquisition manifest requires a non-empty canonical CVE catalogue"
        )

    return ApprovedEpssPanel(
        source=source,
        database=initialise_database(database),
        root=root,
        files=files,
        retrieved_at_utc=retrieval,
        fingerprint=fingerprint,
        upstream_commit=upstream_commit,
        first_score_date=first_date,
        last_score_date=last_date,
        model_version=model_version,
        canonical_cves=canonical,
    )


def _snapshot(
    connection: sqlite3.Connection,
    inputs: ApprovedEpssPanel,
    daily: ApprovedDailyFile,
) -> str:
    checksum = f"sha256:{daily.sha256}"
    snapshot_id = _stable_id("snapshot", "first_epss", checksum)
    metadata = {
        "contract": INGESTION_CONTRACT,
        "acquisition_contract": ACQUISITION_CONTRACT,
        "archive_commit": inputs.upstream_commit,
        "panel_fingerprint_sha256": inputs.fingerprint,
        "published_at": daily.published_at,
        "score_date_availability": "23:59:59 UTC",
        "source_records": daily.source_records,
        "records_matching_vulzoo": daily.records_matching_vulzoo,
        "records_not_in_vulzoo": daily.records_not_in_vulzoo,
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
            "first_epss",
            inputs.model_version,
            daily.score_date,
            inputs.retrieved_at_utc,
            checksum,
            daily.upstream_url,
            daily.relative_path,
            json.dumps(metadata, separators=(",", ":"), sort_keys=True),
            _now_utc(),
        ),
    )
    existing = connection.execute(
        "SELECT source_name, source_version, snapshot_date, retrieved_at_utc, checksum "
        "FROM source_snapshot WHERE source_snapshot_id = ?",
        (snapshot_id,),
    ).fetchone()
    if existing != (
        "first_epss",
        inputs.model_version,
        daily.score_date,
        inputs.retrieved_at_utc,
        checksum,
    ):
        raise RuntimeError("An existing EPSS source snapshot conflicts with approved provenance")
    return snapshot_id


def _header(stream: Any, daily: ApprovedDailyFile, model_version: str) -> csv.reader:
    comment = stream.readline().strip()
    if not comment.startswith("#"):
        raise ValueError("The approved EPSS CSV must begin with its official metadata comment")
    metadata: dict[str, str] = {}
    for part in comment[1:].split(","):
        if ":" not in part:
            raise ValueError("The approved EPSS metadata comment is malformed")
        key, value = part.split(":", 1)
        metadata[key.strip()] = value.strip()
    if metadata.get("model_version") != model_version:
        raise ValueError("The approved EPSS CSV changed its model version after acquisition")
    if metadata.get("score_date") != daily.published_at:
        raise ValueError(
            "The approved EPSS CSV changed its publication timestamp after acquisition"
        )
    reader = csv.reader(stream)
    if next(reader, None) != CSV_COLUMNS:
        raise ValueError("The approved EPSS CSV contains unexpected column names")
    return reader


def _probability(value: str, label: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise ValueError(f"The EPSS {label} is not numeric") from exc
    if not math.isfinite(number) or not 0 <= number <= 1:
        raise ValueError(f"The EPSS {label} must be finite and between zero and one")
    return number


def _flush(connection: sqlite3.Connection, rows: list[tuple[Any, ...]]) -> int:
    before = connection.total_changes
    connection.executemany(
        """
        INSERT OR IGNORE INTO epss_observation(
            epss_observation_id, cve_id, score, percentile,
            score_date, model_version, source_name, retrieved_at_utc,
            created_at_utc, source_snapshot_id, ingestion_run_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    inserted = connection.total_changes - before
    rows.clear()
    return inserted


def _ingest_day(
    connection: sqlite3.Connection,
    inputs: ApprovedEpssPanel,
    daily: ApprovedDailyFile,
    canonical_cves: set[str],
    *,
    processed_before: int,
    progress_every: int,
) -> dict[str, Any]:
    snapshot_id = _snapshot(connection, inputs, daily)
    run_id = f"run:{uuid.uuid4()}"
    started_at = _now_utc()
    configuration = {
        "contract": INGESTION_CONTRACT,
        "score_date": daily.score_date,
        "model_version": inputs.model_version,
        "panel_fingerprint_sha256": inputs.fingerprint,
        "unmatched_cve_policy": "exclude_without_canonical_or_rejection_row",
        "temporal_policy": "source_date_end_of_day_and_actual_local_retrieval",
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
            started_at,
            "running",
            inputs.fingerprint,
            json.dumps(configuration, separators=(",", ":"), sort_keys=True),
            started_at,
        ),
    )
    connection.commit()

    seen_cves: set[str] = set()
    pending: list[tuple[Any, ...]] = []
    matched = 0
    excluded = 0
    inserted = 0

    try:
        connection.execute("BEGIN IMMEDIATE")
        with gzip.open(daily.path, "rt", encoding="utf-8-sig", newline="") as stream:
            for row_number, row in enumerate(_header(stream, daily, inputs.model_version), start=3):
                if len(row) != 3:
                    raise ValueError(f"Malformed EPSS row at {daily.score_date}:{row_number}")
                cve_id, score_text, percentile_text = row
                if CVE_PATTERN.fullmatch(cve_id) is None:
                    raise ValueError(
                        f"Invalid EPSS CVE identifier at {daily.score_date}:{row_number}"
                    )
                if cve_id in seen_cves:
                    raise ValueError(
                        f"Duplicate EPSS CVE identifier at {daily.score_date}:{row_number}"
                    )
                seen_cves.add(cve_id)
                score = _probability(score_text, "probability")
                percentile = _probability(percentile_text, "percentile")

                if cve_id not in canonical_cves:
                    excluded += 1
                else:
                    matched += 1
                    pending.append(
                        (
                            _stable_id(
                                "epss", cve_id, daily.score_date, inputs.model_version, snapshot_id
                            ),
                            cve_id,
                            score,
                            percentile,
                            daily.score_date,
                            inputs.model_version,
                            "first_epss",
                            inputs.retrieved_at_utc,
                            started_at,
                            snapshot_id,
                            run_id,
                        )
                    )
                    if len(pending) == INSERT_BATCH_SIZE:
                        inserted += _flush(connection, pending)

                processed = processed_before + len(seen_cves)
                if progress_every and processed % progress_every == 0:
                    print(
                        f"Processed {processed:,} EPSS source records; "
                        f"current score date: {daily.score_date}",
                        file=sys.stderr,
                        flush=True,
                    )

        if pending:
            inserted += _flush(connection, pending)
        if (
            len(seen_cves) != daily.source_records
            or matched != daily.records_matching_vulzoo
            or excluded != daily.records_not_in_vulzoo
        ):
            raise RuntimeError("EPSS ingestion counts differ from the approved acquisition audit")

        connection.execute(
            """
            UPDATE ingestion_run
            SET completed_at_utc = ?, status = ?, input_record_count = ?,
                accepted_record_count = ?, rejected_record_count = ?
            WHERE ingestion_run_id = ?
            """,
            (_now_utc(), "succeeded", len(seen_cves), matched, 0, run_id),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        connection.execute(
            "UPDATE ingestion_run SET completed_at_utc = ?, status = ? WHERE ingestion_run_id = ?",
            (_now_utc(), "failed", run_id),
        )
        connection.commit()
        raise

    return {
        "score_date": daily.score_date,
        "source_snapshot_id": snapshot_id,
        "ingestion_run_id": run_id,
        "source_records": len(seen_cves),
        "matched_records": matched,
        "outside_vulzoo_snapshot": excluded,
        "new_observations": inserted,
    }


def ingest_epss_panel(
    config_path: str | Path,
    database_path: str | Path,
    acquisition_manifest_path: str | Path,
    *,
    progress_every: int = 0,
) -> dict[str, Any]:
    """Ingest an approved daily FIRST EPSS panel without adding out-of-snapshot CVEs."""
    if isinstance(progress_every, bool) or not isinstance(progress_every, int):
        raise ValueError("progress_every must be an integer")
    if not 0 <= progress_every <= 10_000_000:
        raise ValueError("progress_every must be between 0 and 10,000,000")

    inputs = _validated_inputs(config_path, database_path, acquisition_manifest_path)

    with closing(sqlite3.connect(inputs.database)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
        connection.execute("PRAGMA cache_size = -131072")
        connection.execute("PRAGMA busy_timeout = 15000")

        canonical_cves = {str(row[0]) for row in connection.execute("SELECT cve_id FROM cve")}
        if len(canonical_cves) != inputs.canonical_cves:
            raise RuntimeError("The canonical VulZoo catalogue changed after EPSS acquisition")

        daily_results = []
        processed = 0
        for index, daily in enumerate(inputs.files, start=1):
            print(
                f"Ingesting EPSS day {index}/{len(inputs.files)}: {daily.score_date}",
                file=sys.stderr,
                flush=True,
            )
            result = _ingest_day(
                connection,
                inputs,
                daily,
                canonical_cves,
                processed_before=processed,
                progress_every=progress_every,
            )
            processed += daily.source_records
            daily_results.append(result)

    return {
        "contract": INGESTION_CONTRACT,
        "status": "succeeded",
        "input_fingerprint_sha256": inputs.fingerprint,
        "retrieved_at_utc": inputs.retrieved_at_utc,
        "archive_commit": inputs.upstream_commit,
        "model_version": inputs.model_version,
        "panel": {
            "first_score_date": inputs.first_score_date,
            "last_score_date": inputs.last_score_date,
            "days": len(inputs.files),
        },
        "totals": {
            "source_records": sum(item["source_records"] for item in daily_results),
            "matched_records": sum(item["matched_records"] for item in daily_results),
            "outside_vulzoo_snapshot": sum(
                item["outside_vulzoo_snapshot"] for item in daily_results
            ),
            "new_observations": sum(item["new_observations"] for item in daily_results),
            "rejected_records": 0,
            "source_snapshots": len(daily_results),
            "ingestion_runs": len(daily_results),
        },
        "daily": daily_results,
        "scope": {
            "network_accessed": False,
            "dataset_mutated": False,
            "canonical_cves_created": False,
            "raw_records_included": False,
            "historical_ground_truth_claimed": False,
        },
        "research_status": "date_pinned_epss_panel_for_source_effective_reconstruction",
    }
