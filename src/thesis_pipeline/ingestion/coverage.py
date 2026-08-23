from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from thesis_pipeline.ingestion.source import (
    load_vulzoo_source_config,
    resolve_vulzoo_root,
)

CVE_ID_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
CWE_ID_PATTERN = re.compile(r"^CWE-[0-9]+$")
CWE_PLACEHOLDERS = {"NVD-CWE-noinfo", "NVD-CWE-Other"}
MAX_JSON_COVERAGE_BYTES = 25 * 1024 * 1024
MAX_REJECTION_SAMPLE_LIMIT = 100
MAX_REPORTED_CATEGORIES = 100
MAX_CATEGORY_TEXT_LENGTH = 100


@dataclass
class ValueRange:
    minimum: date | datetime | None = None
    maximum: date | datetime | None = None

    def add(self, value: date | datetime) -> None:
        if self.minimum is None or value < self.minimum:
            self.minimum = value
        if self.maximum is None or value > self.maximum:
            self.maximum = value

    def serialise(self) -> dict[str, str | None]:
        return {
            "minimum": _temporal_text(self.minimum),
            "maximum": _temporal_text(self.maximum),
        }


@dataclass
class RejectionTracker:
    sample_limit: int
    reasons: Counter[str] = field(default_factory=Counter)
    samples: list[dict[str, str | None]] = field(default_factory=list)

    def add(
        self,
        reason: str,
        relative_path: str,
        record_hash_sha256: str | None,
        *,
        source_record_id: str | None = None,
        field_name: str | None = None,
    ) -> None:
        self.reasons[reason] += 1

        if len(self.samples) >= self.sample_limit:
            return

        self.samples.append(
            {
                "reason_code": reason,
                "source_relative_path": relative_path,
                "source_record_id": source_record_id,
                "field_name": field_name,
                "record_hash_sha256": record_hash_sha256,
            }
        )

    def serialise(self) -> dict[str, Any]:
        return {
            "count": sum(self.reasons.values()),
            "reason_counts": _counter_dict(self.reasons),
            "samples": self.samples,
            "sample_limit": self.sample_limit,
            "raw_records_included": False,
        }


def _counter_dict(counter: Counter[str]) -> dict[str, int]:
    ranked = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    selected = ranked[:MAX_REPORTED_CATEGORIES]
    result = {key: count for key, count in sorted(selected)}
    omitted = ranked[MAX_REPORTED_CATEGORIES:]
    if omitted:
        result["<other_categories>"] = sum(count for _, count in omitted)
    return result


def _category_text(value: Any) -> str:
    if value is None:
        return "<missing>"
    if not isinstance(value, (str, int, float, bool)):
        return "<invalid_type>"
    text = str(value).strip()
    if not text:
        return "<missing>"
    if len(text) > MAX_CATEGORY_TEXT_LENGTH:
        return "<overlong>"
    if any(character.isspace() and character != " " for character in text):
        return "<invalid>"
    return text


def _temporal_text(value: date | datetime | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return value.isoformat()


def _parse_utc_datetime(
    value: Any,
    *,
    assume_utc_if_naive: bool = False,
) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        if not assume_utc_if_naive:
            return None
        parsed = parsed.replace(tzinfo=UTC)

    return parsed.astimezone(UTC)


def _datetime_interpretation(value: Any) -> str:
    if not isinstance(value, str):
        return "invalid"
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return "invalid"
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return "naive_assumed_utc"
    return "explicit_offset"


def _parse_date(value: Any) -> date | None:
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        return date.fromisoformat(value.strip())
    except ValueError:
        return None


def _sorted_files(root: Path) -> Iterator[Path]:
    for current_root, directories, filenames in os.walk(root):
        directories.sort()
        for filename in sorted(filenames):
            yield Path(current_root) / filename


def _update_fingerprint(
    fingerprint: Any,
    relative_path: str,
    size: int,
    digest: str,
) -> None:
    fingerprint.update(relative_path.encode("utf-8"))
    fingerprint.update(b"\0")
    fingerprint.update(str(size).encode("ascii"))
    fingerprint.update(b"\0")
    fingerprint.update(digest.encode("ascii"))
    fingerprint.update(b"\n")


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(
    path: Path,
    root: Path,
    max_json_bytes: int,
    fingerprint: Any,
    rejections: RejectionTracker,
) -> tuple[Any, str, str] | None:
    relative_path = path.relative_to(root).as_posix()

    try:
        resolved_path = path.resolve(strict=True)
    except OSError:
        _update_fingerprint(fingerprint, relative_path, -1, "stat_error")
        rejections.add("file_stat_error", relative_path, None)
        return None

    if not resolved_path.is_relative_to(root):
        _update_fingerprint(fingerprint, relative_path, -1, "outside_root")
        rejections.add("file_outside_approved_root", relative_path, None)
        return None

    try:
        size = path.stat().st_size
    except OSError:
        _update_fingerprint(fingerprint, relative_path, -1, "stat_error")
        rejections.add("file_stat_error", relative_path, None)
        return None

    if size > max_json_bytes:
        try:
            digest = _hash_file(path)
        except OSError:
            _update_fingerprint(fingerprint, relative_path, size, "read_error")
            rejections.add("file_read_error", relative_path, None)
            return None
        _update_fingerprint(fingerprint, relative_path, size, digest)
        rejections.add("json_size_limit", relative_path, digest)
        return None

    try:
        payload = path.read_bytes()
    except OSError:
        _update_fingerprint(fingerprint, relative_path, size, "read_error")
        rejections.add("file_read_error", relative_path, None)
        return None

    digest = hashlib.sha256(payload).hexdigest()
    _update_fingerprint(fingerprint, relative_path, size, digest)

    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        rejections.add("json_parse_error", relative_path, digest)
        return None

    return document, digest, relative_path


def _nvd_cvss_counts(metrics: Any, summary: dict[str, Any]) -> None:
    if not isinstance(metrics, dict):
        summary["quality_counts"]["metrics_not_mapping"] += 1
        return

    for group_name in sorted(metrics):
        metric_group = metrics[group_name]
        summary["cvss_metric_group_counts"][_category_text(group_name)] += 1

        if not isinstance(metric_group, list):
            summary["quality_counts"]["cvss_group_not_list"] += 1
            continue

        for metric in metric_group:
            if not isinstance(metric, dict):
                summary["quality_counts"]["cvss_metric_not_mapping"] += 1
                continue

            cvss_data = metric.get("cvssData")
            if not isinstance(cvss_data, dict):
                summary["quality_counts"]["cvss_data_missing"] += 1
                continue

            version = cvss_data.get("version")
            version_key = _category_text(version)
            summary["cvss_version_counts"][version_key] += 1
            summary["cvss_metric_source_counts"][_category_text(metric.get("source"))] += 1
            summary["cvss_metric_type_counts"][_category_text(metric.get("type"))] += 1

            if cvss_data.get("baseScore") is None:
                summary["quality_counts"]["cvss_base_score_missing"] += 1
            if not cvss_data.get("vectorString"):
                summary["quality_counts"]["cvss_vector_missing"] += 1


def _nvd_cwe_counts(weaknesses: Any, summary: dict[str, Any]) -> None:
    if not isinstance(weaknesses, list):
        summary["quality_counts"]["weaknesses_not_list"] += 1
        return

    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            summary["quality_counts"]["weakness_not_mapping"] += 1
            continue

        descriptions = weakness.get("description")
        if not isinstance(descriptions, list):
            summary["quality_counts"]["weakness_description_not_list"] += 1
            continue

        for description in descriptions:
            if not isinstance(description, dict):
                summary["quality_counts"]["weakness_description_not_mapping"] += 1
                continue

            value = description.get("value")
            if value in CWE_PLACEHOLDERS:
                summary["cwe_counts"]["placeholder"] += 1
            elif isinstance(value, str) and CWE_ID_PATTERN.fullmatch(value):
                summary["cwe_counts"]["valid"] += 1
            else:
                summary["cwe_counts"]["invalid_or_missing"] += 1


def _nvd_cpe_counts(configurations: Any, summary: dict[str, Any]) -> None:
    if not isinstance(configurations, list):
        summary["quality_counts"]["configurations_not_list"] += 1
        return

    pending = list(configurations)

    while pending:
        node = pending.pop()
        if not isinstance(node, dict):
            summary["quality_counts"]["configuration_node_not_mapping"] += 1
            continue

        child_nodes = node.get("nodes")
        if isinstance(child_nodes, list):
            pending.extend(child_nodes)

        matches = node.get("cpeMatch")
        if matches is None:
            continue
        if not isinstance(matches, list):
            summary["quality_counts"]["cpe_match_not_list"] += 1
            continue

        for match in matches:
            if not isinstance(match, dict):
                summary["quality_counts"]["cpe_match_not_mapping"] += 1
                continue

            summary["cpe_match_count"] += 1
            vulnerable = match.get("vulnerable")
            if isinstance(vulnerable, bool):
                vulnerable_category = str(vulnerable).casefold()
            elif vulnerable is None:
                vulnerable_category = "<missing>"
            else:
                vulnerable_category = "<invalid_type>"
            summary["cpe_vulnerable_counts"][vulnerable_category] += 1

            if not match.get("criteria"):
                summary["quality_counts"]["cpe_criteria_missing"] += 1


def _scan_nvd(
    collection_root: Path,
    root: Path,
    max_json_bytes: int,
    fingerprint: Any,
    rejections: RejectionTracker,
) -> tuple[dict[str, Any], set[str]]:
    published_range = ValueRange()
    modified_range = ValueRange()
    identifiers: set[str] = set()
    summary: dict[str, Any] = {
        "files_seen": 0,
        "accepted_records": 0,
        "rejected_records": 0,
        "duplicate_identifiers": 0,
        "vulnerability_status_counts": Counter(),
        "cvss_metric_group_counts": Counter(),
        "cvss_version_counts": Counter(),
        "cvss_metric_source_counts": Counter(),
        "cvss_metric_type_counts": Counter(),
        "cwe_counts": Counter(),
        "cwe_record_counts": Counter(),
        "cpe_match_count": 0,
        "cpe_record_counts": Counter(),
        "cpe_vulnerable_counts": Counter(),
        "quality_counts": Counter(),
        "datetime_interpretation_counts": Counter(),
    }

    for path in _sorted_files(collection_root):
        summary["files_seen"] += 1
        result = _read_json(path, root, max_json_bytes, fingerprint, rejections)

        if result is None:
            summary["rejected_records"] += 1
            continue

        document, digest, relative_path = result
        if not isinstance(document, dict):
            rejections.add("nvd_record_not_mapping", relative_path, digest)
            summary["rejected_records"] += 1
            continue

        cve_id = document.get("id")
        if not isinstance(cve_id, str) or not CVE_ID_PATTERN.fullmatch(cve_id):
            rejections.add(
                "nvd_invalid_cve_id",
                relative_path,
                digest,
                field_name="id",
            )
            summary["rejected_records"] += 1
            continue

        if path.stem != cve_id:
            rejections.add(
                "nvd_filename_id_mismatch",
                relative_path,
                digest,
                source_record_id=cve_id,
                field_name="id",
            )
            summary["rejected_records"] += 1
            continue

        if cve_id in identifiers:
            rejections.add(
                "nvd_duplicate_cve_id",
                relative_path,
                digest,
                source_record_id=cve_id,
                field_name="id",
            )
            summary["duplicate_identifiers"] += 1
            summary["rejected_records"] += 1
            continue

        published_value = document.get("published")
        modified_value = document.get("lastModified")
        published = _parse_utc_datetime(
            published_value,
            assume_utc_if_naive=True,
        )
        modified = _parse_utc_datetime(
            modified_value,
            assume_utc_if_naive=True,
        )

        if published is None or modified is None:
            missing_field = "published" if published is None else "lastModified"
            rejections.add(
                "nvd_invalid_required_datetime",
                relative_path,
                digest,
                source_record_id=cve_id,
                field_name=missing_field,
            )
            summary["rejected_records"] += 1
            continue

        identifiers.add(cve_id)
        summary["accepted_records"] += 1
        summary["datetime_interpretation_counts"][
            f"published_{_datetime_interpretation(published_value)}"
        ] += 1
        summary["datetime_interpretation_counts"][
            f"last_modified_{_datetime_interpretation(modified_value)}"
        ] += 1
        published_range.add(published)
        modified_range.add(modified)
        summary["vulnerability_status_counts"][_category_text(document.get("vulnStatus"))] += 1

        valid_cwe_before = summary["cwe_counts"]["valid"]
        placeholder_cwe_before = summary["cwe_counts"]["placeholder"]
        _nvd_cvss_counts(document.get("metrics"), summary)
        _nvd_cwe_counts(document.get("weaknesses"), summary)
        if summary["cwe_counts"]["valid"] > valid_cwe_before:
            summary["cwe_record_counts"]["with_valid_cwe"] += 1
        else:
            summary["cwe_record_counts"]["without_valid_cwe"] += 1
        if summary["cwe_counts"]["placeholder"] > placeholder_cwe_before:
            summary["cwe_record_counts"]["with_placeholder_cwe"] += 1

        cpe_before = summary["cpe_match_count"]
        _nvd_cpe_counts(document.get("configurations"), summary)
        if summary["cpe_match_count"] > cpe_before:
            summary["cpe_record_counts"]["with_cpe_match"] += 1
        else:
            summary["cpe_record_counts"]["without_cpe_match"] += 1

    return (
        {
            **summary,
            "identifier_count": len(identifiers),
            "published_at_utc": published_range.serialise(),
            "modified_at_utc": modified_range.serialise(),
            "vulnerability_status_counts": _counter_dict(
                summary["vulnerability_status_counts"]
            ),
            "cvss_metric_group_counts": _counter_dict(summary["cvss_metric_group_counts"]),
            "cvss_version_counts": _counter_dict(summary["cvss_version_counts"]),
            "cvss_metric_source_counts": _counter_dict(
                summary["cvss_metric_source_counts"]
            ),
            "cvss_metric_type_counts": _counter_dict(summary["cvss_metric_type_counts"]),
            "cwe_counts": _counter_dict(summary["cwe_counts"]),
            "cwe_record_counts": _counter_dict(summary["cwe_record_counts"]),
            "cpe_record_counts": _counter_dict(summary["cpe_record_counts"]),
            "cpe_vulnerable_counts": _counter_dict(summary["cpe_vulnerable_counts"]),
            "quality_counts": _counter_dict(summary["quality_counts"]),
            "datetime_interpretation_counts": _counter_dict(
                summary["datetime_interpretation_counts"]
            ),
        },
        identifiers,
    )


def _scan_legacy_cve(
    collection_root: Path,
    root: Path,
    max_json_bytes: int,
    fingerprint: Any,
    rejections: RejectionTracker,
) -> tuple[dict[str, Any], set[str]]:
    date_public_range = ValueRange()
    identifiers: set[str] = set()
    state_counts: Counter[str] = Counter()
    data_version_counts: Counter[str] = Counter()
    quality_counts: Counter[str] = Counter()
    files_seen = 0
    accepted_records = 0
    rejected_records = 0
    duplicate_identifiers = 0

    for path in _sorted_files(collection_root):
        files_seen += 1
        result = _read_json(path, root, max_json_bytes, fingerprint, rejections)

        if result is None:
            rejected_records += 1
            continue

        document, digest, relative_path = result
        metadata = document.get("CVE_data_meta") if isinstance(document, dict) else None

        if not isinstance(metadata, dict):
            rejections.add("legacy_cve_metadata_missing", relative_path, digest)
            rejected_records += 1
            continue

        cve_id = metadata.get("ID")
        if not isinstance(cve_id, str) or not CVE_ID_PATTERN.fullmatch(cve_id):
            rejections.add(
                "legacy_cve_invalid_id",
                relative_path,
                digest,
                field_name="CVE_data_meta.ID",
            )
            rejected_records += 1
            continue

        if path.stem != cve_id:
            rejections.add(
                "legacy_cve_filename_id_mismatch",
                relative_path,
                digest,
                source_record_id=cve_id,
                field_name="CVE_data_meta.ID",
            )
            rejected_records += 1
            continue

        if cve_id in identifiers:
            rejections.add(
                "legacy_cve_duplicate_id",
                relative_path,
                digest,
                source_record_id=cve_id,
                field_name="CVE_data_meta.ID",
            )
            duplicate_identifiers += 1
            rejected_records += 1
            continue

        identifiers.add(cve_id)
        accepted_records += 1
        state_counts[_category_text(metadata.get("STATE"))] += 1
        data_version_counts[_category_text(document.get("data_version"))] += 1

        public_value = metadata.get("DATE_PUBLIC")
        if public_value is None:
            quality_counts["date_public_missing"] += 1
        else:
            public_date = _parse_date(public_value)
            public_datetime = _parse_utc_datetime(public_value)
            if public_date is not None:
                date_public_range.add(public_date)
            elif public_datetime is not None:
                date_public_range.add(public_datetime.date())
            else:
                quality_counts["date_public_invalid"] += 1

        descriptions = document.get("description")
        if not isinstance(descriptions, dict) or not descriptions.get("description_data"):
            quality_counts["description_missing"] += 1
        problemtype = document.get("problemtype")
        if not isinstance(problemtype, dict) or not problemtype.get("problemtype_data"):
            quality_counts["problemtype_missing"] += 1

    return (
        {
            "files_seen": files_seen,
            "accepted_records": accepted_records,
            "rejected_records": rejected_records,
            "identifier_count": len(identifiers),
            "duplicate_identifiers": duplicate_identifiers,
            "date_public": date_public_range.serialise(),
            "state_counts": _counter_dict(state_counts),
            "data_version_counts": _counter_dict(data_version_counts),
            "quality_counts": _counter_dict(quality_counts),
        },
        identifiers,
    )


def _scan_kev(
    path: Path,
    root: Path,
    max_json_bytes: int,
    fingerprint: Any,
    rejections: RejectionTracker,
) -> tuple[dict[str, Any], set[str]]:
    result = _read_json(path, root, max_json_bytes, fingerprint, rejections)
    if result is None:
        return {"files_seen": 1, "accepted_records": 0, "rejected_records": 1}, set()

    document, digest, relative_path = result
    if not isinstance(document, dict) or not isinstance(document.get("vulnerabilities"), list):
        rejections.add("kev_catalogue_invalid", relative_path, digest)
        return {"files_seen": 1, "accepted_records": 0, "rejected_records": 1}, set()

    records = document["vulnerabilities"]
    identifiers: set[str] = set()
    date_added_range = ValueRange()
    due_date_range = ValueRange()
    ransomware_counts: Counter[str] = Counter()
    cwe_counts: Counter[str] = Counter()
    quality_counts: Counter[str] = Counter()
    accepted_records = 0
    rejected_records = 0
    duplicate_identifiers = 0

    for record in records:
        if not isinstance(record, dict):
            rejections.add("kev_record_not_mapping", relative_path, digest)
            rejected_records += 1
            continue

        cve_id = record.get("cveID")
        if not isinstance(cve_id, str) or not CVE_ID_PATTERN.fullmatch(cve_id):
            rejections.add(
                "kev_invalid_cve_id",
                relative_path,
                digest,
                field_name="cveID",
            )
            rejected_records += 1
            continue

        if cve_id in identifiers:
            rejections.add(
                "kev_duplicate_cve_id",
                relative_path,
                digest,
                source_record_id=cve_id,
                field_name="cveID",
            )
            duplicate_identifiers += 1
            rejected_records += 1
            continue

        date_added = _parse_date(record.get("dateAdded"))
        due_date = _parse_date(record.get("dueDate"))

        if date_added is None:
            rejections.add(
                "kev_invalid_date_added",
                relative_path,
                digest,
                source_record_id=cve_id,
                field_name="dateAdded",
            )
            rejected_records += 1
            continue

        if record.get("dueDate") is not None and due_date is None:
            rejections.add(
                "kev_invalid_due_date",
                relative_path,
                digest,
                source_record_id=cve_id,
                field_name="dueDate",
            )
            rejected_records += 1
            continue

        identifiers.add(cve_id)
        accepted_records += 1
        date_added_range.add(date_added)
        if due_date is not None:
            due_date_range.add(due_date)
        ransomware_counts[_category_text(record.get("knownRansomwareCampaignUse"))] += 1

        cwes = record.get("cwes")
        if not isinstance(cwes, list):
            cwe_counts["missing_or_not_list"] += 1
        else:
            for cwe_id in cwes:
                if isinstance(cwe_id, str) and CWE_ID_PATTERN.fullmatch(cwe_id):
                    cwe_counts["valid"] += 1
                else:
                    cwe_counts["invalid"] += 1

    date_released = _parse_utc_datetime(document.get("dateReleased"))
    if date_released is None:
        quality_counts["date_released_invalid_or_missing"] += 1

    declared_count = document.get("count")
    if isinstance(declared_count, bool) or not isinstance(declared_count, int):
        quality_counts["declared_count_invalid_or_missing"] += 1
        declared_count_matches_actual = False
    else:
        declared_count_matches_actual = declared_count == len(records)
        if not declared_count_matches_actual:
            quality_counts["declared_count_mismatch"] += 1

    return (
        {
            "files_seen": 1,
            "catalog_version": _category_text(document.get("catalogVersion")),
            "date_released_utc": _temporal_text(date_released),
            "declared_count": declared_count,
            "actual_count": len(records),
            "declared_count_matches_actual": declared_count_matches_actual,
            "accepted_records": accepted_records,
            "rejected_records": rejected_records,
            "identifier_count": len(identifiers),
            "duplicate_identifiers": duplicate_identifiers,
            "date_added": date_added_range.serialise(),
            "due_date": due_date_range.serialise(),
            "known_ransomware_campaign_use_counts": _counter_dict(ransomware_counts),
            "cwe_counts": _counter_dict(cwe_counts),
            "quality_counts": _counter_dict(quality_counts),
        },
        identifiers,
    )


def _scan_kev_relationship(
    path: Path,
    root: Path,
    max_json_bytes: int,
    fingerprint: Any,
    rejections: RejectionTracker,
) -> tuple[dict[str, Any], set[str]]:
    result = _read_json(path, root, max_json_bytes, fingerprint, rejections)
    if result is None:
        return {"files_seen": 1, "accepted_identifiers": 0}, set()

    document, digest, relative_path = result
    if not isinstance(document, list):
        rejections.add("kev_relationship_not_list", relative_path, digest)
        return {"files_seen": 1, "accepted_identifiers": 0}, set()

    identifiers: set[str] = set()
    invalid_identifiers = 0
    duplicate_identifiers = 0

    for value in document:
        if not isinstance(value, str) or not CVE_ID_PATTERN.fullmatch(value):
            rejections.add(
                "kev_relationship_invalid_cve_id",
                relative_path,
                digest,
                field_name="[]",
            )
            invalid_identifiers += 1
            continue
        if value in identifiers:
            rejections.add(
                "kev_relationship_duplicate_cve_id",
                relative_path,
                digest,
                source_record_id=value,
                field_name="[]",
            )
            duplicate_identifiers += 1
        identifiers.add(value)

    return (
        {
            "files_seen": 1,
            "record_count": len(document),
            "accepted_identifiers": len(identifiers),
            "invalid_identifiers": invalid_identifiers,
            "duplicate_identifiers": duplicate_identifiers,
        },
        identifiers,
    )


def scan_vulzoo_coverage(
    config_path: str | Path,
    *,
    max_json_bytes: int = 5 * 1024 * 1024,
    rejection_sample_limit: int = 20,
) -> dict[str, Any]:
    if not 1 <= max_json_bytes <= MAX_JSON_COVERAGE_BYTES:
        raise ValueError(
            f"max_json_bytes must be between 1 and {MAX_JSON_COVERAGE_BYTES}"
        )
    if not 0 <= rejection_sample_limit <= MAX_REJECTION_SAMPLE_LIMIT:
        raise ValueError(
            "rejection_sample_limit must be between 0 and "
            f"{MAX_REJECTION_SAMPLE_LIMIT}"
        )

    source = load_vulzoo_source_config(config_path)
    root = resolve_vulzoo_root(source)
    processed_root = root / "processed"
    nvd_root = processed_root / "nvd-database"
    legacy_cve_root = processed_root / "cve-database"
    kev_path = processed_root / "cisa-kev-database" / "kev.json"
    kev_relationship_path = processed_root / "relationships" / "rel-cve-kev.json"

    required_paths = (
        (nvd_root, "directory"),
        (legacy_cve_root, "directory"),
        (kev_path, "file"),
        (kev_relationship_path, "file"),
    )
    missing_paths = []
    for path, expected_type in required_paths:
        exists_as_expected = path.is_dir() if expected_type == "directory" else path.is_file()
        if not exists_as_expected:
            missing_paths.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "expected_type": expected_type,
                }
            )
    if missing_paths:
        raise RuntimeError(f"Required VulZoo coverage inputs are missing: {missing_paths}")

    fingerprint = hashlib.sha256()
    fingerprint.update(
        json.dumps(
            {
                "contract": "vulzoo-coverage-v2",
                "source_checksum": source.get("checksum"),
                "max_json_bytes": max_json_bytes,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    fingerprint.update(b"\n")
    rejections = RejectionTracker(rejection_sample_limit)

    nvd, nvd_ids = _scan_nvd(
        nvd_root,
        root,
        max_json_bytes,
        fingerprint,
        rejections,
    )
    legacy_cve, legacy_cve_ids = _scan_legacy_cve(
        legacy_cve_root,
        root,
        max_json_bytes,
        fingerprint,
        rejections,
    )
    kev, kev_ids = _scan_kev(
        kev_path,
        root,
        max_json_bytes,
        fingerprint,
        rejections,
    )
    kev_relationship, kev_relationship_ids = _scan_kev_relationship(
        kev_relationship_path,
        root,
        max_json_bytes,
        fingerprint,
        rejections,
    )

    return {
        "source": {
            "url": source.get("url"),
            "retrieval_date": source.get("retrieval_date"),
            "readme_snapshot_date": source.get("snapshot_date"),
            "readme_snapshot_note": source.get("snapshot_date_note"),
            "checksum": source.get("checksum"),
            "local_relative_path": source.get("local_relative_path"),
        },
        "scope": {
            "collections": [
                "processed/nvd-database",
                "processed/cve-database",
                "processed/cisa-kev-database/kev.json",
                "processed/relationships/rel-cve-kev.json",
            ],
            "excluded_collections": ["processed/exploit-db-database"],
            "raw_records_included": False,
            "files_executed": False,
            "network_accessed": False,
            "dataset_mutated": False,
        },
        "policy": {
            "contract": "vulzoo-coverage-v2",
            "max_json_bytes": max_json_bytes,
            "rejection_sample_limit": rejection_sample_limit,
            "max_reported_categories": MAX_REPORTED_CATEGORIES,
            "deterministic_traversal": True,
            "content_sha256_fingerprint": True,
            "nvd_naive_datetime_interpretation": "UTC (NVD default GMT)",
        },
        "nvd": nvd,
        "legacy_cve": legacy_cve,
        "cisa_kev": kev,
        "kev_relationship": kev_relationship,
        "cross_source": {
            "nvd_legacy_cve_intersection": len(nvd_ids & legacy_cve_ids),
            "nvd_only": len(nvd_ids - legacy_cve_ids),
            "legacy_cve_only": len(legacy_cve_ids - nvd_ids),
            "kev_missing_nvd": len(kev_ids - nvd_ids),
            "kev_missing_legacy_cve": len(kev_ids - legacy_cve_ids),
            "kev_catalogue_only": len(kev_ids - kev_relationship_ids),
            "kev_relationship_only": len(kev_relationship_ids - kev_ids),
        },
        "totals": {
            "files_seen": (
                nvd["files_seen"]
                + legacy_cve["files_seen"]
                + kev["files_seen"]
                + kev_relationship["files_seen"]
            ),
            "accepted_source_records": (
                nvd["accepted_records"]
                + legacy_cve["accepted_records"]
                + kev["accepted_records"]
            ),
            "rejected_source_records": (
                nvd["rejected_records"]
                + legacy_cve["rejected_records"]
                + kev["rejected_records"]
            ),
        },
        "rejections": rejections.serialise(),
        "input_fingerprint_sha256": fingerprint.hexdigest(),
        "research_status": "metadata_only_engineering_profile",
    }
