from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import sys
import uuid
from collections import Counter, defaultdict
from collections.abc import Iterator
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from thesis_pipeline.ingestion.catalogue import canonical_cve_ids_sha256
from thesis_pipeline.ingestion.normalise import DatabaseRejections, _now_utc, _stable_id
from thesis_pipeline.storage.schema import initialise_database

INGESTION_CONTRACT = "diversevul-ingestion-v2"
PROFILE_CONTRACT = "diversevul-profile-v2"
ACQUISITION_CONTRACT = "diversevul-acquisition-v1"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)
COMMIT_URL_PATTERN = re.compile(r"/commits?/([0-9a-f]{7,40})(?:[/?#]|$)", re.IGNORECASE)
CVE_PATTERN = re.compile(r"(?<![A-Z0-9])CVE-[0-9]{4}-[0-9]{4,}(?![A-Z0-9])", re.I)
CWE_PATTERN = re.compile(r"(?<![A-Z0-9])CWE-[0-9]+(?![A-Z0-9])", re.I)
MAX_TEXT_LENGTH = 2_048


@dataclass(frozen=True)
class ApprovedInputs:
    source: dict[str, Any]
    root: Path
    dataset: Path
    metadata: Path
    database: Path
    manifest: dict[str, Any]
    profile: dict[str, Any]
    fingerprint: str
    retrieved_at_utc: str


@dataclass
class DiverseVulContext:
    connection: sqlite3.Connection
    inputs: ApprovedInputs
    snapshot_id: str
    run_id: str
    created_at_utc: str
    rejections: DatabaseRejections
    canonical_cves: set[str]
    progress_every: int
    metadata_rows: int = 0
    metadata_accepted: int = 0
    metadata_recovered_commits: int = 0
    function_rows: int = 0
    function_accepted: int = 0
    empty_functions: int = 0
    functions_with_cve: int = 0
    labels: Counter[str] = field(default_factory=Counter)
    new_rows: Counter[str] = field(default_factory=Counter)
    evidence_rows: Counter[str] = field(default_factory=Counter)
    projects: set[str] = field(default_factory=set)
    commits: set[str] = field(default_factory=set)
    matched_cves: set[str] = field(default_factory=set)
    unmatched_cves: set[str] = field(default_factory=set)
    metadata_cves: dict[tuple[str, str], set[str]] = field(default_factory=lambda: defaultdict(set))
    metadata_projects_by_commit: dict[str, set[str]] = field(
        default_factory=lambda: defaultdict(set)
    )
    project_mismatches: set[tuple[str, str]] = field(default_factory=set)


def _read_document(path: str | Path, label: str) -> dict[str, Any]:
    document_path = Path(path).expanduser().resolve()
    if not document_path.is_file():
        raise ValueError(f"An existing {label} document is required")
    try:
        document = json.loads(document_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"The {label} document cannot be parsed") from exc
    if not isinstance(document, dict):
        raise ValueError(f"The {label} document must contain a JSON object")
    return document


def _load_source(config_path: str | Path) -> dict[str, Any]:
    try:
        document = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
        source = document["sources"]["diversevul"]
    except (OSError, UnicodeError, yaml.YAMLError, KeyError, TypeError) as exc:
        raise ValueError("DiverseVul source configuration is missing or invalid") from exc
    if not isinstance(source, dict):
        raise ValueError("DiverseVul source configuration must be a mapping")
    if source.get("enabled") is not True:
        raise RuntimeError("DiverseVul is not enabled in the data-source configuration")
    return source


def _approved_relative(root: Path, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"DiverseVul {label} is missing or invalid")
    relative = Path(value)
    if relative.is_absolute():
        raise ValueError(f"DiverseVul {label} must be relative")
    resolved = (root / relative).resolve()
    if resolved == root or not resolved.is_relative_to(root):
        raise ValueError(f"DiverseVul {label} must remain beneath its approved root")
    return resolved


def _checksum(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ValueError(f"DiverseVul {label} must start with sha256:")
    digest = value.removeprefix("sha256:")
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise ValueError(f"DiverseVul {label} must contain a lowercase SHA-256 digest")
    return digest


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _retrieved_at(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("The DiverseVul acquisition timestamp must be an aware UTC datetime")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("The DiverseVul acquisition timestamp is invalid") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("The DiverseVul acquisition timestamp must include a UTC offset")
    return result.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _manifest_retrieved_at(manifest: dict[str, Any], source: dict[str, Any]) -> str:
    for name in (
        "acquired_at_utc",
        "retrieved_at_utc",
        "generated_at_utc",
        "created_at_utc",
    ):
        if name in manifest:
            return _retrieved_at(manifest[name])

    configured = source.get("retrieval_date")
    if not isinstance(configured, str):
        raise ValueError("The DiverseVul retrieval date is missing or invalid")
    try:
        retrieval_date = date.fromisoformat(configured)
    except ValueError as exc:
        raise ValueError("The DiverseVul retrieval date is missing or invalid") from exc
    return f"{retrieval_date.isoformat()}T23:59:59Z"


def _validated_inputs(
    config_path: str | Path,
    database_path: str | Path,
    acquisition_manifest_path: str | Path,
    profile_report_path: str | Path,
) -> ApprovedInputs:
    source = _load_source(config_path)
    configured_root = os.environ.get("THESIS_DATA_ROOT")
    if not configured_root:
        raise RuntimeError("THESIS_DATA_ROOT must be configured before DiverseVul ingestion")
    data_root = Path(configured_root).expanduser().resolve()
    if any("onedrive" in component.casefold() for component in data_root.parts):
        raise RuntimeError("THESIS_DATA_ROOT must remain outside OneDrive")

    root = _approved_relative(data_root, source.get("local_relative_path"), "local_relative_path")
    if not root.is_dir():
        raise RuntimeError("The approved DiverseVul root does not exist")
    dataset = _approved_relative(root, source.get("dataset_relative_path"), "dataset_relative_path")
    metadata = _approved_relative(
        root, source.get("metadata_relative_path"), "metadata_relative_path"
    )
    if not dataset.is_file() or not metadata.is_file():
        raise RuntimeError("The approved DiverseVul dataset and metadata files must exist")

    database = Path(database_path).expanduser().resolve()
    if not database.is_relative_to(data_root) or database.is_relative_to(root):
        raise ValueError(
            "The SQLite database must remain beneath THESIS_DATA_ROOT and outside DiverseVul"
        )
    if not database.is_file():
        raise ValueError("Initialise the approved SQLite database before DiverseVul ingestion")

    dataset_checksum = _checksum(source.get("checksum"), "checksum")
    metadata_checksum = _checksum(source.get("metadata_checksum"), "metadata_checksum")
    upstream_commit = source.get("upstream_commit")
    if not isinstance(upstream_commit, str) or COMMIT_PATTERN.fullmatch(upstream_commit) is None:
        raise ValueError("DiverseVul upstream_commit must be an approved Git commit")

    manifest = _read_document(acquisition_manifest_path, "DiverseVul acquisition manifest")
    if manifest.get("contract") != ACQUISITION_CONTRACT:
        raise ValueError("The DiverseVul acquisition manifest contract is invalid")
    if manifest.get("upstream_commit") != upstream_commit:
        raise ValueError("The acquisition manifest does not match the configured upstream commit")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ValueError("The acquisition manifest must describe the approved files")
    entries = {entry.get("role"): entry for entry in files if isinstance(entry, dict)}
    if set(entries) != {"dataset", "metadata"} or len(files) != 2:
        raise ValueError(
            "The acquisition manifest must contain exactly one dataset and metadata file"
        )
    for role, expected_path, expected_checksum in (
        ("dataset", dataset, dataset_checksum),
        ("metadata", metadata, metadata_checksum),
    ):
        entry = entries[role]
        local_path = entry.get("local_path")
        if (
            not isinstance(local_path, str)
            or Path(local_path).expanduser().resolve() != expected_path
        ):
            raise ValueError(f"The acquisition manifest {role} path is outside the approved source")
        if entry.get("sha256") != expected_checksum:
            raise ValueError(
                f"The acquisition manifest {role} checksum does not match configuration"
            )
        if _file_sha256(expected_path) != expected_checksum:
            raise RuntimeError(f"The approved DiverseVul {role} changed after acquisition")

    profile = _read_document(profile_report_path, "DiverseVul profile report")
    if profile.get("contract") != PROFILE_CONTRACT:
        raise ValueError("The DiverseVul profile report contract is invalid")
    scope = profile.get("scope")
    if not isinstance(scope, dict) or any(
        scope.get(field) is not False
        for field in (
            "raw_records_included",
            "source_code_included",
            "source_code_executed",
            "network_accessed",
            "dataset_mutated",
            "database_mutated",
        )
    ):
        raise ValueError("The DiverseVul profile report violates the approved data boundary")
    profile_source = profile.get("source")
    if not isinstance(profile_source, dict) or (
        profile_source.get("dataset_sha256"),
        profile_source.get("metadata_sha256"),
        profile_source.get("upstream_commit"),
    ) != (dataset_checksum, metadata_checksum, upstream_commit):
        raise ValueError("The DiverseVul profile report does not match the approved source")

    fingerprint = hashlib.sha256(
        f"{dataset_checksum}\n{metadata_checksum}\n{upstream_commit}\n".encode("ascii")
    ).hexdigest()
    if profile.get("input_fingerprint_sha256") != fingerprint:
        raise ValueError("The DiverseVul profile fingerprint does not match the approved inputs")
    dataset_profile = profile.get("dataset")
    metadata_profile = profile.get("metadata")
    join_profile = profile.get("vulzoo_join")
    if not isinstance(dataset_profile, dict) or not isinstance(metadata_profile, dict):
        raise ValueError("The DiverseVul profile does not contain dataset and metadata counts")
    if not isinstance(join_profile, dict):
        raise ValueError("The DiverseVul profile does not contain a VulZoo join summary")
    canonical_count = join_profile.get("canonical_cves_available")
    canonical_fingerprint = join_profile.get("canonical_cve_ids_sha256")
    if (
        isinstance(canonical_count, bool)
        or not isinstance(canonical_count, int)
        or canonical_count <= 0
        or not isinstance(canonical_fingerprint, str)
        or SHA256_PATTERN.fullmatch(canonical_fingerprint) is None
    ):
        raise ValueError(
            "The DiverseVul profile must approve the exact canonical CVE catalogue"
        )

    return ApprovedInputs(
        source=source,
        root=root,
        dataset=dataset,
        metadata=metadata,
        database=initialise_database(database),
        manifest=manifest,
        profile=profile,
        fingerprint=fingerprint,
        retrieved_at_utc=_manifest_retrieved_at(manifest, source),
    )


def _bounded(value: Any, maximum: int = MAX_TEXT_LENGTH) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if value and len(value) <= maximum else None


def _url(value: Any) -> str | None:
    result = _bounded(value)
    if result is None:
        return None
    parts = urlsplit(result)
    return result if parts.scheme in {"http", "https"} and parts.netloc else None


def _extract(pattern: re.Pattern[str], value: Any) -> set[str]:
    if isinstance(value, str):
        return {match.group(0).upper() for match in pattern.finditer(value)}
    if isinstance(value, list):
        return {identifier for item in value for identifier in _extract(pattern, item)}
    return set()


def _jsonl(
    path: Path,
    context: DiverseVulContext,
    collection: str,
) -> Iterator[tuple[int, dict[str, Any], str]]:
    relative = path.relative_to(context.inputs.root).as_posix()
    with path.open("r", encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            digest = hashlib.sha256(line.encode("utf-8")).hexdigest()
            try:
                document = json.loads(line)
            except json.JSONDecodeError:
                context.rejections.add(
                    f"{collection}_json_parse_error",
                    relative,
                    digest,
                    source_record_id=str(line_number),
                )
                continue
            if not isinstance(document, dict):
                context.rejections.add(
                    f"{collection}_record_not_object",
                    relative,
                    digest,
                    source_record_id=str(line_number),
                )
                continue
            yield line_number, document, digest


def _metadata_identity(record: dict[str, Any]) -> tuple[str | None, str | None, bool]:
    raw = record.get("commit_id")
    direct = raw.strip().lower() if isinstance(raw, str) else None
    if direct is not None and COMMIT_PATTERN.fullmatch(direct) is None:
        direct = None
    url = _url(record.get("commit_url"))
    match = COMMIT_URL_PATTERN.search(url) if url else None
    recovered = match.group(1).lower() if match else None
    if direct and recovered and direct != recovered:
        return None, None, True
    if direct:
        return direct, "metadata_commit_id", False
    if recovered:
        return recovered, "metadata_commit_url", False
    return None, None, False


def _insert_snapshot(connection: sqlite3.Connection, inputs: ApprovedInputs) -> str:
    checksum = f"sha256:{inputs.fingerprint}"
    snapshot_id = _stable_id("snapshot", "diversevul", checksum)
    metadata = {
        "contract": INGESTION_CONTRACT,
        "upstream_commit": inputs.source["upstream_commit"],
        "dataset_checksum": inputs.source["checksum"],
        "metadata_checksum": inputs.source["metadata_checksum"],
        "snapshot_checksum_policy": "sha256_of_dataset_metadata_and_upstream_commit",
        "snapshot_date_verified": False,
        "source_code_persisted": False,
        "label_interpretation": "research_label_not_confirmed_asset_exposure",
        "paper_reference_comparison": inputs.profile.get("reference_count_comparison", {}),
        "license_status": inputs.manifest.get("license_status"),
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
            "diversevul",
            inputs.source["upstream_commit"],
            None,
            inputs.retrieved_at_utc,
            checksum,
            inputs.source.get("url"),
            inputs.source["local_relative_path"],
            json.dumps(metadata, separators=(",", ":"), sort_keys=True),
            _now_utc(),
        ),
    )
    return snapshot_id


def _insert_metadata(context: DiverseVulContext) -> None:
    relative = context.inputs.metadata.relative_to(context.inputs.root).as_posix()
    seen: dict[tuple[str, str], tuple[tuple[str, ...], str | None]] = {}

    for line_number, record, digest in _jsonl(context.inputs.metadata, context, "metadata"):
        context.metadata_rows += 1
        project = _bounded(record.get("project"), 500)
        commit, identity_source, conflicting = _metadata_identity(record)
        if project is None:
            context.rejections.add(
                "metadata_invalid_project",
                relative,
                digest,
                source_record_id=str(line_number),
                field_name="project",
            )
            continue
        if conflicting or commit is None or identity_source is None:
            context.rejections.add(
                "metadata_commit_identity_conflict"
                if conflicting
                else "metadata_invalid_commit_id",
                relative,
                digest,
                source_record_id=str(line_number),
                field_name="commit_id",
            )
            continue

        cves = _extract(CVE_PATTERN, record.get("CVE"))
        cwes = _extract(CWE_PATTERN, record.get("CWE"))
        key = (project, commit)
        repository_url = _url(record.get("repo_url"))
        identity = (tuple(sorted(cves)), repository_url)
        if key in seen:
            context.rejections.add(
                "metadata_conflicting_commit"
                if seen[key] != identity
                else "metadata_duplicate_commit",
                relative,
                digest,
                source_record_id=commit,
                field_name="commit_id",
            )
            continue
        seen[key] = identity
        context.metadata_cves[key].update(cves)
        context.metadata_projects_by_commit[commit].add(project)
        context.metadata_recovered_commits += identity_source == "metadata_commit_url"

        previous_changes = context.connection.total_changes
        context.connection.execute(
            """
            INSERT OR IGNORE INTO diversevul_commit(
                diversevul_commit_id, source_snapshot_id, ingestion_run_id,
                project, commit_sha, commit_identity_source, commit_url,
                repository_url, declared_cve_ids_json, declared_cwe_ids_json,
                metadata_line_number, created_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _stable_id("diversevul_commit", context.snapshot_id, project, commit),
                context.snapshot_id,
                context.run_id,
                project,
                commit,
                identity_source,
                _url(record.get("commit_url")),
                repository_url,
                json.dumps(sorted(cves), separators=(",", ":")),
                json.dumps(sorted(cwes), separators=(",", ":")),
                line_number,
                context.created_at_utc,
            ),
        )
        if context.connection.total_changes > previous_changes:
            context.new_rows["diversevul_commit"] += 1
        context.metadata_accepted += 1


def _function_values(record: dict[str, Any]) -> tuple[str, str, str, str, int, int] | None:
    project = _bounded(record.get("project"), 500)
    raw_commit = record.get("commit_id")
    commit = raw_commit.strip().lower() if isinstance(raw_commit, str) else None
    source = record.get("func")
    message = record.get("message")
    source_hash = record.get("hash")
    target = record.get("target")
    if (
        project is None
        or commit is None
        or COMMIT_PATTERN.fullmatch(commit) is None
        or not isinstance(source, str)
        or not isinstance(message, str)
        or isinstance(source_hash, bool)
        or not isinstance(source_hash, int)
        or isinstance(target, bool)
        or target not in (0, 1)
    ):
        return None
    return project, commit, source, message, source_hash, target


def _record_unknown_cve(context: DiverseVulContext, cve_id: str, source: str) -> None:
    if cve_id in context.unmatched_cves:
        return
    context.unmatched_cves.add(cve_id)
    context.rejections.add(
        "cve_not_in_vulzoo_snapshot",
        context.inputs.dataset.relative_to(context.inputs.root).as_posix(),
        None,
        source_record_id=cve_id,
        field_name=source,
    )


def _insert_cve_links(
    context: DiverseVulContext,
    function_id: str,
    metadata_cves: set[str],
    message_cves: set[str],
) -> bool:
    matched = False
    for evidence_source, candidates in (
        ("metadata_cve_field", metadata_cves),
        ("commit_message", message_cves),
    ):
        for cve_id in sorted(candidates):
            if cve_id not in context.canonical_cves:
                _record_unknown_cve(context, cve_id, evidence_source)
                continue
            matched = True
            context.matched_cves.add(cve_id)
            previous_changes = context.connection.total_changes
            context.connection.execute(
                """
                INSERT OR IGNORE INTO diversevul_function_cve(
                    diversevul_function_cve_id, diversevul_function_id, cve_id,
                    evidence_source, source_snapshot_id, ingestion_run_id, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _stable_id("diversevul_function_cve", function_id, cve_id, evidence_source),
                    function_id,
                    cve_id,
                    evidence_source,
                    context.snapshot_id,
                    context.run_id,
                    context.created_at_utc,
                ),
            )
            if context.connection.total_changes > previous_changes:
                context.new_rows["diversevul_function_cve"] += 1
            context.evidence_rows[evidence_source] += 1
    return matched


def _insert_functions(context: DiverseVulContext) -> None:
    relative = context.inputs.dataset.relative_to(context.inputs.root).as_posix()

    for line_number, record, digest in _jsonl(context.inputs.dataset, context, "function"):
        context.function_rows += 1
        values = _function_values(record)
        if values is None:
            context.rejections.add(
                "function_invalid_required_fields",
                relative,
                digest,
                source_record_id=str(line_number),
            )
            continue

        project, commit, source, message, source_hash, label = values
        cwes = record.get("cwe")
        reported_size = record.get("size")
        if not isinstance(cwes, list) or (
            reported_size is not None
            and (
                isinstance(reported_size, bool)
                or not isinstance(reported_size, int)
                or reported_size < 0
            )
        ):
            context.rejections.add(
                "function_invalid_annotations",
                relative,
                digest,
                source_record_id=str(line_number),
            )
            continue

        encoded = source.encode("utf-8")
        function_digest = hashlib.sha256(encoded).hexdigest() if source else None
        message_digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
        function_id = _stable_id("diversevul_function", context.snapshot_id, line_number)
        key = (project, commit)
        metadata_cves = context.metadata_cves.get(key, set())

        if (
            not metadata_cves
            and commit in context.metadata_projects_by_commit
            and key not in context.project_mismatches
            and project not in context.metadata_projects_by_commit[commit]
        ):
            context.project_mismatches.add(key)
            context.rejections.add(
                "metadata_project_mismatch",
                relative,
                None,
                source_record_id=commit,
                field_name="project",
            )

        previous_changes = context.connection.total_changes
        context.connection.execute(
            """
            INSERT OR IGNORE INTO diversevul_function(
                diversevul_function_id, source_snapshot_id, ingestion_run_id,
                source_line_number, project, commit_sha, source_function_hash,
                function_sha256, function_size_bytes, source_reported_size,
                vulnerability_label, cwe_ids_json, commit_message_sha256, created_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                function_id,
                context.snapshot_id,
                context.run_id,
                line_number,
                project,
                commit,
                str(source_hash),
                function_digest,
                len(encoded),
                reported_size,
                label,
                json.dumps(sorted(_extract(CWE_PATTERN, cwes)), separators=(",", ":")),
                message_digest,
                context.created_at_utc,
            ),
        )
        if context.connection.total_changes > previous_changes:
            context.new_rows["diversevul_function"] += 1

        message_cves = _extract(CVE_PATTERN, message)
        context.functions_with_cve += _insert_cve_links(
            context, function_id, metadata_cves, message_cves
        )
        context.function_accepted += 1
        context.empty_functions += not source
        context.labels["vulnerable" if label else "non_vulnerable"] += 1
        context.projects.add(project)
        context.commits.add(commit)

        if context.progress_every and context.function_rows % context.progress_every == 0:
            print(
                f"Processed {context.function_rows:,} DiverseVul functions...",
                file=sys.stderr,
                flush=True,
            )


def _verify_profile(context: DiverseVulContext) -> None:
    dataset = context.inputs.profile["dataset"]
    metadata = context.inputs.profile["metadata"]
    labels = dataset.get("labels")
    if not isinstance(labels, dict):
        raise RuntimeError("The approved DiverseVul profile does not contain label counts")
    expected = {
        "dataset records": (context.function_rows, dataset.get("records")),
        "vulnerable labels": (context.labels["vulnerable"], labels.get("vulnerable", 0)),
        "non-vulnerable labels": (
            context.labels["non_vulnerable"],
            labels.get("non_vulnerable", 0),
        ),
        "projects": (len(context.projects), dataset.get("unique_projects")),
        "dataset commits": (len(context.commits), dataset.get("unique_commits")),
        "metadata records": (context.metadata_rows, metadata.get("top_level_entries")),
        "functions without source code": (
            context.empty_functions,
            dataset.get("missing_source_code", 0),
        ),
    }
    for label, (actual, approved) in expected.items():
        if actual != approved:
            raise RuntimeError(
                f"DiverseVul {label} differ from the approved profile: "
                f"actual={actual}; approved={approved}"
            )
    if context.function_accepted != context.function_rows:
        raise RuntimeError("At least one profiled DiverseVul function failed ingestion validation")


def ingest_diversevul(
    config_path: str | Path,
    database_path: str | Path,
    acquisition_manifest_path: str | Path,
    profile_report_path: str | Path,
    *,
    progress_every: int = 0,
) -> dict[str, Any]:
    if isinstance(progress_every, bool) or not isinstance(progress_every, int):
        raise ValueError("progress_every must be an integer")
    if not 0 <= progress_every <= 1_000_000:
        raise ValueError("progress_every must be between 0 and 1,000,000")

    inputs = _validated_inputs(
        config_path, database_path, acquisition_manifest_path, profile_report_path
    )

    with closing(sqlite3.connect(inputs.database)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
        connection.execute("PRAGMA cache_size = -65536")
        connection.execute("PRAGMA busy_timeout = 10000")
        canonical_cves = {
            str(row[0]).upper() for row in connection.execute("SELECT cve_id FROM cve")
        }
        approved_cves = inputs.profile["vulzoo_join"].get("canonical_cves_available")
        if len(canonical_cves) != approved_cves:
            raise RuntimeError(
                "The canonical VulZoo CVE catalogue changed after DiverseVul profiling"
            )
        approved_catalogue = inputs.profile["vulzoo_join"].get(
            "canonical_cve_ids_sha256"
        )
        if canonical_cve_ids_sha256(canonical_cves) != approved_catalogue:
            raise RuntimeError(
                "The canonical VulZoo CVE identities changed after DiverseVul profiling"
            )

        snapshot_id = _insert_snapshot(connection, inputs)
        run_id = f"run:{uuid.uuid4()}"
        started_at_utc = _now_utc()
        configuration = {
            "contract": INGESTION_CONTRACT,
            "profile_contract": PROFILE_CONTRACT,
            "source_code_persisted": False,
            "metadata_cve_policy": "authoritative_CVE_field_only",
            "message_cve_policy": "exact_explicit_cve_identifier_with_provenance",
            "metadata_join_policy": "exact_project_and_commit",
            "unmatched_cve_policy": "bounded_rejection_without_canonical_insertion",
            "label_policy": "research_label_not_confirmed_asset_exposure",
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
                inputs.fingerprint,
                json.dumps(configuration, separators=(",", ":"), sort_keys=True),
                started_at_utc,
            ),
        )
        connection.commit()
        context = DiverseVulContext(
            connection=connection,
            inputs=inputs,
            snapshot_id=snapshot_id,
            run_id=run_id,
            created_at_utc=started_at_utc,
            rejections=DatabaseRejections(connection, run_id),
            canonical_cves=canonical_cves,
            progress_every=progress_every,
        )

        try:
            connection.execute("BEGIN IMMEDIATE")
            _insert_metadata(context)
            _insert_functions(context)
            _verify_profile(context)
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise RuntimeError("DiverseVul ingestion produced invalid foreign keys")
            rejected = sum(context.rejections.reasons.values())
            accepted = context.metadata_accepted + context.function_accepted
            connection.execute(
                """
                UPDATE ingestion_run
                SET completed_at_utc = ?, status = ?, input_record_count = ?,
                    accepted_record_count = ?, rejected_record_count = ?
                WHERE ingestion_run_id = ?
                """,
                (_now_utc(), "succeeded", accepted + rejected, accepted, rejected, run_id),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            connection.execute(
                "UPDATE ingestion_run SET completed_at_utc = ?, status = ? "
                "WHERE ingestion_run_id = ?",
                (_now_utc(), "failed", run_id),
            )
            connection.commit()
            raise

    return {
        "contract": INGESTION_CONTRACT,
        "status": "succeeded",
        "source_snapshot_id": snapshot_id,
        "ingestion_run_id": run_id,
        "input_fingerprint_sha256": inputs.fingerprint,
        "retrieved_at_utc": inputs.retrieved_at_utc,
        "metadata": {
            "input_records": context.metadata_rows,
            "accepted_records": context.metadata_accepted,
            "commit_ids_recovered_from_url": context.metadata_recovered_commits,
        },
        "functions": {
            "input_records": context.function_rows,
            "accepted_records": context.function_accepted,
            "vulnerable_labels": context.labels["vulnerable"],
            "non_vulnerable_labels": context.labels["non_vulnerable"],
            "without_source_code": context.empty_functions,
            "projects": len(context.projects),
            "commits": len(context.commits),
        },
        "vulzoo_join": {
            "functions_with_matched_cve": context.functions_with_cve,
            "unique_matched_cves": len(context.matched_cves),
            "unique_unmatched_cves": len(context.unmatched_cves),
            "unmatched_cve_sample": sorted(context.unmatched_cves)[:10],
            "evidence_counts": dict(sorted(context.evidence_rows.items())),
            "project_mismatch_count": len(context.project_mismatches),
        },
        "new_rows": dict(sorted(context.new_rows.items())),
        "bounded_rejections": {
            "count": sum(context.rejections.reasons.values()),
            "reason_counts": dict(sorted(context.rejections.reasons.items())),
            "raw_records_included": False,
        },
        "scope": {
            "network_accessed": False,
            "dataset_mutated": False,
            "source_code_persisted": False,
            "source_code_executed": False,
            "canonical_cves_created": False,
            "epss_ingested": False,
            "exploit_references_ingested": False,
        },
        "research_status": "function_level_research_labels_not_operational_exploitability",
    }
