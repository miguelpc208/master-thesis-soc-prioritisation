from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import sys
import uuid
from collections import Counter, defaultdict
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import parse_qs, urlsplit, urlunsplit

import yaml

from thesis_pipeline.ingestion.normalise import DatabaseRejections, _now_utc, _stable_id
from thesis_pipeline.ingestion.source import load_vulzoo_source_config, resolve_vulzoo_root
from thesis_pipeline.storage.schema import initialise_database

INGESTION_CONTRACT = "vulzoo-github-advisory-remediation-v2"
ACQUISITION_CONTRACT = "vulzoo-github-advisory-acquisition-v1"
AUDIT_CONTRACT = "vulzoo-patch-advisory-audit-v1"
COLLECTION_PATH = "processed/github-advisory-database"
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
GHSA_PATTERN = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.I)
PATH_COMMIT_PATTERN = re.compile(
    r"/(?:-|commit|commits)/([0-9a-fA-F]{7,64})(?:/|$)|"
    r"/(?:commit|commits)/([0-9a-fA-F]{7,64})(?:/|$)",
    re.I,
)
HEX_PATH_PATTERN = re.compile(r"/([0-9a-fA-F]{40})(?:/|$)")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
GIT_TREE_PATTERN = re.compile(r"^[0-9a-f]{40}$")
MAX_RELATIONSHIP_BYTES = 80 * 1024 * 1024
MAX_ADVISORY_BYTES = 2 * 1024 * 1024
EVENT_KINDS = ("introduced", "fixed", "last_affected", "limit")


@dataclass(frozen=True)
class ApprovedAdvisoryInputs:
    root: Path
    database: Path
    advisory_root: Path
    source: dict[str, Any]
    vulzoo_source: dict[str, Any]
    manifest: dict[str, Any]
    audit: dict[str, Any]
    relationship_paths: dict[str, Path]
    decision_at_utc: str
    retrieved_at_utc: str
    fingerprint: str
    upstream_commit: str
    git_tree: str


@dataclass
class AdvisoryContext:
    connection: sqlite3.Connection
    inputs: ApprovedAdvisoryInputs
    snapshot_id: str
    run_id: str
    canonical_cves: set[str]
    rejections: DatabaseRejections
    progress_every: int
    counters: Counter[str] = field(default_factory=Counter)
    new_rows: Counter[str] = field(default_factory=Counter)
    exclusions: Counter[str] = field(default_factory=Counter)
    package_ecosystems: Counter[str] = field(default_factory=Counter)
    advisory_anchors: dict[tuple[str, str], list[tuple[str, str]]] = field(
        default_factory=lambda: defaultdict(list)
    )


def _read_document(value: str | Path, label: str) -> dict[str, Any]:
    path = Path(value).expanduser().resolve()
    try:
        result = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"The approved {label} is missing or invalid") from exc
    if not isinstance(result, dict):
        raise ValueError(f"The approved {label} must contain a JSON object")
    return result


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"The {label} must contain an explicit UTC offset")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"The {label} is not a valid UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"The {label} must contain an explicit UTC offset")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _bounded(value: Any, maximum: int = 500) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    return candidate if candidate and len(candidate) <= maximum else None


def _normalised_url(value: Any) -> tuple[str, str, Any] | None:
    candidate = _bounded(value, 2000)
    if candidate is None:
        return None
    try:
        parts = urlsplit(candidate)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https"} or hostname is None:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    netloc = hostname.lower()
    if ":" in netloc:
        netloc = f"[{netloc}]"
    if port is not None:
        netloc = f"{netloc}:{port}"
    normalised = urlunsplit(
        (parts.scheme.lower(), netloc, parts.path or "/", parts.query, "")
    )
    return normalised, hostname.lower(), parts


def _commit_reference(value: Any) -> tuple[str, str] | None:
    result = _normalised_url(value)
    if result is None:
        return None
    normalised, hostname, parts = result
    matched = PATH_COMMIT_PATTERN.search(parts.path)
    commit = next((item for item in matched.groups() if item), None) if matched else None
    if commit is None and hostname.startswith("commits."):
        direct = HEX_PATH_PATTERN.search(parts.path)
        if direct:
            commit = direct.group(1)
    if commit is None and any(
        token in hostname for token in ("git.kernel.org", "git.savannah")
    ):
        candidate = parse_qs(parts.query).get("id", [None])[0]
        if isinstance(candidate, str) and COMMIT_PATTERN.fullmatch(candidate):
            commit = candidate
    if commit is None or COMMIT_PATTERN.fullmatch(commit) is None:
        return None
    return normalised, commit.lower()


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _relationship(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size > MAX_RELATIONSHIP_BYTES:
        raise ValueError(f"The approved relationship is absent or exceeds its bound: {path.name}")
    document = _read_document(path, f"VulZoo relationship {path.name}")
    return document


def _advisory_path(root: Path, value: Any) -> tuple[Path, str] | None:
    if not isinstance(value, str) or "\\" in value:
        return None
    relative = PurePosixPath(value)
    parts = relative.parts
    if (
        relative.is_absolute()
        or ".." in parts
        or len(parts) != 5
        or parts[0] != "github-advisory-database"
        or re.fullmatch(r"[0-9]{4}", parts[1]) is None
        or re.fullmatch(r"(?:0[1-9]|1[0-2])", parts[2]) is None
        or not parts[4].endswith(".json")
    ):
        return None
    identifier = parts[4][:-5]
    if GHSA_PATTERN.fullmatch(identifier) is None or parts[3].upper() != identifier.upper():
        return None
    path = (root / "processed" / Path(*parts)).resolve()
    advisory_root = (root / COLLECTION_PATH).resolve()
    if not path.is_relative_to(advisory_root):
        return None
    return path, identifier


def _load_sources(config_path: str | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    vulzoo = load_vulzoo_source_config(config_path)
    try:
        document = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
        advisory = document["sources"]["github_advisory"]
    except (OSError, UnicodeError, yaml.YAMLError, KeyError, TypeError) as exc:
        raise ValueError("The approved GitHub advisory source configuration is invalid") from exc
    if not isinstance(advisory, dict) or advisory.get("enabled") is not True:
        raise ValueError("The approved GitHub advisory source must be explicitly enabled")
    return vulzoo, advisory


def _validated_inputs(
    config_path: str | Path,
    database_path: str | Path,
    acquisition_manifest_path: str | Path,
    audit_report_path: str | Path,
    decision_at: str,
) -> ApprovedAdvisoryInputs:
    vulzoo_source, source = _load_sources(config_path)
    root = resolve_vulzoo_root(vulzoo_source)
    data_root = Path(os.environ["THESIS_DATA_ROOT"]).expanduser().resolve()
    database = Path(database_path).expanduser().resolve()
    if not database.is_file() or not database.is_relative_to(data_root):
        raise ValueError("The existing technical database must remain beneath THESIS_DATA_ROOT")
    if database.is_relative_to(root):
        raise ValueError("The technical database must remain outside the VulZoo checkout")

    manifest = _read_document(acquisition_manifest_path, "GitHub advisory acquisition manifest")
    audit = _read_document(audit_report_path, "patch and advisory read-only audit")
    if manifest.get("contract") != ACQUISITION_CONTRACT:
        raise ValueError("The GitHub advisory acquisition manifest contract is invalid")
    if audit.get("contract") != AUDIT_CONTRACT:
        raise ValueError("The patch and advisory read-only audit contract is invalid")
    if manifest.get("collection") != COLLECTION_PATH:
        raise ValueError("The advisory acquisition manifest points outside the approved collection")
    if manifest.get("patch_payloads_acquired") is not False:
        raise ValueError("The advisory acquisition manifest permits excluded patch payloads")
    if manifest.get("exploit_payloads_acquired") is not False:
        raise ValueError("The advisory acquisition manifest permits excluded exploit payloads")

    upstream_commit = manifest.get("vulzoo_commit")
    expected_commit = str(vulzoo_source.get("checksum", "")).removeprefix("git-commit-sha1:")
    if (
        not isinstance(upstream_commit, str)
        or GIT_TREE_PATTERN.fullmatch(upstream_commit) is None
        or upstream_commit != expected_commit
        or upstream_commit != source.get("upstream_commit")
        or audit.get("vulzoo_commit") != upstream_commit
    ):
        raise ValueError("The advisory sources do not agree on the pinned VulZoo Git commit")

    git_tree = manifest.get("git_tree_object")
    if (
        not isinstance(git_tree, str)
        or GIT_TREE_PATTERN.fullmatch(git_tree) is None
        or source.get("checksum") != f"git-tree-sha1:{git_tree}"
    ):
        raise ValueError("The approved advisory Git tree does not match source configuration")

    retrieved_at = _timestamp(manifest.get("acquired_at_utc"), "advisory retrieval time")
    decision = _timestamp(decision_at, "scenario decision time")
    if audit.get("decision_at_utc") != decision:
        raise ValueError("The approved advisory audit does not match the requested decision time")
    audit_scope = audit.get("scope")
    if not isinstance(audit_scope, dict) or any(
        audit_scope.get(field) is not False
        for field in (
            "database_mutated",
            "dataset_mutated",
            "network_accessed",
            "patch_payloads_read",
            "exploit_payloads_read",
            "raw_advisory_bodies_included",
            "raw_source_records_included",
            "optional_collections_acquired",
        )
    ):
        raise ValueError("The approved advisory audit violates its read-only source boundary")
    advisory_report = audit.get("github_advisories")
    if (
        not isinstance(advisory_report, dict)
        or advisory_report.get("metadata_collection_present") is not True
    ):
        raise ValueError("The approved audit did not inspect the acquired advisory metadata")

    advisory_root = root / COLLECTION_PATH
    if not advisory_root.is_dir():
        raise ValueError("The approved GitHub advisory collection is absent")
    if (root / "processed" / "exploit-db-database").exists():
        raise ValueError("The excluded Exploit-DB payload collection must remain absent")
    if (root / "processed" / "patch-database").exists():
        raise ValueError("The excluded patch payload collection must remain absent")

    relationship_paths = {
        "patch_urls": root / "processed" / "relationships" / "temp-nvd-patch-links.json",
        "patch_hashes": root / "processed" / "relationships" / "rel-cve-patch.json",
        "github_advisories": (
            root / "processed" / "relationships" / "rel-cve-github-advisory.json"
        ),
    }
    audited_files = audit.get("source_files")
    if not isinstance(audited_files, dict):
        raise ValueError("The approved advisory audit does not identify its relationship inputs")
    relationship_hashes = {}
    for name, path in relationship_paths.items():
        record = audited_files.get(name)
        if not isinstance(record, dict) or not path.is_file():
            raise ValueError(f"The approved advisory relationship is missing: {name}")
        digest = _sha256(path)
        if digest != record.get("sha256"):
            raise ValueError(f"The approved advisory relationship changed after auditing: {name}")
        relationship_hashes[name] = digest

    acquisition_count = manifest.get("file_count")
    if not isinstance(acquisition_count, int) or acquisition_count <= 0:
        raise ValueError("The approved advisory manifest must record a positive file count")
    input_fingerprint = audit.get("input_fingerprint_sha256")
    if (
        not isinstance(input_fingerprint, str)
        or SHA256_PATTERN.fullmatch(input_fingerprint) is None
    ):
        raise ValueError("The approved advisory audit fingerprint is not a lowercase SHA-256")
    material = {
        "contract": INGESTION_CONTRACT,
        "upstream_commit": upstream_commit,
        "git_tree": git_tree,
        "decision_at_utc": decision,
        "audit_fingerprint_sha256": input_fingerprint,
        "relationship_hashes": relationship_hashes,
    }
    fingerprint = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    return ApprovedAdvisoryInputs(
        root=root,
        database=initialise_database(database),
        advisory_root=advisory_root,
        source=source,
        vulzoo_source=vulzoo_source,
        manifest=manifest,
        audit=audit,
        relationship_paths=relationship_paths,
        decision_at_utc=decision,
        retrieved_at_utc=retrieved_at,
        fingerprint=fingerprint,
        upstream_commit=upstream_commit,
        git_tree=git_tree,
    )


def _insert_snapshot(connection: sqlite3.Connection, inputs: ApprovedAdvisoryInputs) -> str:
    checksum = f"git-tree-sha1:{inputs.git_tree}"
    snapshot_id = _stable_id("snapshot", "vulzoo_github_advisory", checksum)
    metadata = {
        "contract": INGESTION_CONTRACT,
        "acquisition_contract": ACQUISITION_CONTRACT,
        "audit_contract": AUDIT_CONTRACT,
        "vulzoo_commit": inputs.upstream_commit,
        "collection": COLLECTION_PATH,
        "collection_file_count": inputs.manifest["file_count"],
        "decision_at_utc": inputs.decision_at_utc,
        "audit_fingerprint_sha256": inputs.audit["input_fingerprint_sha256"],
        "historical_ground_truth_claimed": False,
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
            "vulzoo_github_advisory",
            inputs.upstream_commit,
            None,
            inputs.retrieved_at_utc,
            checksum,
            inputs.vulzoo_source.get("url"),
            f"VulZoo/{COLLECTION_PATH}",
            json.dumps(metadata, sort_keys=True, separators=(",", ":")),
            _now_utc(),
        ),
    )
    return snapshot_id


def _insert_counted(
    context: AdvisoryContext,
    table: str,
    statement: str,
    values: tuple[Any, ...],
) -> None:
    before = context.connection.total_changes
    context.connection.execute(statement, values)
    if context.connection.total_changes > before:
        context.new_rows[table] += 1


def _reject(
    context: AdvisoryContext,
    reason: str,
    relative_path: str,
    digest: str | None,
    cve_id: str | None = None,
    field_name: str | None = None,
) -> None:
    context.exclusions[reason] += 1
    context.rejections.add(
        reason,
        relative_path,
        digest,
        source_record_id=cve_id,
        field_name=field_name,
    )


def _insert_package_versions(
    context: AdvisoryContext,
    package_id: str,
    package: dict[str, Any],
    relative_path: str,
    digest: str,
) -> None:
    versions = package.get("versions", [])
    if not isinstance(versions, list):
        _reject(context, "advisory_versions_not_list", relative_path, digest)
        versions = []
    for position, raw_version in enumerate(versions):
        version = _bounded(raw_version)
        if version is None:
            _reject(context, "advisory_invalid_affected_version", relative_path, digest)
            continue
        identifier = _stable_id("advisory-version", package_id, position)
        _insert_counted(
            context,
            "github_advisory_affected_version",
            """
            INSERT OR IGNORE INTO github_advisory_affected_version(
                github_advisory_affected_version_id, github_advisory_package_id,
                version, source_position, source_snapshot_id, ingestion_run_id, created_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                identifier,
                package_id,
                version,
                position,
                context.snapshot_id,
                context.run_id,
                _now_utc(),
            ),
        )
        context.counters["affected_versions"] += 1

    ranges = package.get("ranges", [])
    if not isinstance(ranges, list):
        _reject(context, "advisory_ranges_not_list", relative_path, digest)
        return
    for range_position, affected_range in enumerate(ranges):
        if not isinstance(affected_range, dict):
            _reject(context, "advisory_invalid_range", relative_path, digest)
            continue
        range_type = _bounded(affected_range.get("type"), 50)
        events = affected_range.get("events")
        if range_type is None or not isinstance(events, list):
            _reject(context, "advisory_invalid_range_structure", relative_path, digest)
            continue
        repository = _normalised_url(affected_range.get("repo"))
        repository_url = repository[0] if repository is not None else None
        for event_position, event in enumerate(events):
            if not isinstance(event, dict):
                _reject(context, "advisory_invalid_version_event", relative_path, digest)
                continue
            allowed = [kind for kind in EVENT_KINDS if kind in event]
            if len(allowed) != 1:
                _reject(context, "advisory_ambiguous_version_event", relative_path, digest)
                continue
            kind = allowed[0]
            value = _bounded(event.get(kind))
            if value is None:
                _reject(context, "advisory_invalid_version_value", relative_path, digest)
                continue
            identifier = _stable_id(
                "advisory-event", package_id, range_position, event_position, kind
            )
            _insert_counted(
                context,
                "github_advisory_version_event",
                """
                INSERT OR IGNORE INTO github_advisory_version_event(
                    github_advisory_version_event_id, github_advisory_package_id,
                    range_position, event_position, range_type, repository_url,
                    event_kind, event_value, source_snapshot_id, ingestion_run_id,
                    created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    identifier,
                    package_id,
                    range_position,
                    event_position,
                    range_type,
                    repository_url,
                    kind,
                    value,
                    context.snapshot_id,
                    context.run_id,
                    _now_utc(),
                ),
            )
            context.counters["version_events"] += 1
            if kind == "fixed":
                context.counters["fixed_version_events"] += 1


def _insert_packages(
    context: AdvisoryContext,
    advisory_id: str,
    document: dict[str, Any],
    relative_path: str,
    digest: str,
) -> None:
    affected = document.get("affected", [])
    if not isinstance(affected, list):
        _reject(context, "advisory_affected_not_list", relative_path, digest)
        return
    for position, affected_package in enumerate(affected):
        if not isinstance(affected_package, dict):
            _reject(context, "advisory_invalid_affected_package", relative_path, digest)
            continue
        identity = affected_package.get("package")
        if not isinstance(identity, dict):
            _reject(context, "advisory_missing_package_identity", relative_path, digest)
            continue
        ecosystem = _bounded(identity.get("ecosystem"), 100)
        package_name = _bounded(identity.get("name"))
        if ecosystem is None or package_name is None:
            _reject(context, "advisory_invalid_package_identity", relative_path, digest)
            continue
        package_id = _stable_id("advisory-package", advisory_id, position)
        _insert_counted(
            context,
            "github_advisory_package",
            """
            INSERT OR IGNORE INTO github_advisory_package(
                github_advisory_package_id, github_advisory_id, ecosystem,
                package_name, package_purl, source_position,
                source_snapshot_id, ingestion_run_id, created_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                package_id,
                advisory_id,
                ecosystem,
                package_name,
                _bounded(identity.get("purl")),
                position,
                context.snapshot_id,
                context.run_id,
                _now_utc(),
            ),
        )
        context.counters["affected_packages"] += 1
        context.package_ecosystems[ecosystem] += 1
        _insert_package_versions(context, package_id, affected_package, relative_path, digest)


def _anchor_references(
    context: AdvisoryContext,
    cve_id: str,
    advisory_id: str,
    source_available_at: str,
    document: dict[str, Any],
) -> None:
    references = document.get("references", [])
    if not isinstance(references, list):
        return
    seen: set[str] = set()
    for reference in references:
        raw_url = reference.get("url") if isinstance(reference, dict) else None
        parsed = _commit_reference(raw_url)
        if parsed is None:
            continue
        url, _ = parsed
        if url in seen:
            continue
        seen.add(url)
        context.advisory_anchors[(cve_id, url)].append(
            (source_available_at, advisory_id)
        )


def _ingest_advisories(context: AdvisoryContext) -> None:
    relationships = _relationship(context.inputs.relationship_paths["github_advisories"])
    processed_records: set[str] = set()
    for cve_id, targets in sorted(relationships.items()):
        if (
            not isinstance(cve_id, str)
            or CVE_PATTERN.fullmatch(cve_id.upper()) is None
            or not isinstance(targets, list)
        ):
            _reject(
                context,
                "advisory_invalid_relationship",
                "processed/relationships/rel-cve-github-advisory.json",
                None,
            )
            continue
        cve_id = cve_id.upper()
        for raw_target in targets:
            context.counters["relationship_records"] += 1
            approved = _advisory_path(context.inputs.root, raw_target)
            if approved is None:
                _reject(
                    context,
                    "advisory_invalid_target_path",
                    "processed/relationships/rel-cve-github-advisory.json",
                    None,
                    cve_id,
                )
                continue
            path, identifier = approved
            relative = path.relative_to(context.inputs.root).as_posix()
            if not path.is_file() or path.stat().st_size > MAX_ADVISORY_BYTES:
                _reject(context, "advisory_missing_or_oversized", relative, None, cve_id)
                continue
            digest = _sha256(path)
            try:
                document = _read_document(path, "GitHub advisory source record")
            except ValueError:
                _reject(context, "advisory_invalid_json", relative, digest, cve_id)
                continue
            if str(document.get("id", "")).upper() != identifier.upper():
                _reject(context, "advisory_identifier_mismatch", relative, digest, cve_id)
                continue
            aliases = document.get("aliases", [])
            valid_aliases = (
                {
                    alias.upper()
                    for alias in aliases
                    if isinstance(alias, str) and CVE_PATTERN.fullmatch(alias.upper())
                }
                if isinstance(aliases, list)
                else set()
            )
            if cve_id in valid_aliases:
                context.counters["verified_alias_links_observed"] += 1
            else:
                context.counters["alias_conflicts_observed"] += 1
            if document.get("withdrawn") is not None:
                context.counters["withdrawn_advisories_observed"] += 1
            if cve_id not in context.canonical_cves:
                _reject(context, "advisory_cve_not_in_vulzoo_snapshot", relative, digest, cve_id)
                continue
            if cve_id not in valid_aliases:
                _reject(context, "advisory_cve_alias_mismatch", relative, digest, cve_id)
                continue
            if document.get("withdrawn") is not None:
                _reject(context, "advisory_withdrawn", relative, digest, cve_id)
                continue
            try:
                published = _timestamp(document.get("published"), "advisory publication time")
                modified = _timestamp(document.get("modified"), "advisory modification time")
            except ValueError:
                _reject(context, "advisory_invalid_timestamp", relative, digest, cve_id)
                continue
            if published > context.inputs.decision_at_utc:
                _reject(context, "advisory_published_after_decision", relative, digest, cve_id)
                continue
            if modified > context.inputs.decision_at_utc:
                _reject(context, "advisory_modified_after_decision", relative, digest, cve_id)
                continue
            source_available = max(published, modified)

            ghsa_id = identifier.upper()
            advisory_id = _stable_id("github-advisory", ghsa_id, context.snapshot_id)
            if ghsa_id not in processed_records:
                specific = document.get("database_specific", {})
                severity = (
                    _bounded(specific.get("severity"), 30)
                    if isinstance(specific, dict)
                    else None
                )
                _insert_counted(
                    context,
                    "github_advisory",
                    """
                    INSERT OR IGNORE INTO github_advisory(
                        github_advisory_id, ghsa_id, published_at_utc,
                        modified_at_utc, source_available_at_utc,
                        withdrawn_at_utc, severity,
                        source_relative_path, record_sha256,
                        source_snapshot_id, ingestion_run_id, created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        advisory_id,
                        ghsa_id,
                        published,
                        modified,
                        source_available,
                        None,
                        severity,
                        relative,
                        digest,
                        context.snapshot_id,
                        context.run_id,
                        _now_utc(),
                    ),
                )
                processed_records.add(ghsa_id)
                context.counters["accepted_advisories"] += 1
                _insert_packages(context, advisory_id, document, relative, digest)

            link_id = _stable_id("github-advisory-cve", advisory_id, cve_id)
            _insert_counted(
                context,
                "github_advisory_cve",
                """
                INSERT OR IGNORE INTO github_advisory_cve(
                    github_advisory_cve_id, github_advisory_id, cve_id,
                    evidence_source, source_snapshot_id, ingestion_run_id, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    link_id,
                    advisory_id,
                    cve_id,
                    "authoritative_alias",
                    context.snapshot_id,
                    context.run_id,
                    _now_utc(),
                ),
            )
            context.counters["accepted_advisory_cve_links"] += 1
            _anchor_references(
                context,
                cve_id,
                advisory_id,
                source_available,
                document,
            )
            if (
                context.progress_every
                and context.counters["relationship_records"] % context.progress_every == 0
            ):
                print(
                    f"Processed {context.counters['relationship_records']:,} GitHub advisories...",
                    file=sys.stderr,
                    flush=True,
                )


def _ingest_patches(context: AdvisoryContext) -> None:
    raw_urls = _relationship(context.inputs.relationship_paths["patch_urls"])
    raw_hashes = _relationship(context.inputs.relationship_paths["patch_hashes"])
    urls_by_hash: dict[tuple[str, str], set[str]] = defaultdict(set)
    for cve_id, values in raw_urls.items():
        if (
            not isinstance(cve_id, str)
            or cve_id.upper() not in context.canonical_cves
            or not isinstance(values, list)
        ):
            continue
        cve_id = cve_id.upper()
        for value in values:
            approved = _commit_reference(value)
            if approved is not None:
                url, commit = approved
                urls_by_hash[(cve_id, commit)].add(url)

    seen: set[tuple[str, str]] = set()
    for cve_id, values in sorted(raw_hashes.items()):
        if (
            not isinstance(cve_id, str)
            or cve_id.upper() not in context.canonical_cves
            or not isinstance(values, list)
        ):
            continue
        cve_id = cve_id.upper()
        for value in values:
            if not isinstance(value, str) or COMMIT_PATTERN.fullmatch(value) is None:
                context.counters["invalid_patch_hashes"] += 1
                continue
            commit = value.lower()
            identity = (cve_id, commit)
            if identity in seen:
                context.counters["duplicate_patch_hashes"] += 1
                continue
            seen.add(identity)
            urls = urls_by_hash.get(identity)
            if not urls:
                context.counters["unmatched_patch_hashes"] += 1
                continue
            anchors = sorted(
                (available, url, advisory)
                for url in urls
                for available, advisory in context.advisory_anchors.get((cve_id, url), [])
            )
            if anchors:
                observed, selected_url, advisory_id = anchors[0]
                timing = "authoritative_advisory_available"
                context.counters["temporally_anchored_patch_commits"] += 1
            else:
                observed = None
                selected_url = sorted(urls)[0]
                advisory_id = None
                timing = "undated_context_only"
                context.counters["undated_context_only_patch_commits"] += 1
            identifier = _stable_id("corroborated-patch", cve_id, commit, context.snapshot_id)
            existing = context.connection.execute(
                """
                SELECT patch_reference_id, evidence_time_status
                FROM patch_reference
                WHERE cve_id = ? AND commit_sha = ? AND source_snapshot_id = ?
                """,
                (cve_id, commit, context.snapshot_id),
            ).fetchone()
            if (
                existing is not None
                and timing == "authoritative_advisory_available"
                and existing[1] == "undated_context_only"
            ):
                context.connection.execute(
                    """
                    UPDATE patch_reference
                    SET reference_url = ?, published_at_utc = ?, ingestion_run_id = ?,
                        evidence_time_status = ?, anchor_github_advisory_id = ?
                    WHERE patch_reference_id = ?
                    """,
                    (
                        selected_url,
                        observed,
                        context.run_id,
                        timing,
                        advisory_id,
                        existing[0],
                    ),
                )
                context.counters["reanchored_patch_commits"] += 1
            elif existing is None:
                _insert_counted(
                    context,
                    "patch_reference",
                    """
                    INSERT INTO patch_reference(
                        patch_reference_id, cve_id, reference_url,
                        published_at_utc, source_name, retrieved_at_utc,
                        created_at_utc, source_snapshot_id, ingestion_run_id,
                        commit_sha, reference_kind, evidence_time_status,
                        anchor_github_advisory_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        identifier,
                        cve_id,
                        selected_url,
                        observed,
                        "vulzoo_corroborated_patch",
                        context.inputs.retrieved_at_utc,
                        _now_utc(),
                        context.snapshot_id,
                        context.run_id,
                        commit,
                        "corroborated_commit",
                        timing,
                        advisory_id,
                    ),
                )
            context.counters["corroborated_patch_commits"] += 1


def _verify_audit(context: AdvisoryContext) -> None:
    report = context.inputs.audit
    expected_canonical = report["database"]["counts"].get("canonical_cves")
    if len(context.canonical_cves) != expected_canonical:
        raise RuntimeError("The canonical VulZoo catalogue changed after the approved audit")
    observed = report["github_advisories"]
    if context.counters["relationship_records"] != observed.get("raw_references"):
        raise RuntimeError("GitHub advisory relationship counts differ from the approved audit")
    if context.counters["verified_alias_links_observed"] != observed.get(
        "cve_alias_verified_links"
    ):
        raise RuntimeError("GitHub advisory CVE alias counts differ from the approved audit")
    if context.counters["alias_conflicts_observed"] != observed.get("cve_alias_mismatch_links"):
        raise RuntimeError("GitHub advisory CVE conflicts differ from the approved audit")
    expected_withdrawn = observed.get("metadata_date_counts", {}).get("withdrawn_advisories", 0)
    if context.counters["withdrawn_advisories_observed"] != expected_withdrawn:
        raise RuntimeError("GitHub advisory withdrawal counts differ from the approved audit")
    expected_patches = report["patch_hashes"].get("corroborated_by_same_cve_commit_url")
    if context.counters["corroborated_patch_commits"] != expected_patches:
        raise RuntimeError("Corroborated patch commits differ from the approved audit")
    if context.connection.execute("PRAGMA foreign_key_check").fetchall():
        raise RuntimeError("Advisory ingestion produced invalid foreign-key relationships")


def ingest_github_advisories(
    config_path: str | Path,
    database_path: str | Path,
    acquisition_manifest_path: str | Path,
    audit_report_path: str | Path,
    decision_at: str,
    *,
    progress_every: int = 0,
) -> dict[str, Any]:
    """Integrate verified GHSA remediation metadata and corroborated undated/dated commits."""
    if isinstance(progress_every, bool) or not isinstance(progress_every, int):
        raise ValueError("progress_every must be an integer")
    if not 0 <= progress_every <= 1_000_000:
        raise ValueError("progress_every must be between 0 and 1,000,000")

    inputs = _validated_inputs(
        config_path,
        database_path,
        acquisition_manifest_path,
        audit_report_path,
        decision_at,
    )

    with closing(sqlite3.connect(inputs.database)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
        connection.execute("PRAGMA cache_size = -65536")
        connection.execute("PRAGMA busy_timeout = 15000")
        canonical = {row[0] for row in connection.execute("SELECT cve_id FROM cve")}
        if len(canonical) != inputs.audit["database"]["counts"].get("canonical_cves"):
            raise RuntimeError("The canonical VulZoo catalogue changed after the approved audit")
        snapshot_id = _insert_snapshot(connection, inputs)
        run_id = f"run:{uuid.uuid4()}"
        started_at = _now_utc()
        configuration = {
            "contract": INGESTION_CONTRACT,
            "decision_at_utc": inputs.decision_at_utc,
            "advisory_alias_policy": "authoritative_cve_alias_and_existing_canonical_cve",
            "withdrawn_policy": "reject_all_withdrawn_advisories",
            "source_version_policy": (
                "published_and_modified_not_after_decision_with_source_availability_max"
            ),
            "patch_policy": "same_cve_exact_40_character_hash_and_direct_commit_url",
            "patch_timing_policy": (
                "exact_same_cve_url_uses_source_available_at_otherwise_undated"
            ),
            "patch_payloads_read": False,
            "exploit_payloads_read": False,
            "historical_ground_truth_claimed": False,
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
                json.dumps(configuration, sort_keys=True, separators=(",", ":")),
                started_at,
            ),
        )
        connection.commit()
        context = AdvisoryContext(
            connection=connection,
            inputs=inputs,
            snapshot_id=snapshot_id,
            run_id=run_id,
            canonical_cves=canonical,
            rejections=DatabaseRejections(connection, run_id),
            progress_every=progress_every,
        )

        try:
            connection.execute("BEGIN IMMEDIATE")
            _ingest_advisories(context)
            _ingest_patches(context)
            _verify_audit(context)
            accepted = (
                context.counters["accepted_advisory_cve_links"]
                + context.counters["corroborated_patch_commits"]
            )
            rejected = sum(context.rejections.reasons.values())
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
        "decision_at_utc": inputs.decision_at_utc,
        "retrieved_at_utc": inputs.retrieved_at_utc,
        "vulzoo_commit": inputs.upstream_commit,
        "github_advisory_git_tree": inputs.git_tree,
        "advisories": {
            "relationship_records": context.counters["relationship_records"],
            "accepted_advisories": context.counters["accepted_advisories"],
            "accepted_cve_links": context.counters["accepted_advisory_cve_links"],
            "verified_alias_links_observed": context.counters["verified_alias_links_observed"],
            "alias_conflicts_observed": context.counters["alias_conflicts_observed"],
            "withdrawn_observed": context.counters["withdrawn_advisories_observed"],
            "affected_packages": context.counters["affected_packages"],
            "affected_versions": context.counters["affected_versions"],
            "version_events": context.counters["version_events"],
            "fixed_version_events": context.counters["fixed_version_events"],
            "package_ecosystems": dict(sorted(context.package_ecosystems.items())),
        },
        "patches": {
            "corroborated_commit_references": context.counters["corroborated_patch_commits"],
            "temporally_anchored": context.counters["temporally_anchored_patch_commits"],
            "reanchored_from_context_only": context.counters["reanchored_patch_commits"],
            "undated_context_only": context.counters["undated_context_only_patch_commits"],
            "unmatched_hashes_excluded": context.counters["unmatched_patch_hashes"],
            "duplicate_hashes_excluded": context.counters["duplicate_patch_hashes"],
            "invalid_hashes_excluded": context.counters["invalid_patch_hashes"],
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
            "canonical_cves_created": False,
            "raw_advisory_bodies_persisted": False,
            "patch_payloads_read": False,
            "exploit_payloads_read": False,
            "exploit_references_ingested": False,
            "historical_ground_truth_claimed": False,
        },
        "research_status": "source_effective_single_snapshot_remediation_reconstruction",
    }
