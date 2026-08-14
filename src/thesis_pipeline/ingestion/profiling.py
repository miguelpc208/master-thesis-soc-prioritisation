from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

EXCLUDED_COLLECTIONS = {"exploit-db-database"}
MAX_REPORTED_KEYS = 30
MAX_SAMPLE_LIMIT = 100
MAX_JSON_PROFILE_BYTES = 100 * 1024 * 1024


def _load_source_config(config_path: str | Path) -> dict[str, Any]:
    document = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))

    try:
        source = document["sources"]["vulzoo"]
    except (KeyError, TypeError) as exc:
        raise ValueError("VulZoo source configuration is missing or invalid") from exc

    if not source.get("enabled"):
        raise RuntimeError("VulZoo is not enabled in the data-source configuration")

    return source


def _resolve_root(source: dict[str, Any]) -> Path:
    data_root = os.environ.get("THESIS_DATA_ROOT")

    if not data_root:
        raise RuntimeError(
            "THESIS_DATA_ROOT is not set; approve a non-OneDrive path first"
        )

    root_path = Path(data_root).expanduser().resolve()

    if any("onedrive" in part.casefold() for part in root_path.parts):
        raise RuntimeError("THESIS_DATA_ROOT must remain outside OneDrive")

    root = root_path / source["local_relative_path"]

    if not root.is_dir():
        raise RuntimeError(f"Approved VulZoo directory does not exist: {root}")

    return root


def _detect_format(path: Path) -> str:
    if path.suffix.casefold() == ".json":
        return "json"

    if path.suffix:
        return path.suffix.casefold().lstrip(".")

    prefix = path.read_bytes()[:2048]
    text = prefix.decode("utf-8", errors="replace")
    stripped = text.lstrip("\ufeff\r\n")

    if stripped.startswith("diff --git "):
        return "git_diff"

    required_headers = ("Date:", "From:", "Subject:")

    if all(header in text for header in required_headers):
        return "rfc822_like"

    return "extensionless"


def _profile_sample(path: Path, root: Path, max_json_bytes: int) -> dict[str, Any]:
    size = path.stat().st_size
    detected_format = _detect_format(path)

    result: dict[str, Any] = {
        "relative_path": path.relative_to(root).as_posix(),
        "bytes": size,
        "format": detected_format,
    }

    if detected_format != "json":
        result["status"] = "classified_without_content"
        return result

    if size > max_json_bytes:
        result["status"] = "skipped_size_limit"
        return result

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, OSError) as exc:
        result["status"] = "parse_error"
        result["error_type"] = type(exc).__name__
        return result

    result["status"] = "parsed"
    result["top_level_type"] = type(document).__name__

    if isinstance(document, dict):
        result["top_level_keys"] = sorted(document)[:MAX_REPORTED_KEYS]
    elif isinstance(document, list):
        result["list_length"] = len(document)

        if document and isinstance(document[0], dict):
            result["first_item_keys"] = sorted(document[0])[:MAX_REPORTED_KEYS]
        elif document:
            result["first_item_type"] = type(document[0]).__name__

    return result


def _relationship_contracts(
    relationships_root: Path,
    max_json_bytes: int,
) -> list[dict[str, Any]]:
    contracts: list[dict[str, Any]] = []

    if not relationships_root.is_dir():
        return contracts

    for path in sorted(relationships_root.glob("*.json")):
        size = path.stat().st_size
        contract: dict[str, Any] = {
            "file": path.name,
            "bytes": size,
        }

        if size > max_json_bytes:
            contract["status"] = "skipped_size_limit"
            contracts.append(contract)
            continue

        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, OSError) as exc:
            contract["status"] = "parse_error"
            contract["error_type"] = type(exc).__name__
            contracts.append(contract)
            continue

        contract["status"] = "parsed"
        contract["top_level_type"] = type(document).__name__

        if isinstance(document, dict):
            contract["record_count"] = len(document)
            contract["approximate_link_count"] = sum(
                len(value) if isinstance(value, (dict, list)) else 1
                for value in document.values()
            )

            if document:
                sample_key = next(iter(document))
                contract["sample_key"] = sample_key
                contract["sample_value_type"] = type(document[sample_key]).__name__

        elif isinstance(document, list):
            contract["record_count"] = len(document)
            contract["approximate_link_count"] = len(document)

            if document:
                contract["sample_value_type"] = type(document[0]).__name__

        contracts.append(contract)

    return contracts


def _known_metadata(processed_root: Path, max_json_bytes: int) -> dict[str, Any]:
    metadata: dict[str, Any] = {}

    known_paths = {
        "cisa_kev": processed_root / "cisa-kev-database" / "kev.json",
        "cwe": processed_root / "cwe-database" / "cwec.json",
        "capec": processed_root / "capec-database" / "capec.json",
    }

    documents: dict[str, Any] = {}

    for name, path in known_paths.items():
        if not path.is_file():
            metadata[name] = {"status": "missing"}
            continue

        if path.stat().st_size > max_json_bytes:
            metadata[name] = {
                "status": "skipped_size_limit",
                "bytes": path.stat().st_size,
            }
            continue

        try:
            documents[name] = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, OSError) as exc:
            metadata[name] = {
                "status": "parse_error",
                "error_type": type(exc).__name__,
            }

    if "cisa_kev" in documents:
        document = documents["cisa_kev"]
        metadata["cisa_kev"] = {
            "status": "parsed",
            "catalog_version": document.get("catalogVersion"),
            "date_released": document.get("dateReleased"),
            "declared_count": document.get("count"),
            "actual_count": len(document.get("vulnerabilities", [])),
        }

    if "cwe" in documents:
        catalog = documents["cwe"].get("Weakness_Catalog", {})
        metadata["cwe"] = {
            "status": "parsed",
            "name": catalog.get("@Name"),
            "version": catalog.get("@Version"),
            "date": catalog.get("@Date"),
        }

    if "capec" in documents:
        catalog = documents["capec"].get("Attack_Pattern_Catalog", {})
        metadata["capec"] = {
            "status": "parsed",
            "name": catalog.get("@Name"),
            "version": catalog.get("@Version"),
            "date": catalog.get("@Date"),
        }

    return metadata


def profile_vulzoo(
    config_path: str | Path,
    *,
    sample_limit: int = 2,
    max_json_bytes: int = 50 * 1024 * 1024,
) -> dict[str, Any]:
    if not 1 <= sample_limit <= MAX_SAMPLE_LIMIT:
        raise ValueError(f"sample_limit must be between 1 and {MAX_SAMPLE_LIMIT}")

    if not 1 <= max_json_bytes <= MAX_JSON_PROFILE_BYTES:
        raise ValueError(
            "max_json_bytes must be between 1 and "
            f"{MAX_JSON_PROFILE_BYTES}"
        )

    source = _load_source_config(config_path)
    root = _resolve_root(source)
    processed_root = root / "processed"

    if not processed_root.is_dir():
        raise RuntimeError(f"Processed VulZoo directory does not exist: {processed_root}")

    collection_profiles: list[dict[str, Any]] = []
    total_files = 0
    total_bytes = 0

    collections = sorted(
        path
        for path in processed_root.iterdir()
        if path.is_dir() and path.name not in EXCLUDED_COLLECTIONS
    )

    for collection in collections:
        extension_counts: Counter[str] = Counter()
        collection_files = 0
        collection_bytes = 0
        sample_candidates: list[tuple[str, Path]] = []

        for path in collection.rglob("*"):
            if not path.is_file():
                continue

            size = path.stat().st_size
            relative = path.relative_to(root).as_posix()
            extension = path.suffix.casefold() or "<none>"

            collection_files += 1
            collection_bytes += size
            extension_counts[extension] += 1

            sample_candidates.append((relative, path))
            sample_candidates.sort(key=lambda item: item[0])

            if len(sample_candidates) > sample_limit:
                sample_candidates.pop()

        total_files += collection_files
        total_bytes += collection_bytes

        collection_profiles.append(
            {
                "name": collection.name,
                "file_count": collection_files,
                "total_bytes": collection_bytes,
                "extensions": dict(sorted(extension_counts.items())),
                "samples": [
                    _profile_sample(path, root, max_json_bytes)
                    for _, path in sample_candidates
                ],
            }
        )

    return {
        "source": {
            "url": source.get("url"),
            "retrieval_date": source.get("retrieval_date"),
            "readme_snapshot_date": source.get("snapshot_date"),
            "checksum": source.get("checksum"),
            "local_relative_path": source.get("local_relative_path"),
        },
        "scope": {
            "included": "processed approved collections",
            "excluded_collections": sorted(EXCLUDED_COLLECTIONS),
            "raw_content_included": False,
            "files_executed": False,
        },
        "policy": {
            "sample_limit_per_collection": sample_limit,
            "max_json_bytes": max_json_bytes,
            "deterministic": True,
        },
        "root": str(root),
        "totals": {
            "collection_count": len(collection_profiles),
            "file_count": total_files,
            "total_bytes": total_bytes,
        },
        "collections": collection_profiles,
        "known_metadata": _known_metadata(processed_root, max_json_bytes),
        "relationship_contracts": _relationship_contracts(
            processed_root / "relationships",
            max_json_bytes,
        ),
    }
