from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


def load_vulzoo_source_config(config_path: str | Path) -> dict[str, Any]:
    document = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))

    try:
        source = document["sources"]["vulzoo"]
    except (KeyError, TypeError) as exc:
        raise ValueError("VulZoo source configuration is missing or invalid") from exc

    if not isinstance(source, dict):
        raise ValueError("VulZoo source configuration must be a mapping")

    if not source.get("enabled"):
        raise RuntimeError("VulZoo is not enabled in the data-source configuration")

    return source


def resolve_vulzoo_root(source: dict[str, Any]) -> Path:
    data_root = os.environ.get("THESIS_DATA_ROOT")

    if not data_root:
        raise RuntimeError("THESIS_DATA_ROOT is not set; approve a non-OneDrive path first")

    root_path = Path(data_root).expanduser().resolve()

    if any("onedrive" in part.casefold() for part in root_path.parts):
        raise RuntimeError("THESIS_DATA_ROOT must remain outside OneDrive")

    relative_path = source.get("local_relative_path")

    if not isinstance(relative_path, str) or not relative_path.strip():
        raise ValueError("VulZoo local_relative_path is missing or invalid")

    root = (root_path / relative_path).resolve()

    if root == root_path or not root.is_relative_to(root_path):
        raise ValueError("VulZoo local_relative_path must remain beneath THESIS_DATA_ROOT")

    if not root.is_dir():
        raise RuntimeError(f"Approved VulZoo directory does not exist: {root}")

    return root
