from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


def inventory_vulzoo(config_path: str | Path) -> dict[str, Any]:
    """Inventory an existing local clone without downloading or reading full files."""
    data_root = os.environ.get("THESIS_DATA_ROOT")
    if not data_root:
        raise RuntimeError("THESIS_DATA_ROOT is not set; approve a non-OneDrive path first")
    document = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
    relative = document["sources"]["vulzoo"]["local_relative_path"]
    root = Path(data_root).expanduser().resolve() / relative
    if not root.is_dir():
        raise RuntimeError(f"Approved VulZoo directory does not exist: {root}")
    files = [path for path in root.rglob("*") if path.is_file() and ".git" not in path.parts]
    extensions: dict[str, int] = {}
    total_bytes = 0
    for path in files:
        extension = path.suffix.lower() or "<none>"
        extensions[extension] = extensions.get(extension, 0) + 1
        total_bytes += path.stat().st_size
    return {
        "root": str(root),
        "file_count": len(files),
        "total_bytes": total_bytes,
        "extensions": dict(sorted(extensions.items())),
        "note": (
            "Metadata inventory only; schemas, encodings, and join keys still require profiling."
        ),
    }
