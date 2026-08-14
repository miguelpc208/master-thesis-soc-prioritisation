from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from thesis_pipeline.run import project_root


def initialise_database(database_path: str | Path) -> Path:
    """Apply the versioned SQLite schema outside the Git repository."""
    path = Path(database_path).expanduser().resolve()
    root = project_root().resolve()
    if path == root or root in path.parents:
        raise ValueError("SQLite databases must be created outside the Git repository")
    if path.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
        raise ValueError("Database path must end with .db, .sqlite, or .sqlite3")
    path.parent.mkdir(parents=True, exist_ok=True)
    schema_path = root / "schemas/001_initial.sql"
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript(schema_path.read_text(encoding="utf-8"))
        connection.commit()
    return path
