from __future__ import annotations

import re
import sqlite3
from contextlib import closing
from pathlib import Path

from thesis_pipeline.run import project_root

MIGRATION_NAME = re.compile(r"^(?P<version>[0-9]{3})_[a-z0-9_]+[.]sql$")


def _migration_paths(schema_directory: Path) -> list[tuple[int, Path]]:
    migrations: list[tuple[int, Path]] = []

    for path in sorted(schema_directory.glob("*.sql")):
        match = MIGRATION_NAME.fullmatch(path.name)

        if match is None:
            raise RuntimeError(f"Invalid migration filename: {path.name}")

        migrations.append((int(match.group("version")), path))

    versions = [version for version, _ in migrations]

    if not migrations:
        raise RuntimeError(f"No schema migrations found in {schema_directory}")

    if versions != list(range(1, len(versions) + 1)):
        raise RuntimeError(f"Schema migration versions must be contiguous from 1; got {versions}")

    return migrations


def _applied_versions(connection: sqlite3.Connection) -> set[int]:
    table_exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'"
    ).fetchone()

    if table_exists is None:
        return set()

    return {
        int(row[0])
        for row in connection.execute("SELECT version FROM schema_version ORDER BY version")
    }


def _apply_migrations(connection: sqlite3.Connection, schema_directory: Path) -> None:
    migrations = _migration_paths(schema_directory)
    available = {version for version, _ in migrations}
    applied = _applied_versions(connection)

    if applied:
        expected_applied = set(range(1, max(applied) + 1))

        if applied != expected_applied:
            raise RuntimeError(f"Applied schema versions are not contiguous: {sorted(applied)}")

        unavailable = applied - available

        if unavailable:
            raise RuntimeError(
                f"Applied schema versions have no migration files: {sorted(unavailable)}"
            )

    for version, path in migrations:
        if version in applied:
            continue

        connection.executescript(path.read_text(encoding="utf-8-sig"))

        if version not in _applied_versions(connection):
            raise RuntimeError(
                f"Migration {path.name} did not register schema version {version}"
            )

        applied.add(version)


def initialise_database(database_path: str | Path) -> Path:
    """Apply the versioned SQLite schema outside the Git repository."""
    path = Path(database_path).expanduser().resolve()
    root = project_root().resolve()
    if path == root or root in path.parents:
        raise ValueError("SQLite databases must be created outside the Git repository")
    if path.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
        raise ValueError("Database path must end with .db, .sqlite, or .sqlite3")
    path.parent.mkdir(parents=True, exist_ok=True)
    schema_directory = root / "schemas"

    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _apply_migrations(connection, schema_directory)

        foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()

        if foreign_key_errors:
            raise RuntimeError(f"Schema foreign-key check failed: {foreign_key_errors}")

        connection.commit()

    return path
