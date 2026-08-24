import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from thesis_pipeline.storage import initialise_database

SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "schemas"


class SchemaTests(unittest.TestCase):
    def test_versioned_schema_initialises_outside_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = initialise_database(Path(directory) / "thesis.sqlite")
            self.assertEqual(path, initialise_database(path))

            with closing(sqlite3.connect(path)) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                versions = [
                    row[0]
                    for row in connection.execute(
                        "SELECT version FROM schema_version ORDER BY version"
                    )
                ]
                cve_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(cve)")
                }
                cvss_columns = {
                    row[1]
                    for row in connection.execute("PRAGMA table_info(cvss_observation)")
                }
                kev_columns = {
                    row[1]
                    for row in connection.execute("PRAGMA table_info(kev_observation)")
                }

            self.assertIn("priority_decision", tables)
            self.assertIn("dynamic_exploit_evidence", tables)
            self.assertIn("source_snapshot", tables)
            self.assertIn("ingestion_run", tables)
            self.assertIn("ingestion_rejection", tables)
            self.assertIn("cve_cwe", tables)
            self.assertIn("cve_cpe", tables)
            self.assertIn("diversevul_commit", tables)
            self.assertIn("diversevul_function", tables)
            self.assertIn("diversevul_function_cve", tables)
            self.assertEqual(versions, [1, 2, 3, 4])
            self.assertTrue(
                {"vulnerability_status", "source_snapshot_id", "ingestion_run_id"}
                <= cve_columns
            )
            self.assertTrue(
                {
                    "base_severity",
                    "exploitability_score",
                    "impact_score",
                    "metric_source",
                    "metric_type",
                    "source_snapshot_id",
                    "ingestion_run_id",
                }
                <= cvss_columns
            )
            self.assertTrue(
                {
                    "vendor_project",
                    "product",
                    "vulnerability_name",
                    "short_description",
                    "required_action",
                    "notes",
                    "source_snapshot_id",
                    "ingestion_run_id",
                }
                <= kev_columns
            )

    def test_vulnerability_ingestion_constraints_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = initialise_database(Path(directory) / "thesis.sqlite")

            with closing(sqlite3.connect(path)) as connection:
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute(
                    """
                    INSERT INTO source_snapshot(
                        source_snapshot_id,
                        source_name,
                        source_version,
                        snapshot_date,
                        retrieved_at_utc,
                        checksum,
                        upstream_url,
                        local_relative_path,
                        metadata_json,
                        created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "snapshot:test",
                        "vulzoo",
                        "test-version",
                        "2025-03-19",
                        "2026-08-14T00:00:00Z",
                        "git:test",
                        "https://example.invalid/VulZoo",
                        "VulZoo",
                        "{}",
                        "2026-08-14T00:00:00Z",
                    ),
                )

                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        """
                        INSERT INTO source_snapshot(
                            source_snapshot_id,
                            source_name,
                            retrieved_at_utc,
                            checksum,
                            metadata_json,
                            created_at_utc
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "snapshot:duplicate",
                            "vulzoo",
                            "2026-08-14T00:00:00Z",
                            "git:test",
                            "{}",
                            "2026-08-14T00:00:00Z",
                        ),
                    )

                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        """
                        INSERT INTO ingestion_run(
                            ingestion_run_id,
                            source_snapshot_id,
                            started_at_utc,
                            status,
                            input_fingerprint_sha256,
                            configuration_json,
                            created_at_utc
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "run:test",
                            "snapshot:test",
                            "2026-08-14T00:00:00Z",
                            "invalid",
                            "a" * 64,
                            "{}",
                            "2026-08-14T00:00:00Z",
                        ),
                    )

                rejection_columns = {
                    row[1]
                    for row in connection.execute("PRAGMA table_info(ingestion_rejection)")
                }

            self.assertNotIn("payload_json", rejection_columns)
            self.assertNotIn("raw_record", rejection_columns)

    def test_existing_version_one_database_upgrades_to_latest_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "thesis.sqlite"

            with closing(sqlite3.connect(path)) as connection:
                connection.executescript(
                    (SCHEMA_ROOT / "001_initial.sql").read_text(encoding="utf-8-sig")
                )

            initialise_database(path)

            with closing(sqlite3.connect(path)) as connection:
                versions = [
                    row[0]
                    for row in connection.execute(
                        "SELECT version FROM schema_version ORDER BY version"
                    )
                ]

            self.assertEqual(versions, [1, 2, 3, 4])

    def test_version_two_upgrade_preserves_existing_cpe_relationships(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "thesis.sqlite"
            timestamp = "2026-08-14T00:00:00Z"

            with closing(sqlite3.connect(path)) as connection:
                connection.execute("PRAGMA foreign_keys = ON")
                for name in ("001_initial.sql", "002_vulnerability_ingestion.sql"):
                    connection.executescript(
                        (SCHEMA_ROOT / name).read_text(encoding="utf-8-sig")
                    )
                connection.execute(
                    """
                    INSERT INTO source_snapshot(
                        source_snapshot_id, source_name, retrieved_at_utc,
                        checksum, metadata_json, created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    ("snapshot:test", "vulzoo", timestamp, "git:test", "{}", timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO ingestion_run(
                        ingestion_run_id, source_snapshot_id, started_at_utc,
                        status, input_fingerprint_sha256, configuration_json,
                        created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "run:test",
                        "snapshot:test",
                        timestamp,
                        "succeeded",
                        "a" * 64,
                        "{}",
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO cve(cve_id, source_name, retrieved_at_utc, created_at_utc)
                    VALUES (?, ?, ?, ?)
                    """,
                    ("CVE-2024-0001", "nvd", timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO cpe(cpe_id, cpe_uri, source_name, retrieved_at_utc, created_at_utc)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    ("cpe:test", "cpe:2.3:a:example:product", "nvd", timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO cve_cpe(
                        cve_cpe_id, cve_id, cpe_id, vulnerable, criteria_id,
                        version_end_excluding, observed_at_utc, source_name,
                        retrieved_at_utc, source_snapshot_id, ingestion_run_id,
                        created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "mapping:first",
                        "CVE-2024-0001",
                        "cpe:test",
                        1,
                        "criteria:first",
                        "2.0",
                        timestamp,
                        "nvd",
                        timestamp,
                        "snapshot:test",
                        "run:test",
                        timestamp,
                    ),
                )
                connection.commit()

            initialise_database(path)

            with closing(sqlite3.connect(path)) as connection:
                connection.execute("PRAGMA foreign_keys = ON")
                self.assertEqual(
                    connection.execute(
                        "SELECT version_end_excluding FROM cve_cpe"
                    ).fetchall(),
                    [("2.0",)],
                )
                connection.execute(
                    """
                    INSERT INTO cve_cpe(
                        cve_cpe_id, cve_id, cpe_id, vulnerable, criteria_id,
                        version_end_excluding, observed_at_utc, source_name,
                        retrieved_at_utc, source_snapshot_id, ingestion_run_id,
                        created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "mapping:second",
                        "CVE-2024-0001",
                        "cpe:test",
                        1,
                        "criteria:second",
                        "3.0",
                        timestamp,
                        "nvd",
                        timestamp,
                        "snapshot:test",
                        "run:test",
                        timestamp,
                    ),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT version_end_excluding FROM cve_cpe "
                        "ORDER BY version_end_excluding"
                    ).fetchall(),
                    [("2.0",), ("3.0",)],
                )


if __name__ == "__main__":
    unittest.main()
