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
                cve_columns = {row[1] for row in connection.execute("PRAGMA table_info(cve)")}
                cvss_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(cvss_observation)")
                }
                kev_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(kev_observation)")
                }
                epss_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(epss_observation)")
                }
                advisory_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(github_advisory)")
                }

            self.assertIn("priority_decision", tables)
            self.assertIn("dynamic_exploit_evidence", tables)
            self.assertIn("source_snapshot", tables)
            self.assertIn("ingestion_run", tables)
            self.assertIn("ingestion_rejection", tables)
            self.assertIn("cve_cwe", tables)
            self.assertIn("cve_cpe", tables)
            self.assertIn("cve_configuration_node", tables)
            self.assertIn("cve_configuration_match", tables)
            self.assertIn("diversevul_commit", tables)
            self.assertIn("diversevul_function", tables)
            self.assertIn("diversevul_function_cve", tables)
            self.assertIn("evidence_time_policy", tables)
            self.assertIn("github_advisory", tables)
            self.assertIn("github_advisory_cve", tables)
            self.assertIn("github_advisory_package", tables)
            self.assertIn("github_advisory_affected_version", tables)
            self.assertIn("github_advisory_version_event", tables)
            self.assertIn("epss_panel_ingestion", tables)
            self.assertIn("epss_panel_ingestion_day", tables)
            self.assertEqual(versions, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
            self.assertTrue(
                {"vulnerability_status", "source_snapshot_id", "ingestion_run_id"} <= cve_columns
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
            self.assertTrue({"source_snapshot_id", "ingestion_run_id"} <= epss_columns)
            self.assertIn("source_available_at_utc", advisory_columns)

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
                    row[1] for row in connection.execute("PRAGMA table_info(ingestion_rejection)")
                }

            self.assertNotIn("payload_json", rejection_columns)
            self.assertNotIn("raw_record", rejection_columns)

    def test_configuration_tree_rejects_cross_snapshot_relationships(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = initialise_database(Path(directory) / "thesis.sqlite")
            timestamp = "2026-08-24T00:00:00Z"

            with closing(sqlite3.connect(path)) as connection:
                connection.execute("PRAGMA foreign_keys = ON")
                for suffix in ("one", "two"):
                    connection.execute(
                        """
                        INSERT INTO source_snapshot(
                            source_snapshot_id, source_name, retrieved_at_utc,
                            checksum, metadata_json, created_at_utc
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            f"snapshot:{suffix}",
                            "vulzoo",
                            timestamp,
                            f"git:{suffix}",
                            "{}",
                            timestamp,
                        ),
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
                            f"run:{suffix}",
                            f"snapshot:{suffix}",
                            timestamp,
                            "succeeded",
                            suffix[0] * 64,
                            "{}",
                            timestamp,
                        ),
                    )

                connection.execute(
                    """
                    INSERT INTO cve(
                        cve_id, source_name, retrieved_at_utc, created_at_utc,
                        source_snapshot_id, ingestion_run_id
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "CVE-2024-0001",
                        "nvd",
                        timestamp,
                        timestamp,
                        "snapshot:one",
                        "run:one",
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO cpe(
                        cpe_id, cpe_uri, source_name, retrieved_at_utc,
                        created_at_utc, source_snapshot_id, ingestion_run_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "cpe:one",
                        "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
                        "nvd",
                        timestamp,
                        timestamp,
                        "snapshot:one",
                        "run:one",
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO cve_cpe(
                        cve_cpe_id, cve_id, cpe_id, vulnerable,
                        observed_at_utc, source_name, retrieved_at_utc,
                        source_snapshot_id, ingestion_run_id, created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "mapping:one",
                        "CVE-2024-0001",
                        "cpe:one",
                        1,
                        timestamp,
                        "nvd",
                        timestamp,
                        "snapshot:one",
                        "run:one",
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO cve_configuration_node(
                        cve_configuration_node_id, cve_id, node_kind,
                        source_path, depth, sibling_position, logical_operator,
                        negate, observed_at_utc, source_name, retrieved_at_utc,
                        source_snapshot_id, ingestion_run_id, created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "node:one",
                        "CVE-2024-0001",
                        "configuration",
                        "configurations[0]",
                        0,
                        0,
                        "OR",
                        0,
                        timestamp,
                        "nvd",
                        timestamp,
                        "snapshot:one",
                        "run:one",
                        timestamp,
                    ),
                )

                with self.assertRaisesRegex(
                    sqlite3.IntegrityError,
                    "configuration match node does not match CVE snapshot",
                ):
                    connection.execute(
                        """
                        INSERT INTO cve_configuration_match(
                            cve_configuration_match_id, cve_id,
                            cve_configuration_node_id, cve_cpe_id, source_path,
                            match_position, source_snapshot_id, ingestion_run_id,
                            created_at_utc
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "match:invalid",
                            "CVE-2024-0001",
                            "node:one",
                            "mapping:one",
                            "configurations[0].cpeMatch[0]",
                            0,
                            "snapshot:two",
                            "run:two",
                            timestamp,
                        ),
                    )

    def test_epss_observation_constraints_require_bounded_daily_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = initialise_database(Path(directory) / "thesis.sqlite")
            retrieved = "2026-08-24T12:00:00Z"

            with closing(sqlite3.connect(path)) as connection:
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute(
                    "INSERT INTO cve(cve_id, source_name, retrieved_at_utc, created_at_utc) "
                    "VALUES (?, ?, ?, ?)",
                    ("CVE-2024-0001", "nvd", retrieved, retrieved),
                )
                connection.execute(
                    """
                    INSERT INTO source_snapshot(
                        source_snapshot_id, source_name, source_version, snapshot_date,
                        retrieved_at_utc, checksum, metadata_json, created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "snapshot:epss",
                        "first_epss",
                        "v2025.03.14",
                        "2025-12-31",
                        retrieved,
                        "sha256:test",
                        "{}",
                        retrieved,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO ingestion_run(
                        ingestion_run_id, source_snapshot_id, started_at_utc, status,
                        input_fingerprint_sha256, configuration_json, created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "run:epss",
                        "snapshot:epss",
                        retrieved,
                        "running",
                        "a" * 64,
                        "{}",
                        retrieved,
                    ),
                )

                def insert(identifier: str, score: float, score_date: str) -> None:
                    connection.execute(
                        """
                        INSERT INTO epss_observation(
                            epss_observation_id, cve_id, score, percentile,
                            score_date, model_version, source_name, retrieved_at_utc,
                            created_at_utc, source_snapshot_id, ingestion_run_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            identifier,
                            "CVE-2024-0001",
                            score,
                            0.9,
                            score_date,
                            "v2025.03.14",
                            "first_epss",
                            retrieved,
                            retrieved,
                            "snapshot:epss",
                            "run:epss",
                        ),
                    )

                with self.assertRaisesRegex(sqlite3.IntegrityError, "probability"):
                    insert("epss:invalid-score", 1.5, "2025-12-31")

                with self.assertRaisesRegex(sqlite3.IntegrityError, "snapshot"):
                    insert("epss:invalid-date", 0.5, "2026-01-01")

                insert("epss:valid", 0.5, "2025-12-31")
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM epss_observation").fetchone(),
                    (1,),
                )

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

            self.assertEqual(versions, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])

    def test_version_eight_upgrade_preserves_advisory_and_patch_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "thesis.sqlite"
            timestamp = "2026-08-25T00:00:00Z"

            with closing(sqlite3.connect(path)) as connection:
                connection.execute("PRAGMA foreign_keys = ON")
                for migration in sorted(SCHEMA_ROOT.glob("*.sql")):
                    if int(migration.name[:3]) > 8:
                        break
                    connection.executescript(migration.read_text(encoding="utf-8-sig"))
                connection.execute(
                    "INSERT INTO source_snapshot(source_snapshot_id, source_name, "
                    "retrieved_at_utc, checksum, metadata_json, created_at_utc) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "snapshot:ghsa",
                        "vulzoo_github_advisory",
                        timestamp,
                        "git:test",
                        "{}",
                        timestamp,
                    ),
                )
                connection.execute(
                    "INSERT INTO ingestion_run(ingestion_run_id, source_snapshot_id, "
                    "started_at_utc, status, input_fingerprint_sha256, configuration_json, "
                    "created_at_utc) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        "run:ghsa",
                        "snapshot:ghsa",
                        timestamp,
                        "succeeded",
                        "a" * 64,
                        "{}",
                        timestamp,
                    ),
                )
                connection.execute(
                    "INSERT INTO cve(cve_id, source_name, retrieved_at_utc, created_at_utc) "
                    "VALUES (?, ?, ?, ?)",
                    ("CVE-2024-0001", "nvd", timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO github_advisory(
                        github_advisory_id, ghsa_id, published_at_utc,
                        modified_at_utc, severity, source_relative_path,
                        record_sha256, source_snapshot_id, ingestion_run_id,
                        created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "ghsa:test",
                        "GHSA-AAAA-BBBB-CCCC",
                        "2025-01-01T00:00:00Z",
                        "2025-02-01T00:00:00Z",
                        "HIGH",
                        "processed/github-advisory-database/test.json",
                        "b" * 64,
                        "snapshot:ghsa",
                        "run:ghsa",
                        timestamp,
                    ),
                )
                connection.execute(
                    "INSERT INTO github_advisory_cve(github_advisory_cve_id, "
                    "github_advisory_id, cve_id, evidence_source, source_snapshot_id, "
                    "ingestion_run_id, created_at_utc) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        "ghsa-cve:test",
                        "ghsa:test",
                        "CVE-2024-0001",
                        "authoritative_alias",
                        "snapshot:ghsa",
                        "run:ghsa",
                        timestamp,
                    ),
                )
                connection.execute(
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
                        "patch:test",
                        "CVE-2024-0001",
                        "https://github.com/acme/repo/commit/" + ("c" * 40),
                        "2025-02-01T00:00:00Z",
                        "vulzoo_corroborated_patch",
                        timestamp,
                        timestamp,
                        "snapshot:ghsa",
                        "run:ghsa",
                        "c" * 40,
                        "corroborated_commit",
                        "authoritative_advisory_modified",
                        "ghsa:test",
                    ),
                )
                connection.commit()

            initialise_database(path)

            with closing(sqlite3.connect(path)) as connection:
                advisory = connection.execute(
                    "SELECT published_at_utc, modified_at_utc, source_available_at_utc "
                    "FROM github_advisory"
                ).fetchone()
                patch_status = connection.execute(
                    "SELECT evidence_time_status FROM patch_reference"
                ).fetchone()[0]
                foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()

            self.assertEqual(
                advisory,
                (
                    "2025-01-01T00:00:00Z",
                    "2025-02-01T00:00:00Z",
                    "2025-02-01T00:00:00Z",
                ),
            )
            self.assertEqual(patch_status, "authoritative_advisory_available")
            self.assertEqual(foreign_keys, [])

    def test_version_two_upgrade_preserves_existing_cpe_relationships(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "thesis.sqlite"
            timestamp = "2026-08-14T00:00:00Z"

            with closing(sqlite3.connect(path)) as connection:
                connection.execute("PRAGMA foreign_keys = ON")
                for name in ("001_initial.sql", "002_vulnerability_ingestion.sql"):
                    connection.executescript((SCHEMA_ROOT / name).read_text(encoding="utf-8-sig"))
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
                    connection.execute("SELECT version_end_excluding FROM cve_cpe").fetchall(),
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
                        "SELECT version_end_excluding FROM cve_cpe ORDER BY version_end_excluding"
                    ).fetchall(),
                    [("2.0",), ("3.0",)],
                )


if __name__ == "__main__":
    unittest.main()
