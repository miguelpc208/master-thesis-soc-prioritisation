import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime
from pathlib import Path

from thesis_pipeline.quality.evidence_as_of import audit_technical_evidence_as_of
from thesis_pipeline.storage import initialise_database


class TemporalEvidenceTests(unittest.TestCase):
    def _database(self, directory: str) -> Path:
        path = initialise_database(Path(directory) / "technical.sqlite")
        vulzoo_retrieved = "2026-08-14T23:59:59Z"
        diversevul_retrieved = "2026-08-23T12:30:00Z"
        epss_retrieved = "2026-08-24T12:00:00Z"

        with closing(sqlite3.connect(path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            for snapshot_id, source_name, retrieved_at, checksum in (
                ("snapshot:vulzoo", "vulzoo", vulzoo_retrieved, "git:test"),
                ("snapshot:diversevul", "diversevul", diversevul_retrieved, "sha256:data"),
                ("snapshot:epss", "first_epss", epss_retrieved, "sha256:epss"),
            ):
                connection.execute(
                    """
                    INSERT INTO source_snapshot(
                        source_snapshot_id, source_name, source_version,
                        snapshot_date, retrieved_at_utc, checksum,
                        metadata_json, created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot_id,
                        source_name,
                        "test",
                        "2024-08-01" if source_name == "first_epss" else "2025-03-19",
                        retrieved_at,
                        checksum,
                        "{}",
                        retrieved_at,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO ingestion_run(
                        ingestion_run_id, source_snapshot_id, started_at_utc,
                        completed_at_utc, status, input_fingerprint_sha256,
                        configuration_json, created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"run:{source_name}",
                        snapshot_id,
                        retrieved_at,
                        retrieved_at,
                        "succeeded",
                        source_name[0] * 64,
                        "{}",
                        retrieved_at,
                    ),
                )

            connection.execute(
                """
                INSERT INTO cve(
                    cve_id, published_at_utc, modified_at_utc, source_name,
                    retrieved_at_utc, created_at_utc, source_snapshot_id,
                    ingestion_run_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "CVE-2024-0001",
                    "2024-01-01T00:00:00Z",
                    "2024-06-01T00:00:00Z",
                    "nvd",
                    vulzoo_retrieved,
                    vulzoo_retrieved,
                    "snapshot:vulzoo",
                    "run:vulzoo",
                ),
            )
            connection.execute(
                """
                INSERT INTO cvss_observation(
                    cvss_observation_id, cve_id, version, base_score,
                    observed_at_utc, source_name, retrieved_at_utc,
                    created_at_utc, source_snapshot_id, ingestion_run_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "cvss:test",
                    "CVE-2024-0001",
                    "3.1",
                    9.8,
                    "2024-06-01T00:00:00Z",
                    "nvd",
                    vulzoo_retrieved,
                    vulzoo_retrieved,
                    "snapshot:vulzoo",
                    "run:vulzoo",
                ),
            )
            connection.execute(
                """
                INSERT INTO kev_observation(
                    kev_observation_id, cve_id, date_added, catalogue_date,
                    source_name, retrieved_at_utc, created_at_utc,
                    source_snapshot_id, ingestion_run_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "kev:test",
                    "CVE-2024-0001",
                    "2024-07-01",
                    "2025-03-19",
                    "cisa_kev",
                    vulzoo_retrieved,
                    vulzoo_retrieved,
                    "snapshot:vulzoo",
                    "run:vulzoo",
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
                    "cpe:test",
                    "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
                    "nvd",
                    vulzoo_retrieved,
                    vulzoo_retrieved,
                    "snapshot:vulzoo",
                    "run:vulzoo",
                ),
            )
            connection.execute(
                """
                INSERT INTO cve_cpe(
                    cve_cpe_id, cve_id, cpe_id, vulnerable, observed_at_utc,
                    source_name, retrieved_at_utc, source_snapshot_id,
                    ingestion_run_id, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "mapping:test",
                    "CVE-2024-0001",
                    "cpe:test",
                    1,
                    "2024-06-01T00:00:00Z",
                    "nvd",
                    vulzoo_retrieved,
                    "snapshot:vulzoo",
                    "run:vulzoo",
                    vulzoo_retrieved,
                ),
            )
            connection.execute(
                """
                INSERT INTO cve_configuration_node(
                    cve_configuration_node_id, cve_id, node_kind, source_path,
                    depth, sibling_position, logical_operator, negate,
                    observed_at_utc, source_name, retrieved_at_utc,
                    source_snapshot_id, ingestion_run_id, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "node:test",
                    "CVE-2024-0001",
                    "configuration",
                    "configurations[0]",
                    0,
                    0,
                    "OR",
                    0,
                    "2024-06-01T00:00:00Z",
                    "nvd",
                    vulzoo_retrieved,
                    "snapshot:vulzoo",
                    "run:vulzoo",
                    vulzoo_retrieved,
                ),
            )
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
                    "configuration-match:test",
                    "CVE-2024-0001",
                    "node:test",
                    "mapping:test",
                    "configurations[0].cpeMatch[0]",
                    0,
                    "snapshot:vulzoo",
                    "run:vulzoo",
                    vulzoo_retrieved,
                ),
            )
            connection.execute(
                """
                INSERT INTO diversevul_function(
                    diversevul_function_id, source_snapshot_id,
                    ingestion_run_id, source_line_number, project,
                    commit_sha, source_function_hash, function_sha256,
                    function_size_bytes, vulnerability_label, cwe_ids_json,
                    commit_message_sha256, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "function:test",
                    "snapshot:diversevul",
                    "run:diversevul",
                    1,
                    "example",
                    "abcdef1",
                    "123",
                    "a" * 64,
                    10,
                    1,
                    "[]",
                    "b" * 64,
                    diversevul_retrieved,
                ),
            )
            connection.execute(
                """
                INSERT INTO epss_observation(
                    epss_observation_id, cve_id, score, percentile,
                    score_date, model_version, source_name, retrieved_at_utc,
                    created_at_utc, source_snapshot_id, ingestion_run_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "epss:test",
                    "CVE-2024-0001",
                    0.8,
                    0.9,
                    "2024-08-01",
                    "test",
                    "first_epss",
                    epss_retrieved,
                    epss_retrieved,
                    "snapshot:epss",
                    "run:first_epss",
                ),
            )
            connection.commit()

        return path

    def test_strict_mode_waits_for_local_snapshot_availability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._database(directory)
            result = audit_technical_evidence_as_of(
                path,
                "2025-04-01T00:00:00Z",
                mode="strict_snapshot",
            )

        self.assertEqual(result["contract"], "technical-evidence-as-of-v1")
        self.assertEqual(result["totals"]["eligible_records"], 0)
        self.assertEqual(result["totals"]["excluded_after_cutoff"], 6)
        self.assertFalse(result["scope"]["database_mutated"])

    def test_reconstruction_uses_source_dates_but_not_unknown_diversevul_time(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._database(directory)
            result = audit_technical_evidence_as_of(
                path,
                "2025-04-01T00:00:00+00:00",
                mode="source_effective_reconstruction",
            )

        by_kind = {item["evidence_kind"]: item for item in result["evidence"]}
        self.assertEqual(result["totals"]["eligible_records"], 5)
        self.assertEqual(by_kind["diversevul_label"]["reconstruction_eligible"], 0)
        self.assertEqual(by_kind["epss_score"]["reconstruction_eligible"], 1)
        self.assertEqual(
            result["research_status"],
            "source_effective_reconstruction_not_historical_ground_truth",
        )

    def test_strict_mode_includes_all_records_after_retrieval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._database(directory)
            result = audit_technical_evidence_as_of(
                path,
                "2026-09-01T00:00:00Z",
            )

        self.assertEqual(result["totals"]["eligible_records"], 6)
        self.assertEqual(result["totals"]["excluded_after_cutoff"], 0)
        self.assertEqual(result["totals"]["prioritisation_evidence_eligible"], 3)
        self.assertEqual(result["totals"]["applicability_evidence_eligible"], 1)
        self.assertEqual(result["totals"]["catalogue_records_eligible"], 1)
        self.assertEqual(result["totals"]["offline_labels_eligible"], 1)
        self.assertRegex(result["input_fingerprint_sha256"], r"^[0-9a-f]{64}$")

    def test_naive_decision_timestamp_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._database(directory)
            with self.assertRaisesRegex(ValueError, "explicit UTC offset"):
                audit_technical_evidence_as_of(
                    path,
                    datetime(2025, 4, 1),
                )


if __name__ == "__main__":
    unittest.main()
