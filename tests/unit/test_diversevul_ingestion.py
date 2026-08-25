import contextlib
import hashlib
import io
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from thesis_pipeline.cli import main
from thesis_pipeline.ingestion.diversevul import ingest_diversevul
from thesis_pipeline.storage.schema import initialise_database


class DiverseVulIngestionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        environment = patch.dict(os.environ, {"THESIS_DATA_ROOT": str(self.root)})
        environment.start()
        self.addCleanup(environment.stop)

        self.source = self.root / "DiverseVul"
        dataset_directory = self.source / "downloads" / "dataset"
        metadata_directory = self.source / "downloads" / "metadata"
        dataset_directory.mkdir(parents=True)
        metadata_directory.mkdir(parents=True)
        self.dataset = dataset_directory / "diversevul.json"
        self.metadata = metadata_directory / "diversevul_metadata.json"
        self.commit_a = "a" * 40
        self.commit_b = "b" * 40
        self.commit_c = "c" * 40
        self.commit_d = "d" * 40
        self.upstream_commit = "e" * 40

        metadata_records = [
            {
                "project": "alpha",
                "commit_id": self.commit_a,
                "commit_url": f"https://example.invalid/alpha/commit/{self.commit_a}",
                "repo_url": "https://example.invalid/alpha",
                "CVE": "CVE-2024-0001",
                "CWE": "CWE-79",
                "bug_info": "CVE-2024-0999 must never become authoritative",
            },
            {
                "project": "alpha",
                "commit_id": "not-a-valid-commit",
                "commit_url": f"https://example.invalid/alpha/commit/{self.commit_b}",
                "repo_url": "https://example.invalid/alpha",
                "CVE": "CVE-2024-0002",
                "CWE": "CWE-89",
            },
            {
                "project": "alpha",
                "commit_id": "invalid",
                "commit_url": "https://example.invalid/alpha/commit/not-valid",
                "CVE": "CVE-2024-0003",
                "CWE": None,
            },
            {
                "project": "alpha",
                "commit_id": self.commit_c,
                "commit_url": f"https://example.invalid/alpha/commit/{self.commit_c}",
                "repo_url": None,
                "CVE": None,
                "CWE": "CWE-20",
                "bug_info": "CVE-2024-0002 in free text is not a field-level mapping",
            },
        ]
        dataset_records = [
            {
                "project": "alpha",
                "commit_id": self.commit_a,
                "func": "int vulnerable(void) { return 1; }",
                "hash": 111,
                "size": 34,
                "target": 1,
                "cwe": ["CWE-79"],
                "message": "Fix CVE-2024-0001 and historical CVE-2024-4040",
            },
            {
                "project": "alpha",
                "commit_id": self.commit_b,
                "func": "int safe(void) { return 0; }",
                "hash": 222,
                "size": 28,
                "target": 0,
                "cwe": ["CWE-89"],
                "message": "Validated commit URL recovery",
            },
            {
                "project": "alpha",
                "commit_id": self.commit_c,
                "func": "",
                "hash": 333,
                "size": 0,
                "target": 0,
                "cwe": ["CWE-20"],
                "message": "Related to CVE-2024-0003",
            },
            {
                "project": "beta",
                "commit_id": self.commit_d,
                "func": "int unrelated(void) { return 2; }",
                "hash": 444,
                "size": 33,
                "target": 0,
                "cwe": [],
                "message": "No vulnerability reference",
            },
        ]
        self.metadata.write_text(
            "".join(json.dumps(record) + "\n" for record in metadata_records),
            encoding="utf-8",
        )
        self.dataset.write_text(
            "".join(json.dumps(record) + "\n" for record in dataset_records),
            encoding="utf-8",
        )

        self.database = initialise_database(self.root / "databases" / "thesis.sqlite")
        with contextlib.closing(sqlite3.connect(self.database)) as connection, connection:
            for cve_id in ("CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"):
                connection.execute(
                    """
                    INSERT INTO cve(cve_id, source_name, retrieved_at_utc, created_at_utc)
                    VALUES (?, ?, ?, ?)
                    """,
                    (cve_id, "nvd", "2026-08-23T00:00:00Z", "2026-08-23T00:00:00Z"),
                )

        self.config = self.root / "sources.yaml"
        self.manifest = self.root / "acquisition.json"
        self.profile = self.root / "profile.json"
        self._write_documents()

    def _write_documents(self) -> None:
        dataset_checksum = hashlib.sha256(self.dataset.read_bytes()).hexdigest()
        metadata_checksum = hashlib.sha256(self.metadata.read_bytes()).hexdigest()
        fingerprint = hashlib.sha256(
            f"{dataset_checksum}\n{metadata_checksum}\n{self.upstream_commit}\n".encode("ascii")
        ).hexdigest()
        configuration = {
            "sources": {
                "diversevul": {
                    "url": "https://example.invalid/diversevul",
                    "upstream_commit": self.upstream_commit,
                    "retrieval_date": "2026-08-23",
                    "checksum": f"sha256:{dataset_checksum}",
                    "metadata_checksum": f"sha256:{metadata_checksum}",
                    "local_relative_path": "DiverseVul",
                    "dataset_relative_path": "downloads/dataset/diversevul.json",
                    "metadata_relative_path": "downloads/metadata/diversevul_metadata.json",
                    "enabled": True,
                }
            }
        }
        self.config.write_text(yaml.safe_dump(configuration), encoding="utf-8")
        manifest = {
            "contract": "diversevul-acquisition-v1",
            "upstream_commit": self.upstream_commit,
            "acquired_at_utc": "2026-08-23T12:30:00Z",
            "license_status": "not_declared_by_upstream",
            "files": [
                {"role": "dataset", "local_path": str(self.dataset), "sha256": dataset_checksum},
                {
                    "role": "metadata",
                    "local_path": str(self.metadata),
                    "sha256": metadata_checksum,
                },
            ],
        }
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        profile = {
            "contract": "diversevul-profile-v1",
            "input_fingerprint_sha256": fingerprint,
            "scope": {
                "raw_records_included": False,
                "source_code_included": False,
                "source_code_executed": False,
                "network_accessed": False,
                "dataset_mutated": False,
                "database_mutated": False,
            },
            "source": {
                "upstream_commit": self.upstream_commit,
                "dataset_sha256": dataset_checksum,
                "metadata_sha256": metadata_checksum,
            },
            "dataset": {
                "records": 4,
                "labels": {"vulnerable": 1, "non_vulnerable": 3},
                "unique_projects": 2,
                "unique_commits": 4,
                "missing_source_code": 1,
            },
            "metadata": {"top_level_entries": 4},
            "vulzoo_join": {"canonical_cves_available": 3},
            "reference_count_comparison": {"records": {"matches": False}},
        }
        self.profile.write_text(json.dumps(profile), encoding="utf-8")

    def _ingest(self) -> dict[str, object]:
        return ingest_diversevul(self.config, self.database, self.manifest, self.profile)

    def test_ingestion_preserves_cve_evidence_and_never_stores_raw_function_code(self) -> None:
        result = self._ingest()
        with contextlib.closing(sqlite3.connect(self.database)) as connection, connection:
            functions = connection.execute(
                "SELECT vulnerability_label, function_size_bytes, function_sha256 "
                "FROM diversevul_function ORDER BY source_line_number"
            ).fetchall()
            associations = connection.execute(
                "SELECT cve_id, evidence_source FROM diversevul_function_cve "
                "ORDER BY cve_id, evidence_source"
            ).fetchall()
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(diversevul_function)")
            }
            rejection_ids = connection.execute(
                "SELECT reason_code, source_record_id FROM ingestion_rejection ORDER BY reason_code"
            ).fetchall()

        self.assertEqual(result["contract"], "diversevul-ingestion-v1")
        self.assertEqual(result["metadata"]["input_records"], 4)
        self.assertEqual(result["metadata"]["accepted_records"], 3)
        self.assertEqual(result["metadata"]["commit_ids_recovered_from_url"], 1)
        self.assertEqual(result["functions"]["accepted_records"], 4)
        self.assertEqual(result["functions"]["without_source_code"], 1)
        self.assertEqual(result["vulzoo_join"]["functions_with_matched_cve"], 3)
        self.assertEqual(result["vulzoo_join"]["unique_matched_cves"], 3)
        self.assertEqual(result["vulzoo_join"]["unmatched_cve_sample"], ["CVE-2024-4040"])
        self.assertEqual(
            associations,
            [
                ("CVE-2024-0001", "commit_message"),
                ("CVE-2024-0001", "metadata_cve_field"),
                ("CVE-2024-0002", "metadata_cve_field"),
                ("CVE-2024-0003", "commit_message"),
            ],
        )
        self.assertIsNone(functions[2][2])
        self.assertNotIn("func", columns)
        self.assertNotIn("source_code", columns)
        self.assertEqual(
            rejection_ids,
            [
                ("cve_not_in_vulzoo_snapshot", "CVE-2024-4040"),
                ("metadata_invalid_commit_id", "3"),
            ],
        )
        self.assertFalse(result["scope"]["source_code_persisted"])
        self.assertFalse(result["scope"]["canonical_cves_created"])

    def test_conflicting_commit_url_is_rejected_without_authoritative_cve_link(self) -> None:
        records = [
            json.loads(line) for line in self.metadata.read_text(encoding="utf-8").splitlines()
        ]
        records[0]["commit_url"] = f"https://example.invalid/alpha/commit/{self.commit_b}"
        self.metadata.write_text(
            "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
        )
        self._write_documents()

        result = self._ingest()

        with contextlib.closing(sqlite3.connect(self.database)) as connection, connection:
            authoritative_links = connection.execute(
                "SELECT COUNT(*) FROM diversevul_function_cve "
                "WHERE cve_id = ? AND evidence_source = ?",
                ("CVE-2024-0001", "metadata_cve_field"),
            ).fetchone()

        self.assertEqual(authoritative_links, (0,))
        self.assertEqual(
            result["bounded_rejections"]["reason_counts"]["metadata_commit_identity_conflict"],
            1,
        )

    def test_metadata_from_another_project_never_creates_a_cross_project_cve_link(self) -> None:
        records = [
            json.loads(line) for line in self.metadata.read_text(encoding="utf-8").splitlines()
        ]
        records[0]["project"] = "different-project"
        self.metadata.write_text(
            "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
        )
        self._write_documents()

        result = self._ingest()

        with contextlib.closing(sqlite3.connect(self.database)) as connection, connection:
            authoritative_links = connection.execute(
                "SELECT COUNT(*) FROM diversevul_function_cve "
                "WHERE cve_id = ? AND evidence_source = ?",
                ("CVE-2024-0001", "metadata_cve_field"),
            ).fetchone()

        self.assertEqual(authoritative_links, (0,))
        self.assertEqual(result["vulzoo_join"]["project_mismatch_count"], 1)
        self.assertEqual(
            result["bounded_rejections"]["reason_counts"]["metadata_project_mismatch"], 1
        )

    def test_repeated_ingestion_is_idempotent_and_records_separate_runs(self) -> None:
        first = self._ingest()
        second = self._ingest()
        with contextlib.closing(sqlite3.connect(self.database)) as connection, connection:
            snapshots = connection.execute(
                "SELECT COUNT(*) FROM source_snapshot WHERE source_name = 'diversevul'"
            ).fetchone()
            runs = connection.execute("SELECT COUNT(*) FROM ingestion_run").fetchone()
            functions = connection.execute("SELECT COUNT(*) FROM diversevul_function").fetchone()
            associations = connection.execute(
                "SELECT COUNT(*) FROM diversevul_function_cve"
            ).fetchone()

        self.assertNotEqual(first["ingestion_run_id"], second["ingestion_run_id"])
        self.assertEqual(second["new_rows"], {})
        self.assertEqual(snapshots, (1,))
        self.assertEqual(runs, (2,))
        self.assertEqual(functions, (4,))
        self.assertEqual(associations, (4,))

    def test_manifest_timestamp_variants_preserve_approved_retrieval_provenance(self) -> None:
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["generated_at_utc"] = manifest.pop("acquired_at_utc")
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")

        result = self._ingest()

        self.assertEqual(result["retrieved_at_utc"], "2026-08-23T12:30:00Z")

    def test_missing_manifest_timestamp_uses_conservative_configured_retrieval_date(self) -> None:
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest.pop("acquired_at_utc")
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")

        result = self._ingest()

        self.assertEqual(result["retrieved_at_utc"], "2026-08-23T23:59:59Z")

    def test_changed_dataset_is_rejected_before_a_database_run_is_created(self) -> None:
        self.dataset.write_text(self.dataset.read_text(encoding="utf-8") + "\n", encoding="utf-8")

        with self.assertRaisesRegex(RuntimeError, "changed after acquisition"):
            self._ingest()

        with contextlib.closing(sqlite3.connect(self.database)) as connection, connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM ingestion_run").fetchone(), (0,)
            )

    def test_profile_count_mismatch_rolls_back_rows_and_records_a_failed_run(self) -> None:
        profile = json.loads(self.profile.read_text(encoding="utf-8"))
        profile["dataset"]["records"] = 99
        self.profile.write_text(json.dumps(profile), encoding="utf-8")

        with self.assertRaisesRegex(RuntimeError, "dataset records differ"):
            self._ingest()

        with contextlib.closing(sqlite3.connect(self.database)) as connection, connection:
            self.assertEqual(
                connection.execute("SELECT status FROM ingestion_run").fetchall(), [("failed",)]
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM diversevul_function").fetchone(), (0,)
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM diversevul_commit").fetchone(), (0,)
            )

    def test_profile_scope_and_database_location_are_enforced(self) -> None:
        profile = json.loads(self.profile.read_text(encoding="utf-8"))
        profile["scope"]["source_code_included"] = True
        self.profile.write_text(json.dumps(profile), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "approved data boundary"):
            self._ingest()

        self._write_documents()
        outside = Path(tempfile.gettempdir()) / f"outside-{self.root.name}.sqlite"
        with self.assertRaisesRegex(ValueError, "beneath THESIS_DATA_ROOT"):
            ingest_diversevul(self.config, outside, self.manifest, self.profile)

    def test_cli_returns_a_metadata_only_summary(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main(
                [
                    "ingest-diversevul",
                    "--config",
                    str(self.config),
                    "--database",
                    str(self.database),
                    "--acquisition-manifest",
                    str(self.manifest),
                    "--profile-report",
                    str(self.profile),
                    "--progress-every",
                    "0",
                ]
            )

        result = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(result["status"], "succeeded")
        self.assertNotIn("int vulnerable(void)", output.getvalue())
        self.assertNotIn(str(self.root), output.getvalue())


if __name__ == "__main__":
    unittest.main()
