import contextlib
import csv
import gzip
import hashlib
import io
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

import yaml

from thesis_pipeline.cli import main
from thesis_pipeline.ingestion.epss import ARCHIVE_REPOSITORY, _panel_fingerprint, ingest_epss_panel
from thesis_pipeline.quality.evidence_as_of import audit_technical_evidence_as_of
from thesis_pipeline.storage.schema import initialise_database


class EpssIngestionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        environment = patch.dict(os.environ, {"THESIS_DATA_ROOT": str(self.root)})
        environment.start()
        self.addCleanup(environment.stop)

        self.epss_root = self.root / "snapshots" / "epss"
        self.panel = self.epss_root / "panels" / "2025-12-31_to_2026-01-01"
        self.panel.mkdir(parents=True)
        manifests = self.epss_root / "manifests"
        manifests.mkdir()
        self.manifest = manifests / "acquisition.json"
        self.config = self.root / "sources.yaml"
        self.archive_commit = "a" * 40
        self.model_version = "v2025.03.14"
        self.retrieved_at = "2026-08-24T12:00:00Z"

        self._write_daily(
            "2025-12-31",
            [
                ("CVE-2024-0001", "0.8", "0.9"),
                ("CVE-2024-0002", "0.2", "0.4"),
                ("CVE-2026-9999", "0.1", "0.3"),
            ],
        )
        self._write_daily(
            "2026-01-01",
            [
                ("CVE-2024-0001", "0.7", "0.8"),
                ("CVE-2024-0003", "0.5", "0.6"),
                ("CVE-2026-9999", "0.15", "0.35"),
            ],
        )

        self.database = initialise_database(self.root / "databases" / "thesis.sqlite")
        with contextlib.closing(sqlite3.connect(self.database)) as connection, connection:
            for cve_id in ("CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"):
                connection.execute(
                    "INSERT INTO cve(cve_id, source_name, retrieved_at_utc, created_at_utc) "
                    "VALUES (?, ?, ?, ?)",
                    (cve_id, "nvd", self.retrieved_at, self.retrieved_at),
                )

        self._write_documents()

    def _write_daily(self, score_date: str, rows: list[tuple[str, str, str]]) -> Path:
        path = self.panel / f"epss_scores-{score_date}.csv.gz"
        with gzip.open(path, "wt", encoding="utf-8", newline="") as stream:
            stream.write(
                f"#model_version:{self.model_version},score_date:{score_date}T00:00:00+0000\n"
            )
            writer = csv.writer(stream)
            writer.writerow(["cve", "epss", "percentile"])
            writer.writerows(rows)
        return path

    def _write_documents(self, first: date | None = None) -> None:
        files = []
        if first is None:
            first = date(2025, 12, 31)
        last = first + timedelta(days=1)
        canonical = {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}

        for offset in range(2):
            current = first + timedelta(days=offset)
            day = current.isoformat()
            path = self.panel / f"epss_scores-{day}.csv.gz"
            with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
                stream.readline()
                reader = csv.reader(stream)
                next(reader)
                rows = list(reader)
            matched = sum(row[0] in canonical for row in rows)
            files.append(
                {
                    "score_date": day,
                    "relative_path": path.relative_to(self.root).as_posix(),
                    "upstream_url": (
                        "https://raw.githubusercontent.com/empiricalsec/epss_scores/"
                        f"{self.archive_commit}/{current.year}/{path.name}"
                    ),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "compressed_bytes": path.stat().st_size,
                    "model_version": self.model_version,
                    "published_at": f"{day}T00:00:00+0000",
                    "columns": ["cve", "epss", "percentile"],
                    "source_records": len(rows),
                    "records_matching_vulzoo": matched,
                    "records_not_in_vulzoo": len(rows) - matched,
                }
            )

        fingerprint = _panel_fingerprint(
            self.archive_commit,
            first.isoformat(),
            last.isoformat(),
            self.model_version,
            files,
        )
        source = {
            "url": "https://www.first.org/epss/data",
            "archive_url": ARCHIVE_REPOSITORY,
            "retrieval_date": "2026-08-24",
            "model_version": self.model_version,
            "upstream_commit": self.archive_commit,
            "checksum": f"sha256:{fingerprint}",
            "local_relative_path": "snapshots/epss",
            "panel_relative_path": self.panel.relative_to(self.epss_root).as_posix(),
            "panel_start_date": first.isoformat(),
            "panel_end_date": last.isoformat(),
            "enabled": True,
        }
        self.config.write_text(yaml.safe_dump({"sources": {"epss": source}}), encoding="utf-8")
        manifest = {
            "contract": "first-epss-acquisition-v1",
            "retrieved_at_utc": self.retrieved_at,
            "source": {
                "archive_repository": ARCHIVE_REPOSITORY,
                "archive_commit": self.archive_commit,
            },
            "panel": {
                "first_score_date": first.isoformat(),
                "last_score_date": last.isoformat(),
                "days": 2,
                "model_version": self.model_version,
                "temporal_mode": "source_effective_reconstruction",
                "historical_ground_truth_claimed": False,
            },
            "files": files,
            "totals": {
                "canonical_vulzoo_cves": len(canonical),
                "source_records": sum(item["source_records"] for item in files),
                "records_matching_vulzoo": sum(item["records_matching_vulzoo"] for item in files),
                "records_not_in_vulzoo": sum(item["records_not_in_vulzoo"] for item in files),
            },
            "scope": {
                "database_mutated": False,
                "raw_score_records_included_in_manifest": False,
                "source_api_used_for_bulk_download": False,
            },
            "input_fingerprint_sha256": fingerprint,
        }
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")

    def _ingest(self) -> dict[str, object]:
        return ingest_epss_panel(self.config, self.database, self.manifest)

    def _connection(self) -> contextlib.AbstractContextManager[sqlite3.Connection]:
        return contextlib.closing(sqlite3.connect(self.database))

    def test_panel_preserves_daily_scores_snapshot_provenance_and_model_version(self) -> None:
        result = self._ingest()

        with self._connection() as connection:
            observations = connection.execute(
                "SELECT cve_id, score_date, score, percentile, model_version "
                "FROM epss_observation ORDER BY score_date, cve_id"
            ).fetchall()
            snapshots = connection.execute(
                "SELECT snapshot_date, source_version, retrieved_at_utc "
                "FROM source_snapshot WHERE source_name = 'first_epss' ORDER BY snapshot_date"
            ).fetchall()
            runs = connection.execute(
                "SELECT status, input_record_count, accepted_record_count, rejected_record_count "
                "FROM ingestion_run ORDER BY started_at_utc"
            ).fetchall()
            unknown = connection.execute(
                "SELECT COUNT(*) FROM cve WHERE cve_id = 'CVE-2026-9999'"
            ).fetchone()[0]
            rejections = connection.execute("SELECT COUNT(*) FROM ingestion_rejection").fetchone()[
                0
            ]

        self.assertEqual(result["contract"], "first-epss-ingestion-v1")
        self.assertEqual(result["totals"]["source_records"], 6)
        self.assertEqual(result["totals"]["matched_records"], 4)
        self.assertEqual(result["totals"]["outside_vulzoo_snapshot"], 2)
        self.assertEqual(result["totals"]["new_observations"], 4)
        self.assertEqual(
            observations,
            [
                ("CVE-2024-0001", "2025-12-31", 0.8, 0.9, self.model_version),
                ("CVE-2024-0002", "2025-12-31", 0.2, 0.4, self.model_version),
                ("CVE-2024-0001", "2026-01-01", 0.7, 0.8, self.model_version),
                ("CVE-2024-0003", "2026-01-01", 0.5, 0.6, self.model_version),
            ],
        )
        self.assertEqual(
            snapshots,
            [
                ("2025-12-31", self.model_version, self.retrieved_at),
                ("2026-01-01", self.model_version, self.retrieved_at),
            ],
        )
        self.assertEqual(runs, [("succeeded", 3, 2, 0), ("succeeded", 3, 2, 0)])
        self.assertEqual(unknown, 0)
        self.assertEqual(rejections, 0)
        self.assertFalse(result["scope"]["canonical_cves_created"])

    def test_repeated_panel_ingestion_is_idempotent_and_records_new_runs(self) -> None:
        first = self._ingest()
        second = self._ingest()

        with self._connection() as connection:
            counts = tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("source_snapshot", "ingestion_run", "epss_observation")
            )

        self.assertEqual(first["totals"]["new_observations"], 4)
        self.assertEqual(second["totals"]["new_observations"], 0)
        self.assertEqual(counts, (2, 4, 4))

    def test_new_panel_preserves_existing_dates_observations_and_provenance(self) -> None:
        archived = self._ingest()
        self.panel = self.epss_root / "panels" / "2025-03-21_to_2025-03-22"
        self.panel.mkdir()
        self._write_daily(
            "2025-03-21",
            [
                ("CVE-2024-0001", "0.4", "0.5"),
                ("CVE-2024-0002", "0.3", "0.4"),
                ("CVE-2026-9999", "0.1", "0.2"),
            ],
        )
        self._write_daily(
            "2025-03-22",
            [
                ("CVE-2024-0001", "0.5", "0.6"),
                ("CVE-2024-0003", "0.6", "0.7"),
                ("CVE-2026-9999", "0.2", "0.3"),
            ],
        )
        self._write_documents(date(2025, 3, 21))

        aligned = self._ingest()
        reconstruction = audit_technical_evidence_as_of(
            self.database,
            "2025-03-22T09:00:00Z",
            mode="source_effective_reconstruction",
        )
        strict = audit_technical_evidence_as_of(
            self.database,
            "2025-03-22T09:00:00Z",
            mode="strict_snapshot",
        )
        reconstructed_epss = next(
            entry for entry in reconstruction["evidence"] if entry["evidence_kind"] == "epss_score"
        )
        strict_epss = next(
            entry for entry in strict["evidence"] if entry["evidence_kind"] == "epss_score"
        )

        with self._connection() as connection:
            daily_counts = connection.execute(
                "SELECT score_date, COUNT(*) FROM epss_observation "
                "GROUP BY score_date ORDER BY score_date"
            ).fetchall()
            snapshots = connection.execute(
                "SELECT snapshot_date FROM source_snapshot "
                "WHERE source_name = 'first_epss' ORDER BY snapshot_date"
            ).fetchall()
            runs = connection.execute(
                "SELECT COUNT(*) FROM ingestion_run WHERE status = 'succeeded'"
            ).fetchone()[0]

        self.assertEqual(archived["totals"]["new_observations"], 4)
        self.assertEqual(aligned["totals"]["new_observations"], 4)
        self.assertNotEqual(
            archived["input_fingerprint_sha256"], aligned["input_fingerprint_sha256"]
        )
        self.assertEqual(
            daily_counts,
            [
                ("2025-03-21", 2),
                ("2025-03-22", 2),
                ("2025-12-31", 2),
                ("2026-01-01", 2),
            ],
        )
        self.assertEqual(
            snapshots,
            [
                ("2025-03-21",),
                ("2025-03-22",),
                ("2025-12-31",),
                ("2026-01-01",),
            ],
        )
        self.assertEqual(runs, 4)
        self.assertEqual(reconstructed_epss["reconstruction_eligible"], 2)
        self.assertEqual(strict_epss["strict_snapshot_eligible"], 0)

    def test_changed_daily_file_is_rejected_before_snapshot_or_run_creation(self) -> None:
        changed = self.panel / "epss_scores-2025-12-31.csv.gz"
        with changed.open("ab") as stream:
            stream.write(b"tampered")

        with self.assertRaisesRegex(RuntimeError, "changed after acquisition"):
            self._ingest()

        with self._connection() as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM ingestion_run").fetchone()[0], 0
            )

    def test_model_version_boundary_is_rejected_before_ingestion(self) -> None:
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["files"][1]["model_version"] = "v2026.06.15"
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "model-version boundary"):
            self._ingest()

    def test_missing_panel_day_is_rejected(self) -> None:
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["files"].pop()
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "exactly one file"):
            self._ingest()

    def test_out_of_range_score_rolls_back_only_the_failed_daily_transaction(self) -> None:
        self._write_daily(
            "2026-01-01",
            [
                ("CVE-2024-0001", "1.5", "0.8"),
                ("CVE-2024-0003", "0.5", "0.6"),
                ("CVE-2026-9999", "0.15", "0.35"),
            ],
        )
        self._write_documents()

        with self.assertRaisesRegex(ValueError, "between zero and one"):
            self._ingest()

        with self._connection() as connection:
            dates = connection.execute(
                "SELECT DISTINCT score_date FROM epss_observation"
            ).fetchall()
            states = connection.execute(
                "SELECT status FROM ingestion_run ORDER BY started_at_utc"
            ).fetchall()

        self.assertEqual(dates, [("2025-12-31",)])
        self.assertEqual(states, [("succeeded",), ("failed",)])

    def test_duplicate_daily_cve_rolls_back_the_daily_transaction(self) -> None:
        self._write_daily(
            "2025-12-31",
            [
                ("CVE-2024-0001", "0.8", "0.9"),
                ("CVE-2024-0001", "0.7", "0.8"),
                ("CVE-2026-9999", "0.1", "0.3"),
            ],
        )
        self._write_documents()

        with self.assertRaisesRegex(ValueError, "Duplicate EPSS CVE"):
            self._ingest()

        with self._connection() as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM epss_observation").fetchone()[0], 0
            )
            self.assertEqual(
                connection.execute("SELECT status FROM ingestion_run").fetchall(), [("failed",)]
            )

    def test_conservative_date_boundary_and_actual_retrieval_prevent_look_ahead(self) -> None:
        self._ingest()
        reconstruction = audit_technical_evidence_as_of(
            self.database,
            "2026-01-01T09:00:00Z",
            mode="source_effective_reconstruction",
        )
        strict = audit_technical_evidence_as_of(
            self.database,
            "2026-01-01T09:00:00Z",
            mode="strict_snapshot",
        )
        reconstructed_epss = next(
            entry for entry in reconstruction["evidence"] if entry["evidence_kind"] == "epss_score"
        )
        strict_epss = next(
            entry for entry in strict["evidence"] if entry["evidence_kind"] == "epss_score"
        )

        self.assertEqual(reconstructed_epss["reconstruction_eligible"], 2)
        self.assertEqual(strict_epss["strict_snapshot_eligible"], 0)
        self.assertFalse(reconstruction["limitations"]["reconstruction_is_historical_ground_truth"])

    def test_manifest_claim_boundary_is_enforced(self) -> None:
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["panel"]["historical_ground_truth_claimed"] = True
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "overclaims historical availability"):
            self._ingest()

    def test_manifest_must_remain_beneath_the_approved_manifest_root(self) -> None:
        outside = self.root / "outside-manifest.json"
        outside.write_text(self.manifest.read_text(encoding="utf-8"), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "approved manifest root"):
            ingest_epss_panel(self.config, self.database, outside)

    def test_cli_returns_only_the_metadata_summary(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            exit_code = main(
                [
                    "ingest-epss-panel",
                    "--config",
                    str(self.config),
                    "--database",
                    str(self.database),
                    "--acquisition-manifest",
                    str(self.manifest),
                    "--progress-every",
                    "0",
                ]
            )

        result = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(result["totals"]["matched_records"], 4)
        self.assertNotIn(str(self.root), output.getvalue())
        self.assertFalse(result["scope"]["raw_records_included"])


if __name__ == "__main__":
    unittest.main()
