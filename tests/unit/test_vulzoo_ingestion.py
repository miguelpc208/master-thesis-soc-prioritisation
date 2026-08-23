import contextlib
import io
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from thesis_pipeline.cli import main
from thesis_pipeline.ingestion.coverage import scan_vulzoo_coverage
from thesis_pipeline.ingestion.normalise import ingest_vulzoo
from thesis_pipeline.storage.schema import initialise_database


class VulZooIngestionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.environment = patch.dict(os.environ, {"THESIS_DATA_ROOT": str(self.root)})
        self.environment.start()
        self.addCleanup(self.environment.stop)

        self.source = self.root / "VulZoo"
        nvd = self.source / "processed" / "nvd-database" / "CVE-2024"
        legacy = self.source / "processed" / "cve-database" / "2024"
        kev = self.source / "processed" / "cisa-kev-database"
        relationships = self.source / "processed" / "relationships"
        for directory in (nvd, legacy, kev, relationships):
            directory.mkdir(parents=True)

        self.nvd_file = nvd / "CVE-2024-0001.json"
        self.nvd_file.write_text(
            json.dumps(
                {
                    "id": "CVE-2024-0001",
                    "published": "2024-01-01T10:30:00.000",
                    "lastModified": "2024-02-01T11:45:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "NVD primary description"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": source,
                                "type": "Primary",
                                "exploitabilityScore": 3.9,
                                "impactScore": 5.9,
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                    "vectorString": (
                                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                                    ),
                                },
                            }
                            for source in ("nvd@nist.gov", "vendor@example.invalid")
                        ]
                    },
                    "weaknesses": [
                        {
                            "description": [
                                {"lang": "en", "value": "CWE-79"},
                                {"lang": "en", "value": "NVD-CWE-noinfo"},
                            ]
                        }
                    ],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": (
                                                "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*"
                                            ),
                                            "matchCriteriaId": "criteria-1",
                                            "versionEndExcluding": "2.0",
                                        },
                                        {
                                            "vulnerable": True,
                                            "criteria": (
                                                "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*"
                                            ),
                                            "matchCriteriaId": "criteria-2",
                                            "versionEndExcluding": "3.0",
                                        },
                                    ]
                                }
                            ]
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (nvd / "CVE-2024-0002.json").write_text(
            json.dumps(
                {
                    "id": "CVE-2024-9999",
                    "published": "2024-01-01T00:00:00Z",
                    "lastModified": "2024-01-02T00:00:00Z",
                }
            ),
            encoding="utf-8",
        )
        (nvd / "CVE-2024-0006.json").write_text("{malformed", encoding="utf-8")

        for cve_id, description in (
            ("CVE-2024-0001", "Legacy must not replace NVD"),
            ("CVE-2024-0003", "Legacy-only supplemental description"),
        ):
            (legacy / f"{cve_id}.json").write_text(
                json.dumps(
                    {
                        "CVE_data_meta": {"ID": cve_id, "STATE": "PUBLIC"},
                        "description": {
                            "description_data": [{"lang": "eng", "value": description}]
                        },
                        "problemtype": {"problemtype_data": []},
                    }
                ),
                encoding="utf-8",
            )

        (kev / "kev.json").write_text(
            json.dumps(
                {
                    "catalogVersion": "2025.03.19",
                    "dateReleased": "2025-03-19T00:00:00Z",
                    "count": 2,
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2024-0001",
                            "vendorProject": "Example",
                            "product": "Product",
                            "vulnerabilityName": "Known exploited example",
                            "shortDescription": "KEV historical description",
                            "requiredAction": "Apply the vendor update",
                            "notes": "Approved historical catalogue",
                            "dateAdded": "2024-04-01",
                            "dueDate": "2024-04-22",
                            "knownRansomwareCampaignUse": "Known",
                            "cwes": ["CWE-79"],
                        },
                        {
                            "cveID": "CVE-2024-0004",
                            "dateAdded": "2024-05-01",
                            "dueDate": "2024-05-22",
                            "knownRansomwareCampaignUse": "Unknown",
                            "cwes": [],
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        (relationships / "rel-cve-kev.json").write_text(
            json.dumps(["CVE-2024-0001", "CVE-2024-0005"]),
            encoding="utf-8",
        )

        self.config = self.root / "sources.yaml"
        self.config.write_text(
            "\n".join(
                (
                    "sources:",
                    "  vulzoo:",
                    "    url: https://example.invalid/VulZoo",
                    '    retrieval_date: "2026-08-14"',
                    '    snapshot_date: "2024-07-06"',
                    '    snapshot_date_note: "README index date only"',
                    '    checksum: "git:test"',
                    "    local_relative_path: VulZoo",
                    "    enabled: true",
                    "",
                )
            ),
            encoding="utf-8",
        )
        self.database = initialise_database(self.root / "databases" / "thesis.sqlite")
        self.report = self.root / "coverage.json"
        self.refresh_report()

    def refresh_report(self) -> None:
        self.report.write_text(json.dumps(scan_vulzoo_coverage(self.config)), encoding="utf-8")

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        return connection

    def test_ingestion_normalises_all_sources_and_preserves_metric_providers(self) -> None:
        result = ingest_vulzoo(self.config, self.database, self.report)
        connection = self.connect()

        self.assertEqual(result["contract"], "vulzoo-ingestion-v1")
        self.assertEqual(
            result["source_counts"]["nvd"], {"accepted_records": 1, "rejected_records": 2}
        )
        self.assertEqual(result["source_counts"]["legacy_cve"]["accepted_records"], 2)
        self.assertEqual(result["source_counts"]["cisa_kev"]["accepted_records"], 2)
        self.assertEqual(result["retrieved_at_utc"], "2026-08-14T23:59:59Z")
        self.assertEqual(
            result["new_rows"],
            {
                "cpe": 1,
                "cve": 3,
                "cve_cpe": 2,
                "cve_cwe": 1,
                "cvss_observation": 2,
                "cwe": 1,
                "kev_observation": 2,
            },
        )
        self.assertEqual(
            result["kev_reconciliation"], {"catalogue_only": 1, "relationship_only": 1}
        )
        self.assertFalse(result["scope"]["epss_ingested"])
        self.assertFalse(result["scope"]["exploit_references_ingested"])

        cve = connection.execute(
            """
            SELECT description, published_at_utc, modified_at_utc,
                   vulnerability_status, source_name
            FROM cve WHERE cve_id = ?
            """,
            ("CVE-2024-0001",),
        ).fetchone()
        self.assertEqual(
            cve,
            (
                "NVD primary description",
                "2024-01-01T10:30:00Z",
                "2024-02-01T11:45:00Z",
                "Analyzed",
                "nvd",
            ),
        )
        providers = connection.execute(
            "SELECT metric_source FROM cvss_observation ORDER BY metric_source"
        ).fetchall()
        self.assertEqual(providers, [("nvd@nist.gov",), ("vendor@example.invalid",)])
        self.assertEqual(connection.execute("SELECT cwe_id FROM cwe").fetchall(), [("CWE-79",)])
        self.assertEqual(
            connection.execute(
                "SELECT version_end_excluding FROM cve_cpe ORDER BY version_end_excluding"
            ).fetchall(),
            [("2.0",), ("3.0",)],
        )
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM epss_observation").fetchone(), (0,)
        )
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM exploit_reference").fetchone(), (0,)
        )
        self.assertEqual(
            connection.execute("SELECT status FROM ingestion_run").fetchone(), ("succeeded",)
        )
        rejection_text = json.dumps(
            connection.execute(
                "SELECT source_relative_path, reason_code FROM ingestion_rejection"
            ).fetchall()
        )
        self.assertNotIn("NVD primary description", rejection_text)
        self.assertNotIn("Legacy must not replace NVD", rejection_text)
        self.assertNotIn(str(self.root), rejection_text)

    def test_repeated_ingestion_is_idempotent_and_records_separate_runs(self) -> None:
        first = ingest_vulzoo(self.config, self.database, self.report)
        second = ingest_vulzoo(self.config, self.database, self.report)
        connection = self.connect()

        self.assertEqual(first["input_fingerprint_sha256"], second["input_fingerprint_sha256"])
        self.assertNotEqual(first["ingestion_run_id"], second["ingestion_run_id"])
        self.assertEqual(second["new_rows"], {})
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM source_snapshot").fetchone(), (1,)
        )
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM ingestion_run").fetchone(), (2,))
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM cve").fetchone(), (3,))
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM cvss_observation").fetchone(), (2,)
        )
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM kev_observation").fetchone(), (2,)
        )
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM ingestion_rejection").fetchone(), (4,)
        )

    def test_changed_source_fingerprint_rolls_back_technical_rows(self) -> None:
        document = json.loads(self.nvd_file.read_text(encoding="utf-8"))
        document["descriptions"][0]["value"] = "Changed after coverage approval"
        self.nvd_file.write_text(json.dumps(document), encoding="utf-8")

        with self.assertRaisesRegex(RuntimeError, "fingerprint changed"):
            ingest_vulzoo(self.config, self.database, self.report)

        connection = self.connect()
        for table in (
            "cve",
            "cvss_observation",
            "kev_observation",
            "cwe",
            "cpe",
            "cve_cwe",
            "cve_cpe",
            "ingestion_rejection",
        ):
            self.assertEqual(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone(), (0,))
        self.assertEqual(
            connection.execute("SELECT status FROM ingestion_run").fetchall(), [("failed",)]
        )

    def test_invalid_metric_is_rejected_without_discarding_the_cve(self) -> None:
        document = json.loads(self.nvd_file.read_text(encoding="utf-8"))
        document["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"] = "UNKNOWN"
        self.nvd_file.write_text(json.dumps(document), encoding="utf-8")
        self.refresh_report()

        result = ingest_vulzoo(self.config, self.database, self.report)
        connection = self.connect()

        self.assertEqual(result["source_counts"]["nvd"]["accepted_records"], 1)
        self.assertEqual(result["new_rows"]["cvss_observation"], 1)
        self.assertEqual(
            result["bounded_rejections"]["reason_counts"],
            {
                "cvss_invalid_base_severity": 1,
                "json_parse_error": 1,
                "nvd_filename_id_mismatch": 1,
            },
        )
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM cve").fetchone(), (3,))

    def test_coverage_contract_and_database_location_are_enforced(self) -> None:
        report = json.loads(self.report.read_text(encoding="utf-8"))
        report["scope"]["network_accessed"] = True
        self.report.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "approved data boundary"):
            ingest_vulzoo(self.config, self.database, self.report)

        self.refresh_report()
        outside = Path(tempfile.gettempdir()) / f"outside-{self.root.name}.sqlite"
        with self.assertRaisesRegex(ValueError, "beneath THESIS_DATA_ROOT"):
            ingest_vulzoo(self.config, outside, self.report)

    def test_cli_emits_metadata_only_ingestion_summary(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(
                [
                    "ingest-vulzoo",
                    "--config",
                    str(self.config),
                    "--database",
                    str(self.database),
                    "--coverage-report",
                    str(self.report),
                    "--progress-every",
                    "0",
                ]
            )

        report = json.loads(output.getvalue())
        self.assertEqual(result, 0)
        self.assertEqual(report["status"], "succeeded")
        self.assertNotIn("NVD primary description", output.getvalue())
        self.assertNotIn(str(self.root), output.getvalue())


if __name__ == "__main__":
    unittest.main()
