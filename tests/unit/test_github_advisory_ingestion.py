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
from thesis_pipeline.ingestion.advisories import ingest_github_advisories
from thesis_pipeline.quality.evidence_as_of import audit_technical_evidence_as_of
from thesis_pipeline.storage.schema import initialise_database


class GithubAdvisoryIngestionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        environment = patch.dict(os.environ, {"THESIS_DATA_ROOT": str(self.root)})
        environment.start()
        self.addCleanup(environment.stop)
        self.vulzoo = self.root / "VulZoo"
        self.relationships = self.vulzoo / "processed" / "relationships"
        self.relationships.mkdir(parents=True)
        self.advisory_root = self.vulzoo / "processed" / "github-advisory-database"
        self.advisory_root.mkdir()
        self.commit = "a" * 40
        self.tree = "b" * 40
        self.first_patch = "1234567890abcdef1234567890abcdef12345678"
        self.second_patch = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
        self.unmatched_patch = "0123456789012345678901234567890123456789"
        self.decision = "2025-03-22T09:00:00Z"
        self.retrieved = "2026-08-24T20:31:11Z"
        self.config = self.root / "sources.yaml"
        self.manifest = self.root / "manifest.json"
        self.audit = self.root / "audit.json"
        self.database = initialise_database(self.root / "databases" / "thesis.sqlite")
        with contextlib.closing(sqlite3.connect(self.database)) as connection, connection:
            for index in range(1, 7):
                connection.execute(
                    "INSERT INTO cve(cve_id, source_name, retrieved_at_utc, created_at_utc) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        f"CVE-2024-{index:04d}",
                        "nvd",
                        self.retrieved,
                        self.retrieved,
                    ),
                )
        self._write_sources()

    def _advisory(
        self,
        ghsa: str,
        cve: str,
        *,
        aliases: list[str] | None = None,
        published: str = "2024-01-01T00:00:00Z",
        modified: str = "2025-02-01T00:00:00Z",
        withdrawn: str | None = None,
        references: list[str] | None = None,
        affected: list[dict] | None = None,
    ) -> str:
        relative = f"github-advisory-database/2024/01/{ghsa}/{ghsa}.json"
        path = self.vulzoo / "processed" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "id": ghsa,
            "aliases": aliases if aliases is not None else [cve],
            "published": published,
            "modified": modified,
            "affected": affected or [],
            "references": [{"type": "WEB", "url": url} for url in references or []],
            "database_specific": {"severity": "HIGH"},
            "details": "RAW ADVISORY DESCRIPTION MUST NEVER BE PERSISTED",
            "summary": "RAW SUMMARY MUST NEVER BE PERSISTED",
        }
        if withdrawn is not None:
            payload["withdrawn"] = withdrawn
        path.write_text(json.dumps(payload), encoding="utf-8")
        return relative

    def _write_sources(self) -> None:
        first_url = f"https://github.com/acme/project/commit/{self.first_patch}"
        second_url = f"https://github.com/acme/project/commit/{self.second_patch}"
        first_packages = [
            {
                "package": {
                    "ecosystem": "PyPI",
                    "name": "acme",
                    "purl": "pkg:pypi/acme",
                },
                "versions": ["1.0", "1.1"],
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.0"}],
                    }
                ],
            }
        ]
        second_packages = [
            {
                "package": {"ecosystem": "Maven", "name": "org.acme:demo"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0"}, {"fixed": "3.0"}],
                    }
                ],
            }
        ]
        advisory_relationships = {
            "CVE-2024-0001": [
                self._advisory(
                    "GHSA-aaaa-bbbb-cccc",
                    "CVE-2024-0001",
                    references=[first_url],
                    affected=first_packages,
                )
            ],
            "CVE-2024-0002": [
                self._advisory(
                    "GHSA-dddd-eeee-ffff",
                    "CVE-2024-0002",
                    published="2025-02-02T00:00:00Z",
                    modified="2025-02-01T00:00:00Z",
                    references=["https://github.com/acme/project/issues/1"],
                    affected=second_packages,
                )
            ],
            "CVE-2024-0003": [
                self._advisory(
                    "GHSA-gggg-hhhh-iiii",
                    "CVE-2024-0003",
                    withdrawn="2025-01-01T00:00:00Z",
                )
            ],
            "CVE-2024-0004": [
                self._advisory(
                    "GHSA-jjjj-kkkk-llll",
                    "CVE-2024-0004",
                    aliases=["CVE-2024-0001"],
                )
            ],
            "CVE-2024-0005": [
                self._advisory(
                    "GHSA-mmmm-nnnn-oooo",
                    "CVE-2024-0005",
                    published="2025-04-01T00:00:00Z",
                    modified="2025-04-01T01:00:00Z",
                )
            ],
            "CVE-2024-0006": [
                self._advisory(
                    "GHSA-pppp-qqqq-rrrr",
                    "CVE-2024-0006",
                    modified="2025-04-01T00:00:00Z",
                )
            ],
            "CVE-2024-9999": [
                self._advisory("GHSA-ssss-tttt-uuuu", "CVE-2024-9999")
            ],
        }
        documents = {
            "patch_urls": (
                "temp-nvd-patch-links.json",
                {
                    "CVE-2024-0001": [first_url, first_url],
                    "CVE-2024-0002": [second_url],
                },
            ),
            "patch_hashes": (
                "rel-cve-patch.json",
                {
                    "CVE-2024-0001": [
                        self.first_patch.upper(),
                        self.first_patch,
                        self.unmatched_patch,
                    ],
                    "CVE-2024-0002": [self.second_patch],
                },
            ),
            "github_advisories": (
                "rel-cve-github-advisory.json",
                advisory_relationships,
            ),
        }
        source_files = {}
        for role, (name, payload) in documents.items():
            path = self.relationships / name
            path.write_text(json.dumps(payload), encoding="utf-8")
            source_files[role] = {
                "relative_path": path.relative_to(self.vulzoo).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "dictionary_keys": len(payload),
            }

        sources = {
            "sources": {
                "vulzoo": {
                    "url": "https://github.com/NUS-Curiosity/VulZoo",
                    "local_relative_path": "VulZoo",
                    "checksum": f"git-commit-sha1:{self.commit}",
                    "enabled": True,
                },
                "github_advisory": {
                    "upstream_commit": self.commit,
                    "checksum": f"git-tree-sha1:{self.tree}",
                    "enabled": True,
                },
            }
        }
        self.config.write_text(yaml.safe_dump(sources), encoding="utf-8")
        manifest = {
            "contract": "vulzoo-github-advisory-acquisition-v1",
            "acquired_at_utc": self.retrieved,
            "vulzoo_commit": self.commit,
            "collection": "processed/github-advisory-database",
            "git_tree_object": self.tree,
            "file_count": 7,
            "patch_payloads_acquired": False,
            "exploit_payloads_acquired": False,
        }
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        audit = {
            "contract": "vulzoo-patch-advisory-audit-v1",
            "decision_at_utc": self.decision,
            "vulzoo_commit": self.commit,
            "input_fingerprint_sha256": "c" * 64,
            "scope": {
                "database_mutated": False,
                "dataset_mutated": False,
                "network_accessed": False,
                "patch_payloads_read": False,
                "exploit_payloads_read": False,
                "raw_advisory_bodies_included": False,
                "raw_source_records_included": False,
                "optional_collections_acquired": False,
            },
            "source_files": source_files,
            "database": {"counts": {"canonical_cves": 6}},
            "github_advisories": {
                "metadata_collection_present": True,
                "raw_references": 7,
                "cve_alias_verified_links": 6,
                "cve_alias_mismatch_links": 1,
                "metadata_date_counts": {"withdrawn_advisories": 1},
            },
            "patch_hashes": {"corroborated_by_same_cve_commit_url": 2},
        }
        self.audit.write_text(json.dumps(audit), encoding="utf-8")

    def _ingest(self) -> dict:
        return ingest_github_advisories(
            self.config,
            self.database,
            self.manifest,
            self.audit,
            self.decision,
        )

    def _connection(self) -> contextlib.AbstractContextManager[sqlite3.Connection]:
        return contextlib.closing(sqlite3.connect(self.database))

    def test_validated_advisories_preserve_packages_versions_and_commit_provenance(self) -> None:
        result = self._ingest()
        with self._connection() as connection:
            advisories = connection.execute(
                "SELECT ghsa_id, published_at_utc, modified_at_utc, "
                "source_available_at_utc "
                "FROM github_advisory ORDER BY ghsa_id"
            ).fetchall()
            packages = connection.execute(
                "SELECT ecosystem, package_name FROM github_advisory_package ORDER BY ecosystem"
            ).fetchall()
            fixed = connection.execute(
                "SELECT event_value FROM github_advisory_version_event "
                "WHERE event_kind = 'fixed' ORDER BY event_value"
            ).fetchall()
            affected_versions = connection.execute(
                "SELECT version FROM github_advisory_affected_version ORDER BY source_position"
            ).fetchall()
            patches = connection.execute(
                "SELECT cve_id, commit_sha, evidence_time_status, published_at_utc "
                "FROM patch_reference ORDER BY cve_id"
            ).fetchall()

        self.assertEqual(result["contract"], "vulzoo-github-advisory-remediation-v2")
        self.assertEqual(
            advisories,
            [
                (
                    "GHSA-AAAA-BBBB-CCCC",
                    "2024-01-01T00:00:00Z",
                    "2025-02-01T00:00:00Z",
                    "2025-02-01T00:00:00Z",
                ),
                (
                    "GHSA-DDDD-EEEE-FFFF",
                    "2025-02-02T00:00:00Z",
                    "2025-02-01T00:00:00Z",
                    "2025-02-02T00:00:00Z",
                ),
            ],
        )
        self.assertEqual(packages, [("Maven", "org.acme:demo"), ("PyPI", "acme")])
        self.assertEqual(fixed, [("2.0",), ("3.0",)])
        self.assertEqual(affected_versions, [("1.0",), ("1.1",)])
        self.assertEqual(
            patches,
            [
                (
                    "CVE-2024-0001",
                    self.first_patch,
                    "authoritative_advisory_available",
                    "2025-02-01T00:00:00Z",
                ),
                ("CVE-2024-0002", self.second_patch, "undated_context_only", None),
            ],
        )
        self.assertEqual(result["patches"]["temporally_anchored"], 1)
        self.assertEqual(result["patches"]["undated_context_only"], 1)
        self.assertEqual(result["patches"]["unmatched_hashes_excluded"], 1)

    def test_late_publication_recovers_advisory_and_reanchors_existing_commit(self) -> None:
        first = self._ingest()
        self.assertEqual(first["patches"]["undated_context_only"], 1)

        advisory_path = (
            self.advisory_root
            / "2024"
            / "01"
            / "GHSA-dddd-eeee-ffff"
            / "GHSA-dddd-eeee-ffff.json"
        )
        document = json.loads(advisory_path.read_text(encoding="utf-8"))
        document["references"] = [
            {
                "type": "WEB",
                "url": (
                    "https://github.com/acme/project/commit/"
                    f"{self.second_patch}"
                ),
            }
        ]
        advisory_path.write_text(json.dumps(document), encoding="utf-8")

        second = self._ingest()
        with self._connection() as connection:
            patch_row = connection.execute(
                """
                SELECT evidence_time_status, published_at_utc,
                       anchor_github_advisory_id
                FROM patch_reference
                WHERE cve_id = 'CVE-2024-0002'
                """
            ).fetchone()

        self.assertEqual(second["patches"]["reanchored_from_context_only"], 1)
        self.assertEqual(second["patches"]["temporally_anchored"], 2)
        self.assertEqual(second["patches"]["undated_context_only"], 0)
        self.assertEqual(patch_row[0], "authoritative_advisory_available")
        self.assertEqual(patch_row[1], "2025-02-02T00:00:00Z")
        self.assertIsNotNone(patch_row[2])

    def test_withdrawn_conflicting_unknown_and_future_advisories_are_rejected(self) -> None:
        result = self._ingest()
        reasons = result["bounded_rejections"]["reason_counts"]
        self.assertEqual(reasons["advisory_withdrawn"], 1)
        self.assertEqual(reasons["advisory_cve_alias_mismatch"], 1)
        self.assertEqual(reasons["advisory_cve_not_in_vulzoo_snapshot"], 1)
        self.assertEqual(reasons["advisory_published_after_decision"], 1)
        self.assertEqual(reasons["advisory_modified_after_decision"], 1)
        self.assertEqual(result["bounded_rejections"]["count"], 5)
        with self._connection() as connection:
            count = connection.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
            withdrawn = connection.execute(
                "SELECT COUNT(*) FROM github_advisory WHERE withdrawn_at_utc IS NOT NULL"
            ).fetchone()[0]
        self.assertEqual(count, 6)
        self.assertEqual(withdrawn, 0)

    def test_undated_commits_are_excluded_from_historical_reconstruction(self) -> None:
        self._ingest()
        reconstruction = audit_technical_evidence_as_of(
            self.database,
            self.decision,
            mode="source_effective_reconstruction",
        )
        strict = audit_technical_evidence_as_of(
            self.database,
            self.decision,
            mode="strict_snapshot",
        )
        reconstructed = {row["evidence_kind"]: row for row in reconstruction["evidence"]}
        strict_rows = {row["evidence_kind"]: row for row in strict["evidence"]}
        self.assertEqual(reconstructed["github_advisory"]["reconstruction_eligible"], 2)
        self.assertEqual(
            reconstructed["github_advisory_fixed_version"]["reconstruction_eligible"], 2
        )
        self.assertEqual(
            reconstructed["corroborated_patch_commit"]["reconstruction_eligible"], 1
        )
        self.assertEqual(reconstructed["corroborated_patch_commit"]["missing_effective_time"], 1)
        self.assertEqual(strict_rows["github_advisory"]["strict_snapshot_eligible"], 0)
        self.assertEqual(strict_rows["corroborated_patch_commit"]["strict_snapshot_eligible"], 0)

    def test_repeated_ingestion_is_idempotent_and_retains_separate_runs(self) -> None:
        first = self._ingest()
        second = self._ingest()
        with self._connection() as connection:
            counts = {
                table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "source_snapshot",
                    "ingestion_run",
                    "github_advisory",
                    "github_advisory_cve",
                    "github_advisory_package",
                    "github_advisory_version_event",
                    "patch_reference",
                )
            }
        self.assertEqual(first["new_rows"]["github_advisory"], 2)
        self.assertEqual(second["new_rows"], {})
        self.assertEqual(counts["source_snapshot"], 1)
        self.assertEqual(counts["ingestion_run"], 2)
        self.assertEqual(counts["github_advisory"], 2)
        self.assertEqual(counts["github_advisory_cve"], 2)
        self.assertEqual(counts["github_advisory_package"], 2)
        self.assertEqual(counts["github_advisory_version_event"], 4)
        self.assertEqual(counts["patch_reference"], 2)

    def test_changed_relationship_is_rejected_before_a_database_run(self) -> None:
        relation = self.relationships / "rel-cve-patch.json"
        relation.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "changed after auditing"):
            self._ingest()
        with self._connection() as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM ingestion_run").fetchone(),
                (0,),
            )

    def test_invalid_source_tree_or_unsafe_audit_is_rejected(self) -> None:
        manifest = json.loads(self.manifest.read_text())
        manifest["git_tree_object"] = "d" * 40
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Git tree"):
            self._ingest()

        self._write_sources()
        audit = json.loads(self.audit.read_text())
        audit["scope"]["network_accessed"] = True
        self.audit.write_text(json.dumps(audit), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "read-only"):
            self._ingest()

    def test_audit_mismatch_rolls_back_all_accepted_rows_and_marks_failed_run(self) -> None:
        audit = json.loads(self.audit.read_text())
        audit["patch_hashes"]["corroborated_by_same_cve_commit_url"] = 999
        self.audit.write_text(json.dumps(audit), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "Corroborated patch"):
            self._ingest()
        with self._connection() as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM github_advisory").fetchone(),
                (0,),
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM patch_reference").fetchone(),
                (0,),
            )
            self.assertEqual(
                connection.execute("SELECT status FROM ingestion_run").fetchall(),
                [("failed",)],
            )

    def test_no_raw_advisory_body_or_exploit_reference_is_persisted(self) -> None:
        result = self._ingest()
        encoded = json.dumps(result)
        self.assertNotIn("RAW ADVISORY DESCRIPTION", encoded)
        self.assertFalse(result["scope"]["raw_advisory_bodies_persisted"])
        self.assertFalse(result["scope"]["exploit_payloads_read"])
        with self._connection() as connection:
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(github_advisory)")
            }
            self.assertNotIn("details", columns)
            self.assertNotIn("summary", columns)
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM exploit_reference").fetchone(),
                (0,),
            )

    def test_patch_anchor_trigger_rejects_inconsistent_advisory_time(self) -> None:
        self._ingest()
        with self._connection() as connection, connection:
            connection.execute("PRAGMA foreign_keys = ON")
            snapshot, run = connection.execute(
                "SELECT source_snapshot_id, ingestion_run_id FROM github_advisory LIMIT 1"
            ).fetchone()
            advisory = connection.execute(
                "SELECT github_advisory_id FROM github_advisory_cve "
                "WHERE cve_id = 'CVE-2024-0001'"
            ).fetchone()[0]
            with self.assertRaisesRegex(sqlite3.IntegrityError, "advisory anchor"):
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
                        "patch:invalid",
                        "CVE-2024-0001",
                        "https://github.com/acme/project/commit/" + ("f" * 40),
                        "2020-01-01T00:00:00Z",
                        "vulzoo_corroborated_patch",
                        self.retrieved,
                        self.retrieved,
                        snapshot,
                        run,
                        "f" * 40,
                        "corroborated_commit",
                        "authoritative_advisory_available",
                        advisory,
                    ),
                )

    def test_cli_returns_a_metadata_only_ingestion_report(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main(
                [
                    "ingest-github-advisories",
                    "--config",
                    str(self.config),
                    "--database",
                    str(self.database),
                    "--acquisition-manifest",
                    str(self.manifest),
                    "--audit-report",
                    str(self.audit),
                    "--decision-at",
                    self.decision,
                ]
            )
        result = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(result["advisories"]["accepted_advisories"], 2)
        self.assertEqual(result["patches"]["corroborated_commit_references"], 2)
        self.assertFalse(result["scope"]["historical_ground_truth_claimed"])
