import json
from pathlib import Path

import pytest

from thesis_pipeline.ingestion.coverage import (
    MAX_JSON_COVERAGE_BYTES,
    MAX_REJECTION_SAMPLE_LIMIT,
    scan_vulzoo_coverage,
)


def _write_config(path: Path) -> None:
    path.write_text(
        """
sources:
  vulzoo:
    url: https://example.invalid/VulZoo
    retrieval_date: "2026-08-14"
    snapshot_date: "2024-07-06"
    snapshot_date_note: "test index date only"
    checksum: "git:test"
    local_relative_path: VulZoo
    enabled: true
""".lstrip(),
        encoding="utf-8",
    )


def _build_fixture(root: Path) -> Path:
    nvd = root / "processed" / "nvd-database" / "CVE-2024" / "CVE-2024-00xx"
    legacy_cve = root / "processed" / "cve-database" / "2024" / "0xxx"
    kev = root / "processed" / "cisa-kev-database"
    relationships = root / "processed" / "relationships"

    for directory in (nvd, legacy_cve, kev, relationships):
        directory.mkdir(parents=True)

    (nvd / "CVE-2024-0001.json").write_text(
        json.dumps(
            {
                "id": "CVE-2024-0001",
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2024-02-01T00:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "raw nvd text must not leak"}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "baseScore": 9.8,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            },
                        }
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
                                        "criteria": "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
                                    }
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
                "published": "2024-03-01T00:00:00Z",
                "lastModified": "2024-03-02T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (nvd / "CVE-2024-0006.json").write_text(
        "{not valid json",
        encoding="utf-8",
    )

    for cve_id, state, date_public, description_data in (
        (
            "CVE-2024-0001",
            "PUBLIC",
            "2024-01-01",
            [{"lang": "eng", "value": "raw legacy text must not leak"}],
        ),
        ("CVE-2024-0003", "RESERVED", None, []),
    ):
        metadata = {"ID": cve_id, "STATE": state}
        if date_public is not None:
            metadata["DATE_PUBLIC"] = date_public
        (legacy_cve / f"{cve_id}.json").write_text(
            json.dumps(
                {
                    "CVE_data_meta": metadata,
                    "data_version": "4.0",
                    "description": {"description_data": description_data},
                    "problemtype": {"problemtype_data": []},
                }
            ),
            encoding="utf-8",
        )

    (kev / "kev.json").write_text(
        json.dumps(
            {
                "catalogVersion": "test",
                "dateReleased": "2025-03-19T00:00:00Z",
                "count": 2,
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2024-0001",
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

    return root


def test_scan_reports_temporal_coverage_without_raw_records(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("THESIS_DATA_ROOT", str(tmp_path))
    _build_fixture(tmp_path / "VulZoo")
    config = tmp_path / "data_sources.yaml"
    _write_config(config)

    report = scan_vulzoo_coverage(config)
    serialised = json.dumps(report, sort_keys=True)

    assert report == scan_vulzoo_coverage(config)
    assert report["nvd"]["files_seen"] == 3
    assert report["nvd"]["accepted_records"] == 1
    assert report["nvd"]["rejected_records"] == 2
    assert report["nvd"]["published_at_utc"] == {
        "minimum": "2024-01-01T00:00:00Z",
        "maximum": "2024-01-01T00:00:00Z",
    }
    assert report["nvd"]["datetime_interpretation_counts"] == {
        "last_modified_naive_assumed_utc": 1,
        "published_naive_assumed_utc": 1,
    }
    assert report["nvd"]["cvss_version_counts"] == {"3.1": 1}
    assert report["nvd"]["cwe_counts"] == {"placeholder": 1, "valid": 1}
    assert report["nvd"]["cwe_record_counts"] == {
        "with_placeholder_cwe": 1,
        "with_valid_cwe": 1,
    }
    assert report["nvd"]["cpe_match_count"] == 1
    assert report["nvd"]["cpe_record_counts"] == {"with_cpe_match": 1}
    assert report["legacy_cve"]["accepted_records"] == 2
    assert report["cisa_kev"]["declared_count"] == 2
    assert report["cisa_kev"]["accepted_records"] == 2
    assert report["cisa_kev"]["declared_count_matches_actual"] is True
    assert report["cisa_kev"]["date_released_utc"] == "2025-03-19T00:00:00Z"
    assert report["cisa_kev"]["quality_counts"] == {}
    assert report["cross_source"] == {
        "nvd_legacy_cve_intersection": 1,
        "nvd_only": 0,
        "legacy_cve_only": 1,
        "kev_missing_nvd": 1,
        "kev_missing_legacy_cve": 1,
        "kev_catalogue_only": 1,
        "kev_relationship_only": 1,
    }
    assert report["rejections"]["reason_counts"] == {
        "json_parse_error": 1,
        "nvd_filename_id_mismatch": 1,
    }
    assert report["totals"] == {
        "files_seen": 7,
        "accepted_source_records": 5,
        "rejected_source_records": 2,
    }
    assert len(report["input_fingerprint_sha256"]) == 64
    assert report["policy"]["contract"] == "vulzoo-coverage-v2"
    assert report["policy"]["nvd_naive_datetime_interpretation"] == (
        "UTC (NVD default GMT)"
    )
    assert report["scope"]["raw_records_included"] is False
    assert str(tmp_path) not in serialised
    assert "raw nvd text must not leak" not in serialised
    assert "raw legacy text must not leak" not in serialised


def test_scan_rejects_unbounded_parameters() -> None:
    with pytest.raises(ValueError, match="max_json_bytes"):
        scan_vulzoo_coverage("unused.yaml", max_json_bytes=0)

    with pytest.raises(ValueError, match="max_json_bytes"):
        scan_vulzoo_coverage(
            "unused.yaml",
            max_json_bytes=MAX_JSON_COVERAGE_BYTES + 1,
        )

    with pytest.raises(ValueError, match="rejection_sample_limit"):
        scan_vulzoo_coverage("unused.yaml", rejection_sample_limit=-1)

    with pytest.raises(ValueError, match="rejection_sample_limit"):
        scan_vulzoo_coverage(
            "unused.yaml",
            rejection_sample_limit=MAX_REJECTION_SAMPLE_LIMIT + 1,
        )


def test_scan_rejects_source_path_outside_data_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("THESIS_DATA_ROOT", str(tmp_path / "approved"))
    outside = tmp_path / "outside"
    outside.mkdir()
    config = tmp_path / "data_sources.yaml"
    _write_config(config)
    document = config.read_text(encoding="utf-8").replace(
        "local_relative_path: VulZoo",
        "local_relative_path: ../outside",
    )
    config.write_text(document, encoding="utf-8")

    with pytest.raises(ValueError, match="beneath THESIS_DATA_ROOT"):
        scan_vulzoo_coverage(config)
