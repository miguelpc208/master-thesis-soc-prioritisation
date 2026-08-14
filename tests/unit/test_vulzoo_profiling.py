import json
from pathlib import Path

import pytest

from thesis_pipeline.ingestion.profiling import profile_vulzoo


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


def test_profile_classifies_data_without_raw_content(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("THESIS_DATA_ROOT", str(tmp_path))

    root = tmp_path / "VulZoo"
    nvd = root / "processed" / "nvd-database"
    mail = root / "processed" / "bugtraq-database"
    patch = root / "processed" / "patch-database"
    relationships = root / "processed" / "relationships"
    exploit_db = root / "processed" / "exploit-db-database"

    for directory in (nvd, mail, patch, relationships, exploit_db):
        directory.mkdir(parents=True)

    (nvd / "CVE-TEST.json").write_text(
        json.dumps({"id": "CVE-TEST", "metrics": {}}),
        encoding="utf-8",
    )
    (mail / "message").write_text(
        "Date: today\nFrom: sender\nSubject: test\n\nBody not exported.",
        encoding="utf-8",
    )
    (patch / "commit").write_text(
        "diff --git a/file b/file\n--- a/file\n+++ b/file\n",
        encoding="utf-8",
    )
    (relationships / "rel-cve-kev.json").write_text(
        json.dumps(["CVE-TEST"]),
        encoding="utf-8",
    )
    (exploit_db / "payload.py").write_text(
        "content that must never be profiled",
        encoding="utf-8",
    )

    config = tmp_path / "data_sources.yaml"
    _write_config(config)

    profile = profile_vulzoo(config)

    collections = {
        collection["name"]: collection
        for collection in profile["collections"]
    }

    assert profile["source"]["readme_snapshot_note"] == "test index date only"
    assert profile["scope"]["raw_content_included"] is False
    assert profile["scope"]["files_executed"] is False
    assert "exploit-db-database" not in collections
    assert "Body not exported." not in json.dumps(profile)
    assert "content that must never be profiled" not in json.dumps(profile)
    assert collections["bugtraq-database"]["samples"][0]["format"] == "rfc822_like"
    assert collections["patch-database"]["samples"][0]["format"] == "git_diff"
    assert collections["nvd-database"]["samples"][0]["status"] == "parsed"
    assert profile["relationship_contracts"][0]["record_count"] == 1
    assert profile == profile_vulzoo(config)


def test_profile_respects_json_size_limit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("THESIS_DATA_ROOT", str(tmp_path))

    collection = (
        tmp_path
        / "VulZoo"
        / "processed"
        / "large-json-database"
    )
    collection.mkdir(parents=True)

    (collection / "large.json").write_text(
        json.dumps({"payload": "x" * 200}),
        encoding="utf-8",
    )

    config = tmp_path / "data_sources.yaml"
    _write_config(config)

    profile = profile_vulzoo(
        config,
        sample_limit=1,
        max_json_bytes=50,
    )

    sample = profile["collections"][0]["samples"][0]
    assert sample["status"] == "skipped_size_limit"


def test_profile_rejects_unbounded_parameters() -> None:
    with pytest.raises(ValueError, match="sample_limit"):
        profile_vulzoo("unused.yaml", sample_limit=101)

    with pytest.raises(ValueError, match="max_json_bytes"):
        profile_vulzoo(
            "unused.yaml",
            max_json_bytes=(100 * 1024 * 1024) + 1,
        )
