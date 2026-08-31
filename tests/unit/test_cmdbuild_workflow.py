from pathlib import Path

from thesis_pipeline.cli import build_parser
from thesis_pipeline.cmdbuild.workflow import (
    WORKFLOW_CONTRACT,
    build_cmdbuild_plans,
)

ROOT = Path(__file__).resolve().parents[2]


def test_versioned_cmdbuild_workflow_rebuilds_approved_business_contract() -> None:
    plans = build_cmdbuild_plans(
        scenario_path=ROOT / "configs/scenarios/smoke.yaml",
        mapping_path=ROOT / "config/cmdbuild_fields.json",
        simulation_contract_path=ROOT / "config/simulation.json",
    )

    assert WORKFLOW_CONTRACT == "cmdbuild-reproducible-workflow-v1"
    assert plans.dataset.fingerprint == (
        "f2f4889ae4431e88d1c169598d0d357dd97dc176783b6c5d4fcc70904f9e65ca"
    )
    assert plans.business.fingerprint == (
        "862dfe848a8d566adb4e896bad5906f91e6bb123ebfe383fc343366c6988c4ef"
    )
    assert len(plans.dataset.findings) == 240
    assert len(plans.business.cards) == 234
    assert len(plans.business.relations) == 260


def test_cli_exposes_all_versioned_cmdbuild_entry_points() -> None:
    parser = build_parser()

    preview = parser.parse_args(["cmdbuild-preview"])
    business = parser.parse_args(
        ["cmdbuild-ingest-business", "--expected-fingerprint", "a" * 64]
    )
    operational = parser.parse_args(
        [
            "cmdbuild-ingest-operational",
            "--database",
            "vulzoo-ingestion.sqlite",
            "--expected-fingerprint",
            "b" * 64,
        ]
    )
    evidence = parser.parse_args(
        [
            "cmdbuild-export-evidence",
            "--database",
            "vulzoo-ingestion.sqlite",
            "--output",
            "evidence.json",
        ]
    )

    assert preview.command == "cmdbuild-preview"
    assert business.command == "cmdbuild-ingest-business"
    assert operational.command == "cmdbuild-ingest-operational"
    assert evidence.command == "cmdbuild-export-evidence"
