"""Versioned reconstruction and execution entry points for the CMDBuild integration."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from thesis_pipeline.cmdbuild.business_payloads import (
    BusinessPayloadPlan,
    build_business_payload_plan,
)
from thesis_pipeline.cmdbuild.business_writer import (
    execute_business_ingestion,
    prepare_business_ingestion,
)
from thesis_pipeline.cmdbuild.client import CMDBuildClient, CMDBuildSettings
from thesis_pipeline.cmdbuild.operational_payloads import (
    OperationalPayloadPlan,
    build_operational_payload_plan,
)
from thesis_pipeline.cmdbuild.operational_writer import (
    execute_operational_ingestion,
    prepare_operational_ingestion,
)
from thesis_pipeline.cmdbuild.public_cve import PublicCVEBindingResult, bind_public_cves
from thesis_pipeline.config import load_scenario
from thesis_pipeline.prioritisation.strategies import CvssStrategy
from thesis_pipeline.run import project_root
from thesis_pipeline.simulation.workflow import SimulationResult, simulate_workflow
from thesis_pipeline.synthetic_org.generator import SyntheticDataset, generate_dataset

WORKFLOW_CONTRACT = "cmdbuild-reproducible-workflow-v1"
MINIMUM_KEV = 4
OPERATIONAL_POLICY = "cvss"


@dataclass(frozen=True, slots=True)
class CMDBuildPlans:
    dataset: SyntheticDataset
    business: BusinessPayloadPlan
    binding: PublicCVEBindingResult | None
    simulation: SimulationResult | None
    operational: OperationalPayloadPlan | None
    mapping: dict[str, Any]


def _json_object(path: str | Path, label: str) -> dict[str, Any]:
    candidate = Path(path)
    try:
        document = json.loads(candidate.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"The {label} is missing or invalid") from exc
    if not isinstance(document, dict):
        raise ValueError(f"The {label} must contain a JSON object")
    return document


def build_cmdbuild_plans(
    *,
    scenario_path: str | Path,
    mapping_path: str | Path,
    simulation_contract_path: str | Path,
    database_path: str | Path | None = None,
) -> CMDBuildPlans:
    """Rebuild deterministic business plans and, when requested, operational plans."""
    scenario = load_scenario(scenario_path)
    mapping = _json_object(mapping_path, "CMDBuild mapping contract")
    simulation_contract = _json_object(
        simulation_contract_path, "CMDBuild simulation contract"
    )
    dataset = generate_dataset(scenario)
    business = build_business_payload_plan(
        dataset, scenario, mapping, simulation_contract
    )
    if database_path is None:
        return CMDBuildPlans(dataset, business, None, None, None, mapping)

    binding = bind_public_cves(
        dataset,
        scenario,
        database_path,
        minimum_kev=MINIMUM_KEV,
    )
    simulation = simulate_workflow(binding.findings, scenario, CvssStrategy())
    operational = build_operational_payload_plan(
        simulation,
        mapping,
        public_binding_fingerprint=binding.binding_fingerprint,
        policy=OPERATIONAL_POLICY,
    )
    return CMDBuildPlans(
        dataset, business, binding, simulation, operational, mapping
    )


def _client(env_file: str | Path) -> CMDBuildClient:
    client = CMDBuildClient(CMDBuildSettings.from_env_file(env_file))
    client.authenticate()
    return client


def _business_preview(preview: Any, plan: BusinessPayloadPlan) -> dict[str, Any]:
    return {
        "fingerprint_sha256": plan.fingerprint,
        "cards": len(plan.cards),
        "relations": len(plan.relations),
        "card_operations": dict(preview.card_operations),
        "relation_operations": dict(preview.relation_operations),
    }


def _operational_preview(preview: Any, plan: OperationalPayloadPlan) -> dict[str, Any]:
    return {
        "fingerprint_sha256": plan.fingerprint,
        "support_cards": len(plan.support_cards),
        "processes": len(plan.processes),
        "relations": len(plan.relations),
        "support_operations": dict(preview.support_operations),
        "process_operations": dict(preview.process_operations),
        "relation_operations": dict(preview.relation_operations),
    }


def preview_cmdbuild(
    plans: CMDBuildPlans,
    *,
    env_file: str | Path,
    phase: str,
) -> dict[str, Any]:
    """Inspect live CMDBuild state without invoking any mutation method."""
    if phase not in {"business", "operational", "all"}:
        raise ValueError("CMDBuild preview phase is invalid")
    if phase in {"operational", "all"} and plans.operational is None:
        raise ValueError("Operational preview requires the canonical SQLite database")
    client = _client(env_file)
    try:
        result: dict[str, Any] = {
            "contract": WORKFLOW_CONTRACT,
            "mode": "preview",
            "phase": phase,
            "source_dataset_fingerprint": plans.dataset.fingerprint,
            "cmdbuild_writes": 0,
            "sqlite_writes": 0,
        }
        if phase in {"business", "all"}:
            result["business"] = _business_preview(
                prepare_business_ingestion(client, plans.business, plans.mapping),
                plans.business,
            )
        if phase in {"operational", "all"}:
            assert plans.operational is not None
            result["operational"] = _operational_preview(
                prepare_operational_ingestion(client, plans.operational),
                plans.operational,
            )
            assert plans.binding is not None
            result["public_binding_fingerprint"] = plans.binding.binding_fingerprint
        return result
    finally:
        client.close()


def ingest_business_cmdbuild(
    plans: CMDBuildPlans,
    *,
    env_file: str | Path,
    expected_fingerprint: str,
) -> dict[str, Any]:
    """Run the existing rollback-capable business executor behind an exact fingerprint gate."""
    client = _client(env_file)
    try:
        result = execute_business_ingestion(
            client,
            plans.business,
            plans.mapping,
            expected_fingerprint=expected_fingerprint,
        )
        return {
            "contract": WORKFLOW_CONTRACT,
            "mode": "ingest",
            "phase": "business",
            "fingerprint_sha256": plans.business.fingerprint,
            "created_cards": len(result.created_cards),
            "created_relations": len(result.created_relations),
            "merge_performed": False,
        }
    finally:
        client.close()


def ingest_operational_cmdbuild(
    plans: CMDBuildPlans,
    *,
    env_file: str | Path,
    expected_fingerprint: str,
) -> dict[str, Any]:
    """Run the native operational executor behind an exact fingerprint gate."""
    if plans.operational is None:
        raise ValueError("Operational ingestion requires the canonical SQLite database")
    client = _client(env_file)
    try:
        result = execute_operational_ingestion(
            client,
            plans.operational,
            expected_fingerprint=expected_fingerprint,
        )
        return {
            "contract": WORKFLOW_CONTRACT,
            "mode": "ingest",
            "phase": "operational",
            "fingerprint_sha256": plans.operational.fingerprint,
            "created_support_cards": len(result.created_support_cards),
            "created_processes": len(result.created_processes),
            "created_relations": len(result.created_relations),
            "merge_performed": False,
        }
    finally:
        client.close()


def export_cmdbuild_evidence(
    plans: CMDBuildPlans,
    preview: dict[str, Any],
    output_path: str | Path,
) -> dict[str, Any]:
    """Write a deterministic, metadata-only evidence file outside the Git worktree."""
    output = Path(output_path).expanduser().resolve()
    root = project_root().resolve()
    if output == root or output.is_relative_to(root):
        raise ValueError("CMDBuild evidence must be written outside the Git repository")
    if output.exists():
        raise ValueError("CMDBuild evidence output already exists")
    if plans.operational is None or plans.binding is None or plans.simulation is None:
        raise ValueError("Complete evidence export requires operational plans")

    document = {
        "contract": WORKFLOW_CONTRACT,
        "source_dataset_fingerprint": plans.dataset.fingerprint,
        "business_payload_fingerprint": plans.business.fingerprint,
        "public_binding_fingerprint": plans.binding.binding_fingerprint,
        "operational_payload_fingerprint": plans.operational.fingerprint,
        "counts": {
            "raw_findings": len(plans.dataset.findings),
            "unique_occurrences": plans.simulation.correlated_case_count,
            "duplicate_findings": (
                len(plans.dataset.findings) - plans.simulation.correlated_case_count
            ),
            "actionable_occurrences": sum(
                record.finding.actionable for record in plans.simulation.records
            ),
            "selected_kev_occurrences": plans.binding.selected_kev_count,
            "business_cards": len(plans.business.cards),
            "business_relations": len(plans.business.relations),
            "operational_support_cards": len(plans.operational.support_cards),
            "operational_processes": len(plans.operational.processes),
            "operational_relations": len(plans.operational.relations),
        },
        "live_preview": preview,
        "scope": {
            "raw_source_records_included": False,
            "credentials_included": False,
            "cmdbuild_writes": 0,
            "sqlite_writes": 0,
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return {"output": str(output), "evidence": document}
