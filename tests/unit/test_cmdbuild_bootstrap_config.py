import json
from datetime import timedelta
from pathlib import Path

from thesis_pipeline.config import load_scenario
from thesis_pipeline.synthetic_org.generator import generate_dataset

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def load_configuration(filename: str) -> dict:
    path = REPOSITORY_ROOT / "config" / filename
    return json.loads(path.read_text(encoding="utf-8"))


def test_cmdbuild_identifiers_are_discovered_and_portable() -> None:
    config = load_configuration("cmdbuild_fields.json")

    assert config["discovery_status"] == "confirmed"
    assert all(
        isinstance(entity["cmdbuild_id"], str) and entity["cmdbuild_id"]
        for entity in config["entities"].values()
    )
    assert all(
        isinstance(domain["cmdbuild_id"], str) and domain["cmdbuild_id"]
        for domain in config["domains"].values()
    )
    assert all(
        isinstance(code, str)
        for lookup in config["lookups"].values()
        for code in lookup["codes"].values()
    )


def test_unmapped_fields_are_explicitly_external_or_relation_backed() -> None:
    config = load_configuration("cmdbuild_fields.json")
    unresolved = {
        f"{entity_name}.{field_name}"
        for entity_name, entity in config["entities"].items()
        for field_name, field_value in entity["fields"].items()
        if field_value is None
    }
    declared_external = {
        f"{entity_name}.{field_name}"
        for entity_name, fields in config["integration"]["external_fields"].items()
        for field_name in fields
    }
    relation_backed = set(config["integration"]["relation_fields"])

    assert unresolved == declared_external | relation_backed


def test_business_entities_and_workflows_are_distinct() -> None:
    config = load_configuration("cmdbuild_fields.json")
    entities = config["entities"]

    assert entities["server"]["kind"] == "class"
    assert entities["business_service"]["kind"] == "class"
    assert entities["incident"]["kind"] == "process"
    assert entities["change"]["kind"] == "process"
    assert entities["incident"]["cmdbuild_id"] == "IncidentMgt"
    assert entities["change"]["cmdbuild_id"] == "ChangeMgt"


def test_native_relationships_preserve_actual_domain_directions() -> None:
    config = load_configuration("cmdbuild_fields.json")
    domains = config["domains"]

    assert domains["vendor_contract"]["cmdbuild_id"] == "SupplierContract"
    assert domains["contract_sla"]["cmdbuild_id"] == "SLAContract"
    assert domains["contract_sla"]["direction"] == "inverse"
    assert domains["application_server"]["cmdbuild_id"] == "HardwareSoftwareInstance"
    assert domains["application_server"]["direction"] == "inverse"
    assert domains["incident_asset"]["cmdbuild_id"] == "ITProcCI"


def test_native_sla_codes_and_workflow_start_activities_are_stable() -> None:
    config = load_configuration("cmdbuild_fields.json")
    entities = config["entities"]
    lookups = config["lookups"]

    assert entities["sla"]["fields"]["target_minutes"] == "Threshold"
    assert lookups["sla_object"]["codes"] == {
        "triage": "charge",
        "resolution": "resolution",
    }
    assert lookups["sla_threshold_type"]["codes"]["minutes"] == "MM"
    assert entities["incident"]["start_activity"] == "IM02-HDOpening"
    assert entities["change"]["start_activity"] == "CM01-Opening"


def test_read_only_and_hidden_fields_are_not_treated_as_writable() -> None:
    config = load_configuration("cmdbuild_fields.json")
    entities = config["entities"]

    assert entities["incident"]["fields"]["triage_started_at"] == "TakeChargeTimestamp"
    assert "triage_started_at" in entities["incident"]["read_only_fields"]
    assert entities["application"]["fields"]["name"] is None
    assert "Description" in entities["application"]["hidden_system_fields"]
    assert entities["application"]["fields"]["server"] == "Hardware"


def test_occurrence_preserves_cve_and_asset_grain() -> None:
    config = load_configuration("cmdbuild_fields.json")

    assert config["integration"]["occurrence_grain"] == [
        "cve_id",
        "asset_id",
    ]


def test_simulation_is_reproducible_and_temporally_safe() -> None:
    config = load_configuration("simulation.json")

    scenario = load_scenario(REPOSITORY_ROOT / config["simulation"]["scenario_path"])
    assert config["simulation"]["scenario_id"] == scenario.scenario_id
    assert config["simulation"]["seed"] == scenario.seed
    assert config["simulation"]["start_date"] == scenario.start_time_utc.date().isoformat()
    assert config["simulation"]["end_date"] == (
        scenario.start_time_utc + timedelta(hours=scenario.horizon_hours)
    ).date().isoformat()
    assert config["time_model"]["timezone"] == "UTC"
    assert config["time_model"][
        "enforce_technical_evidence_as_of_detection"
    ]
    assert config["evaluation"]["same_random_seed"]


def test_operational_lookup_codes_are_verified_and_portable() -> None:
    config = load_configuration("cmdbuild_fields.json")
    lookups = config["lookups"]

    assert lookups["business_service_state"]["codes"] == {
        "active": "Active",
        "inactive": "NonActive",
    }
    assert lookups["business_service_impact"]["codes"] == {
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }
    assert lookups["application_environment"]["codes"] == {
        "production": "Production",
        "test": "Test",
    }
    assert lookups["process_priority"]["codes"] == {
        "normal": "1",
        "medium": "2",
        "high": "3",
        "critical": "4",
    }


def test_smoke_population_reuses_existing_experimental_scenario() -> None:
    config = load_configuration("simulation.json")
    mapping = load_configuration("cmdbuild_fields.json")
    scenario = load_scenario(REPOSITORY_ROOT / config["simulation"]["scenario_path"])
    population = config["population"]

    assert population["vendors"] == scenario.departments
    assert population["contracts"] == scenario.services
    assert population["business_services"] == scenario.services
    assert population["applications"] == scenario.assets
    assert population["servers"] == scenario.assets
    dataset = generate_dataset(scenario)
    occurrence_keys = {
        (finding.cve_id, finding.asset_id)
        for finding in dataset.findings
    }
    assert population["raw_findings"] == scenario.findings
    assert population["vulnerability_occurrences"] == len(occurrence_keys)
    assert population["duplicate_findings"] == (
        scenario.findings - len(occurrence_keys)
    )
    assert population["slas"] == (
        len(scenario.sla_hours) * len(mapping["lookups"]["sla_object"]["codes"])
    )


def test_smoke_generation_strategies_preserve_native_cmdbuild_constraints() -> None:
    config = load_configuration("simulation.json")
    mapping = load_configuration("cmdbuild_fields.json")
    generation = config["generation"]
    priority_codes = mapping["lookups"]["process_priority"]["codes"]

    assert generation["vendor_strategy"] == "one_per_department"
    assert generation["contract_strategy"] == "one_per_business_service"
    assert generation["application_strategy"] == "one_per_server"
    assert generation["sla_strategy"] == "shared_by_severity_and_object"
    assert generation["severity_to_priority"] == {
        "low": "normal",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }
    assert {
        severity: priority_codes[priority]
        for severity, priority in generation["severity_to_priority"].items()
    } == {
        "low": "1",
        "medium": "2",
        "high": "3",
        "critical": "4",
    }


def test_smoke_backlog_requires_public_cve_binding_before_cmdbuild() -> None:
    config = load_configuration("simulation.json")
    scenario = load_scenario(REPOSITORY_ROOT / config["simulation"]["scenario_path"])
    dataset = generate_dataset(scenario)
    findings = list(dataset.findings)
    generation = config["generation"]

    expected_batch_start = scenario.start_time_utc - timedelta(
        minutes=(scenario.findings * scenario.arrival_interval_minutes) + 10
    )
    expected_last_finding = expected_batch_start + timedelta(
        minutes=(scenario.findings - 1) * scenario.arrival_interval_minutes
    )

    assert min(finding.finding_created for finding in findings) == expected_batch_start
    assert max(finding.finding_created for finding in findings) == expected_last_finding
    assert all(finding.finding_created < scenario.start_time_utc for finding in findings)
    assert all(finding.cve_id.startswith("CVE-SYNTH-") for finding in findings)
    assert (
        generation["finding_timeline_strategy"]
        == "preloaded_backlog_before_operational_horizon"
    )
    assert generation["occurrence_grain"] == "cve_id_and_asset_id"
    assert (
        generation["cve_binding_strategy"]
        == "replace_synthetic_identifiers_from_public_dataset"
    )
    assert generation["allow_synthetic_cve_ids_in_cmdbuild"] is False
