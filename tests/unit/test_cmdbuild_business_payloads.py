import json
from dataclasses import replace
from pathlib import Path

import pytest

from thesis_pipeline.cmdbuild.business_payloads import (
    BusinessPayloadError,
    CardReference,
    LookupReference,
    build_business_payload_plan,
)
from thesis_pipeline.config import load_scenario
from thesis_pipeline.synthetic_org.generator import generate_dataset

ROOT = Path(__file__).resolve().parents[2]


def _load_json(relative_path: str) -> dict:
    return json.loads((ROOT / relative_path).read_text(encoding="utf-8"))


def _smoke_plan():
    scenario = load_scenario(ROOT / "configs/scenarios/smoke.yaml")
    dataset = generate_dataset(scenario)
    mapping = _load_json("config/cmdbuild_fields.json")
    simulation = _load_json("config/simulation.json")
    return (
        build_business_payload_plan(dataset, scenario, mapping, simulation),
        scenario,
        dataset,
        mapping,
        simulation,
    )


def test_smoke_business_payload_plan_is_complete_and_deterministic() -> None:
    first, scenario, dataset, mapping, simulation = _smoke_plan()
    second = build_business_payload_plan(dataset, scenario, mapping, simulation)

    assert first == second
    assert len(first.fingerprint) == 64
    assert first.source_dataset_fingerprint == dataset.fingerprint
    assert dict(first.card_counts) == {
        "vendor": 3,
        "contract": 10,
        "sla": 8,
        "service_category": 3,
        "business_service": 10,
        "server": 100,
        "application": 100,
    }
    assert len(first.cards) == 234
    assert dict(first.relation_counts) == {
        "contract_sla": 80,
        "sla_business_service": 80,
        "business_service_application": 100,
    }
    assert len(first.relations) == 260


def test_pre_production_assets_use_the_ready2use_test_lookup() -> None:
    plan, _scenario, dataset, mapping, _simulation = _smoke_plan()
    pre_production_keys = {
        f"application:{asset.asset_id}"
        for asset in dataset.assets
        if asset.environment == "pre-production"
    }
    assert pre_production_keys

    environment_field = mapping["entities"]["application"]["fields"]["environment"]
    expected_lookup = LookupReference(
        family="application_environment",
        lookup_type="SWInstance - Environment",
        code="Test",
    )
    assert {
        card.attribute(environment_field)
        for card in plan.cards
        if card.key in pre_production_keys
    } == {expected_lookup}


def test_cards_are_topologically_ordered_and_references_are_symbolic() -> None:
    plan, _scenario, _dataset, _mapping, _simulation = _smoke_plan()
    entity_rank = {
        entity: index
        for index, entity in enumerate(
            (
                "vendor",
                "contract",
                "sla",
                "service_category",
                "business_service",
                "server",
                "application",
            )
        )
    }
    assert [entity_rank[card.entity] for card in plan.cards] == sorted(
        entity_rank[card.entity] for card in plan.cards
    )
    planned_entities = {card.entity for card in plan.cards}
    assert not ({"incident", "change", "vulnerability_occurrence"} & planned_entities)

    planned_keys = {(card.entity, card.key) for card in plan.cards}
    for card in plan.cards:
        for _name, value in card.attributes:
            if isinstance(value, CardReference):
                assert (value.entity, value.key) in planned_keys
            if isinstance(value, LookupReference):
                assert value.code
                assert value.lookup_type
                assert not value.code.isdigit() or value.family == "process_priority"
    for relation in plan.relations:
        assert (relation.source.entity, relation.source.key) in planned_keys
        assert (relation.destination.entity, relation.destination.key) in planned_keys


def test_reference_backed_domains_are_not_duplicated_as_relations() -> None:
    plan, _scenario, _dataset, mapping, _simulation = _smoke_plan()
    assert {relation.domain for relation in plan.relations} == {
        "contract_sla",
        "sla_business_service",
        "business_service_application",
    }
    assert {relation.domain_id for relation in plan.relations} == {
        "SLAContract",
        "SLAService",
        "CIDependency",
    }
    assert {
        relation.domain: relation.direction for relation in plan.relations
    } == {
        "contract_sla": "inverse",
        "sla_business_service": "direct",
        "business_service_application": "direct",
    }

    physical_fields = {
        entity: mapping["entities"][entity]["fields"]
        for entity in ("contract", "business_service", "application")
    }
    for card in plan.cards:
        attributes = dict(card.attributes)
        if card.entity == "contract":
            assert isinstance(
                attributes[physical_fields["contract"]["vendor"]], CardReference
            )
        elif card.entity == "business_service":
            assert isinstance(
                attributes[physical_fields["business_service"]["category"]],
                CardReference,
            )
            assert isinstance(
                attributes[physical_fields["business_service"]["contract"]],
                CardReference,
            )
        elif card.entity == "application":
            assert isinstance(
                attributes[physical_fields["application"]["server"]], CardReference
            )


def test_payload_omits_read_only_fields_and_derives_eight_incident_slas() -> None:
    plan, scenario, _dataset, mapping, _simulation = _smoke_plan()
    cards_by_entity = {
        entity: [card for card in plan.cards if card.entity == entity]
        for entity in ("vendor", "contract", "server", "sla")
    }
    assert all(
        mapping["entities"]["vendor"]["fields"]["description"]
        not in dict(card.attributes)
        for card in cards_by_entity["vendor"]
    )
    assert all(
        mapping["entities"]["contract"]["fields"]["name"]
        not in dict(card.attributes)
        for card in cards_by_entity["contract"]
    )
    assert all(
        mapping["entities"]["server"]["fields"]["name"]
        not in dict(card.attributes)
        for card in cards_by_entity["server"]
    )

    threshold_field = mapping["entities"]["sla"]["fields"]["target_minutes"]
    code_field = mapping["entities"]["sla"]["fields"]["code"]
    targets = {
        dict(card.attributes)[code_field]: dict(card.attributes)[threshold_field]
        for card in cards_by_entity["sla"]
    }
    expected_triage = {
        "normal": scenario.triage_minutes_max,
        "medium": round(
            scenario.triage_minutes_max
            - (scenario.triage_minutes_max - scenario.triage_minutes_min) / 3
        ),
        "high": round(
            scenario.triage_minutes_max
            - 2 * (scenario.triage_minutes_max - scenario.triage_minutes_min) / 3
        ),
        "critical": scenario.triage_minutes_min,
    }
    for priority, minutes in expected_triage.items():
        assert targets[f"SLA-{priority.upper()}-TRIAGE"] == minutes
    for priority in ("normal", "medium", "high", "critical"):
        scenario_key = "low" if priority == "normal" else priority
        assert targets[f"SLA-{priority.upper()}-RESOLUTION"] == round(
            scenario.sla_hours[scenario_key] * 60
        )


def test_population_drift_is_rejected_before_any_external_operation() -> None:
    scenario = load_scenario(ROOT / "configs/scenarios/smoke.yaml")
    dataset = generate_dataset(scenario)
    mapping = _load_json("config/cmdbuild_fields.json")
    simulation = _load_json("config/simulation.json")
    invalid_population = dict(simulation["population"])
    invalid_population["applications"] += 1
    invalid_simulation = dict(simulation)
    invalid_simulation["population"] = invalid_population

    with pytest.raises(
        BusinessPayloadError, match="Population mismatch for applications"
    ):
        build_business_payload_plan(dataset, scenario, mapping, invalid_simulation)

    changed_dataset = replace(dataset, assets=dataset.assets[:-1])
    with pytest.raises(BusinessPayloadError, match="Population mismatch"):
        build_business_payload_plan(changed_dataset, scenario, mapping, simulation)
