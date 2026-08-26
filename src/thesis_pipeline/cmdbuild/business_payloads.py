"""Build deterministic READY2USE business-context payloads without REST writes."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from thesis_pipeline.models import ScenarioConfig

CARD_ORDER = (
    "vendor",
    "contract",
    "sla",
    "service_category",
    "business_service",
    "server",
    "application",
)
RELATION_ORDER = (
    "contract_sla",
    "sla_business_service",
    "business_service_application",
)
IMPACT_ORDER = ("high", "medium", "low")
PRIORITY_ORDER = ("normal", "medium", "high", "critical")
SLA_OBJECT_ORDER = ("triage", "resolution")


class BusinessPayloadError(RuntimeError):
    """Raised when the deterministic business payload contract is invalid."""


@dataclass(frozen=True, slots=True)
class LookupReference:
    """Portable lookup reference resolved by type and stable code at write time."""

    family: str
    lookup_type: str
    code: str


@dataclass(frozen=True, slots=True)
class CardReference:
    """Reference to another planned card, before CMDBuild assigns a numeric ID."""

    entity: str
    key: str


PayloadValue = str | int | float | bool | LookupReference | CardReference


@dataclass(frozen=True, slots=True)
class BusinessCardPayload:
    """One mapping-bound card payload with symbolic references."""

    entity: str
    class_id: str
    key: str
    attributes: tuple[tuple[str, PayloadValue], ...]

    def attribute(self, name: str) -> PayloadValue:
        """Return one physical CMDBuild attribute by name."""

        for attribute_name, value in self.attributes:
            if attribute_name == name:
                return value
        raise KeyError(name)


@dataclass(frozen=True, slots=True)
class BusinessRelationPayload:
    """One independent domain relation between two planned cards."""

    domain: str
    domain_id: str
    direction: str
    source: CardReference
    destination: CardReference


@dataclass(frozen=True, slots=True)
class BusinessPayloadPlan:
    """Deterministic, auditable Stage 6 plan; it performs no external I/O."""

    cards: tuple[BusinessCardPayload, ...]
    relations: tuple[BusinessRelationPayload, ...]
    source_dataset_fingerprint: str
    fingerprint: str

    @property
    def card_counts(self) -> tuple[tuple[str, int], ...]:
        counts = Counter(card.entity for card in self.cards)
        return tuple((entity, counts[entity]) for entity in CARD_ORDER)

    @property
    def relation_counts(self) -> tuple[tuple[str, int], ...]:
        counts = Counter(relation.domain for relation in self.relations)
        return tuple((domain, counts[domain]) for domain in RELATION_ORDER)


def _section(configuration: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = configuration.get(name)
    if not isinstance(value, Mapping):
        raise BusinessPayloadError(f"Configuration section is missing: {name}")
    return value


def _required_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BusinessPayloadError(f"Configuration value is missing: {context}")
    return value


def _entity_class(mapping: Mapping[str, Any], entity: str) -> str:
    entity_config = _section(_section(mapping, "entities"), entity)
    if entity_config.get("kind") != "class":
        raise BusinessPayloadError(f"Stage 6 entity is not a class: {entity}")
    return _required_string(entity_config.get("cmdbuild_id"), f"entities.{entity}")


def _field(mapping: Mapping[str, Any], entity: str, logical_field: str) -> str:
    entity_config = _section(_section(mapping, "entities"), entity)
    fields = _section(entity_config, "fields")
    return _required_string(
        fields.get(logical_field), f"entities.{entity}.fields.{logical_field}"
    )


def _lookup(
    mapping: Mapping[str, Any], family: str, code_key: str
) -> LookupReference:
    lookup_config = _section(_section(mapping, "lookups"), family)
    codes = _section(lookup_config, "codes")
    return LookupReference(
        family=family,
        lookup_type=_required_string(lookup_config.get("type"), f"lookups.{family}"),
        code=_required_string(codes.get(code_key), f"lookups.{family}.{code_key}"),
    )


def _domain(
    mapping: Mapping[str, Any], domain: str
) -> tuple[str, str]:
    domain_config = _section(_section(mapping, "domains"), domain)
    direction = _required_string(
        domain_config.get("direction"), f"domains.{domain}.direction"
    )
    if direction not in {"direct", "inverse"}:
        raise BusinessPayloadError(f"Unsupported domain direction: {direction}")
    return (
        _required_string(domain_config.get("cmdbuild_id"), f"domains.{domain}"),
        direction,
    )


def _population_count(simulation: Mapping[str, Any], name: str) -> int:
    value = _section(simulation, "population").get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BusinessPayloadError(f"Invalid population count: {name}")
    return value


def _impact(criticality: int) -> str:
    if isinstance(criticality, bool) or not isinstance(criticality, int):
        raise BusinessPayloadError("Service criticality must be an integer")
    if criticality >= 4:
        return "high"
    if criticality == 3:
        return "medium"
    if criticality >= 1:
        return "low"
    raise BusinessPayloadError("Service criticality must be positive")


def _environment(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")
    if normalized in {"production", "prod"}:
        return "production"
    if normalized in {
        "test",
        "testing",
        "qa",
        "quality_assurance",
        "development",
        "dev",
        "staging",
        "nonproduction",
        "non_production",
        "pre_production",
    }:
        return "test"
    raise BusinessPayloadError(f"Unsupported application environment: {value}")


def _triage_target_minutes(scenario: ScenarioConfig, priority_index: int) -> int:
    minimum = scenario.triage_minutes_min
    maximum = scenario.triage_minutes_max
    if minimum <= 0 or maximum < minimum:
        raise BusinessPayloadError("Invalid configured triage duration range")
    if len(PRIORITY_ORDER) == 1:
        return maximum
    ratio = priority_index / (len(PRIORITY_ORDER) - 1)
    return round(maximum - ((maximum - minimum) * ratio))


def _resolution_target_minutes(scenario: ScenarioConfig, priority: str) -> int:
    scenario_key = "low" if priority == "normal" else priority
    hours = scenario.sla_hours.get(scenario_key)
    if isinstance(hours, bool) or not isinstance(hours, (int, float)) or hours <= 0:
        raise BusinessPayloadError(f"Missing positive SLA hours for {scenario_key}")
    return round(hours * 60)


def _attributes(**values: PayloadValue) -> tuple[tuple[str, PayloadValue], ...]:
    return tuple(values.items())


def _card(
    mapping: Mapping[str, Any],
    entity: str,
    key: str,
    attributes: tuple[tuple[str, PayloadValue], ...],
) -> BusinessCardPayload:
    return BusinessCardPayload(
        entity=entity,
        class_id=_entity_class(mapping, entity),
        key=key,
        attributes=attributes,
    )


def _relation(
    mapping: Mapping[str, Any],
    domain: str,
    source: CardReference,
    destination: CardReference,
) -> BusinessRelationPayload:
    domain_id, direction = _domain(mapping, domain)
    return BusinessRelationPayload(
        domain=domain,
        domain_id=domain_id,
        direction=direction,
        source=source,
        destination=destination,
    )


def _serialise_value(value: PayloadValue) -> Any:
    if isinstance(value, LookupReference):
        return {
            "kind": "lookup",
            "family": value.family,
            "lookup_type": value.lookup_type,
            "code": value.code,
        }
    if isinstance(value, CardReference):
        return {"kind": "card", "entity": value.entity, "key": value.key}
    return value


def _fingerprint(
    cards: tuple[BusinessCardPayload, ...],
    relations: tuple[BusinessRelationPayload, ...],
    source_dataset_fingerprint: str,
) -> str:
    manifest = {
        "source_dataset_fingerprint": source_dataset_fingerprint,
        "card_order": list(CARD_ORDER),
        "cards": [
            {
                "entity": card.entity,
                "class_id": card.class_id,
                "key": card.key,
                "attributes": [
                    [name, _serialise_value(value)] for name, value in card.attributes
                ],
            }
            for card in cards
        ],
        "relations": [
            {
                "domain": relation.domain,
                "domain_id": relation.domain_id,
                "direction": relation.direction,
                "source": _serialise_value(relation.source),
                "destination": _serialise_value(relation.destination),
            }
            for relation in relations
        ],
    }
    encoded = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _validate_references(
    cards: tuple[BusinessCardPayload, ...],
    relations: tuple[BusinessRelationPayload, ...],
) -> None:
    keys = {(card.entity, card.key) for card in cards}
    if len(keys) != len(cards):
        raise BusinessPayloadError("Planned card keys are not unique")
    for card in cards:
        names = [name for name, _value in card.attributes]
        if len(names) != len(set(names)):
            raise BusinessPayloadError(
                f"Duplicate attribute in planned card: {card.key}"
            )
        for _name, value in card.attributes:
            if (
                isinstance(value, CardReference)
                and (value.entity, value.key) not in keys
            ):
                raise BusinessPayloadError(f"Unresolved card reference: {value}")
    relation_keys: set[tuple[str, CardReference, CardReference]] = set()
    for relation in relations:
        for reference in (relation.source, relation.destination):
            if (reference.entity, reference.key) not in keys:
                raise BusinessPayloadError(
                    f"Unresolved relation reference: {reference}"
                )
        relation_key = (relation.domain, relation.source, relation.destination)
        if relation_key in relation_keys:
            raise BusinessPayloadError(f"Duplicate planned relation: {relation_key}")
        relation_keys.add(relation_key)


def build_business_payload_plan(
    dataset: Any,
    scenario: ScenarioConfig,
    mapping: Mapping[str, Any],
    simulation: Mapping[str, Any],
) -> BusinessPayloadPlan:
    """Build the complete Stage 6 payload plan without files, databases, or REST."""

    if mapping.get("discovery_status") != "confirmed":
        raise BusinessPayloadError("CMDBuild field discovery must be confirmed")
    source_fingerprint = _required_string(
        getattr(dataset, "fingerprint", None), "dataset.fingerprint"
    )
    services = tuple(sorted(dataset.services, key=lambda item: item.service_id))
    assets = tuple(sorted(dataset.assets, key=lambda item: item.asset_id))
    findings = tuple(dataset.findings)
    service_by_id = {service.service_id: service for service in services}
    asset_ids = {asset.asset_id for asset in assets}
    if len(service_by_id) != len(services) or len(asset_ids) != len(assets):
        raise BusinessPayloadError(
            "Synthetic service and asset identifiers must be unique"
        )
    if any(asset.service_id not in service_by_id for asset in assets):
        raise BusinessPayloadError("Every asset must reference a generated service")

    departments = tuple(sorted({service.department_id for service in services}))
    occurrence_count = len({(item.cve_id, item.asset_id) for item in findings})
    expected_counts = {
        "vendors": len(departments),
        "contracts": len(services),
        "slas": len(PRIORITY_ORDER) * len(SLA_OBJECT_ORDER),
        "business_services": len(services),
        "applications": len(assets),
        "servers": len(assets),
        "raw_findings": len(findings),
        "vulnerability_occurrences": occurrence_count,
        "duplicate_findings": len(findings) - occurrence_count,
    }
    for name, actual in expected_counts.items():
        configured = _population_count(simulation, name)
        if configured != actual:
            raise BusinessPayloadError(
                f"Population mismatch for {name}: "
                f"configured {configured}, actual {actual}"
            )

    cards: list[BusinessCardPayload] = []
    vendor_key_by_department: dict[str, str] = {}
    for index, department_id in enumerate(departments, start=1):
        key = f"vendor:{department_id}"
        vendor_key_by_department[department_id] = key
        cards.append(
            _card(
                mapping,
                "vendor",
                key,
                _attributes(
                    **{
                        _field(mapping, "vendor", "code"): f"SUP-{index:03d}",
                        _field(mapping, "vendor", "name"): (
                            f"Synthetic Supplier {index:02d}"
                        ),
                    }
                ),
            )
        )

    contract_key_by_service: dict[str, str] = {}
    end_date = (
        scenario.start_time_utc + timedelta(hours=scenario.horizon_hours)
    ).date()
    for index, service in enumerate(services, start=1):
        key = f"contract:{service.service_id}"
        contract_key_by_service[service.service_id] = key
        cards.append(
            _card(
                mapping,
                "contract",
                key,
                _attributes(
                    **{
                        _field(mapping, "contract", "code"): f"CTR-{index:04d}",
                        _field(mapping, "contract", "start_date"): (
                            scenario.start_time_utc.date().isoformat()
                        ),
                        _field(mapping, "contract", "end_date"): end_date.isoformat(),
                        _field(mapping, "contract", "vendor"): CardReference(
                            "vendor", vendor_key_by_department[service.department_id]
                        ),
                    }
                ),
            )
        )

    sla_keys: list[str] = []
    for priority_index, priority in enumerate(PRIORITY_ORDER):
        for sla_object in SLA_OBJECT_ORDER:
            key = f"sla:{priority}:{sla_object}"
            sla_keys.append(key)
            target = (
                _triage_target_minutes(scenario, priority_index)
                if sla_object == "triage"
                else _resolution_target_minutes(scenario, priority)
            )
            cards.append(
                _card(
                    mapping,
                    "sla",
                    key,
                    _attributes(
                        **{
                            _field(mapping, "sla", "code"): (
                                f"SLA-{priority.upper()}-{sla_object.upper()}"
                            ),
                            _field(mapping, "sla", "name"): (
                                f"{priority.title()} {sla_object} target"
                            ),
                            _field(mapping, "sla", "target_minutes"): target,
                            _field(mapping, "sla", "priority"): _lookup(
                                mapping, "process_priority", priority
                            ),
                            _field(mapping, "sla", "object"): _lookup(
                                mapping, "sla_object", sla_object
                            ),
                            _field(mapping, "sla", "threshold_type"): _lookup(
                                mapping, "sla_threshold_type", "minutes"
                            ),
                            _field(mapping, "sla", "workflow"): _lookup(
                                mapping, "workflow", "incident"
                            ),
                        }
                    ),
                )
            )

    category_names = {
        "high": "Critical business services",
        "medium": "Important business services",
        "low": "Supporting business services",
    }
    for index, impact in enumerate(IMPACT_ORDER, start=1):
        cards.append(
            _card(
                mapping,
                "service_category",
                f"category:{impact}",
                _attributes(
                    **{
                        _field(mapping, "service_category", "name"): (
                            category_names[impact]
                        ),
                        _field(mapping, "service_category", "state"): _lookup(
                            mapping, "service_category_state", "active"
                        ),
                        _field(mapping, "service_category", "index"): f"{index:03d}",
                    }
                ),
            )
        )

    for index, service in enumerate(services, start=1):
        impact = _impact(service.criticality)
        cards.append(
            _card(
                mapping,
                "business_service",
                service.service_id,
                _attributes(
                    **{
                        _field(mapping, "business_service", "code"): service.service_id,
                        _field(mapping, "business_service", "name"): (
                            f"Synthetic Business Service {index:02d}"
                        ),
                        _field(mapping, "business_service", "criticality"): _lookup(
                            mapping, "business_service_impact", impact
                        ),
                        _field(mapping, "business_service", "category"): CardReference(
                            "service_category", f"category:{impact}"
                        ),
                        _field(mapping, "business_service", "state"): _lookup(
                            mapping, "business_service_state", "active"
                        ),
                        _field(mapping, "business_service", "contract"): CardReference(
                            "contract", contract_key_by_service[service.service_id]
                        ),
                    }
                ),
            )
        )

    for asset in assets:
        hostname = re.sub(r"[^a-z0-9-]+", "-", asset.asset_id.lower()).strip("-")
        cards.append(
            _card(
                mapping,
                "server",
                asset.asset_id,
                _attributes(
                    **{
                        _field(mapping, "server", "code"): asset.asset_id,
                        _field(mapping, "server", "hostname"): f"{hostname}.invalid",
                    }
                ),
            )
        )

    application_key_by_asset: dict[str, str] = {}
    for index, asset in enumerate(assets, start=1):
        key = f"application:{asset.asset_id}"
        application_key_by_asset[asset.asset_id] = key
        cards.append(
            _card(
                mapping,
                "application",
                key,
                _attributes(
                    **{
                        _field(mapping, "application", "code"): f"APP-{index:06d}",
                        _field(mapping, "application", "environment"): _lookup(
                            mapping,
                            "application_environment",
                            _environment(asset.environment),
                        ),
                        _field(mapping, "application", "server"): CardReference(
                            "server", asset.asset_id
                        ),
                    }
                ),
            )
        )

    relations: list[BusinessRelationPayload] = []
    for service in services:
        contract_reference = CardReference(
            "contract", contract_key_by_service[service.service_id]
        )
        service_reference = CardReference("business_service", service.service_id)
        for sla_key in sla_keys:
            sla_reference = CardReference("sla", sla_key)
            relations.append(
                _relation(mapping, "contract_sla", contract_reference, sla_reference)
            )
            relations.append(
                _relation(
                    mapping, "sla_business_service", sla_reference, service_reference
                )
            )
    for asset in assets:
        relations.append(
            _relation(
                mapping,
                "business_service_application",
                CardReference("business_service", asset.service_id),
                CardReference("application", application_key_by_asset[asset.asset_id]),
            )
        )

    card_tuple = tuple(cards)
    relation_tuple = tuple(relations)
    _validate_references(card_tuple, relation_tuple)
    return BusinessPayloadPlan(
        cards=card_tuple,
        relations=relation_tuple,
        source_dataset_fingerprint=source_fingerprint,
        fingerprint=_fingerprint(card_tuple, relation_tuple, source_fingerprint),
    )
