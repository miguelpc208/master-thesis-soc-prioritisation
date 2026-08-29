"""Build deterministic READY2USE operational payloads without REST mutations."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from thesis_pipeline.cmdbuild.business_payloads import LookupReference
from thesis_pipeline.models import WorkflowRecord
from thesis_pipeline.simulation.workflow import SimulationResult

PROCESS_ORDER = ("incident", "change")
RELATION_ORDER = ("incident_asset", "change_asset", "incident_change")
SUPPORT_ORDER = ("area",)
OPERATIONAL_CONTRACT_VERSION = "monitoring-native-start-v2"


class OperationalPayloadError(RuntimeError):
    """Raised when a portable operational payload cannot be constructed."""


@dataclass(frozen=True, slots=True)
class RoleReference:
    """Stable role-card identity resolved to a numeric reference at write time."""

    class_id: str
    identity_attribute: str
    identity_value: str


@dataclass(frozen=True, slots=True)
class SupportReference:
    """Reference to one planned operational support card."""

    key: str


OperationalValue = (
    str | int | float | bool | LookupReference | RoleReference | SupportReference
)


@dataclass(frozen=True, slots=True)
class OperationalSupportCardPayload:
    """One support card required by native READY2USE opening forms."""

    key: str
    class_id: str
    identity_attribute: str
    identity_value: str
    attributes: tuple[tuple[str, OperationalValue], ...]


@dataclass(frozen=True, slots=True)
class OperationalProcessPayload:
    """One IncidentMgt or ChangeMgt instance held at its start activity."""

    entity: str
    process_id: str
    key: str
    start_activity: str
    identity_attribute: str
    identity_value: str
    attributes: tuple[tuple[str, OperationalValue], ...]


@dataclass(frozen=True, slots=True)
class OperationalEndpointReference:
    """Symbolic relation endpoint resolved from a process key or asset code."""

    kind: str
    type_id: str
    key: str


@dataclass(frozen=True, slots=True)
class OperationalRelationPayload:
    """One explicit relation between operational process and business objects."""

    domain: str
    domain_id: str
    direction: str
    source: OperationalEndpointReference
    destination: OperationalEndpointReference


@dataclass(frozen=True, slots=True)
class OperationalPayloadPlan:
    """Deterministic Stage 7 plan that performs no external I/O."""

    support_cards: tuple[OperationalSupportCardPayload, ...]
    processes: tuple[OperationalProcessPayload, ...]
    relations: tuple[OperationalRelationPayload, ...]
    public_binding_fingerprint: str
    policy: str
    fingerprint: str

    @property
    def support_counts(self) -> tuple[tuple[str, int], ...]:
        counts = Counter(card.key.split(":", 1)[0] for card in self.support_cards)
        return tuple((entity, counts[entity]) for entity in SUPPORT_ORDER)

    @property
    def process_counts(self) -> tuple[tuple[str, int], ...]:
        counts = Counter(process.entity for process in self.processes)
        return tuple((entity, counts[entity]) for entity in PROCESS_ORDER)

    @property
    def relation_counts(self) -> tuple[tuple[str, int], ...]:
        counts = Counter(relation.domain for relation in self.relations)
        return tuple((domain, counts[domain]) for domain in RELATION_ORDER)


def _section(configuration: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    section = configuration.get(name)
    if not isinstance(section, Mapping):
        raise OperationalPayloadError(f"Configuration section is missing: {name}")
    return section


def _required_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OperationalPayloadError(f"Configuration value is missing: {context}")
    return value


def _entity(mapping: Mapping[str, Any], entity: str) -> Mapping[str, Any]:
    return _section(_section(mapping, "entities"), entity)


def _process_id(mapping: Mapping[str, Any], entity: str) -> str:
    return _required_string(
        _entity(mapping, entity).get("cmdbuild_id"),
        f"entities.{entity}.cmdbuild_id",
    )


def _start_activity(mapping: Mapping[str, Any], entity: str) -> str:
    return _required_string(
        _entity(mapping, entity).get("start_activity"),
        f"entities.{entity}.start_activity",
    )


def _start_activity_fields(mapping: Mapping[str, Any], entity: str) -> tuple[str, ...]:
    values = _entity(mapping, entity).get("start_activity_fields")
    if not isinstance(values, list) or not values:
        raise OperationalPayloadError(
            f"Start-activity field contract is missing: entities.{entity}"
        )
    fields = tuple(
        _required_string(value, f"entities.{entity}.start_activity_fields")
        for value in values
    )
    if len(set(fields)) != len(fields):
        raise OperationalPayloadError(
            f"Start-activity field contract contains duplicates: {entity}"
        )
    return fields


def _start_attributes(
    mapping: Mapping[str, Any],
    entity: str,
    attributes: tuple[tuple[str, OperationalValue], ...],
) -> tuple[tuple[str, OperationalValue], ...]:
    expected = _start_activity_fields(mapping, entity)
    actual = tuple(name for name, _value in attributes)
    if actual != expected:
        raise OperationalPayloadError(
            f"Payload does not match {entity} start-activity fields: {actual}"
        )
    return attributes


def _support(mapping: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    return _section(_section(mapping, "operational_support"), name)


def _domain(
    mapping: Mapping[str, Any],
    name: str,
) -> tuple[str, str]:
    domain = _section(_section(mapping, "domains"), name)
    return (
        _required_string(domain.get("cmdbuild_id"), f"domains.{name}.cmdbuild_id"),
        _required_string(domain.get("direction"), f"domains.{name}.direction"),
    )


def _code(prefix: str, key: str) -> str:
    fingerprint_input = f"{OPERATIONAL_CONTRACT_VERSION}:{key}"
    digest = hashlib.sha256(fingerprint_input.encode("utf-8")).hexdigest()[:20].upper()
    return f"{prefix}-{digest}"


def _priority(record: WorkflowRecord) -> str:
    if record.finding.cvss >= 9.0:
        return "critical"
    if record.finding.cvss >= 7.0:
        return "high"
    if record.finding.cvss >= 4.0:
        return "medium"
    return "normal"


def _serialise_value(value: OperationalValue) -> Any:
    if isinstance(value, LookupReference):
        return {
            "kind": "lookup",
            "family": value.family,
            "lookup_type": value.lookup_type,
            "code": value.code,
        }
    if isinstance(value, RoleReference):
        return {
            "kind": "role",
            "class_id": value.class_id,
            "identity_attribute": value.identity_attribute,
            "identity_value": value.identity_value,
        }
    if isinstance(value, SupportReference):
        return {"kind": "support", "key": value.key}
    return value


def _fingerprint(
    support_cards: tuple[OperationalSupportCardPayload, ...],
    processes: tuple[OperationalProcessPayload, ...],
    relations: tuple[OperationalRelationPayload, ...],
    public_binding_fingerprint: str,
    policy: str,
) -> str:
    document = {
        "public_binding_fingerprint": public_binding_fingerprint,
        "policy": policy,
        "support_cards": [
            {
                "key": card.key,
                "class_id": card.class_id,
                "identity_attribute": card.identity_attribute,
                "identity_value": card.identity_value,
                "attributes": [
                    [name, _serialise_value(value)] for name, value in card.attributes
                ],
            }
            for card in support_cards
        ],
        "processes": [
            {
                "entity": process.entity,
                "process_id": process.process_id,
                "key": process.key,
                "start_activity": process.start_activity,
                "identity_attribute": process.identity_attribute,
                "identity_value": process.identity_value,
                "attributes": [
                    [name, _serialise_value(value)]
                    for name, value in process.attributes
                ],
            }
            for process in processes
        ],
        "relations": [
            {
                "domain": relation.domain,
                "domain_id": relation.domain_id,
                "direction": relation.direction,
                "source": {
                    "kind": relation.source.kind,
                    "type_id": relation.source.type_id,
                    "key": relation.source.key,
                },
                "destination": {
                    "kind": relation.destination.kind,
                    "type_id": relation.destination.type_id,
                    "key": relation.destination.key,
                },
            }
            for relation in relations
        ],
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _support_cards(mapping: Mapping[str, Any]) -> tuple[OperationalSupportCardPayload, ...]:
    area = _support(mapping, "area")
    role = _support(mapping, "role")

    area_class = _required_string(area.get("class_id"), "area.class_id")
    area_identity = _required_string(area.get("identity_attribute"), "area.identity_attribute")
    area_value = _required_string(area.get("identity_value"), "area.identity_value")
    role_attribute = _required_string(area.get("role_attribute"), "area.role_attribute")

    role_reference = RoleReference(
        class_id=_required_string(role.get("class_id"), "role.class_id"),
        identity_attribute=_required_string(
            role.get("identity_attribute"), "role.identity_attribute"
        ),
        identity_value=_required_string(role.get("identity_value"), "role.identity_value"),
    )

    return (
        OperationalSupportCardPayload(
            key="area:Synthetic SOC Operations",
            class_id=area_class,
            identity_attribute=area_identity,
            identity_value=area_value,
            attributes=(
                (area_identity, area_value),
                (role_attribute, role_reference),
            ),
        ),
    )


def build_operational_payload_plan(
    result: SimulationResult,
    mapping: Mapping[str, Any],
    *,
    public_binding_fingerprint: str,
    policy: str,
) -> OperationalPayloadPlan:
    """Build support cards, process instances and independent process relations."""

    if not public_binding_fingerprint.strip() or not policy.strip():
        raise OperationalPayloadError("Public binding fingerprint and policy are required")
    if result.correlated_case_count != len(result.records):
        raise OperationalPayloadError("Simulation result contains an invalid correlated count")

    records = sorted(
        result.records,
        key=lambda record: (record.priority_rank, record.finding.correlation_key),
    )
    keys = [record.finding.correlation_key for record in records]
    if len(set(keys)) != len(keys):
        raise OperationalPayloadError("Workflow records do not have unique occurrence keys")

    support_cards = _support_cards(mapping)
    area_reference = SupportReference(support_cards[0].key)
    channel = _support(mapping, "channel")
    channel_reference = LookupReference(
        family="process_channel",
        lookup_type=_required_string(channel.get("lookup_type"), "channel.lookup_type"),
        code=_required_string(channel.get("code"), "channel.code"),
    )

    incident_id = _process_id(mapping, "incident")
    change_id = _process_id(mapping, "change")
    server_id = _process_id(mapping, "server")
    incident_domain_id, incident_direction = _domain(mapping, "incident_asset")
    change_domain_id, change_direction = _domain(mapping, "change_asset")
    parent_domain_id, parent_direction = _domain(mapping, "incident_change")

    processes: list[OperationalProcessPayload] = []
    relations: list[OperationalRelationPayload] = []
    incident_key_by_occurrence: dict[str, str] = {}

    for record in records:
        occurrence_key = record.finding.correlation_key
        incident_key = f"incident:{occurrence_key}"
        incident_key_by_occurrence[occurrence_key] = incident_key
        incident_code = _code("INC2", occurrence_key)
        operational_priority = _priority(record)
        short_description = (
            f"{incident_code} | {operational_priority.upper()} | "
            f"{record.finding.cve_id} on {record.finding.asset_id}"
        )
        processes.append(
            OperationalProcessPayload(
                entity="incident",
                process_id=incident_id,
                key=incident_key,
                start_activity=_start_activity(mapping, "incident"),
                identity_attribute="ShortDescr",
                identity_value=short_description,
                attributes=_start_attributes(
                    mapping,
                    "incident",
                    (
                        ("ShortDescr", short_description),
                        ("AreaRef", area_reference),
                        ("Channel", channel_reference),
                    ),
                ),
            )
        )
        relations.append(
            OperationalRelationPayload(
                domain="incident_asset",
                domain_id=incident_domain_id,
                direction=incident_direction,
                source=OperationalEndpointReference("process", incident_id, incident_key),
                destination=OperationalEndpointReference(
                    "asset", server_id, record.finding.asset_id
                ),
            )
        )

    for record in records:
        if not record.finding.actionable:
            continue
        if record.remediation_started is None or record.remediation_completed is None:
            raise OperationalPayloadError("Actionable occurrence has no remediation lifecycle")

        occurrence_key = record.finding.correlation_key
        change_key = f"change:{occurrence_key}"
        change_code = _code("CHG2", occurrence_key)
        short_description = (
            f"{change_code} | Remediate {record.finding.cve_id} "
            f"on {record.finding.asset_id}"
        )
        processes.append(
            OperationalProcessPayload(
                entity="change",
                process_id=change_id,
                key=change_key,
                start_activity=_start_activity(mapping, "change"),
                identity_attribute="ShortDescr",
                identity_value=short_description,
                attributes=_start_attributes(
                    mapping,
                    "change",
                    (
                        ("Channel", channel_reference),
                        ("ShortDescr", short_description),
                    ),
                ),
            )
        )
        relations.append(
            OperationalRelationPayload(
                domain="change_asset",
                domain_id=change_domain_id,
                direction=change_direction,
                source=OperationalEndpointReference("process", change_id, change_key),
                destination=OperationalEndpointReference(
                    "asset", server_id, record.finding.asset_id
                ),
            )
        )
        relations.append(
            OperationalRelationPayload(
                domain="incident_change",
                domain_id=parent_domain_id,
                direction=parent_direction,
                source=OperationalEndpointReference(
                    "process",
                    incident_id,
                    incident_key_by_occurrence[occurrence_key],
                ),
                destination=OperationalEndpointReference(
                    "process",
                    change_id,
                    change_key,
                ),
            )
        )

    process_tuple = tuple(processes)
    relation_tuple = tuple(relations)
    return OperationalPayloadPlan(
        support_cards=support_cards,
        processes=process_tuple,
        relations=relation_tuple,
        public_binding_fingerprint=public_binding_fingerprint,
        policy=policy,
        fingerprint=_fingerprint(
            support_cards,
            process_tuple,
            relation_tuple,
            public_binding_fingerprint,
            policy,
        ),
    )
