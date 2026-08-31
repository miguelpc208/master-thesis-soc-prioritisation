"""Idempotent, fingerprint-gated execution of READY2USE business payloads."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from thesis_pipeline.cmdbuild.business_payloads import (
    BusinessCardPayload,
    BusinessPayloadPlan,
    BusinessRelationPayload,
    CardReference,
    LookupReference,
    PayloadValue,
)

IDENTITY_LOGICAL_FIELD = {
    "vendor": "code",
    "contract": "code",
    "sla": "code",
    "service_category": "index",
    "business_service": "code",
    "server": "code",
    "application": "code",
}


class BusinessIngestionError(RuntimeError):
    """Raised when business ingestion cannot proceed or roll back safely."""


class BusinessWriteClient(Protocol):
    """REST operations required by the business ingestion executor."""

    def resolve_lookup(self, lookup_type: str, code: str) -> int: ...

    def cards(self, class_id: str) -> list[dict[str, Any]]: ...

    def domain_relations(self, domain_id: str) -> list[dict[str, Any]]: ...

    def create_card(self, class_id: str, attributes: Mapping[str, Any]) -> int: ...

    def delete_card(self, class_id: str, card_id: int) -> None: ...

    def create_relation(
        self,
        domain_id: str,
        source_type: str,
        source_id: int,
        destination_type: str,
        destination_id: int,
    ) -> int: ...

    def delete_relation(self, domain_id: str, relation_id: int) -> None: ...


@dataclass(frozen=True, slots=True)
class CardWriteAction:
    """One card create or reuse decision."""

    card: BusinessCardPayload
    operation: str
    card_id: int
    resolved_attributes: tuple[tuple[str, Any], ...]


@dataclass(frozen=True, slots=True)
class RelationWriteAction:
    """One relation create or reuse decision in physical domain direction."""

    relation: BusinessRelationPayload
    operation: str
    relation_id: int | None
    source_type: str
    source_id: int
    destination_type: str
    destination_id: int


@dataclass(frozen=True, slots=True)
class BusinessIngestionPreview:
    """Read-only execution plan produced before any mutation is authorized."""

    payload_fingerprint: str
    cards: tuple[CardWriteAction, ...]
    relations: tuple[RelationWriteAction, ...]

    @property
    def card_operations(self) -> tuple[tuple[str, int], ...]:
        counts = Counter(action.operation for action in self.cards)
        return tuple((operation, counts[operation]) for operation in ("create", "reuse"))

    @property
    def relation_operations(self) -> tuple[tuple[str, int], ...]:
        counts = Counter(action.operation for action in self.relations)
        return tuple((operation, counts[operation]) for operation in ("create", "reuse"))


@dataclass(frozen=True, slots=True)
class BusinessIngestionResult:
    """Committed execution result with the identifiers created by this run."""

    preview: BusinessIngestionPreview
    created_cards: tuple[tuple[str, int], ...]
    created_relations: tuple[tuple[str, int], ...]


def _identifier(value: Any, resource: str) -> int:
    if isinstance(value, str) and value.isdecimal():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise BusinessIngestionError(f"Invalid existing {resource} identifier")
    return value


def _actual_value(value: Any) -> Any:
    if isinstance(value, dict) and "_id" in value:
        return value["_id"]
    return value


def _values_match(actual: Any, expected: Any) -> bool:
    actual = _actual_value(actual)
    if (
        isinstance(expected, int)
        and not isinstance(expected, bool)
        and isinstance(actual, str)
        and actual.isdecimal()
    ):
        actual = int(actual)
    if actual == expected:
        return True
    if (
        isinstance(actual, str)
        and isinstance(expected, str)
        and re.fullmatch(r"\d{4}-\d{2}-\d{2}", expected)
    ):
        return actual.startswith(expected)
    return False


def _resolve_value(
    value: PayloadValue,
    card_ids: Mapping[tuple[str, str], int],
    client: BusinessWriteClient,
) -> Any:
    if isinstance(value, LookupReference):
        return client.resolve_lookup(value.lookup_type, value.code)
    if isinstance(value, CardReference):
        try:
            return card_ids[(value.entity, value.key)]
        except KeyError as exc:
            raise BusinessIngestionError(f"Unresolved symbolic card reference: {value}") from exc
    return value


def _mapping_section(
    configuration: Mapping[str, Any],
    name: str,
    context: str,
) -> Mapping[str, Any]:
    value = configuration.get(name)
    if not isinstance(value, Mapping):
        raise BusinessIngestionError(f"Missing mapping section: {context}.{name}")
    return value


def _identity_attribute(
    card: BusinessCardPayload,
    mapping: Mapping[str, Any],
) -> str:
    try:
        logical_field = IDENTITY_LOGICAL_FIELD[card.entity]
    except KeyError as exc:
        raise BusinessIngestionError(f"Unsupported business entity: {card.entity}") from exc
    entities = _mapping_section(mapping, "entities", "mapping")
    entity = _mapping_section(entities, card.entity, "mapping.entities")
    fields = _mapping_section(
        entity,
        "fields",
        f"mapping.entities.{card.entity}",
    )
    attribute = fields.get(logical_field)
    if not isinstance(attribute, str) or not attribute.strip():
        raise BusinessIngestionError(
            f"Missing identity mapping for business entity: {card.entity}"
        )
    return attribute


def _identity(
    card: BusinessCardPayload,
    mapping: Mapping[str, Any],
) -> tuple[str, Any]:
    attribute = _identity_attribute(card, mapping)
    attributes = dict(card.attributes)
    if attribute not in attributes:
        raise BusinessIngestionError(
            f"Card payload is missing identity attribute {attribute}: {card.key}"
        )
    value = attributes[attribute]
    if isinstance(value, (CardReference, LookupReference)) or value in {None, ""}:
        raise BusinessIngestionError(f"Invalid identity value for planned card: {card.key}")
    return attribute, value


def _validate_mapping_contract(
    plan: BusinessPayloadPlan,
    mapping: Mapping[str, Any],
) -> None:
    if mapping.get("discovery_status") != "confirmed":
        raise BusinessIngestionError("CMDBuild field discovery must be confirmed")
    entities = _mapping_section(mapping, "entities", "mapping")
    for card in plan.cards:
        entity = _mapping_section(entities, card.entity, "mapping.entities")
        if entity.get("kind") != "class" or entity.get("cmdbuild_id") != card.class_id:
            raise BusinessIngestionError(
                f"Payload class conflicts with confirmed mapping: {card.entity}"
            )
        _identity(card, mapping)
    domains = _mapping_section(mapping, "domains", "mapping")
    for relation in plan.relations:
        domain = _mapping_section(domains, relation.domain, "mapping.domains")
        if (
            domain.get("cmdbuild_id") != relation.domain_id
            or domain.get("direction") != relation.direction
        ):
            raise BusinessIngestionError(
                f"Payload domain conflicts with confirmed mapping: {relation.domain}"
            )


def _index_existing_cards(
    cards: list[dict[str, Any]],
    identity_attribute: str,
) -> dict[Any, dict[str, Any]]:
    indexed: dict[Any, dict[str, Any]] = {}
    for card in cards:
        identity_value = card.get(identity_attribute)
        if identity_value in {None, ""}:
            continue
        if identity_value in indexed:
            raise BusinessIngestionError(
                f"Duplicate existing card identity for {identity_attribute}"
            )
        indexed[identity_value] = card
    return indexed


def _relation_endpoints(
    relation: BusinessRelationPayload,
    card_by_reference: Mapping[tuple[str, str], BusinessCardPayload],
    card_ids: Mapping[tuple[str, str], int],
) -> tuple[str, int, str, int]:
    source_key = (relation.source.entity, relation.source.key)
    destination_key = (relation.destination.entity, relation.destination.key)
    try:
        source_card = card_by_reference[source_key]
        destination_card = card_by_reference[destination_key]
        source_id = card_ids[source_key]
        destination_id = card_ids[destination_key]
    except KeyError as exc:
        raise BusinessIngestionError("Relation references an unknown planned card") from exc
    if relation.direction == "direct":
        return (
            source_card.class_id,
            source_id,
            destination_card.class_id,
            destination_id,
        )
    if relation.direction == "inverse":
        return (
            destination_card.class_id,
            destination_id,
            source_card.class_id,
            source_id,
        )
    raise BusinessIngestionError(f"Unsupported relation direction: {relation.direction}")


def _existing_relation_key(relation: Mapping[str, Any]) -> tuple[str, int, str, int]:
    source_type = relation.get("_sourceType")
    destination_type = relation.get("_destinationType")
    if not isinstance(source_type, str) or not isinstance(destination_type, str):
        raise BusinessIngestionError("Existing relation is missing endpoint types")
    return (
        source_type,
        _identifier(relation.get("_sourceId"), "relation source"),
        destination_type,
        _identifier(relation.get("_destinationId"), "relation destination"),
    )


def prepare_business_ingestion(
    client: BusinessWriteClient,
    plan: BusinessPayloadPlan,
    mapping: Mapping[str, Any],
) -> BusinessIngestionPreview:
    """Inspect live state and prepare an idempotent plan without REST mutations."""

    _validate_mapping_contract(plan, mapping)
    card_by_reference = {
        (card.entity, card.key): card
        for card in plan.cards
    }
    if len(card_by_reference) != len(plan.cards):
        raise BusinessIngestionError("Planned card references are not unique")

    existing_by_entity: dict[str, dict[Any, dict[str, Any]]] = {}
    for entity in dict.fromkeys(card.entity for card in plan.cards):
        entity_cards = [card for card in plan.cards if card.entity == entity]
        identity_attribute, _identity_value = _identity(entity_cards[0], mapping)
        existing_by_entity[entity] = _index_existing_cards(
            client.cards(entity_cards[0].class_id),
            identity_attribute,
        )

    card_ids: dict[tuple[str, str], int] = {}
    existing_cards: dict[tuple[str, str], dict[str, Any]] = {}
    next_placeholder = -1
    for card in plan.cards:
        _identity_attribute_name, identity_value = _identity(card, mapping)
        existing = existing_by_entity[card.entity].get(identity_value)
        reference = (card.entity, card.key)
        if existing is None:
            card_ids[reference] = next_placeholder
            next_placeholder -= 1
        else:
            card_ids[reference] = _identifier(existing.get("_id"), "card")
            existing_cards[reference] = existing

    card_actions: list[CardWriteAction] = []
    for card in plan.cards:
        reference = (card.entity, card.key)
        resolved_attributes = tuple(
            (
                name,
                _resolve_value(value, card_ids, client),
            )
            for name, value in card.attributes
        )
        existing = existing_cards.get(reference)
        if existing is not None:
            mismatches = [
                name
                for name, expected in resolved_attributes
                if not _values_match(existing.get(name), expected)
            ]
            if mismatches:
                raise BusinessIngestionError(
                    f"Existing card conflicts with payload {card.key}: "
                    + ", ".join(mismatches)
                )
        card_actions.append(
            CardWriteAction(
                card=card,
                operation="reuse" if existing is not None else "create",
                card_id=card_ids[reference],
                resolved_attributes=resolved_attributes,
            )
        )

    existing_relations_by_domain: dict[
        str,
        dict[tuple[str, int, str, int], dict[str, Any]],
    ] = {}
    for domain_id in dict.fromkeys(
        relation.domain_id for relation in plan.relations
    ):
        indexed: dict[tuple[str, int, str, int], dict[str, Any]] = {}
        for existing_relation in client.domain_relations(domain_id):
            key = _existing_relation_key(existing_relation)
            if key in indexed:
                raise BusinessIngestionError(
                    f"Duplicate existing relation endpoints in domain {domain_id}"
                )
            indexed[key] = existing_relation
        existing_relations_by_domain[domain_id] = indexed

    relation_actions: list[RelationWriteAction] = []
    for relation in plan.relations:
        endpoints = _relation_endpoints(
            relation,
            card_by_reference,
            card_ids,
        )
        existing = None
        if endpoints[1] > 0 and endpoints[3] > 0:
            existing = existing_relations_by_domain[relation.domain_id].get(endpoints)
        relation_actions.append(
            RelationWriteAction(
                relation=relation,
                operation="reuse" if existing is not None else "create",
                relation_id=(
                    _identifier(existing.get("_id"), "relation")
                    if existing is not None
                    else None
                ),
                source_type=endpoints[0],
                source_id=endpoints[1],
                destination_type=endpoints[2],
                destination_id=endpoints[3],
            )
        )

    return BusinessIngestionPreview(
        payload_fingerprint=plan.fingerprint,
        cards=tuple(card_actions),
        relations=tuple(relation_actions),
    )


def execute_business_ingestion(
    client: BusinessWriteClient,
    plan: BusinessPayloadPlan,
    mapping: Mapping[str, Any],
    *,
    expected_fingerprint: str,
) -> BusinessIngestionResult:
    """Execute a confirmed plan and roll back only objects created by this call."""

    if expected_fingerprint != plan.fingerprint:
        raise BusinessIngestionError("Payload fingerprint confirmation does not match")
    preview = prepare_business_ingestion(client, plan, mapping)
    card_ids: dict[tuple[str, str], int] = {}
    card_by_reference = {
        (card.entity, card.key): card
        for card in plan.cards
    }
    created_cards: list[tuple[str, int]] = []
    created_relations: list[tuple[str, int]] = []
    try:
        for action in preview.cards:
            reference = (action.card.entity, action.card.key)
            if action.operation == "reuse":
                card_ids[reference] = action.card_id
                continue
            attributes = {
                name: _resolve_value(value, card_ids, client)
                for name, value in action.card.attributes
            }
            card_id = client.create_card(action.card.class_id, attributes)
            card_ids[reference] = card_id
            created_cards.append((action.card.class_id, card_id))

        for action in preview.relations:
            if action.operation == "reuse":
                continue
            endpoints = _relation_endpoints(
                action.relation,
                card_by_reference,
                card_ids,
            )
            relation_id = client.create_relation(
                action.relation.domain_id,
                endpoints[0],
                endpoints[1],
                endpoints[2],
                endpoints[3],
            )
            created_relations.append((action.relation.domain_id, relation_id))
    except Exception as exc:
        rollback_errors: list[str] = []
        for domain_id, relation_id in reversed(created_relations):
            try:
                client.delete_relation(domain_id, relation_id)
            except Exception:
                rollback_errors.append(f"relation {domain_id}/{relation_id}")
        for class_id, card_id in reversed(created_cards):
            try:
                client.delete_card(class_id, card_id)
            except Exception:
                rollback_errors.append(f"card {class_id}/{card_id}")
        if rollback_errors:
            raise BusinessIngestionError(
                "Business ingestion failed and rollback was incomplete: "
                + ", ".join(rollback_errors)
            ) from exc
        raise BusinessIngestionError(
            "Business ingestion failed; objects created by this call were rolled back"
        ) from exc

    return BusinessIngestionResult(
        preview=preview,
        created_cards=tuple(created_cards),
        created_relations=tuple(created_relations),
    )
