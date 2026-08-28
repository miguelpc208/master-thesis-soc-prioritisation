"""Idempotent, fingerprint-gated execution of READY2USE operational payloads."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from thesis_pipeline.cmdbuild.business_payloads import LookupReference
from thesis_pipeline.cmdbuild.operational_payloads import (
    OperationalEndpointReference,
    OperationalPayloadPlan,
    OperationalProcessPayload,
    OperationalRelationPayload,
    OperationalSupportCardPayload,
    OperationalValue,
    ProcessReference,
    RoleReference,
    SupportReference,
)


class OperationalIngestionError(RuntimeError):
    """Raised when operational ingestion cannot proceed or roll back safely."""


class OperationalWriteClient(Protocol):
    """REST operations required by the operational ingestion executor."""

    def resolve_lookup(self, lookup_type: str, code: str) -> int: ...

    def cards(self, class_id: str) -> list[dict[str, Any]]: ...

    def process_instances(self, process_id: str) -> list[dict[str, Any]]: ...

    def start_activities(self, process_id: str) -> list[dict[str, Any]]: ...

    def domain_relations(self, domain_id: str) -> list[dict[str, Any]]: ...

    def create_card(self, class_id: str, attributes: Mapping[str, Any]) -> int: ...

    def delete_card(self, class_id: str, card_id: int) -> None: ...

    def create_process_instance(
        self,
        process_id: str,
        activity_id: str,
        attributes: Mapping[str, Any],
        *,
        advance: bool,
    ) -> int: ...

    def delete_process_instance(self, process_id: str, instance_id: int) -> None: ...

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
class SupportWriteAction:
    payload: OperationalSupportCardPayload
    operation: str
    card_id: int
    resolved_attributes: tuple[tuple[str, Any], ...]


@dataclass(frozen=True, slots=True)
class ProcessWriteAction:
    payload: OperationalProcessPayload
    operation: str
    instance_id: int
    resolved_attributes: tuple[tuple[str, Any], ...]


@dataclass(frozen=True, slots=True)
class OperationalRelationWriteAction:
    payload: OperationalRelationPayload
    operation: str
    relation_id: int | None
    source_type: str
    source_id: int
    destination_type: str
    destination_id: int


@dataclass(frozen=True, slots=True)
class OperationalIngestionPreview:
    """Read-only operational execution plan."""

    payload_fingerprint: str
    support_cards: tuple[SupportWriteAction, ...]
    processes: tuple[ProcessWriteAction, ...]
    relations: tuple[OperationalRelationWriteAction, ...]

    @staticmethod
    def _operations(actions: tuple[Any, ...]) -> tuple[tuple[str, int], ...]:
        counts = Counter(action.operation for action in actions)
        return tuple((operation, counts[operation]) for operation in ("create", "reuse"))

    @property
    def support_operations(self) -> tuple[tuple[str, int], ...]:
        return self._operations(self.support_cards)

    @property
    def process_operations(self) -> tuple[tuple[str, int], ...]:
        return self._operations(self.processes)

    @property
    def relation_operations(self) -> tuple[tuple[str, int], ...]:
        return self._operations(self.relations)


@dataclass(frozen=True, slots=True)
class OperationalIngestionResult:
    """Committed operational result with identifiers created by this run."""

    preview: OperationalIngestionPreview
    created_support_cards: tuple[tuple[str, int], ...]
    created_processes: tuple[tuple[str, int], ...]
    created_relations: tuple[tuple[str, int], ...]


def _identifier(value: Any, resource: str) -> int:
    if isinstance(value, str) and value.isdecimal():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise OperationalIngestionError(f"Invalid existing {resource} identifier")
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
    return actual == expected


def _index_cards(
    cards: list[dict[str, Any]],
    identity_attribute: str,
    resource: str,
) -> dict[Any, dict[str, Any]]:
    index: dict[Any, dict[str, Any]] = {}
    for card in cards:
        value = _actual_value(card.get(identity_attribute))
        if value is None:
            continue
        if value in index:
            raise OperationalIngestionError(
                f"Duplicate {resource} identity for {identity_attribute}={value!r}"
            )
        index[value] = card
    return index


def _find_role(
    client: OperationalWriteClient,
    reference: RoleReference,
    cache: dict[tuple[str, str, str], int],
) -> int:
    key = (
        reference.class_id,
        reference.identity_attribute,
        reference.identity_value,
    )
    if key in cache:
        return cache[key]
    matches = [
        card
        for card in client.cards(reference.class_id)
        if _actual_value(card.get(reference.identity_attribute)) == reference.identity_value
    ]
    if len(matches) != 1:
        raise OperationalIngestionError(
            f"Expected one active role card for {reference.identity_value}"
        )
    identifier = _identifier(matches[0].get("_id"), "role card")
    cache[key] = identifier
    return identifier


def _resolve_value(
    value: OperationalValue,
    client: OperationalWriteClient,
    support_ids: Mapping[str, int],
    process_ids: Mapping[str, int],
    role_cache: dict[tuple[str, str, str], int],
) -> Any:
    if isinstance(value, LookupReference):
        return client.resolve_lookup(value.lookup_type, value.code)
    if isinstance(value, RoleReference):
        return _find_role(client, value, role_cache)
    if isinstance(value, SupportReference):
        if value.key not in support_ids:
            raise OperationalIngestionError(f"Unresolved support reference: {value.key}")
        return support_ids[value.key]
    if isinstance(value, ProcessReference):
        if value.key not in process_ids:
            raise OperationalIngestionError(f"Unresolved process reference: {value.key}")
        return process_ids[value.key]
    return value


def _resolved_attributes(
    attributes: tuple[tuple[str, OperationalValue], ...],
    client: OperationalWriteClient,
    support_ids: Mapping[str, int],
    process_ids: Mapping[str, int],
    role_cache: dict[tuple[str, str, str], int],
) -> tuple[tuple[str, Any], ...]:
    return tuple(
        (
            name,
            _resolve_value(
                value,
                client,
                support_ids,
                process_ids,
                role_cache,
            ),
        )
        for name, value in attributes
    )


def _validate_start_activities(
    client: OperationalWriteClient,
    processes: tuple[OperationalProcessPayload, ...],
) -> None:
    expected_by_process: dict[str, str] = {}
    for process in processes:
        previous = expected_by_process.setdefault(process.process_id, process.start_activity)
        if previous != process.start_activity:
            raise OperationalIngestionError(
                f"Conflicting start activities for {process.process_id}"
            )
    for process_id, expected in expected_by_process.items():
        matches = [
            activity
            for activity in client.start_activities(process_id)
            if activity.get("_id") == expected
        ]
        if len(matches) != 1:
            raise OperationalIngestionError(
                f"Expected one start activity {expected} for {process_id}"
            )


def _endpoint_id(
    reference: OperationalEndpointReference,
    process_ids: Mapping[str, int],
    asset_ids: Mapping[str, int],
) -> int:
    if reference.kind == "process":
        identifiers = process_ids
    elif reference.kind == "asset":
        identifiers = asset_ids
    else:
        raise OperationalIngestionError(f"Unsupported endpoint kind: {reference.kind}")
    if reference.key not in identifiers:
        raise OperationalIngestionError(f"Unresolved relation endpoint: {reference.key}")
    return identifiers[reference.key]


def _physical_endpoints(
    relation: OperationalRelationPayload,
    process_ids: Mapping[str, int],
    asset_ids: Mapping[str, int],
) -> tuple[str, int, str, int]:
    source = (relation.source.type_id, _endpoint_id(relation.source, process_ids, asset_ids))
    destination = (
        relation.destination.type_id,
        _endpoint_id(relation.destination, process_ids, asset_ids),
    )
    if relation.direction == "direct":
        return (*source, *destination)
    if relation.direction == "inverse":
        return (*destination, *source)
    raise OperationalIngestionError(f"Unsupported relation direction: {relation.direction}")


def _relation_identifier(
    relations: list[dict[str, Any]],
    source_type: str,
    source_id: int,
    destination_type: str,
    destination_id: int,
) -> int | None:
    matches = [
        relation
        for relation in relations
        if relation.get("_sourceType") == source_type
        and _values_match(relation.get("_sourceId"), source_id)
        and relation.get("_destinationType") == destination_type
        and _values_match(relation.get("_destinationId"), destination_id)
    ]
    if len(matches) > 1:
        raise OperationalIngestionError("Duplicate existing operational relation")
    if not matches:
        return None
    return _identifier(matches[0].get("_id"), "operational relation")


def prepare_operational_ingestion(
    client: OperationalWriteClient,
    plan: OperationalPayloadPlan,
) -> OperationalIngestionPreview:
    """Inspect live state and prepare an idempotent plan without mutations."""

    _validate_start_activities(client, plan.processes)
    role_cache: dict[tuple[str, str, str], int] = {}
    next_placeholder = -1

    support_ids: dict[str, int] = {}
    existing_support: dict[str, dict[str, Any]] = {}
    for payload in plan.support_cards:
        existing = _index_cards(
            client.cards(payload.class_id),
            payload.identity_attribute,
            payload.class_id,
        ).get(payload.identity_value)
        if existing is None:
            support_ids[payload.key] = next_placeholder
            next_placeholder -= 1
        else:
            support_ids[payload.key] = _identifier(existing.get("_id"), "support card")
            existing_support[payload.key] = existing

    process_ids: dict[str, int] = {}
    existing_processes: dict[str, dict[str, Any]] = {}
    indexes: dict[tuple[str, str], dict[Any, dict[str, Any]]] = {}
    for payload in plan.processes:
        index_key = (payload.process_id, payload.identity_attribute)
        if index_key not in indexes:
            indexes[index_key] = _index_cards(
                client.process_instances(payload.process_id),
                payload.identity_attribute,
                payload.process_id,
            )
        existing = indexes[index_key].get(payload.identity_value)
        if existing is None:
            process_ids[payload.key] = next_placeholder
            next_placeholder -= 1
        else:
            process_ids[payload.key] = _identifier(existing.get("_id"), "process instance")
            existing_processes[payload.key] = existing

    server_type = plan.relations[0].destination.type_id if plan.relations else "PhysicalServer"
    server_index = _index_cards(client.cards(server_type), "Code", server_type)
    asset_keys = sorted(
        {
            endpoint.key
            for relation in plan.relations
            for endpoint in (relation.source, relation.destination)
            if endpoint.kind == "asset"
        }
    )
    asset_ids = {
        key: _identifier(server_index[key].get("_id"), "asset card")
        for key in asset_keys
        if key in server_index
    }
    if len(asset_ids) != len(asset_keys):
        missing = sorted(set(asset_keys) - set(asset_ids))
        raise OperationalIngestionError("Missing business assets: " + ", ".join(missing))

    support_actions: list[SupportWriteAction] = []
    for payload in plan.support_cards:
        resolved = _resolved_attributes(
            payload.attributes,
            client,
            support_ids,
            process_ids,
            role_cache,
        )
        existing = existing_support.get(payload.key)
        if existing is not None:
            mismatches = [
                name for name, value in resolved if not _values_match(existing.get(name), value)
            ]
            if mismatches:
                raise OperationalIngestionError(
                    f"Existing support card conflicts with {payload.key}: "
                    + ", ".join(mismatches)
                )
        support_actions.append(
            SupportWriteAction(
                payload=payload,
                operation="reuse" if existing is not None else "create",
                card_id=support_ids[payload.key],
                resolved_attributes=resolved,
            )
        )

    process_actions: list[ProcessWriteAction] = []
    for payload in plan.processes:
        resolved = _resolved_attributes(
            payload.attributes,
            client,
            support_ids,
            process_ids,
            role_cache,
        )
        existing = existing_processes.get(payload.key)
        if existing is not None:
            mismatches = [
                name for name, value in resolved if not _values_match(existing.get(name), value)
            ]
            if mismatches:
                raise OperationalIngestionError(
                    f"Existing process conflicts with {payload.key}: "
                    + ", ".join(mismatches)
                )
        process_actions.append(
            ProcessWriteAction(
                payload=payload,
                operation="reuse" if existing is not None else "create",
                instance_id=process_ids[payload.key],
                resolved_attributes=resolved,
            )
        )

    relations_by_domain = {
        domain_id: client.domain_relations(domain_id)
        for domain_id in dict.fromkeys(relation.domain_id for relation in plan.relations)
    }
    relation_actions: list[OperationalRelationWriteAction] = []
    for payload in plan.relations:
        source_type, source_id, destination_type, destination_id = _physical_endpoints(
            payload,
            process_ids,
            asset_ids,
        )
        relation_id = None
        if source_id > 0 and destination_id > 0:
            relation_id = _relation_identifier(
                relations_by_domain[payload.domain_id],
                source_type,
                source_id,
                destination_type,
                destination_id,
            )
        relation_actions.append(
            OperationalRelationWriteAction(
                payload=payload,
                operation="reuse" if relation_id is not None else "create",
                relation_id=relation_id,
                source_type=source_type,
                source_id=source_id,
                destination_type=destination_type,
                destination_id=destination_id,
            )
        )

    return OperationalIngestionPreview(
        payload_fingerprint=plan.fingerprint,
        support_cards=tuple(support_actions),
        processes=tuple(process_actions),
        relations=tuple(relation_actions),
    )


def execute_operational_ingestion(
    client: OperationalWriteClient,
    plan: OperationalPayloadPlan,
    *,
    expected_fingerprint: str,
) -> OperationalIngestionResult:
    """Execute a validated operational plan with bounded reverse-order rollback."""

    if expected_fingerprint != plan.fingerprint:
        raise OperationalIngestionError("Operational payload fingerprint mismatch")
    preview = prepare_operational_ingestion(client, plan)
    role_cache: dict[tuple[str, str, str], int] = {}
    support_ids = {action.payload.key: action.card_id for action in preview.support_cards}
    process_ids = {action.payload.key: action.instance_id for action in preview.processes}

    server_type = plan.relations[0].destination.type_id if plan.relations else "PhysicalServer"
    server_index = _index_cards(client.cards(server_type), "Code", server_type)
    asset_ids = {
        key: _identifier(card.get("_id"), "asset card") for key, card in server_index.items()
    }

    created_support: list[tuple[str, int]] = []
    created_processes: list[tuple[str, int]] = []
    created_relations: list[tuple[str, int]] = []
    try:
        for action in preview.support_cards:
            if action.operation == "reuse":
                continue
            attributes = dict(
                _resolved_attributes(
                    action.payload.attributes,
                    client,
                    support_ids,
                    process_ids,
                    role_cache,
                )
            )
            card_id = client.create_card(action.payload.class_id, attributes)
            support_ids[action.payload.key] = card_id
            created_support.append((action.payload.class_id, card_id))

        for action in preview.processes:
            if action.operation == "reuse":
                continue
            attributes = dict(
                _resolved_attributes(
                    action.payload.attributes,
                    client,
                    support_ids,
                    process_ids,
                    role_cache,
                )
            )
            instance_id = client.create_process_instance(
                action.payload.process_id,
                action.payload.start_activity,
                attributes,
                advance=False,
            )
            process_ids[action.payload.key] = instance_id
            created_processes.append((action.payload.process_id, instance_id))

        for action in preview.relations:
            if action.operation == "reuse":
                continue
            source_type, source_id, destination_type, destination_id = _physical_endpoints(
                action.payload,
                process_ids,
                asset_ids,
            )
            relation_id = client.create_relation(
                action.payload.domain_id,
                source_type,
                source_id,
                destination_type,
                destination_id,
            )
            created_relations.append((action.payload.domain_id, relation_id))
    except Exception as ingestion_error:
        rollback_errors: list[Exception] = []
        for domain_id, relation_id in reversed(created_relations):
            try:
                client.delete_relation(domain_id, relation_id)
            except Exception as exc:  # noqa: BLE001
                rollback_errors.append(exc)
        for process_id, instance_id in reversed(created_processes):
            try:
                client.delete_process_instance(process_id, instance_id)
            except Exception as exc:  # noqa: BLE001
                rollback_errors.append(exc)
        for class_id, card_id in reversed(created_support):
            try:
                client.delete_card(class_id, card_id)
            except Exception as exc:  # noqa: BLE001
                rollback_errors.append(exc)
        if rollback_errors:
            raise OperationalIngestionError(
                f"Operational rollback failed for {len(rollback_errors)} object(s)"
            ) from ingestion_error
        raise

    return OperationalIngestionResult(
        preview=preview,
        created_support_cards=tuple(created_support),
        created_processes=tuple(created_processes),
        created_relations=tuple(created_relations),
    )
