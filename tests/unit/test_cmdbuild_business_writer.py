import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

from thesis_pipeline.cmdbuild.business_payloads import build_business_payload_plan
from thesis_pipeline.cmdbuild.business_writer import (
    BusinessIngestionError,
    execute_business_ingestion,
    prepare_business_ingestion,
)
from thesis_pipeline.cmdbuild.client import CMDBuildClient, CMDBuildSettings
from thesis_pipeline.config import load_scenario
from thesis_pipeline.synthetic_org.generator import generate_dataset

ROOT = Path(__file__).resolve().parents[2]


def _plan():
    scenario = load_scenario(ROOT / "configs/scenarios/smoke.yaml")
    dataset = generate_dataset(scenario)
    mapping = json.loads(
        (ROOT / "config/cmdbuild_fields.json").read_text(encoding="utf-8")
    )
    simulation = json.loads(
        (ROOT / "config/simulation.json").read_text(encoding="utf-8")
    )
    return build_business_payload_plan(dataset, scenario, mapping, simulation), mapping


class FakeBusinessClient:
    def __init__(self, *, fail_relation_at: int | None = None) -> None:
        self.card_store: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.relation_store: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.lookup_ids: dict[tuple[str, str], int] = {}
        self.next_id = 1000
        self.fail_relation_at = fail_relation_at
        self.relation_attempts = 0
        self.mutations: list[tuple[str, str, int]] = []

    def _id(self) -> int:
        self.next_id += 1
        return self.next_id

    def resolve_lookup(self, lookup_type: str, code: str) -> int:
        key = (lookup_type, code)
        if key not in self.lookup_ids:
            self.lookup_ids[key] = self._id()
        return self.lookup_ids[key]

    def cards(self, class_id: str) -> list[dict[str, Any]]:
        return [dict(card) for card in self.card_store[class_id]]

    def domain_relations(self, domain_id: str) -> list[dict[str, Any]]:
        return [dict(relation) for relation in self.relation_store[domain_id]]

    def create_card(self, class_id: str, attributes: dict[str, Any]) -> int:
        card_id = self._id()
        self.card_store[class_id].append({"_id": card_id, **attributes})
        self.mutations.append(("create_card", class_id, card_id))
        return card_id

    def delete_card(self, class_id: str, card_id: int) -> None:
        self.card_store[class_id] = [
            card for card in self.card_store[class_id] if card["_id"] != card_id
        ]
        self.mutations.append(("delete_card", class_id, card_id))

    def create_relation(
        self,
        domain_id: str,
        source_type: str,
        source_id: int,
        destination_type: str,
        destination_id: int,
    ) -> int:
        self.relation_attempts += 1
        if self.fail_relation_at == self.relation_attempts:
            raise RuntimeError("simulated relation failure")
        relation_id = self._id()
        self.relation_store[domain_id].append(
            {
                "_id": relation_id,
                "_type": domain_id,
                "_sourceType": source_type,
                "_sourceId": source_id,
                "_destinationType": destination_type,
                "_destinationId": destination_id,
            }
        )
        self.mutations.append(("create_relation", domain_id, relation_id))
        return relation_id

    def delete_relation(self, domain_id: str, relation_id: int) -> None:
        self.relation_store[domain_id] = [
            relation
            for relation in self.relation_store[domain_id]
            if relation["_id"] != relation_id
        ]
        self.mutations.append(("delete_relation", domain_id, relation_id))


def test_read_only_preview_plans_the_empty_ready2use_population() -> None:
    plan, mapping = _plan()
    client = FakeBusinessClient()

    preview = prepare_business_ingestion(client, plan, mapping)

    assert dict(preview.card_operations) == {"create": 234, "reuse": 0}
    assert dict(preview.relation_operations) == {"create": 260, "reuse": 0}
    assert preview.payload_fingerprint == plan.fingerprint
    assert client.mutations == []
    assert all(action.card_id < 0 for action in preview.cards)


def test_execution_requires_the_exact_payload_fingerprint() -> None:
    plan, mapping = _plan()
    client = FakeBusinessClient()

    with pytest.raises(BusinessIngestionError, match="fingerprint"):
        execute_business_ingestion(
            client,
            plan,
            mapping,
            expected_fingerprint="wrong",
        )

    assert client.mutations == []


def test_execution_is_idempotent_after_a_successful_commit() -> None:
    plan, mapping = _plan()
    client = FakeBusinessClient()

    first = execute_business_ingestion(
        client,
        plan,
        mapping,
        expected_fingerprint=plan.fingerprint,
    )
    assert len(first.created_cards) == 234
    assert len(first.created_relations) == 260

    mutation_count = len(client.mutations)
    second = execute_business_ingestion(
        client,
        plan,
        mapping,
        expected_fingerprint=plan.fingerprint,
    )
    assert dict(second.preview.card_operations) == {"create": 0, "reuse": 234}
    assert dict(second.preview.relation_operations) == {"create": 0, "reuse": 260}
    assert second.created_cards == ()
    assert second.created_relations == ()
    assert len(client.mutations) == mutation_count


def test_relation_failure_rolls_back_every_card_created_by_the_call() -> None:
    plan, mapping = _plan()
    client = FakeBusinessClient(fail_relation_at=1)

    with pytest.raises(BusinessIngestionError, match="rolled back"):
        execute_business_ingestion(
            client,
            plan,
            mapping,
            expected_fingerprint=plan.fingerprint,
        )

    assert sum(map(len, client.card_store.values())) == 0
    assert sum(map(len, client.relation_store.values())) == 0
    assert sum(item[0] == "create_card" for item in client.mutations) == 234
    assert sum(item[0] == "delete_card" for item in client.mutations) == 234


def test_preview_rejects_conflicting_existing_business_cards() -> None:
    plan, mapping = _plan()
    client = FakeBusinessClient()
    vendor = next(card for card in plan.cards if card.entity == "vendor")
    attributes = dict(vendor.attributes)
    vendor_fields = mapping["entities"]["vendor"]["fields"]
    code_field = vendor_fields["code"]
    name_field = vendor_fields["name"]
    client.card_store[vendor.class_id].append(
        {
            "_id": 77,
            code_field: attributes[code_field],
            name_field: "Conflicting supplier",
        }
    )

    with pytest.raises(BusinessIngestionError, match="conflicts with payload"):
        prepare_business_ingestion(client, plan, mapping)

    assert client.mutations == []


def test_preview_rejects_mapping_drift_before_live_reads() -> None:
    plan, mapping = _plan()
    client = FakeBusinessClient()
    mapping["entities"]["vendor"]["cmdbuild_id"] = "UnexpectedSupplier"

    with pytest.raises(BusinessIngestionError, match="confirmed mapping"):
        prepare_business_ingestion(client, plan, mapping)

    assert client.lookup_ids == {}
    assert client.mutations == []


class Response:
    def __init__(self, data: Any) -> None:
        self.status_code = 200
        self.content = b"json"
        self._data = data

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return {"success": True, "data": self._data}


class RecordingSession:
    def __init__(self, responses: list[Response]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, str, dict[str, Any]]] = []
        self.headers: dict[str, str] = {}
        self.trust_env = True

    def request(self, method: str, url: str, **kwargs: Any) -> Response:
        self.requests.append((method, url, kwargs))
        return self.responses.pop(0)

    def close(self) -> None:
        return None


def test_client_business_write_methods_use_documented_v3_shapes() -> None:
    session = RecordingSession(
        [
            Response([]),
            Response([]),
            Response({"_id": "71"}),
            Response({"_id": 81}),
            Response({}),
            Response({}),
        ]
    )
    client = CMDBuildClient(
        CMDBuildSettings(
            base_url="http://127.0.0.1:8090/cmdbuild",
            username="admin",
            password="secret-password",
        ),
        session=session,
    )
    client._token = "not-displayed"

    assert client.cards("Supplier") == []
    assert client.domain_relations("SLAContract") == []
    assert client.create_card("Supplier", {"Code": "SUP-001"}) == 71
    assert (
        client.create_relation(
            "SLAContract",
            "SLA",
            7,
            "SupplyContract",
            8,
        )
        == 81
    )
    client.delete_relation("SLAContract", 81)
    client.delete_card("Supplier", 71)

    assert [request[0] for request in session.requests] == [
        "GET",
        "GET",
        "POST",
        "POST",
        "DELETE",
        "DELETE",
    ]
    assert session.requests[2][2]["json"] == {"Code": "SUP-001"}
    assert session.requests[3][2]["json"] == {
        "_type": "SLAContract",
        "_sourceType": "SLA",
        "_sourceId": 7,
        "_destinationType": "SupplyContract",
        "_destinationId": 8,
    }
