from __future__ import annotations

import json
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from thesis_pipeline.cmdbuild.client import CMDBuildClient, CMDBuildSettings
from thesis_pipeline.cmdbuild.operational_payloads import (
    ProcessReference,
    build_operational_payload_plan,
)
from thesis_pipeline.cmdbuild.operational_writer import (
    execute_operational_ingestion,
    prepare_operational_ingestion,
)
from thesis_pipeline.models import Finding, WorkflowRecord
from thesis_pipeline.simulation.workflow import SimulationResult

ROOT = Path(__file__).resolve().parents[2]


def _finding(index: int, *, actionable: bool) -> Finding:
    created = datetime(2025, 3, 21, tzinfo=UTC) + timedelta(minutes=index)
    return Finding(
        finding_id=f"FIND-{index:04d}",
        correlation_key=f"CVE-2025-{index:04d}:ASSET-{index % 100:03d}",
        cve_id=f"CVE-2025-{index:04d}",
        asset_id=f"ASSET-{index % 100:03d}",
        service_id=f"SVC-{index % 10:02d}",
        team_id=f"TEAM-{index % 3:02d}",
        finding_created=created,
        cvss=9.2 if actionable else 5.4,
        epss_probability=0.8,
        epss_observed_at=created,
        kev=actionable,
        kev_observed_at=created,
        asset_criticality=4,
        service_criticality=4,
        internet_exposed=True,
        environment="production",
        data_sensitivity=3,
        regulatory_scope=True,
        compensating_control=False,
        triage_minutes=20,
        remediation_minutes=90,
        actionable=actionable,
        risk_weight=9.2,
    )


def _record(index: int, *, actionable: bool) -> WorkflowRecord:
    finding = _finding(index, actionable=actionable)
    alert = finding.finding_created + timedelta(minutes=1)
    correlated = alert + timedelta(minutes=1)
    assigned = correlated + timedelta(minutes=1)
    triage_started = assigned
    triage_completed = triage_started + timedelta(minutes=finding.triage_minutes)
    decision = triage_completed + timedelta(minutes=1)
    remediation_started = decision + timedelta(minutes=30) if actionable else None
    remediation_completed = (
        remediation_started + timedelta(minutes=finding.remediation_minutes)
        if remediation_started is not None
        else None
    )
    return WorkflowRecord(
        finding=finding,
        priority_rank=index,
        finding_created=finding.finding_created,
        alert_created=alert,
        correlated=correlated,
        assigned=assigned,
        triage_started=triage_started,
        triage_completed=triage_completed,
        decision=decision,
        remediation_started=remediation_started,
        remediation_completed=remediation_completed,
        sla_deadline=alert + timedelta(hours=24),
        analyst_id="ANALYST-01",
        remediator_id="REMEDIATOR-01" if actionable else None,
    )


def _mapping() -> dict[str, Any]:
    return json.loads(
        (ROOT / "config/cmdbuild_fields.json").read_text(encoding="utf-8")
    )


def _plan(count: int = 2, actionable: int = 1):
    records = tuple(_record(index, actionable=index <= actionable) for index in range(1, count + 1))
    result = SimulationResult(
        raw_finding_count=count,
        correlated_case_count=count,
        records=records,
    )
    return build_operational_payload_plan(
        result,
        _mapping(),
        public_binding_fingerprint="f" * 64,
        policy="cvss",
    )


class FakeOperationalClient:
    def __init__(self, asset_count: int = 100) -> None:
        self.next_id = 1000
        self.card_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.process_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.relation_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.lookup_ids: dict[tuple[str, str], int] = {}
        self.mutations: list[tuple[str, str, int]] = []
        self.fail_relation_at: int | None = None
        self.relation_attempts = 0
        self.card_rows["Role"].append(
            {"_id": self._id(), "Code": "SuperUser", "Description": "SuperUser"}
        )
        for index in range(asset_count):
            self.card_rows["PhysicalServer"].append(
                {"_id": self._id(), "Code": f"ASSET-{index:03d}"}
            )

    def _id(self) -> int:
        self.next_id += 1
        return self.next_id

    def resolve_lookup(self, lookup_type: str, code: str) -> int:
        key = (lookup_type, code)
        if key not in self.lookup_ids:
            self.lookup_ids[key] = self._id()
        return self.lookup_ids[key]

    def cards(self, class_id: str) -> list[dict[str, Any]]:
        return list(self.card_rows[class_id])

    def process_instances(self, process_id: str) -> list[dict[str, Any]]:
        return list(self.process_rows[process_id])

    def start_activities(self, process_id: str) -> list[dict[str, Any]]:
        activity = "IM02-HDOpening" if process_id == "IncidentMgt" else "CM01-Opening"
        return [{"_id": activity}]

    def domain_relations(self, domain_id: str) -> list[dict[str, Any]]:
        return list(self.relation_rows[domain_id])

    def create_card(self, class_id: str, attributes: dict[str, Any]) -> int:
        identifier = self._id()
        self.card_rows[class_id].append({"_id": identifier, **attributes})
        self.mutations.append(("create_card", class_id, identifier))
        return identifier

    def delete_card(self, class_id: str, card_id: int) -> None:
        self.card_rows[class_id] = [
            card for card in self.card_rows[class_id] if card.get("_id") != card_id
        ]
        self.mutations.append(("delete_card", class_id, card_id))

    def create_process_instance(
        self,
        process_id: str,
        activity_id: str,
        attributes: dict[str, Any],
        *,
        advance: bool,
    ) -> int:
        identifier = self._id()
        self.process_rows[process_id].append(
            {
                "_id": identifier,
                **attributes,
                "_activity": activity_id,
                "_advance": advance,
            }
        )
        self.mutations.append(("create_process", process_id, identifier))
        return identifier

    def delete_process_instance(self, process_id: str, instance_id: int) -> None:
        self.process_rows[process_id] = [
            process
            for process in self.process_rows[process_id]
            if process.get("_id") != instance_id
        ]
        self.mutations.append(("delete_process", process_id, instance_id))

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
            raise RuntimeError("injected relation failure")
        identifier = self._id()
        self.relation_rows[domain_id].append(
            {
                "_id": identifier,
                "_sourceType": source_type,
                "_sourceId": source_id,
                "_destinationType": destination_type,
                "_destinationId": destination_id,
            }
        )
        self.mutations.append(("create_relation", domain_id, identifier))
        return identifier

    def delete_relation(self, domain_id: str, relation_id: int) -> None:
        self.relation_rows[domain_id] = [
            relation
            for relation in self.relation_rows[domain_id]
            if relation.get("_id") != relation_id
        ]
        self.mutations.append(("delete_relation", domain_id, relation_id))


def test_smoke_plan_has_explicit_support_process_and_relation_counts() -> None:
    plan = _plan(count=201, actionable=55)

    assert dict(plan.support_counts) == {"requester": 1, "area": 1}
    assert dict(plan.process_counts) == {"incident": 201, "change": 55}
    assert dict(plan.relation_counts) == {
        "incident_asset": 201,
        "change_asset": 55,
    }
    assert len(plan.support_cards) == 2
    assert len(plan.processes) == 256
    assert len(plan.relations) == 256
    assert len(plan.fingerprint) == 64
    assert plan.fingerprint == _plan(count=201, actionable=55).fingerprint


def test_mapping_uses_portable_workflow_opening_dependencies() -> None:
    support = _mapping()["operational_support"]

    assert support["requester"] == {
        "class_id": "Employee",
        "identity_attribute": "Code",
        "identity_value": "SOC-AUTOMATION",
        "number_attribute": "Number",
        "number": "SOC-AUTOMATION",
    }
    assert support["area"]["identity_value"] == "Synthetic SOC Operations"
    assert support["role"]["identity_value"] == "SuperUser"
    assert support["channel"] == {
        "lookup_type": "ITProc - Channel",
        "code": "Monitoring",
    }


def test_change_uses_parent_reference_without_duplicate_generated_relation() -> None:
    plan = _plan()
    change = next(process for process in plan.processes if process.entity == "change")
    parent = dict(change.attributes)["ParentProcess"]

    assert isinstance(parent, ProcessReference)
    assert parent.key.startswith("incident:")
    assert {relation.domain for relation in plan.relations} == {
        "incident_asset",
        "change_asset",
    }


def test_execution_is_idempotent_and_never_advances_native_workflows() -> None:
    plan = _plan()
    client = FakeOperationalClient()

    first = execute_operational_ingestion(
        client,
        plan,
        expected_fingerprint=plan.fingerprint,
    )
    mutation_count = len(client.mutations)
    second = execute_operational_ingestion(
        client,
        plan,
        expected_fingerprint=plan.fingerprint,
    )

    assert len(first.created_support_cards) == 2
    assert len(first.created_processes) == 3
    assert len(first.created_relations) == 3
    assert second.created_support_cards == ()
    assert second.created_processes == ()
    assert second.created_relations == ()
    assert len(client.mutations) == mutation_count
    assert dict(second.preview.support_operations) == {"create": 0, "reuse": 2}
    assert dict(second.preview.process_operations) == {"create": 0, "reuse": 3}
    assert dict(second.preview.relation_operations) == {"create": 0, "reuse": 3}
    assert all(
        process["_advance"] is False
        for rows in client.process_rows.values()
        for process in rows
    )


def test_failure_rolls_back_only_objects_created_by_the_current_run() -> None:
    plan = _plan()
    client = FakeOperationalClient()
    client.fail_relation_at = 2

    try:
        execute_operational_ingestion(
            client,
            plan,
            expected_fingerprint=plan.fingerprint,
        )
    except RuntimeError as exc:
        assert str(exc) == "injected relation failure"
    else:
        raise AssertionError("The injected failure was not raised")

    assert client.card_rows["Employee"] == []
    assert client.card_rows["ITProcArea"] == []
    assert client.process_rows["IncidentMgt"] == []
    assert client.process_rows["ChangeMgt"] == []
    assert client.relation_rows["ITProcCI"] == []


class FakeResponse:
    def __init__(self, data: Any, *, status_code: int = 200, empty: bool = False) -> None:
        self.data = data
        self.status_code = status_code
        self.content = b"" if empty else b"json"

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return {"success": True, "data": self.data}


class FakeSession:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, str, dict[str, Any]]] = []
        self.headers: dict[str, str] = {}
        self.trust_env = True

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        self.requests.append((method, url, kwargs))
        return self.responses.pop(0)

    def close(self) -> None:
        return None


def test_client_uses_documented_process_instance_payload_contract() -> None:
    session = FakeSession(
        [
            FakeResponse([]),
            FakeResponse({"_id": 71}),
            FakeResponse(None, status_code=204, empty=True),
        ]
    )
    client = CMDBuildClient(
        CMDBuildSettings(
            base_url="http://127.0.0.1:8090/cmdbuild",
            username="admin",
            password="not-displayed",
        ),
        session=session,
    )
    client._token = "not-displayed"

    assert client.process_instances("IncidentMgt") == []
    assert (
        client.create_process_instance(
            "IncidentMgt",
            "IM02-HDOpening",
            {"Code": "INC-001"},
            advance=False,
        )
        == 71
    )
    client.delete_process_instance("IncidentMgt", 71)

    assert [request[0] for request in session.requests] == ["GET", "POST", "DELETE"]
    assert session.requests[1][2]["json"] == {
        "Code": "INC-001",
        "_activity": "IM02-HDOpening",
        "_advance": False,
    }


def test_preview_performs_no_mutations() -> None:
    plan = _plan()
    client = FakeOperationalClient()

    preview = prepare_operational_ingestion(client, plan)

    assert dict(preview.support_operations) == {"create": 2, "reuse": 0}
    assert dict(preview.process_operations) == {"create": 3, "reuse": 0}
    assert dict(preview.relation_operations) == {"create": 3, "reuse": 0}
    assert client.mutations == []
