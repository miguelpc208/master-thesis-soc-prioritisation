import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DISCOVERY_ROOT = ROOT / "sql" / "cmdbuild" / "discovery"
EXPECTED_QUERIES = (
    "01_list_classes.sql", "02_list_attributes.sql", "03_list_domains.sql",
    "04_list_processes.sql", "05_list_inheritance.sql",
)


def read_query(name: str) -> str:
    return (DISCOVERY_ROOT / name).read_text(encoding="utf-8")


def test_complete_discovery_query_set_exists() -> None:
    assert all((DISCOVERY_ROOT / name).is_file() for name in EXPECTED_QUERIES)


def test_discovery_queries_are_read_only() -> None:
    forbidden = re.compile(r"\b(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE)\b")
    for name in EXPECTED_QUERIES:
        query = read_query(name)
        assert "BEGIN TRANSACTION READ ONLY;" in query
        assert query.rstrip().endswith("ROLLBACK;")
        assert not forbidden.search(query.upper())


def test_queries_use_verified_native_metadata_helpers() -> None:
    assert "public._cm3_class_comment_get_jsonb" in read_query("01_list_classes.sql")
    assert "public._cm3_attribute_comment_get" in read_query("02_list_attributes.sql")
    assert "public._cm3_class_comment_get_jsonb" in read_query("03_list_domains.sql")


def test_process_discovery_uses_verified_workflow_markers() -> None:
    query = read_query("04_list_processes.sql")
    assert "WFSAVE" in query and "WFSTATUSATTR" in query and "pg_inherits" in query


def test_inheritance_query_checks_concrete_classes_and_gaps() -> None:
    query = read_query("05_list_inheritance.sql")
    assert "pg_inherits" in query and "SupplyContract" in query
    assert "PhysicalServer" in query and "VirtualServer" in query
    assert "business_service_application" in query and "incident_physical_asset" in query


def test_discovery_does_not_prematurely_mutate_field_mapping() -> None:
    mapping = json.loads((ROOT / "config" / "cmdbuild_fields.json").read_text())
    assert mapping["discovery_status"] == "pending"
    assert all(item["cmdbuild_id"] is None for item in mapping["entities"].values())
    assert all(item["cmdbuild_id"] is None for item in mapping["domains"].values())
