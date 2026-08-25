import json
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def load_configuration(filename: str) -> dict:
    path = REPOSITORY_ROOT / "config" / filename
    return json.loads(path.read_text(encoding="utf-8"))


def test_cmdbuild_identifiers_remain_undiscovered() -> None:
    config = load_configuration("cmdbuild_fields.json")

    assert config["discovery_status"] == "pending"
    assert all(
        entity["cmdbuild_id"] is None
        for entity in config["entities"].values()
    )
    assert all(
        value is None
        for entity in config["entities"].values()
        for value in entity["fields"].values()
    )
    assert all(
        domain["cmdbuild_id"] is None
        for domain in config["domains"].values()
    )


def test_business_entities_and_workflows_are_distinct() -> None:
    config = load_configuration("cmdbuild_fields.json")
    entities = config["entities"]

    assert entities["server"]["kind"] == "class"
    assert entities["business_service"]["kind"] == "class"
    assert entities["incident"]["kind"] == "process"
    assert entities["change"]["kind"] == "process"


def test_occurrence_preserves_cve_and_asset_grain() -> None:
    config = load_configuration("cmdbuild_fields.json")

    assert config["integration"]["occurrence_grain"] == [
        "cve_id",
        "asset_id",
    ]


def test_simulation_is_reproducible_and_temporally_safe() -> None:
    config = load_configuration("simulation.json")

    assert config["simulation"]["seed"] == 42
    assert config["time_model"]["timezone"] == "UTC"
    assert config["time_model"][
        "enforce_technical_evidence_as_of_detection"
    ]
    assert config["evaluation"]["same_random_seed"]
